use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{
    Url,
    blocking::Client,
    header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use serde::Serialize;
use tracing::{debug, warn};

use crate::{config::rule::WebhookRuleConfig, routing_state::RoutingInput};

#[derive(Debug)]
pub(crate) struct RoutingWebhook {
    transport: WebhookTransport,
    headers: HeaderMap,
    deduplication: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

#[derive(Debug)]
enum WebhookTransport {
    Http {
        url: Url,
        client: Client,
    },
    #[cfg(unix)]
    Unix {
        socket: String,
        path: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookEvent {
    email: Option<String>,
    level: Option<u32>,
    protocol: String,
    network: String,
    source: Option<String>,
    destination: Option<String>,
    original_target: Option<String>,
    route_target: Option<String>,
    inbound_tag: String,
    inbound_name: Option<String>,
    inbound_local: Option<String>,
    outbound_tag: String,
    ts: u64,
}

impl RoutingWebhook {
    pub(crate) fn from_config(
        config: WebhookRuleConfig,
    ) -> Result<Option<Arc<Self>>, String> {
        let raw_url = config.url.trim();
        if raw_url.is_empty() {
            return Ok(None);
        }
        let transport = if raw_url.starts_with('/') || raw_url.starts_with('@') {
            #[cfg(unix)]
            {
                let (socket, path) = split_unix_webhook_url(raw_url)?;
                WebhookTransport::Unix { socket, path }
            }
            #[cfg(not(unix))]
            {
                return Err(
                    "routing webhook Unix sockets are not supported on this platform"
                        .into(),
                );
            }
        } else {
            let url = Url::parse(raw_url)
                .map_err(|error| format!("invalid routing webhook URL: {error}"))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(format!(
                    "routing webhook URL scheme {} is not supported",
                    url.scheme()
                ));
            }
            let client = Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|error| {
                format!("failed to build routing webhook client: {error}")
            })?;
            WebhookTransport::Http { url, client }
        };
        let mut headers = HeaderMap::new();
        for (name, value) in config.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                format!("invalid routing webhook header name {name}: {error}")
            })?;
            let value = HeaderValue::from_str(&value).map_err(|error| {
                format!("invalid routing webhook header value for {name}: {error}")
            })?;
            headers.insert(name, value);
        }
        Ok(Some(Arc::new(Self {
            transport,
            headers,
            deduplication: Duration::from_secs(config.deduplication.into()),
            seen: Mutex::new(HashMap::new()),
        })))
    }

    pub(crate) fn fire(self: &Arc<Self>, input: &RoutingInput, outbound_tag: &str) {
        if self.is_duplicate(&input.user) {
            return;
        }
        let event = WebhookEvent::from_input(input, outbound_tag);
        let notifier = Arc::clone(self);
        std::thread::spawn(move || notifier.post(event));
    }

    fn is_duplicate(&self, user: &str) -> bool {
        if self.deduplication.is_zero() || user.is_empty() {
            return false;
        }
        let now = Instant::now();
        let Ok(mut seen) = self.seen.lock() else {
            return false;
        };
        seen.retain(|_, timestamp| {
            now.duration_since(*timestamp) < self.deduplication
        });
        if seen.contains_key(user) {
            return true;
        }
        seen.insert(user.to_string(), now);
        false
    }

    fn post(&self, event: WebhookEvent) {
        let body = match serde_json::to_vec(&event) {
            Ok(body) => body,
            Err(error) => {
                warn!("routing webhook JSON encoding failed: {error}");
                return;
            }
        };
        match &self.transport {
            WebhookTransport::Http { url, client } => {
                let response = client
                    .post(url.clone())
                    .headers(self.headers.clone())
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .send();
                match response {
                    Ok(response) => {
                        let status = response.status();
                        if let Err(error) = response.bytes() {
                            debug!("routing webhook response drain failed: {error}");
                        }
                        if status.as_u16() >= 400 {
                            warn!("routing webhook POST returned status {status}");
                        }
                    }
                    Err(error) => debug!("routing webhook POST failed: {error}"),
                }
            }
            #[cfg(unix)]
            WebhookTransport::Unix { socket, path } => {
                if let Err(error) = post_unix(socket, path, &self.headers, &body) {
                    debug!("routing Unix webhook POST failed: {error}");
                }
            }
        }
    }
}

#[cfg(unix)]
fn split_unix_webhook_url(raw: &str) -> Result<(String, String), String> {
    let (socket, path) = raw
        .find(":/")
        .map(|index| (raw[..index].to_string(), raw[index + 1..].to_string()))
        .unwrap_or_else(|| (raw.to_string(), "/".to_string()));
    if socket.is_empty() {
        return Err("routing webhook Unix socket path is required".into());
    }
    if !socket.starts_with('/') && !socket.starts_with('@') {
        return Err(format!(
            "routing webhook Unix socket path must be absolute or abstract: {socket}"
        ));
    }
    Ok((socket, normalize_http_path(&path)))
}

#[cfg(unix)]
fn normalize_http_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

#[cfg(unix)]
fn post_unix(
    socket: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};

    let mut stream = connect_unix(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )?;
    for (name, value) in headers {
        write!(
            stream,
            "{}: {}\r\n",
            name.as_str(),
            value.to_str().unwrap_or_default()
        )?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut response = [0u8; 256];
    let read = stream.read(&mut response)?;
    let status_line = String::from_utf8_lossy(&response[..read])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let success = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .is_some_and(|status| status < 400);
    if success {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "routing Unix webhook returned {status_line}"
        )))
    }
}

#[cfg(unix)]
fn connect_unix(socket: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    if socket.starts_with('@') {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            return connect_abstract_unix(socket);
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "abstract Unix sockets are not supported on this platform",
            ));
        }
    }
    std::os::unix::net::UnixStream::connect(socket)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn connect_abstract_unix(
    socket: &str,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::{mem::size_of, os::fd::FromRawFd as _};

    let padded = socket.starts_with("@@");
    let name = if padded { &socket[2..] } else { &socket[1..] };
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "abstract Unix socket name is empty",
        ));
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let capacity = address.sun_path.len().saturating_sub(1);
    let name = name.as_bytes();
    if name.len() > capacity {
        unsafe {
            libc::close(fd);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "abstract Unix socket name is too long",
        ));
    }
    for (target, source) in
        address.sun_path[1..].iter_mut().zip(name.iter().copied())
    {
        *target = source as libc::c_char;
    }
    let path_offset = size_of::<libc::sa_family_t>();
    let address_len = if padded {
        size_of::<libc::sockaddr_un>()
    } else {
        path_offset + 1 + name.len()
    } as libc::socklen_t;
    let connected = unsafe {
        libc::connect(
            fd,
            (&raw const address).cast::<libc::sockaddr>(),
            address_len,
        )
    };
    if connected < 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }
    Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) })
}

impl WebhookEvent {
    fn from_input(input: &RoutingInput, outbound_tag: &str) -> Self {
        Self {
            email: (!input.user.is_empty()).then(|| input.user.clone()),
            level: None,
            protocol: input.protocol.clone(),
            network: match input.network {
                2 => "tcp",
                3 => "udp",
                4 => "unix",
                _ => "unknown",
            }
            .to_string(),
            source: endpoint(
                input.source_ips.iter().find_map(|value| decode_ip(value)),
                input.source_port,
                None,
            ),
            destination: endpoint(
                input.target_ips.iter().find_map(|value| decode_ip(value)),
                input.target_port,
                (!input.target_domain.is_empty())
                    .then_some(input.target_domain.as_str()),
            ),
            original_target: None,
            route_target: None,
            inbound_tag: input.inbound_tag.clone(),
            inbound_name: None,
            inbound_local: endpoint(
                input.local_ips.iter().find_map(|value| decode_ip(value)),
                input.local_port,
                None,
            ),
            outbound_tag: outbound_tag.to_string(),
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

fn endpoint(ip: Option<IpAddr>, port: u32, domain: Option<&str>) -> Option<String> {
    let port = port as u16;
    if let Some(domain) = domain {
        return Some(format!("{domain}:{port}"));
    }
    ip.map(|ip| std::net::SocketAddr::new(ip, port).to_string())
}

fn decode_ip(input: &[u8]) -> Option<IpAddr> {
    match input {
        [a, b, c, d] => Some(IpAddr::from([*a, *b, *c, *d])),
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => Some(IpAddr::from([
            *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o, *p,
        ])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_xray_compatible_event_fields() {
        let event = WebhookEvent::from_input(
            &RoutingInput {
                inbound_tag: "in".into(),
                network: 2,
                source_ips: vec![vec![127, 0, 0, 1]],
                source_port: 1234,
                target_domain: "example.com".into(),
                target_port: 443,
                protocol: "tls".into(),
                user: "alice@example.com".into(),
                local_ips: vec![vec![10, 0, 0, 1]],
                local_port: 8443,
                ..RoutingInput::default()
            },
            "direct",
        );
        let value = serde_json::to_value(event).expect("encode webhook event");
        assert_eq!(value["email"], "alice@example.com");
        assert_eq!(value["network"], "tcp");
        assert_eq!(value["source"], "127.0.0.1:1234");
        assert_eq!(value["destination"], "example.com:443");
        assert_eq!(value["inboundTag"], "in");
        assert_eq!(value["inboundLocal"], "10.0.0.1:8443");
        assert_eq!(value["outboundTag"], "direct");
        assert!(value["level"].is_null());
        assert!(value["originalTarget"].is_null());
        assert!(value["routeTarget"].is_null());
        assert!(value["inboundName"].is_null());
    }

    #[cfg(unix)]
    #[test]
    fn splits_xray_unix_webhook_url() {
        assert_eq!(
            split_unix_webhook_url("/tmp/router.sock:/hook").unwrap(),
            ("/tmp/router.sock".into(), "/hook".into())
        );
        assert_eq!(
            split_unix_webhook_url("@router").unwrap(),
            ("@router".into(), "/".into())
        );
    }

    #[cfg(unix)]
    #[test]
    fn posts_webhook_through_filesystem_unix_socket() {
        use std::io::{Read as _, Write as _};

        let path = std::env::temp_dir().join(format!(
            "chimera-routing-webhook-{}-{}.sock",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let listener = std::os::unix::net::UnixListener::bind(&path)
            .expect("bind Unix webhook listener");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept Unix webhook");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).expect("read Unix webhook");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or_default();
                if request.len() >= header_end + content_length {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write Unix webhook response");
            request
        });

        let webhook = RoutingWebhook::from_config(WebhookRuleConfig {
            url: format!("{}:/route", path.display()),
            headers: HashMap::from([("X-Unix".into(), "yes".into())]),
            ..WebhookRuleConfig::default()
        })
        .expect("build Unix webhook")
        .expect("Unix webhook missing");
        webhook.post(WebhookEvent::from_input(
            &RoutingInput {
                inbound_tag: "unix-in".into(),
                target_domain: "example.com".into(),
                target_port: 443,
                ..RoutingInput::default()
            },
            "direct",
        ));

        let request = server.join().expect("Unix webhook server thread");
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("POST /route HTTP/1.1"));
        assert!(request.to_ascii_lowercase().contains("x-unix: yes"));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn posts_webhook_through_abstract_unix_socket() {
        use std::io::{Read as _, Write as _};

        let name = format!(
            "chimera-routing-webhook-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let listener = bind_abstract_listener(&name).expect("bind abstract webhook");
        let server = std::thread::spawn(move || {
            let (mut stream, _) =
                listener.accept().expect("accept abstract webhook");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).expect("read abstract webhook");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or_default();
                if request.len() >= header_end + content_length {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write abstract webhook response");
            request
        });
        let webhook = RoutingWebhook::from_config(WebhookRuleConfig {
            url: format!("@{name}:/abstract"),
            ..WebhookRuleConfig::default()
        })
        .expect("build abstract webhook")
        .expect("abstract webhook missing");
        webhook.post(WebhookEvent::from_input(&RoutingInput::default(), "direct"));
        let request = server.join().expect("abstract webhook server thread");
        assert!(
            String::from_utf8_lossy(&request).starts_with("POST /abstract HTTP/1.1")
        );
    }

    #[cfg(target_os = "linux")]
    fn bind_abstract_listener(
        name: &str,
    ) -> std::io::Result<std::os::unix::net::UnixListener> {
        use std::{mem::size_of, os::fd::FromRawFd as _};

        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if name.len() > address.sun_path.len().saturating_sub(1) {
            unsafe {
                libc::close(fd);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "abstract listener name is too long",
            ));
        }
        for (target, source) in address.sun_path[1..]
            .iter_mut()
            .zip(name.as_bytes().iter().copied())
        {
            *target = source as libc::c_char;
        }
        let address_len =
            (size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
        let bound = unsafe {
            libc::bind(
                fd,
                (&raw const address).cast::<libc::sockaddr>(),
                address_len,
            )
        };
        if bound < 0 || unsafe { libc::listen(fd, 1) } < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }
        Ok(unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) })
    }
}
