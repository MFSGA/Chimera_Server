use std::{
    collections::{HashMap, HashSet},
    io,
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_HEADER_BYTES: usize = 12 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct HttpUpgradeClientConfig {
    host: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl HttpUpgradeClientConfig {
    pub(crate) fn compile(
        host: Option<&str>,
        path: Option<&str>,
        headers: &HashMap<String, String>,
        fallback_host: &str,
        accept_proxy_protocol: bool,
        outbound_tag: &str,
    ) -> Result<Self, String> {
        if accept_proxy_protocol {
            return Err(format!(
                "outbound {outbound_tag} HTTPUpgrade acceptProxyProtocol is server-only"
            ));
        }

        let mut normalized_headers = Vec::with_capacity(headers.len());
        let mut seen_headers = HashSet::with_capacity(headers.len());
        for (name, value) in headers {
            validate_client_header_name(name, outbound_tag)?;
            validate_client_header_value(value, outbound_tag)?;
            let normalized = name.trim().to_ascii_lowercase();
            if !seen_headers.insert(normalized.clone()) {
                return Err(format!(
                    "outbound {outbound_tag} has duplicate HTTPUpgrade header {normalized}"
                ));
            }
            if matches!(normalized.as_str(), "host" | "connection" | "upgrade") {
                return Err(format!(
                    "outbound {outbound_tag} cannot override reserved HTTPUpgrade header {name}"
                ));
            }
            normalized_headers
                .push((name.trim().to_string(), value.trim().to_string()));
        }

        let host = host
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback_host)
            .to_string();
        validate_client_header_value(&host, outbound_tag)?;
        if host.is_empty() {
            return Err(format!(
                "outbound {outbound_tag} HTTPUpgrade host must not be empty"
            ));
        }

        let mut path = path.unwrap_or("/").trim().to_string();
        if path.is_empty() {
            path.push('/');
        } else if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if path.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
            return Err(format!(
                "outbound {outbound_tag} HTTPUpgrade path contains invalid whitespace or control bytes"
            ));
        }
        if path_has_early_data(&path) {
            return Err(format!(
                "outbound {outbound_tag} HTTPUpgrade early data is not supported yet"
            ));
        }

        Ok(Self {
            host,
            path,
            headers: normalized_headers,
        })
    }

    pub(crate) async fn connect(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let mut request = format!(
            concat!(
                "GET {} HTTP/1.1\r\n",
                "Host: {}\r\n",
                "Connection: Upgrade\r\n",
                "Upgrade: websocket\r\n"
            ),
            self.path, self.host,
        );
        for (name, value) in &self.headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let response = timeout(HANDSHAKE_TIMEOUT, read_http_header(&mut stream))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTPUpgrade client handshake timed out",
                )
            })??;
        let (version, status, headers) = parse_response(&response)?;
        if version != "HTTP/1.1" || status != "101" {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("HTTPUpgrade rejected with response {version} {status}"),
            ));
        }
        if !header_contains_token(&headers, "connection", "upgrade")
            || !header_contains_token(&headers, "upgrade", "websocket")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unrecognized HTTPUpgrade response",
            ));
        }
        Ok(stream)
    }
}

#[derive(Debug)]
pub struct HttpUpgradeTcpServerHandler {
    host: Option<String>,
    path: String,
    inner: Box<dyn TcpServerHandler>,
}

impl HttpUpgradeTcpServerHandler {
    pub fn new(
        host: Option<String>,
        path: String,
        inner: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            host: host.map(|value| value.trim().to_ascii_lowercase()),
            path: normalize_path(path),
            inner,
        }
    }

    async fn upgrade(&self, stream: &mut Box<dyn AsyncStream>) -> io::Result<()> {
        let request = timeout(HANDSHAKE_TIMEOUT, read_http_header(stream))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTPUpgrade handshake timed out",
                )
            })??;
        let (method, target, version, headers) = parse_request(&request)?;
        if method != "GET" || version != "HTTP/1.1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPUpgrade requires GET over HTTP/1.1",
            ));
        }
        let path = target.split(['?', '#']).next().unwrap_or(target);
        if path != self.path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("HTTPUpgrade path mismatch: {path}"),
            ));
        }
        if let Some(expected) = &self.host {
            let actual = headers.get("host").map(String::as_str).unwrap_or("");
            if !http_host_matches(actual, expected) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("HTTPUpgrade host mismatch: {actual}"),
                ));
            }
        }
        if headers
            .get("connection")
            .map(|value| value.trim().eq_ignore_ascii_case("upgrade"))
            != Some(true)
            || headers
                .get("upgrade")
                .map(|value| value.trim().eq_ignore_ascii_case("websocket"))
                != Some(true)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unrecognized HTTPUpgrade request",
            ));
        }

        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await?;
        stream.flush().await
    }
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_context(
            server_stream,
            TcpServerConnectionContext::default(),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        self.upgrade(&mut server_stream).await?;
        self.inner
            .setup_server_stream_with_context(server_stream, context)
            .await
    }
}

async fn read_http_header(stream: &mut Box<dyn AsyncStream>) -> io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(512);
    while header.len() < MAX_HEADER_BYTES {
        let byte = stream.read_u8().await?;
        header.push(byte);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTPUpgrade headers exceed 12288 bytes",
    ))
}

fn parse_request(
    request: &[u8],
) -> io::Result<(&str, &str, &str, HashMap<String, String>)> {
    let request = std::str::from_utf8(request).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTPUpgrade header encoding: {error}"),
        )
    })?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade request line",
        ));
    }
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok((method, target, version, headers))
}

fn parse_response(
    response: &[u8],
) -> io::Result<(&str, &str, HashMap<String, String>)> {
    let response = std::str::from_utf8(response).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTPUpgrade response encoding: {error}"),
        )
    })?;
    let mut lines = response.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if version.is_empty() || status.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade response line",
        ));
    }
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok((version, status, headers))
}

fn header_contains_token(
    headers: &HashMap<String, String>,
    name: &str,
    expected: &str,
) -> bool {
    headers.get(name).is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case(expected))
    })
}

fn validate_client_header_name(
    name: &str,
    outbound_tag: &str,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(format!(
            "outbound {outbound_tag} has invalid HTTPUpgrade header name {name}"
        ));
    }
    Ok(())
}

fn validate_client_header_value(
    value: &str,
    outbound_tag: &str,
) -> Result<(), String> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(format!(
            "outbound {outbound_tag} HTTPUpgrade header value contains forbidden control bytes"
        ));
    }
    Ok(())
}

fn path_has_early_data(path: &str) -> bool {
    let Some((_, query)) = path.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        pair.split_once('=')
            .map(|(key, value)| key.eq_ignore_ascii_case("ed") && !value.is_empty())
            .unwrap_or_else(|| pair.eq_ignore_ascii_case("ed"))
    })
}

fn normalize_path(path: String) -> String {
    let path = path.trim();
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn http_host_matches(actual: &str, expected: &str) -> bool {
    let actual = actual.trim().to_ascii_lowercase();
    if actual == expected {
        return true;
    }
    if expected.starts_with('[') {
        return actual
            .strip_suffix(']')
            .is_some_and(|value| format!("{value}]") == expected);
    }
    actual
        .split_once(':')
        .map(|(host, _)| host == expected)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        pin::Pin,
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use crate::{
        address::{Address, NetLocation},
        async_stream::{AsyncPing, AsyncStream},
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::{HttpUpgradeClientConfig, HttpUpgradeTcpServerHandler};

    #[derive(Debug)]
    struct Inner;

    #[async_trait]
    impl TcpServerHandler for Inner {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::TcpForward {
                remote_location: NetLocation::new(
                    Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    443,
                ),
                stream,
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context: None,
            })
        }
    }

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[test]
    fn client_config_normalizes_path_and_rejects_unsupported_features() {
        let config = HttpUpgradeClientConfig::compile(
            Some("upgrade.example"),
            Some("proxy"),
            &HashMap::from([("X-Test".into(), "value".into())]),
            "fallback.example",
            false,
            "proxy",
        )
        .expect("valid HTTPUpgrade client settings should compile");
        assert_eq!(config.host, "upgrade.example");
        assert_eq!(config.path, "/proxy");
        assert_eq!(config.headers, vec![("X-Test".into(), "value".into())]);

        assert!(
            HttpUpgradeClientConfig::compile(
                None,
                Some("/?ed=2048"),
                &HashMap::new(),
                "fallback.example",
                false,
                "proxy",
            )
            .unwrap_err()
            .contains("early data")
        );
        assert!(
            HttpUpgradeClientConfig::compile(
                None,
                None,
                &HashMap::from([("Host".into(), "other.example".into())]),
                "fallback.example",
                false,
                "proxy",
            )
            .unwrap_err()
            .contains("reserved")
        );
        assert!(
            HttpUpgradeClientConfig::compile(
                None,
                None,
                &HashMap::new(),
                "fallback.example",
                true,
                "proxy",
            )
            .unwrap_err()
            .contains("server-only")
        );
    }

    #[tokio::test]
    async fn client_upgrade_returns_raw_stream_and_preserves_response_bytes() {
        let (client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /upgrade HTTP/1.1\r\n"));
            assert!(request.contains("Host: upgrade.example\r\n"));
            assert!(request.contains("X-Test: value\r\n"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nreply",
                )
                .await
                .unwrap();
            let mut protocol = [0u8; 8];
            server.read_exact(&mut protocol).await.unwrap();
            assert_eq!(&protocol, b"protocol");
        });
        let config = HttpUpgradeClientConfig::compile(
            Some("upgrade.example"),
            Some("/upgrade"),
            &HashMap::from([("X-Test".into(), "value".into())]),
            "fallback.example",
            false,
            "proxy",
        )
        .unwrap();
        let mut stream = config
            .connect(Box::new(TestStream(client)))
            .await
            .expect("HTTPUpgrade client handshake should succeed");
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        stream.write_all(b"protocol").await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn upgrades_and_preserves_first_protocol_bytes() {
        let handler = HttpUpgradeTcpServerHandler::new(
            Some("example.com".into()),
            "upgrade".into(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                b"GET /upgrade?x=1 HTTP/1.1\r\n\
                  Host: example.com:80\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\nprotocol",
            )
            .await
            .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("HTTPUpgrade handshake");
        let mut response = vec![0u8; 77];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 101 Switching Protocols")
        );
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("expected forwarded upgraded stream");
        };
        let mut protocol = [0u8; 8];
        stream.read_exact(&mut protocol).await.unwrap();
        assert_eq!(&protocol, b"protocol");
    }

    #[tokio::test]
    async fn rejects_wrong_path() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/expected".into(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(1024);
        client
            .write_all(
                b"GET /wrong HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("wrong path must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("path mismatch"));
    }
}
