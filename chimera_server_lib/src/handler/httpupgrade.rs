use std::{collections::HashMap, io};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

const MAX_HEADER_BYTES: usize = 12 * 1024;

#[derive(Debug)]
pub struct HttpUpgradeTcpServerHandler {
    host: Option<String>,
    path: String,
    accept_proxy_protocol: bool,
    trusted_x_forwarded_for: Vec<String>,
    inner: Box<dyn TcpServerHandler>,
}

impl HttpUpgradeTcpServerHandler {
    pub fn new(
        host: Option<String>,
        path: String,
        accept_proxy_protocol: bool,
        trusted_x_forwarded_for: Vec<String>,
        inner: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            host: host.map(|value| value.trim().to_ascii_lowercase()),
            path: normalize_path(path),
            accept_proxy_protocol,
            trusted_x_forwarded_for,
            inner,
        }
    }

    async fn upgrade(
        &self,
        stream: &mut Box<dyn AsyncStream>,
    ) -> io::Result<Option<std::net::SocketAddr>> {
        // Xray v26.2.6 calls http.ReadRequest directly here. Unlike its
        // WebSocket transport, HTTPUpgrade does not impose a transport-level
        // four-second header timeout; the inner inbound owns its handshake
        // policy after the upgrade completes.
        let request = read_http_header(stream).await?;
        let (method, target, version, headers) = parse_request(&request)?;
        if method != "GET" || version != "HTTP/1.1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPUpgrade requires GET over HTTP/1.1",
            ));
        }
        let path = decode_request_path(target)?;
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

        let forwarded_peer =
            trusted_forwarded_peer(&headers, &self.trusted_x_forwarded_for);
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        Ok(forwarded_peer)
    }
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeTcpServerHandler {
    fn manages_handshake_timeout(&self) -> bool {
        self.inner.manages_handshake_timeout()
    }

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
        // Xray v26.2.6 enables PROXY protocol on the system listener via
        // go-proxyproto. That listener does not impose the WebSocket
        // transport's four-second handshake deadline, so a partial PROXY
        // header remains pending until the connection itself is closed.
        let peer_addr = if self.accept_proxy_protocol {
            read_proxy_protocol(&mut server_stream).await?
        } else {
            None
        };
        let forwarded_peer = self.upgrade(&mut server_stream).await?;
        let effective_peer = forwarded_peer.or(peer_addr);
        let mut context = context;
        if let Some(peer_addr) = effective_peer {
            context.peer_addr = Some(peer_addr);
        }
        let result = self
            .inner
            .setup_server_stream_with_context(server_stream, context)
            .await?;
        Ok(match effective_peer {
            Some(peer_addr) => TcpServerSetupResult::PeerAddrOverride {
                peer_addr,
                inner: Box::new(result),
            },
            None => result,
        })
    }
}

async fn read_proxy_protocol(
    stream: &mut Box<dyn AsyncStream>,
) -> io::Result<Option<std::net::SocketAddr>> {
    const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

    let mut prefix = [0u8; 12];
    stream.read_exact(&mut prefix).await?;
    if &prefix == V2_SIGNATURE {
        let mut fixed = [0u8; 4];
        stream.read_exact(&mut fixed).await?;
        let version_command = fixed[0];
        if version_command >> 4 != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v2 version",
            ));
        }
        let family_protocol = fixed[1];
        let payload_len = u16::from_be_bytes([fixed[2], fixed[3]]) as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await?;

        if version_command & 0x0f == 0 {
            return Ok(None);
        }
        if version_command & 0x0f != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v2 command",
            ));
        }
        match family_protocol >> 4 {
            1 if payload.len() >= 12 => {
                let source = std::net::Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                );
                let source_port = u16::from_be_bytes([payload[8], payload[9]]);
                Ok(Some(std::net::SocketAddr::new(source.into(), source_port)))
            }
            2 if payload.len() >= 36 => {
                let mut source = [0u8; 16];
                source.copy_from_slice(&payload[..16]);
                let source_port = u16::from_be_bytes([payload[32], payload[33]]);
                Ok(Some(std::net::SocketAddr::new(
                    std::net::Ipv6Addr::from(source).into(),
                    source_port,
                )))
            }
            0 => Ok(None),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v2 address family",
            )),
        }
    } else if prefix.starts_with(b"PROXY ") {
        let mut line = prefix.to_vec();
        while !line.ends_with(b"\r\n") {
            if line.len() >= 108 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PROXY protocol v1 header is too long",
                ));
            }
            line.push(stream.read_u8().await?);
        }
        let line = std::str::from_utf8(&line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid PROXY protocol v1 encoding: {error}"),
            )
        })?;
        let mut fields = line.trim_end_matches("\r\n").split_whitespace();
        if fields.next() != Some("PROXY") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v1 header",
            ));
        }
        let family = fields.next().unwrap_or_default();
        if family == "UNKNOWN" {
            return Ok(None);
        }
        if !matches!(family, "TCP4" | "TCP6") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v1 family",
            ));
        }
        let source_ip = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing PROXY source IP")
            })?
            .parse::<std::net::IpAddr>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY source IP: {error}"),
                )
            })?;
        let destination_ip = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing PROXY destination IP",
                )
            })?
            .parse::<std::net::IpAddr>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY destination IP: {error}"),
                )
            })?;
        let source_port = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing PROXY source port",
                )
            })?
            .parse::<u16>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY source port: {error}"),
                )
            })?;
        let _destination_port = fields
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing PROXY destination port",
                )
            })?
            .parse::<u16>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid PROXY destination port: {error}"),
                )
            })?;
        if fields.next().is_some()
            || (family == "TCP4"
                && (!source_ip.is_ipv4() || !destination_ip.is_ipv4()))
            || (family == "TCP6"
                && (!source_ip.is_ipv6() || !destination_ip.is_ipv6()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PROXY protocol v1 address family",
            ));
        }
        Ok(Some(std::net::SocketAddr::new(source_ip, source_port)))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing required PROXY protocol header",
        ))
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

fn trusted_forwarded_peer(
    headers: &HashMap<String, String>,
    trusted_x_forwarded_for: &[String],
) -> Option<std::net::SocketAddr> {
    if !trusted_x_forwarded_for.is_empty()
        && !trusted_x_forwarded_for
            .iter()
            .any(|header| headers.contains_key(&header.to_ascii_lowercase()))
    {
        return None;
    }

    let first = headers.get("x-forwarded-for")?.split(',').next()?;
    let mut candidate = first;
    if candidate.starts_with('[') && candidate.ends_with(']') {
        candidate = &candidate[1..candidate.len() - 1];
    }
    if candidate
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || candidate
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        candidate = candidate.trim();
    }

    let ip = candidate.parse::<std::net::IpAddr>().ok()?;
    let ip = match ip {
        std::net::IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ipv6), std::net::IpAddr::V4),
        ip => ip,
    };
    Some(std::net::SocketAddr::new(ip, 0))
}

fn normalize_path(path: String) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn decode_request_path(target: &str) -> io::Result<String> {
    let raw_path = target.split(['?', '#']).next().unwrap_or(target);
    let bytes = raw_path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade path escape",
            ));
        }
        let high = (bytes[index + 1] as char).to_digit(16);
        let low = (bytes[index + 2] as char).to_digit(16);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade path escape",
            ));
        };
        decoded.push(((high << 4) | low) as u8);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTPUpgrade path is not valid UTF-8",
        )
    })
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
        time::Duration,
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

    use super::{HttpUpgradeTcpServerHandler, trusted_forwarded_peer};

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

    #[derive(Debug)]
    struct TimeoutManagingInner;

    #[async_trait]
    impl TcpServerHandler for TimeoutManagingInner {
        fn manages_handshake_timeout(&self) -> bool {
            true
        }

        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Inner.setup_server_stream(stream).await
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
    fn honors_xray_trusted_forwarded_headers() {
        let headers = HashMap::from([
            (
                "x-forwarded-for".to_string(),
                "203.0.113.77, 198.51.100.2".to_string(),
            ),
            ("x-trusted-cdn".to_string(), "yes".to_string()),
        ]);
        assert_eq!(
            trusted_forwarded_peer(&headers, &[]),
            Some("203.0.113.77:0".parse().unwrap())
        );
        assert_eq!(
            trusted_forwarded_peer(&headers, &["X-Missing".into()]),
            None
        );
        assert_eq!(
            trusted_forwarded_peer(&headers, &["X-Trusted-CDN".into()]),
            Some("203.0.113.77:0".parse().unwrap())
        );
        assert_eq!(
            trusted_forwarded_peer(&headers, &[" X-Trusted-CDN ".into()]),
            None
        );
    }

    #[test]
    fn propagates_inner_handshake_timeout_ownership() {
        let unmanaged = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        assert!(!unmanaged.manages_handshake_timeout());

        let managed = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(TimeoutManagingInner),
        );
        assert!(managed.manages_handshake_timeout());
    }

    #[tokio::test]
    async fn does_not_apply_websocket_four_second_header_timeout() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();

        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
        });
        tokio::time::sleep(Duration::from_millis(4_100)).await;
        assert!(
            !setup.is_finished(),
            "Xray HTTPUpgrade remains pending past the WebSocket four-second deadline"
        );

        client
            .write_all(b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        let result = setup.await.unwrap().expect("HTTPUpgrade handshake");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }

    #[tokio::test]
    async fn upgrades_and_preserves_first_protocol_bytes() {
        let handler = HttpUpgradeTcpServerHandler::new(
            Some("example.com".into()),
            "upgrade".into(),
            false,
            Vec::new(),
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
    async fn preserves_xray_httpupgrade_path_whitespace() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "ws ".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                b"GET /ws%20 HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("percent-encoded Xray HTTPUpgrade path should match");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
        let mut response = vec![0u8; 77];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 101 Switching Protocols")
        );
    }

    #[tokio::test]
    async fn proxy_protocol_does_not_inherit_websocket_four_second_timeout() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client.write_all(b"PROXY ").await.unwrap();

        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
        });
        tokio::time::sleep(Duration::from_millis(4_100)).await;
        assert!(
            !setup.is_finished(),
            "Xray system listener keeps a partial PROXY header pending past four seconds"
        );

        client
            .write_all(
                b"TCP4 198.51.100.7 203.0.113.9 45678 443\r\n\
                  GET /upgrade HTTP/1.1\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let result = setup
            .await
            .unwrap()
            .expect("HTTPUpgrade with delayed PROXY v1");
        let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result
        else {
            panic!("expected peer address override");
        };
        assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
        assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
    }

    #[tokio::test]
    async fn accepts_proxy_protocol_v1_and_overrides_peer_address() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                b"PROXY TCP4 198.51.100.7 203.0.113.9 45678 443\r\n\
                  GET /upgrade HTTP/1.1\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("HTTPUpgrade with PROXY v1");
        let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result
        else {
            panic!("expected peer address override");
        };
        assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
        assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
    }

    #[tokio::test]
    async fn accepts_proxy_protocol_v2_and_overrides_peer_address() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        request.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        request.extend_from_slice(&[198, 51, 100, 8]);
        request.extend_from_slice(&[203, 0, 113, 10]);
        request.extend_from_slice(&45679u16.to_be_bytes());
        request.extend_from_slice(&443u16.to_be_bytes());
        request.extend_from_slice(
            b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );
        client.write_all(&request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("HTTPUpgrade with PROXY v2");
        let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result
        else {
            panic!("expected peer address override");
        };
        assert_eq!(peer_addr, "198.51.100.8:45679".parse().unwrap());
        assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
    }

    #[tokio::test]
    async fn rejects_wrong_path() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/expected".into(),
            false,
            Vec::new(),
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
