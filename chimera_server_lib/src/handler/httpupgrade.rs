use std::{collections::HashMap, io};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

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
            host: host.map(|value| value.to_ascii_lowercase()),
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
        let (_method, target, _version, headers) = parse_request(&request)?;
        let target = parse_request_target(target)?;
        let path = decode_request_path(target.path)?;
        if path != self.path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("HTTPUpgrade path mismatch: {path}"),
            ));
        }
        if let Some(expected) = &self.host {
            // Go's http.ReadRequest gives absolute-form request-target authority
            // precedence over the Host header via req.Host.
            let actual = target
                .authority
                .or_else(|| headers.get("host").map(String::as_str))
                .unwrap_or("");
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
            // go-proxyproto v0.9.2 (used by Xray v26.2.6) still validates the
            // address-block length for LOCAL frames when the family nibble is
            // IPv4, IPv6, or UNIX. The transport nibble itself is ignored for
            // this check. UNSPEC/unknown families remain length-agnostic.
            let minimum_address_len = match family_protocol >> 4 {
                1 => Some(12),
                2 => Some(36),
                3 => Some(216),
                _ => None,
            };
            if minimum_address_len.is_some_and(|minimum| payload_len < minimum) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid PROXY protocol v2 LOCAL address length",
                ));
            }
            return Ok(None);
        }
        if version_command & 0x0f != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported PROXY protocol v2 command",
            ));
        }
        let family = family_protocol >> 4;
        let transport = family_protocol & 0x0f;
        match family {
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
            // go-proxyproto v0.9.2 accepts UNIX addresses but Xray's
            // HTTPUpgrade path only needs the connection to proceed. Chimera's
            // logical peer type is SocketAddr, so consume the address block and
            // keep the underlying TCP peer instead of rejecting the handshake.
            3 if payload.len() >= 216 => Ok(None),
            // The v0.9.2 parser also accepts the odd half-specified family /
            // transport combinations where exactly one nibble is UNSPEC. They
            // carry no IP endpoint, so there is nothing to override locally.
            0 if transport != 0 => Ok(None),
            4..=15 if transport == 0 => Ok(None),
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
        // go-proxyproto v0.9.2 (used by Xray v26.2.6) splits the v1 line on
        // literal single spaces. Repeated whitespace therefore produces empty
        // fields instead of being collapsed like `split_whitespace()` would.
        let mut fields = line.trim_end_matches("\r\n").split(' ');
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
        // Xray's go-proxyproto v0.9.2 only requires at least the six standard
        // TCP4/TCP6 tokens and ignores any trailing tokens before CRLF.
        if (family == "TCP4" && (!source_ip.is_ipv4() || !destination_ip.is_ipv4()))
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
    // Xray v26.2.6 parses HTTPUpgrade with a default 4096-byte bufio.Reader,
    // then discards that reader after http.ReadRequest. Any inner-protocol
    // bytes read ahead into the same buffer are therefore lost. Mirror that
    // observable behavior instead of preserving bytes that arrive together
    // with the upgrade request.
    let mut header = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade request ended before headers completed",
            ));
        }
        header.extend_from_slice(&chunk[..read]);
        if let Some(end) = http_header_end(&header) {
            header.truncate(end);
            return Ok(header);
        }
    }
}

fn http_header_end(header: &[u8]) -> Option<usize> {
    header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            header
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
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
    let mut lines = request
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || !is_xray_http_version(version)
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade request line",
        ));
    }
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut continuation_target: Option<(String, bool)> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let Some((name, keep_value)) = continuation_target.as_ref() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTPUpgrade header continuation",
                ));
            };
            let continuation = line.trim();
            if *keep_value && let Some(value) = headers.get_mut(name) {
                if !value.is_empty() && !continuation.is_empty() {
                    value.push(' ');
                }
                value.push_str(continuation);
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade header line",
            ));
        };
        if name.is_empty() || name.bytes().any(is_invalid_http_header_name_byte) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade header name",
            ));
        }
        if value.bytes().any(is_invalid_http_header_value_byte) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade header value",
            ));
        }
        let name = name.to_ascii_lowercase();
        if headers.contains_key(&name) {
            // Go's textproto reader still folds continuation lines into the
            // most recent duplicate value, while Header.Get() keeps returning
            // the first value. We can discard the duplicate payload itself,
            // but its continuation lines must remain syntactically valid.
            continuation_target = Some((name, false));
            continue;
        }
        headers.insert(name.clone(), value.trim().to_string());
        continuation_target = Some((name, true));
    }
    Ok((method, target, version, headers))
}

fn is_invalid_http_header_name_byte(byte: u8) -> bool {
    byte <= 0x1f || byte == 0x7f
}

fn is_invalid_http_header_value_byte(byte: u8) -> bool {
    (byte < b' ' && byte != b'\t') || byte == 0x7f
}

fn is_xray_http_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    bytes.len() == 8
        && &bytes[..5] == b"HTTP/"
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'.'
        && bytes[7].is_ascii_digit()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HttpUpgradeRequestTarget<'a> {
    path: &'a str,
    authority: Option<&'a str>,
}

fn parse_request_target(target: &str) -> io::Result<HttpUpgradeRequestTarget<'_>> {
    // Go's http.ReadRequest rejects request-target fragments before the
    // HTTPUpgrade handler sees req.URL.Path. A literal '#' therefore must not
    // be treated like a removable URL fragment here; percent-encoded %23 is
    // still decoded later as an ordinary path byte.
    if target.contains('#') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade request target fragment",
        ));
    }

    let Some(scheme_end) = target.find("://") else {
        return Ok(HttpUpgradeRequestTarget {
            path: target,
            authority: None,
        });
    };
    let scheme = &target[..scheme_end];
    let valid_scheme = scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && scheme.as_bytes().iter().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        });
    if !valid_scheme {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade absolute request target",
        ));
    }

    let rest = &target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade absolute request target",
        ));
    }
    let suffix = &rest[authority_end..];
    let path = if suffix.starts_with('/') { suffix } else { "" };
    Ok(HttpUpgradeRequestTarget {
        path,
        authority: Some(authority),
    })
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
    let actual = actual.to_ascii_lowercase();
    if !actual.contains(':') {
        return actual == expected;
    }

    split_http_host_port(&actual).is_some_and(|host| host == expected)
}

fn split_http_host_port(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let closing = rest.find(']')?;
        let host = &rest[..closing];
        let suffix = &rest[closing + 1..];
        return (suffix.starts_with(':') && !suffix[1..].contains(':'))
            .then_some(host);
    }

    let mut parts = authority.split(':');
    let host = parts.next()?;
    parts.next()?;
    parts.next().is_none().then_some(host)
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

    use super::{
        HttpUpgradeTcpServerHandler, http_host_matches, trusted_forwarded_peer,
    };

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

    #[tokio::test]
    async fn preserves_xray_httpupgrade_host_text() {
        let handler = HttpUpgradeTcpServerHandler::new(
            Some(" Example.COM ".into()),
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                b"GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray does not trim configured HTTPUpgrade host text"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("host mismatch"));
    }

    #[test]
    fn matches_xray_ipv6_httpupgrade_host_authorities() {
        assert!(http_host_matches("[::1]:443", "::1"));
        assert!(http_host_matches("[::1]:80", "::1"));
        assert!(!http_host_matches("::1", "::1"));
        assert!(!http_host_matches("[::1]", "::1"));
        assert!(!http_host_matches("[::2]:443", "::1"));
        assert!(http_host_matches("Example.COM:443", "example.com"));
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
    async fn accepts_large_headers_like_xray_v26_2_6() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(128 * 1024);
        let large_value = "A".repeat(64 * 1024);
        let request = format!(
            "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Large: {large_value}\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray v26.2.6 accepts HTTPUpgrade headers beyond 12 KiB");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
        let mut response = vec![0u8; 77];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 101 Switching Protocols")
        );
    }

    #[tokio::test]
    async fn drops_buffered_first_protocol_bytes_like_xray_v26_2_6() {
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

        let mut buffered = [0u8; 8];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                stream.read_exact(&mut buffered),
            )
            .await
            .is_err(),
            "Xray drops inner bytes buffered by http.ReadRequest"
        );

        client.write_all(b"late").await.unwrap();
        let mut late = [0u8; 4];
        stream.read_exact(&mut late).await.unwrap();
        assert_eq!(&late, b"late");
    }

    #[tokio::test]
    async fn accepts_xray_httpupgrade_methods_and_http_versions() {
        for request_line in ["POST /upgrade HTTP/1.0", "FOO /upgrade HTTP/9.9"] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray accepts any parsed method and one-digit HTTP version");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }

        for request_line in [
            "GET /upgrade HTTP/1.10",
            "GET /upgrade BLAH",
            "GET  /upgrade HTTP/1.1",
            "GET /upgrade  HTTP/1.1",
            "GET\t/upgrade HTTP/1.1",
            "GET /upgrade\tHTTP/1.1",
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => {
                    panic!("Xray http.ReadRequest rejects malformed HTTP versions")
                }
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn accepts_bare_lf_http_headers_like_xray_v26_2_6() {
        for request in [
            b"GET /upgrade HTTP/1.1\nHost: localhost\nConnection: Upgrade\nUpgrade: websocket\n\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\n\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray http.ReadRequest accepts bare LF line endings");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }
    }

    #[tokio::test]
    async fn keeps_first_duplicate_upgrade_headers_like_xray_v26_2_6() {
        for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nConnection: nope\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: nope\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray uses the first duplicate HTTPUpgrade header value");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }

        for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: nope\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: nope\r\nUpgrade: websocket\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects when the first duplicate header is invalid"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn matches_xray_httpupgrade_mime_header_parsing() {
        for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection:\r\n Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade:\r\n websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nBad Header: ok\r\nX-Test: a\tb\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nConnection: nope\r\n more\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: nope\r\n more\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray accepts folded MIME header values");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }

        for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection : Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nBadHeader\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nBad\tHeader: ok\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: a\x0bb\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: a\x00b\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: a\x7fb\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects malformed HTTPUpgrade MIME headers"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn matches_xray_absolute_form_request_targets() {
        for request_line in [
            "GET http://example.com/upgrade HTTP/1.1",
            "GET HTTP://example.com/upgrade HTTP/1.1",
            "GET ftp://example.com/upgrade HTTP/1.1",
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                Some("example.com".into()),
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: wrong.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray uses absolute request-target authority and path");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }

        for request_line in [
            "GET http://wrong.example/upgrade HTTP/1.1",
            "GET http://example.com/wrong HTTP/1.1",
            "GET http://example.com/upgrade#fragment HTTP/1.1",
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                Some("example.com".into()),
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            assert!(
                handler
                    .setup_server_stream(Box::new(TestStream(server)))
                    .await
                    .is_err(),
                "Xray rejects mismatched absolute-form authority or path"
            );
        }
    }

    #[tokio::test]
    async fn rejects_literal_request_target_fragments_like_xray_v26_2_6() {
        for target in ["/upgrade#fragment", "/upgrade?x=1#fragment"] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client
                .write_all(
                    format!(
                        "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => {
                    panic!("Xray rejects literal fragments in HTTP request-targets")
                }
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }

        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade#fragment".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                b"GET /upgrade%23fragment HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("percent-encoded hash remains an ordinary Xray path byte");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
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
    async fn proxy_protocol_v1_spacing_matches_xray_v26_2_6() {
        let request = b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(b"PROXY TCP4 198.51.100.7 203.0.113.9 45678 443 EXTRA\r\n")
            .await
            .unwrap();
        client.write_all(request).await.unwrap();
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray v26.2.6 ignores trailing PROXY v1 tokens");
        let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result
        else {
            panic!("expected peer address override");
        };
        assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
        assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));

        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(b"PROXY  TCP4 198.51.100.7 203.0.113.9 45678 443\r\n")
            .await
            .unwrap();
        client.write_all(request).await.unwrap();
        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray v26.2.6 rejects repeated spaces in PROXY v1"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("PROXY protocol v1 family"));
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
    async fn proxy_v2_local_validates_known_family_length_like_xray_v26_2_6() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );

        for family_protocol in [0x11, 0x13] {
            let (mut client, server) = duplex(4096);
            let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            request.extend_from_slice(&[0x20, family_protocol, 0x00, 0x00]);
            request.extend_from_slice(
                b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
            client.write_all(&request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray v26.2.6 rejects short LOCAL IPv4 blocks"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("PROXY protocol v2 LOCAL address length")
            );
        }

        let (mut client, server) = duplex(4096);
        let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        request.extend_from_slice(&[0x20, 0x13, 0x00, 0x0c]);
        request.extend_from_slice(&[0; 12]);
        request.extend_from_slice(
            b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );
        client.write_all(&request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect(
                "Xray v26.2.6 accepts LOCAL IPv4 blocks once length is sufficient",
            );
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }

    #[tokio::test]
    async fn proxy_v2_non_ip_families_match_xray_v26_2_6() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );

        for (family_protocol, payload) in
            [(0x01, Vec::new()), (0x40, Vec::new()), (0x31, vec![0; 216])]
        {
            let (mut client, server) = duplex(4096);
            let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            request.extend_from_slice(&[
                0x21,
                family_protocol,
                (payload.len() >> 8) as u8,
                payload.len() as u8,
            ]);
            request.extend_from_slice(&payload);
            request.extend_from_slice(
                b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
            client.write_all(&request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray v26.2.6 accepts non-IP PROXY v2 family combinations");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
        }

        for family_protocol in [0x00, 0x41] {
            let (mut client, server) = duplex(4096);
            let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            request.extend_from_slice(&[0x21, family_protocol, 0x00, 0x00]);
            request.extend_from_slice(
                b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
            client.write_all(&request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => {
                    panic!("Xray v26.2.6 rejects this PROXY v2 family combination")
                }
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("unsupported PROXY protocol v2 address family")
            );
        }
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
