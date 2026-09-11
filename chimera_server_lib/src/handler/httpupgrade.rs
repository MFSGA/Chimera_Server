use std::{collections::HashMap, io, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{
    async_stream::AsyncStream,
    handler::{
        proxy_protocol::read_proxy_protocol,
        tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
    },
};

const XRAY_HTTPUPGRADE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
const XRAY_HTTPUPGRADE_HEADER_LIMIT: usize = 12_288;

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
            host: host.map(|value| xray_unicode_lowercase(&value)),
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
        // Current Xray applies the same four-second request-header read
        // deadline used by WebSocket before parsing the HTTPUpgrade request.
        // Keep the timeout scoped to the HTTP upgrade itself so PROXY protocol
        // parsing and the inner inbound retain their own timeout policies.
        let request =
            timeout(XRAY_HTTPUPGRADE_HANDSHAKE_TIMEOUT, read_http_header(stream))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HTTPUpgrade handshake timed out",
                    )
                })??;
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

async fn read_http_header(stream: &mut Box<dyn AsyncStream>) -> io::Result<Vec<u8>> {
    // Current Xray wraps HTTPUpgrade parsing in io.LimitReader(conn, 12288),
    // while bufio.ReadRequest may still read ahead within that bound. Discard
    // any such bytes after the request just like Xray's short-lived reader.
    let mut header = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let remaining = XRAY_HTTPUPGRADE_HEADER_LIMIT.saturating_sub(header.len());
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTPUpgrade request exceeded Xray's 12 KiB header limit",
            ));
        }
        let max_read = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..max_read]).await?;
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
    let mut lines = request
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let request_line = std::str::from_utf8(lines.next().unwrap_or_default())
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTPUpgrade request line encoding: {error}"),
            )
        })?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || !method.bytes().all(is_xray_http_method_token_byte)
        || target.is_empty()
        || target.bytes().any(is_xray_http_request_target_ctl_byte)
        || !is_xray_http_version(version)
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade request line",
        ));
    }
    enum ContinuationTarget {
        Header(String, bool),
        ContentLength,
        TransferEncoding,
        Trailer,
    }

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut content_lengths: Vec<String> = Vec::new();
    let mut transfer_encodings: Vec<String> = Vec::new();
    let mut trailers: Vec<String> = Vec::new();
    let mut continuation_target: Option<ContinuationTarget> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            if line.iter().copied().any(is_invalid_http_header_value_byte) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTPUpgrade header value",
                ));
            }
            let Some(target) = continuation_target.as_ref() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTPUpgrade header continuation",
                ));
            };
            let continuation = String::from_utf8_lossy(line).trim().to_string();
            match target {
                ContinuationTarget::Header(name, keep_value) => {
                    if *keep_value && let Some(value) = headers.get_mut(name) {
                        if !value.is_empty() && !continuation.is_empty() {
                            value.push(' ');
                        }
                        value.push_str(&continuation);
                    }
                }
                ContinuationTarget::ContentLength => {
                    if let Some(value) = content_lengths.last_mut() {
                        if !value.is_empty() && !continuation.is_empty() {
                            value.push(' ');
                        }
                        value.push_str(&continuation);
                    }
                }
                ContinuationTarget::TransferEncoding => {
                    if let Some(value) = transfer_encodings.last_mut() {
                        if !value.is_empty() && !continuation.is_empty() {
                            value.push(' ');
                        }
                        value.push_str(&continuation);
                    }
                }
                ContinuationTarget::Trailer => {
                    if let Some(value) = trailers.last_mut() {
                        if !value.is_empty() && !continuation.is_empty() {
                            value.push(' ');
                        }
                        value.push_str(&continuation);
                    }
                }
            }
            continue;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade header line",
            ));
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        let name = std::str::from_utf8(name).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid HTTPUpgrade header name encoding: {error}"),
            )
        })?;
        if name.is_empty() || name.bytes().any(is_invalid_http_header_name_byte) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade header name",
            ));
        }
        if value.iter().copied().any(is_invalid_http_header_value_byte) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade header value",
            ));
        }
        let value = String::from_utf8_lossy(value);
        let name = name.to_ascii_lowercase();
        if name == "content-length" {
            content_lengths.push(value.trim().to_string());
            continuation_target = Some(ContinuationTarget::ContentLength);
            continue;
        }
        if name == "transfer-encoding" {
            transfer_encodings.push(value.trim().to_string());
            continuation_target = Some(ContinuationTarget::TransferEncoding);
            continue;
        }
        if name == "trailer" {
            trailers.push(value.trim().to_string());
            continuation_target = Some(ContinuationTarget::Trailer);
            continue;
        }
        if headers.contains_key(&name) {
            // Go's http.ReadRequest rejects duplicate Host headers before the
            // HTTPUpgrade handler runs, while ordinary MIME headers keep the
            // first value visible through Header.Get().
            if name == "host" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many Host headers",
                ));
            }
            // Go's textproto reader still folds continuation lines into the
            // most recent duplicate value, while Header.Get() keeps returning
            // the first value. We can discard the duplicate payload itself,
            // but its continuation lines must remain syntactically valid.
            continuation_target = Some(ContinuationTarget::Header(name, false));
            continue;
        }
        headers.insert(name.clone(), value.trim().to_string());
        continuation_target = Some(ContinuationTarget::Header(name, true));
    }

    if let Some(first) = content_lengths.first() {
        for value in &content_lengths {
            validate_content_length(value)?;
            if value != first {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "http: message cannot contain multiple Content-Length headers; got {content_lengths:?}"
                    ),
                ));
            }
        }
        headers.insert("content-length".to_string(), first.clone());
    }

    validate_transfer_encoding(&transfer_encodings)?;
    if let Some(value) = transfer_encodings.first() {
        headers.insert("transfer-encoding".to_string(), value.clone());
        validate_chunked_trailers(&trailers)?;
    }
    if let Some(value) = trailers.first() {
        headers.insert("trailer".to_string(), value.clone());
    }

    Ok((method, target, version, headers))
}

fn validate_chunked_trailers(values: &[String]) -> io::Result<()> {
    for value in values {
        for key in value.split(',').map(str::trim) {
            if key.eq_ignore_ascii_case("transfer-encoding")
                || key.eq_ignore_ascii_case("trailer")
                || key.eq_ignore_ascii_case("content-length")
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad trailer key {key:?}"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_transfer_encoding(values: &[String]) -> io::Result<()> {
    if values.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("too many transfer encodings: {values:?}"),
        ));
    }
    if let Some(value) = values.first()
        && !value.eq_ignore_ascii_case("chunked")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported transfer encoding: {value:?}"),
        ));
    }
    Ok(())
}

fn validate_content_length(value: &str) -> io::Result<()> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<i64>().is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad Content-Length {value:?}"),
        ));
    }
    Ok(())
}

fn is_invalid_http_header_name_byte(byte: u8) -> bool {
    !byte.is_ascii() || byte <= 0x1f || byte == 0x7f
}

fn is_invalid_http_header_value_byte(byte: u8) -> bool {
    (byte < b' ' && byte != b'\t') || byte == 0x7f
}

fn is_xray_http_request_target_ctl_byte(byte: u8) -> bool {
    byte <= 0x1f || byte == 0x7f
}

fn is_xray_http_method_token_byte(byte: u8) -> bool {
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
    if trusted_x_forwarded_for.is_empty()
        || !trusted_x_forwarded_for.iter().any(|header| {
            // Go's http.ReadRequest promotes Host into req.Host and removes it
            // from req.Header. Xray therefore never treats the ordinary Host
            // request field as a trusted-XFF marker.
            !header.eq_ignore_ascii_case("host")
                && headers.contains_key(&header.to_ascii_lowercase())
        })
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
    Some(std::net::SocketAddr::new(canonicalize_xray_ip(ip), 0))
}

fn canonicalize_xray_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ipv6), std::net::IpAddr::V4),
        ip => ip,
    }
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
    let raw_authority = &rest[..authority_end];
    validate_absolute_authority_escapes(raw_authority)?;
    let authority = raw_authority
        .rsplit_once('@')
        .map_or(raw_authority, |(_, host)| host);
    if authority.is_empty() {
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

fn validate_absolute_authority_escapes(authority: &str) -> io::Result<()> {
    let bytes = authority.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !(bytes[index + 1] as char).is_ascii_hexdigit()
            || !(bytes[index + 2] as char).is_ascii_hexdigit()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid HTTPUpgrade authority escape",
            ));
        }
        index += 3;
    }
    Ok(())
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
    let actual = xray_unicode_lowercase(actual);
    let expected = xray_unicode_lowercase(expected);
    if !actual.contains(':') {
        return actual == expected;
    }

    split_http_host_port(&actual).is_some_and(|host| host == expected)
}

fn xray_unicode_lowercase(value: &str) -> String {
    // Go's strings.ToLower applies unicode.ToLower to each rune. Unlike Rust's
    // full lowercase mapping, that never expands one input rune into multiple
    // output runes (for example, U+0130 LATIN CAPITAL I WITH DOT ABOVE -> "i").
    value
        .chars()
        .map(|ch| ch.to_lowercase().next().unwrap_or(ch))
        .collect()
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
mod tests;
