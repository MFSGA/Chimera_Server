use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use tokio::{io::AsyncWriteExt, time::timeout};
use tracing::debug;

use crate::{
    async_stream::AsyncStream,
    handler::{
        tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
        ws::{
            parsed_http::{ParsedHttpData, ParsedHttpError},
            websocket_stream::WebsocketStream,
        },
    },
    util::prefixed_stream::PrefixedStream,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub xray_mismatch_404: bool,
    pub trusted_x_forwarded_for: Vec<String>,
    pub handler: Box<dyn TcpServerHandler>,
}

const XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug)]
pub struct WebsocketTcpServerHandler {
    server_targets: Vec<WebsocketServerTarget>,
}

impl WebsocketTcpServerHandler {
    pub fn new(server_targets: Vec<WebsocketServerTarget>) -> Self {
        Self { server_targets }
    }
}

#[async_trait]
impl TcpServerHandler for WebsocketTcpServerHandler {
    fn manages_handshake_timeout(&self) -> bool {
        !self.server_targets.is_empty()
            && self
                .server_targets
                .iter()
                .all(|target| target.handler.manages_handshake_timeout())
    }

    fn pre_transport_handshake_timeout(
        &self,
        _context: &TcpServerConnectionContext,
    ) -> Option<Duration> {
        Some(XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT)
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_context(
            server_stream,
            TcpServerConnectionContext::default(),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        mut context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        tracing::debug!("WebsocketTcpServerHandler setup_server_stream");
        let parsed = timeout(
            XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT,
            ParsedHttpData::parse(&mut server_stream),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "WebSocket handshake timed out",
            )
        })?;
        let ParsedHttpData {
            first_line,
            headers: request_headers,
            line_reader,
        } = match parsed {
            Ok(parsed) => parsed,
            Err(ParsedHttpError::Io(error)) => return Err(error),
            Err(ParsedHttpError::HeaderTooLarge) => {
                write_xray_websocket_header_too_large(&mut server_stream).await?;
                return Err(std::io::Error::other(
                    "websocket request header is too large",
                ));
            }
            Err(ParsedHttpError::InvalidHeaderName { trailing_space }) => {
                if trailing_space {
                    write_xray_invalid_header_name(&mut server_stream).await?;
                } else {
                    write_xray_bad_request_line(&mut server_stream).await?;
                }
                return Err(std::io::Error::other("invalid HTTP header name"));
            }
            Err(ParsedHttpError::InvalidHeaderValue) => {
                write_xray_bad_request_line(&mut server_stream).await?;
                return Err(std::io::Error::other("invalid HTTP header value"));
            }
        };

        if !valid_xray_content_length(&request_headers) {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid Content-Length header"));
        }

        if !valid_xray_transfer_encoding(&request_headers) {
            write_xray_unsupported_transfer_encoding(&mut server_stream).await?;
            return Err(std::io::Error::other("unsupported transfer encoding"));
        }
        if !valid_xray_chunked_trailers(&request_headers) {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid chunked trailer"));
        }

        if request_headers
            .get("host")
            .is_some_and(|values| values.len() > 1)
        {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("too many Host headers"));
        }

        let (method, request_target, host_required) =
            match parse_xray_websocket_request_line(&first_line) {
                Ok(parsed) => parsed,
                Err(WebsocketRequestLineError::Malformed) => {
                    write_xray_bad_request_line(&mut server_stream).await?;
                    return Err(std::io::Error::other(
                        "malformed HTTP request line",
                    ));
                }
                Err(WebsocketRequestLineError::UnsupportedVersion) => {
                    write_xray_unsupported_http_version(&mut server_stream).await?;
                    return Err(std::io::Error::other(
                        "unsupported HTTP protocol version",
                    ));
                }
            };
        let request_host = request_headers
            .get("host")
            .and_then(|values| values.first())
            .map(String::as_str);
        if host_required && request_host.is_none() {
            write_xray_missing_host(&mut server_stream).await?;
            return Err(std::io::Error::other("missing required Host header"));
        }
        let effective_host =
            xray_websocket_absolute_host(request_target).or(request_host);
        if method != "GET" {
            write_xray_method_not_allowed(&mut server_stream).await?;
            return Err(std::io::Error::other("websocket method is not GET"));
        }
        let raw_request_path = websocket_request_path_raw(request_target);
        let xray_request_path = match xray_websocket_request_path(request_target) {
            Ok(path) => path,
            Err(()) => {
                write_xray_bad_request_line(&mut server_stream).await?;
                return Err(std::io::Error::other(
                    "malformed request target escape",
                ));
            }
        };
        debug!(
            "request path is {}",
            String::from_utf8_lossy(&xray_request_path)
        );
        let websocket_key = request_headers
            .get("sec-websocket-key")
            .and_then(|values| values.first())
            .cloned();
        let websocket_early_data = request_headers
            .get("sec-websocket-protocol")
            .and_then(|values| values.first())
            .and_then(|value| decode_xray_websocket_early_data(value));
        if !header_contains_token(&request_headers, "upgrade", "websocket")
            || !header_contains_token(&request_headers, "connection", "upgrade")
            || !header_contains_token(
                &request_headers,
                "sec-websocket-version",
                "13",
            )
            || !websocket_key.as_deref().is_some_and(valid_websocket_key)
        {
            write_bad_websocket_request(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid websocket handshake"));
        }
        let websocket_key = websocket_key.expect("validated websocket key");

        let mut saw_xray_mismatch = false;
        'outer: for server_target in self.server_targets.iter() {
            debug!("checking server target {:?}", server_target);
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                xray_mismatch_404,
                trusted_x_forwarded_for,
                handler,
            } = server_target;
            debug!(
                "matching path is {:?} {:?}",
                matching_path,
                String::from_utf8_lossy(&xray_request_path)
            );
            if let Some(path) = matching_path
                && if *xray_mismatch_404 {
                    path.as_bytes() != xray_request_path.as_slice()
                } else {
                    path != &raw_request_path
                }
            {
                debug!("path not match");
                saw_xray_mismatch |= *xray_mismatch_404;
                continue;
            }
            debug!("matching headers is {:?}", matching_headers);
            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    let matches = if *xray_mismatch_404 && header_key == "host" {
                        effective_host.is_some_and(|actual| {
                            xray_websocket_host_matches(actual, header_val)
                        })
                    } else {
                        request_headers
                            .get(header_key)
                            .and_then(|values| values.first())
                            .is_some_and(|actual| actual == header_val)
                    };
                    if !matches {
                        saw_xray_mismatch |= *xray_mismatch_404;
                        continue 'outer;
                    }
                }
            }

            if let Some(peer_addr) = xray_websocket_forwarded_peer(
                &request_headers,
                trusted_x_forwarded_for,
            ) {
                context.peer_addr = Some(peer_addr);
            }

            let websocket_key_response =
                create_websocket_key_response(websocket_key);

            let mut http_response = format!(
                concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept: {}\r\n"
                ),
                websocket_key_response,
            );
            if websocket_early_data.is_some()
                && let Some(protocol) = request_headers
                    .get("sec-websocket-protocol")
                    .and_then(|values| values.first())
            {
                http_response.push_str("Sec-WebSocket-Protocol: ");
                http_response.push_str(protocol);
                http_response.push_str("\r\n");
            }
            http_response.push_str("\r\n");

            server_stream.write_all(http_response.as_bytes()).await?;

            let websocket_stream: Box<dyn AsyncStream> =
                Box::new(WebsocketStream::new(
                    server_stream,
                    false,
                    line_reader.unparsed_data(),
                ));
            let websocket_stream =
                if let Some(early_data) = websocket_early_data.clone() {
                    Box::new(PrefixedStream::new(early_data, websocket_stream))
                        as Box<dyn AsyncStream>
                } else {
                    websocket_stream
                };

            let mut target_setup_result = handler
                .setup_server_stream_with_context(websocket_stream, context.clone())
                .await;

            if let Ok(ref mut setup_result) = target_setup_result {
                setup_result.set_need_initial_flush(true);
                debug!("todo override_proxy_provider_unspecified");
            }

            return target_setup_result;
        }

        if saw_xray_mismatch {
            write_xray_websocket_not_found(&mut server_stream).await?;
        }
        Err(std::io::Error::other("No matching websocket targets"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebsocketRequestLineError {
    Malformed,
    UnsupportedVersion,
}

fn parse_xray_websocket_request_line(
    line: &str,
) -> Result<(&str, &str, bool), WebsocketRequestLineError> {
    let (method, rest) = line
        .split_once(' ')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    let (request_target, version) = rest
        .split_once(' ')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    if method.is_empty()
        || !method.bytes().all(is_http_method_token_byte)
        || request_target.is_empty()
        || version.is_empty()
        || request_target
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
        || version.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WebsocketRequestLineError::Malformed);
    }

    let version = version
        .strip_prefix("HTTP/")
        .ok_or(WebsocketRequestLineError::Malformed)?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    if major.len() != 1
        || minor.len() != 1
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WebsocketRequestLineError::Malformed);
    }
    if major != "1" {
        return Err(WebsocketRequestLineError::UnsupportedVersion);
    }

    Ok((method, request_target, minor != "0"))
}

fn xray_websocket_absolute_parts(request_target: &str) -> Option<(&str, &str)> {
    let scheme_end = request_target.find("://")?;
    let scheme = &request_target[..scheme_end];
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme.bytes().skip(1).all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
        })
    {
        return None;
    }

    let rest = &request_target[scheme_end + 3..];
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty() {
        return None;
    }

    let path = rest.get(authority_end..).and_then(|remainder| {
        remainder.starts_with('/').then(|| {
            remainder
                .split_once('?')
                .map_or(remainder, |(path, _)| path)
        })
    });
    Some((host, path.unwrap_or("/")))
}

fn xray_websocket_absolute_host(request_target: &str) -> Option<&str> {
    xray_websocket_absolute_parts(request_target).map(|(host, _)| host)
}

fn xray_websocket_host_matches(actual: &str, expected: &str) -> bool {
    let actual = xray_unicode_lowercase(actual);
    let expected = xray_unicode_lowercase(expected);
    if !actual.contains(':') {
        return actual == expected;
    }

    split_http_host_port(&actual).is_some_and(|host| host == expected)
}

fn xray_unicode_lowercase(value: &str) -> String {
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

fn is_http_method_token_byte(byte: u8) -> bool {
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

fn websocket_request_path_raw(request_target: &str) -> String {
    if let Some((_, path)) = xray_websocket_absolute_parts(request_target) {
        return path.to_string();
    }

    request_target
        .split_once('?')
        .map_or(request_target, |(path, _)| path)
        .to_string()
}

fn xray_websocket_request_path(request_target: &str) -> Result<Vec<u8>, ()> {
    let raw = websocket_request_path_raw(request_target);
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let high = decode_hex_nibble(bytes[index + 1]).ok_or(())?;
        let low = decode_hex_nibble(bytes[index + 2]).ok_or(())?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    Ok(decoded)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_xray_content_length(headers: &HashMap<String, Vec<String>>) -> bool {
    let Some(values) = headers.get("content-length") else {
        return true;
    };
    let Some(first) = values.first() else {
        return false;
    };
    if first.is_empty()
        || !first.bytes().all(|byte| byte.is_ascii_digit())
        || first.parse::<i64>().is_err()
    {
        return false;
    }
    values.iter().skip(1).all(|value| value == first)
}

fn valid_xray_transfer_encoding(headers: &HashMap<String, Vec<String>>) -> bool {
    match headers.get("transfer-encoding") {
        None => true,
        Some(values) => {
            values.len() == 1 && values[0].eq_ignore_ascii_case("chunked")
        }
    }
}

fn valid_xray_chunked_trailers(headers: &HashMap<String, Vec<String>>) -> bool {
    if !headers.contains_key("transfer-encoding") {
        return true;
    }

    headers.get("trailer").is_none_or(|values| {
        values.iter().all(|value| {
            value.split(',').map(str::trim).all(|key| {
                !key.eq_ignore_ascii_case("content-length")
                    && !key.eq_ignore_ascii_case("transfer-encoding")
                    && !key.eq_ignore_ascii_case("trailer")
            })
        })
    })
}

fn header_contains_token(
    headers: &HashMap<String, Vec<String>>,
    name: &str,
    token: &str,
) -> bool {
    headers.get(name).is_some_and(|values| {
        values.iter().any(|value| {
            value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case(token))
        })
    })
}

fn valid_websocket_key(key: &str) -> bool {
    BASE64.decode(key).is_ok_and(|decoded| decoded.len() == 16)
}

fn xray_websocket_forwarded_peer(
    headers: &HashMap<String, Vec<String>>,
    trusted_x_forwarded_for: &[String],
) -> Option<SocketAddr> {
    if !trusted_x_forwarded_for.is_empty()
        && !trusted_x_forwarded_for
            .iter()
            .any(|header| headers.contains_key(&header.to_ascii_lowercase()))
    {
        return None;
    }

    let first = headers.get("x-forwarded-for")?.first()?.split(',').next()?;
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

    let ip = candidate.parse::<IpAddr>().ok()?;
    let ip = match ip {
        IpAddr::V6(ipv6) => {
            ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4)
        }
        ip => ip,
    };
    Some(SocketAddr::new(ip, 0))
}

fn decode_xray_websocket_early_data(value: &str) -> Option<Vec<u8>> {
    let normalized = value.replace('+', "-").replace('/', "_").replace('=', "");
    URL_SAFE_NO_PAD
        .decode(normalized)
        .ok()
        .filter(|decoded| !decoded.is_empty())
}

async fn write_xray_websocket_not_found(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    let response = format!(
        concat!(
            "HTTP/1.1 404 Not Found\r\n",
            "Date: {}\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_xray_method_not_allowed(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const BODY: &str = "Method Not Allowed\n";
    let response = format!(
        concat!(
            "HTTP/1.1 405 Method Not Allowed\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Sec-Websocket-Version: 13\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Date: {}\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
        BODY.len(),
        BODY,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_xray_bad_request_line(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
        )
        .await?;
    stream.flush().await
}

async fn write_xray_missing_host(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str = "400 Bad Request: missing required Host header";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_xray_invalid_header_name(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str = "400 Bad Request: invalid header name";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_xray_unsupported_transfer_encoding(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nUnsupported transfer encoding",
        )
        .await?;
    stream.flush().await
}

async fn write_xray_websocket_header_too_large(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large",
        )
        .await?;
    stream.flush().await
}

async fn write_xray_unsupported_http_version(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str =
        "505 HTTP Version Not Supported: unsupported protocol version";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_bad_websocket_request(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const BODY: &str = "Bad Request\n";
    let response = format!(
        concat!(
            "HTTP/1.1 400 Bad Request\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Sec-Websocket-Version: 13\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Date: {}\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
        BODY.len(),
        BODY,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::SocketAddr,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    };

    use crate::{
        async_stream::{AsyncPing, AsyncStream},
        handler::tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
    };

    use super::{
        WebsocketServerTarget, WebsocketTcpServerHandler,
        XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT, xray_websocket_host_matches,
        xray_websocket_request_path,
    };

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

    #[derive(Debug)]
    struct Inner {
        manages_handshake_timeout: bool,
    }

    #[async_trait]
    impl TcpServerHandler for Inner {
        fn manages_handshake_timeout(&self) -> bool {
            self.manages_handshake_timeout
        }

        async fn setup_server_stream(
            &self,
            _server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            unreachable!("handshake ownership test does not enter the inner handler")
        }
    }

    #[derive(Debug)]
    struct AcceptingInner;

    #[derive(Debug)]
    struct CapturingInner {
        captured: Arc<Mutex<Vec<u8>>>,
    }

    #[derive(Debug)]
    struct ContextCapturingInner {
        captured_peer: Arc<Mutex<Option<SocketAddr>>>,
    }

    #[async_trait]
    impl TcpServerHandler for AcceptingInner {
        async fn setup_server_stream(
            &self,
            _server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[async_trait]
    impl TcpServerHandler for CapturingInner {
        async fn setup_server_stream(
            &self,
            mut server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let mut data = [0u8; 4];
            server_stream.read_exact(&mut data).await?;
            self.captured.lock().unwrap().extend_from_slice(&data);
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    #[async_trait]
    impl TcpServerHandler for ContextCapturingInner {
        async fn setup_server_stream(
            &self,
            _server_stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            unreachable!("context-aware setup should be used")
        }

        async fn setup_server_stream_with_context(
            &self,
            _server_stream: Box<dyn AsyncStream>,
            context: TcpServerConnectionContext,
        ) -> std::io::Result<TcpServerSetupResult> {
            *self.captured_peer.lock().unwrap() = context.peer_addr;
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    fn target(manages_handshake_timeout: bool) -> WebsocketServerTarget {
        WebsocketServerTarget {
            matching_path: None,
            matching_headers: None,
            xray_mismatch_404: false,
            trusted_x_forwarded_for: Vec::new(),
            handler: Box::new(Inner {
                manages_handshake_timeout,
            }),
        }
    }

    fn accepting_handler() -> WebsocketTcpServerHandler {
        WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/".to_string()),
            matching_headers: None,
            xray_mismatch_404: false,
            trusted_x_forwarded_for: Vec::new(),
            handler: Box::new(AcceptingInner),
        }])
    }

    async fn run_handshake(
        request: &str,
    ) -> (std::io::Result<TcpServerSetupResult>, String) {
        run_handshake_bytes(request.as_bytes()).await
    }

    async fn run_handshake_bytes(
        request: &[u8],
    ) -> (std::io::Result<TcpServerSetupResult>, String) {
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = accepting_handler();
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });
        peer.write_all(request).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        (task.await.unwrap(), String::from_utf8(response).unwrap())
    }

    #[test]
    fn websocket_request_path_matches_xray_query_absolute_and_escape_semantics() {
        assert_eq!(xray_websocket_request_path("/ws").unwrap(), b"/ws");
        assert_eq!(xray_websocket_request_path("/ws?foo=bar").unwrap(), b"/ws");
        assert_eq!(xray_websocket_request_path("/ws?").unwrap(), b"/ws");
        assert_eq!(
            xray_websocket_request_path("http://example.com/ws?foo=bar").unwrap(),
            b"/ws"
        );
        assert_eq!(
            xray_websocket_request_path("https://example.com/ws?foo=bar").unwrap(),
            b"/ws"
        );
        assert_eq!(
            xray_websocket_request_path("ftp://example.com/ws?foo=bar").unwrap(),
            b"/ws"
        );
        assert_eq!(
            xray_websocket_request_path("HTTP://user@example.com/ws?foo=bar")
                .unwrap(),
            b"/ws"
        );
        assert_eq!(
            xray_websocket_request_path("/ws%3Ffoo=bar").unwrap(),
            b"/ws?foo=bar"
        );
        assert_eq!(
            xray_websocket_request_path("/ws%2Ffoo").unwrap(),
            b"/ws/foo"
        );
        assert_eq!(
            xray_websocket_request_path("/ws%252Ffoo").unwrap(),
            b"/ws%2Ffoo"
        );
        assert!(xray_websocket_request_path("/ws%ZZfoo").is_err());
        assert_eq!(
            xray_websocket_request_path("/ws/foo?x=%ZZ").unwrap(),
            b"/ws/foo"
        );
        assert_eq!(
            xray_websocket_request_path("/ws#frag").unwrap(),
            b"/ws#frag"
        );
    }

    #[tokio::test]
    async fn websocket_xray_path_matching_decodes_percent_escapes() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for (target, expected_status) in [
            ("/ws/foo", "101 Switching Protocols"),
            ("/ws%2Ffoo", "101 Switching Protocols"),
            ("/ws%252Ffoo", "404 Not Found"),
            ("/ws%ZZfoo", "400 Bad Request"),
            (
                "http://example.com/ws%2Ffoo?x=%ZZ",
                "101 Switching Protocols",
            ),
        ] {
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            let (client, mut peer) = tokio::io::duplex(8192);
            let handler =
                WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
                    matching_path: Some("/ws/foo".to_string()),
                    matching_headers: None,
                    xray_mismatch_404: true,
                    trusted_x_forwarded_for: Vec::new(),
                    handler: Box::new(AcceptingInner),
                }]);
            let task = tokio::spawn(async move {
                handler
                    .setup_server_stream(Box::new(TestStream(client)))
                    .await
            });

            peer.write_all(request.as_bytes()).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            let _ = task.await.unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")),
                "{target}: {response:?}"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_request_target_paths() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for target in [
            "/?foo=bar",
            "http://example.com/?foo=bar",
            "https://example.com/?foo=bar",
        ] {
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            let (result, response) = run_handshake(&request).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_request_line_semantics() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let headers = format!(
            "Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        for version in ["HTTP/1.0", "HTTP/1.1", "HTTP/1.2"] {
            let (result, response) =
                run_handshake(&format!("GET / {version}\r\n{headers}")).await;
            assert!(result.is_ok(), "{version}");
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }

        let headers_without_host = format!(
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) =
            run_handshake(&format!("GET / HTTP/1.0\r\n{headers_without_host}"))
                .await;
        assert!(result.is_ok());
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        for version in ["HTTP/1.1", "HTTP/1.2"] {
            let (result, response) =
                run_handshake(&format!("GET / {version}\r\n{headers_without_host}"))
                    .await;
            assert!(result.is_err(), "{version}");
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request: missing required Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: missing required Host header"
            );
        }

        for method in ["POST", "PUT", "G!T", "G~T"] {
            let (result, response) =
                run_handshake(&format!("{method} / HTTP/1.1\r\n{headers}")).await;
            assert!(result.is_err());
            assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
            assert!(response.ends_with("\r\n\r\nMethod Not Allowed\n"));
        }

        for version in ["HTTP/0.9", "HTTP/2.0", "HTTP/9.9"] {
            let (result, response) =
                run_handshake(&format!("GET / {version}\r\n{headers}")).await;
            assert!(result.is_err());
            assert!(response.starts_with(
                "HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version\r\n"
            ));
        }

        for request_line in [
            "GET  / HTTP/1.1",
            "GET\t/\tHTTP/1.1",
            "GET / HTTP/1.x",
            "GET / HTTP/1.10",
            "GET / HTTP/01.1",
            "GET / HTTP/1.01",
            "G@T / HTTP/1.1",
            "G:T / HTTP/1.1",
            "G,T / HTTP/1.1",
            "G/T / HTTP/1.1",
            "G\\T / HTTP/1.1",
            "G[T / HTTP/1.1",
            "G{T / HTTP/1.1",
        ] {
            let (result, response) =
                run_handshake(&format!("{request_line}\r\n{headers}")).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_validates_header_names_like_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let suffix = format!(
            "Upgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );

        let (result, response) = run_handshake(&format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n{suffix}"
        ))
        .await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

        let (result, response) = run_handshake(&format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection : Upgrade\r\n{suffix}"
        ))
        .await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request: invalid header name\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: invalid header name"
        );

        for invalid_header in
            ["Connection\t: Upgrade", "Connec@tion: Upgrade", "X Foo: ok"]
        {
            let (result, response) = run_handshake(&format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\n{invalid_header}\r\nConnection: Upgrade\r\n{suffix}"
            ))
            .await;
            assert!(result.is_err(), "{invalid_header}");
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
                "{invalid_header}"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_accepts_folded_headers_like_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for request in [
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nConnection:\r\n Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade:\r\n websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key:\r\n {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
        ] {
            let (result, response) = run_handshake(&request).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }

        let orphan = format!(
            "GET / HTTP/1.1\r\n continuation\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&orphan).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
        );
    }

    #[tokio::test]
    async fn websocket_handshake_validates_header_values_like_xray_v26_2_6() {
        let base = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Test: ";

        for value in [b"ok".as_slice(), b"a\tb", b"\x80", b"\xff"] {
            let mut request = base.to_vec();
            request.extend_from_slice(value);
            request.extend_from_slice(b"\r\n\r\n");
            let (result, response) = run_handshake_bytes(&request).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }

        for value in [b"a\x0bb".as_slice(), b"a\x00b", b"a\x7fb"] {
            let mut request = base.to_vec();
            request.extend_from_slice(value);
            request.extend_from_slice(b"\r\n\r\n");
            let (result, response) = run_handshake_bytes(&request).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_rejects_duplicate_host_like_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for hosts in [
            "Host: example.com\r\nHost: example.com\r\n",
            "Host: example.com\r\nHost: wrong.com\r\n",
            "Host: wrong.com\r\nHost: example.com\r\n",
        ] {
            let request = format!(
                "GET / HTTP/1.1\r\n{hosts}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            let (result, response) = run_handshake(&request).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_validates_content_length_like_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let base = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );

        for content_length in [
            "Content-Length: 0\r\n",
            "Content-Length: 00\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Content-Length:   0  \r\nContent-Length:\t0\t\r\n",
            "Content-Length: 9223372036854775807\r\n",
        ] {
            let (result, response) =
                run_handshake(&format!("{base}{content_length}\r\n")).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }

        for content_length in [
            "Content-Length:\r\n",
            "Content-Length: nope\r\n",
            "Content-Length: +0\r\n",
            "Content-Length: -0\r\n",
            "Content-Length: 0, 0\r\n",
            "Content-Length: 0\r\nContent-Length: 00\r\n",
            "Content-Length: 0\r\nContent-Length: 1\r\n",
            "Content-Length: 9223372036854775808\r\n",
        ] {
            let (result, response) =
                run_handshake(&format!("{base}{content_length}\r\n")).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_validates_transfer_encoding_like_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let base = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );

        for transfer_encoding in [
            "",
            "Transfer-Encoding: chunked\r\n",
            "Transfer-Encoding: Chunked\r\n",
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
        ] {
            let (result, response) =
                run_handshake(&format!("{base}{transfer_encoding}\r\n")).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }

        for transfer_encoding in [
            "Transfer-Encoding:\r\n",
            "Transfer-Encoding: identity\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Transfer-Encoding: chunked;foo\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        ] {
            let (result, response) =
                run_handshake(&format!("{base}{transfer_encoding}\r\n")).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nUnsupported transfer encoding"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_validates_chunked_trailers_like_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let base = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );

        for trailers in [
            "Trailer: Content-Length\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: X-Foo\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: Host\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: X-Foo, X-Bar\r\n",
        ] {
            let (result, response) =
                run_handshake(&format!("{base}{trailers}\r\n")).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }

        for trailers in [
            "Transfer-Encoding: chunked\r\nTrailer: Content-Length\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: Transfer-Encoding\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: Trailer\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: X-Foo, Content-Length\r\n",
            "Transfer-Encoding: chunked\r\nTrailer: X-Foo\r\nTrailer: Content-Length\r\n",
        ] {
            let (result, response) =
                run_handshake(&format!("{base}{trailers}\r\n")).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_header_budget() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let base = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );

        let large_but_valid =
            format!("{base}X-Fill: {}\r\n\r\n", "a".repeat(12_000));
        let (result, response) = run_handshake(&large_but_valid).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

        let many_headers = format!(
            "{base}{}\r\n",
            (0..100)
                .map(|index| format!("X-{index}: a\r\n"))
                .collect::<String>()
        );
        let (result, response) = run_handshake(&many_headers).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

        let oversized = format!("{base}X-Fill: {}\r\n\r\n", "a".repeat(13_000));
        let (result, response) = run_handshake(&oversized).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large"
        );
    }

    #[tokio::test]
    async fn websocket_handshake_validates_xray_upgrade_headers() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let valid = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&valid).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(!response.contains("Host: example.com\r\n"));
        assert!(!response.contains("Sec-WebSocket-Version: 13\r\n"));

        for invalid in [
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 12\r\n\r\n"
            ),
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n".to_string(),
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n".to_string(),
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key:\r\nSec-WebSocket-Version: 13\r\n\r\n".to_string(),
        ] {
            let (result, response) = run_handshake(&invalid).await;
            assert!(result.is_err());
            assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
            assert!(response.contains("Sec-Websocket-Version: 13\r\n"));
            assert!(response.ends_with("\r\n\r\nBad Request\n"));
        }
    }

    #[tokio::test]
    async fn websocket_x_forwarded_for_overrides_inner_peer_like_xray() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let captured_peer = Arc::new(Mutex::new(None));
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/".to_string()),
            matching_headers: None,
            xray_mismatch_404: false,
            trusted_x_forwarded_for: Vec::new(),
            handler: Box::new(ContextCapturingInner {
                captured_peer: captured_peer.clone(),
            }),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream_with_context(
                    Box::new(TestStream(client)),
                    TcpServerConnectionContext {
                        peer_addr: Some("127.0.0.1:45678".parse().unwrap()),
                        ..Default::default()
                    },
                )
                .await
        });

        peer.write_all(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: example.com\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                "Sec-WebSocket-Version: 13\r\n",
                "X-Forwarded-For: 203.0.113.77, 198.51.100.2\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();

        assert!(matches!(
            task.await.unwrap(),
            Ok(TcpServerSetupResult::AlreadyHandled)
        ));
        assert!(
            String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 101 Switching Protocols\r\n")
        );
        assert_eq!(
            *captured_peer.lock().unwrap(),
            Some("203.0.113.77:0".parse().unwrap())
        );
    }

    #[test]
    fn websocket_x_forwarded_for_matches_xray_first_ip_rules() {
        use super::xray_websocket_forwarded_peer;

        for (value, expected) in [
            ("203.0.113.77, 198.51.100.2", Some("203.0.113.77:0")),
            (" 203.0.113.77 ", Some("203.0.113.77:0")),
            ("[2001:db8::1]", Some("[2001:db8::1]:0")),
            ("[::ffff:192.0.2.1]", Some("192.0.2.1:0")),
            ("example.com, 203.0.113.77", None),
            (" [2001:db8::1] ", None),
        ] {
            let headers = HashMap::from([(
                "x-forwarded-for".to_string(),
                vec![value.to_string()],
            )]);
            assert_eq!(
                xray_websocket_forwarded_peer(&headers, &[]),
                expected.map(|value| value.parse().unwrap()),
                "{value}"
            );
        }

        let mut headers = HashMap::from([(
            "x-forwarded-for".to_string(),
            vec!["203.0.113.77".to_string()],
        )]);
        assert_eq!(
            xray_websocket_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
            None
        );
        headers.insert("x-trusted-cdn".to_string(), vec![String::new()]);
        assert_eq!(
            xray_websocket_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
            Some("203.0.113.77:0".parse().unwrap())
        );
        assert_eq!(
            xray_websocket_forwarded_peer(
                &headers,
                &[" X-Trusted-CDN ".to_string()]
            ),
            None
        );
        assert_eq!(
            xray_websocket_forwarded_peer(
                &headers,
                &["X-Forwarded-For".to_string()]
            ),
            Some("203.0.113.77:0".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_early_data_subprotocol() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/".to_string()),
            matching_headers: None,
            xray_mismatch_404: false,
            trusted_x_forwarded_for: Vec::new(),
            handler: Box::new(CapturingInner {
                captured: captured.clone(),
            }),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        let request = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Protocol: cGluZw==\r\n",
            "\r\n"
        );
        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();

        assert!(matches!(
            task.await.unwrap(),
            Ok(TcpServerSetupResult::AlreadyHandled)
        ));
        assert_eq!(&*captured.lock().unwrap(), b"ping");
        let response = String::from_utf8(response).unwrap();
        assert!(response.contains("Sec-WebSocket-Protocol: cGluZw==\r\n"));
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_duplicate_header_semantics() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let other_key = "MDEyMzQ1Njc4OWFiY2RlZg==";

        let valid_first_key = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Key: bad\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&valid_first_key).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(
            response
                .contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
        );

        let invalid_first_key = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: bad\r\nSec-WebSocket-Key: {other_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&invalid_first_key).await;
        assert!(result.is_err());
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

        for request in [
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 12\r\n\r\n"
            ),
            format!(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: nope\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
        ] {
            let (result, response) = run_handshake(&request).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        }
    }

    #[tokio::test]
    async fn websocket_xray_path_mismatch_returns_not_found_without_changing_generic_targets()
     {
        let request = concat!(
            "GET /other HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "\r\n"
        );

        for (xray_mismatch_404, expect_404) in [(true, true), (false, false)] {
            let (client, mut peer) = tokio::io::duplex(8192);
            let handler =
                WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
                    matching_path: Some("/ws".to_string()),
                    matching_headers: None,
                    xray_mismatch_404,
                    trusted_x_forwarded_for: Vec::new(),
                    handler: Box::new(AcceptingInner),
                }]);
            let task = tokio::spawn(async move {
                handler
                    .setup_server_stream(Box::new(TestStream(client)))
                    .await
            });

            peer.write_all(request.as_bytes()).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            let result = task.await.unwrap();
            assert!(result.is_err());

            if expect_404 {
                let response = String::from_utf8(response).unwrap();
                assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
                assert!(response.contains("Content-Length: 0\r\n"));
                assert!(response.ends_with("\r\n\r\n"));
            } else {
                assert!(response.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn websocket_absolute_request_target_host_matches_xray_v26_2_6() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for (target, host_header, expect_ok) in [
            ("http://example.com/ws", "wrong.example", true),
            ("ftp://example.com/ws", "wrong.example", true),
            ("HTTP://example.com/ws", "wrong.example", true),
            ("http://user@example.com/ws", "wrong.example", true),
            ("http://wrong.example/ws", "example.com", false),
        ] {
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            let (client, mut peer) = tokio::io::duplex(8192);
            let handler =
                WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
                    matching_path: Some("/ws".to_string()),
                    matching_headers: Some(HashMap::from([(
                        "host".to_string(),
                        "example.com".to_string(),
                    )])),
                    xray_mismatch_404: true,
                    trusted_x_forwarded_for: Vec::new(),
                    handler: Box::new(AcceptingInner),
                }]);
            let task = tokio::spawn(async move {
                handler
                    .setup_server_stream(Box::new(TestStream(client)))
                    .await
            });

            peer.write_all(request.as_bytes()).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            let result = task.await.unwrap();
            let response = String::from_utf8(response).unwrap();
            if expect_ok {
                assert!(result.is_ok(), "{target}");
                assert!(
                    response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
                    "{target}"
                );
            } else {
                assert!(result.is_err(), "{target}");
                assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
            }
        }
    }

    #[test]
    fn websocket_xray_host_matching_matches_xray_v26_2_6() {
        assert!(xray_websocket_host_matches("example.com", "example.com"));
        assert!(xray_websocket_host_matches("EXAMPLE.COM", "example.com"));
        assert!(xray_websocket_host_matches(
            "example.com:443",
            "example.com"
        ));
        assert!(xray_websocket_host_matches("[::1]:443", "::1"));
        assert!(!xray_websocket_host_matches("example.com", " Example.COM "));
        assert!(!xray_websocket_host_matches("[::1]", "::1"));
    }

    #[tokio::test]
    async fn websocket_xray_host_mismatch_returns_not_found_without_changing_generic_targets()
     {
        let request = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: wrong.example\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "\r\n"
        );

        for (xray_mismatch_404, expect_404) in [(true, true), (false, false)] {
            let (client, mut peer) = tokio::io::duplex(8192);
            let handler =
                WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
                    matching_path: Some("/ws".to_string()),
                    matching_headers: Some(HashMap::from([(
                        "host".to_string(),
                        "expected.example".to_string(),
                    )])),
                    xray_mismatch_404,
                    trusted_x_forwarded_for: Vec::new(),
                    handler: Box::new(AcceptingInner),
                }]);
            let task = tokio::spawn(async move {
                handler
                    .setup_server_stream(Box::new(TestStream(client)))
                    .await
            });

            peer.write_all(request.as_bytes()).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            let result = task.await.unwrap();
            assert!(result.is_err());

            if expect_404 {
                let response = String::from_utf8(response).unwrap();
                assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
                assert!(response.contains("Content-Length: 0\r\n"));
            } else {
                assert!(response.is_empty());
            }
        }
    }

    #[test]
    fn websocket_propagates_inner_handshake_timeout_ownership() {
        let handler = WebsocketTcpServerHandler::new(vec![target(true)]);
        assert!(handler.manages_handshake_timeout());
        assert_eq!(
            handler.pre_transport_handshake_timeout(
                &TcpServerConnectionContext::default()
            ),
            Some(XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT)
        );

        let handler =
            WebsocketTcpServerHandler::new(vec![target(true), target(false)]);
        assert!(!handler.manages_handshake_timeout());

        let handler = WebsocketTcpServerHandler::new(Vec::new());
        assert!(!handler.manages_handshake_timeout());
    }
}
