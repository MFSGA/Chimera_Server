use std::{
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::HttpUser,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
    util::prefixed_stream::PrefixedStream,
};

const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct HttpTcpServerHandler {
    accounts: Vec<HttpUser>,
    allow_transparent: bool,
    inbound_tag: String,
}

impl HttpTcpServerHandler {
    pub fn new(
        accounts: Vec<HttpUser>,
        allow_transparent: bool,
        inbound_tag: &str,
    ) -> Self {
        Self {
            accounts,
            allow_transparent,
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let request_line =
            read_http_line(&mut server_stream, MAX_REQUEST_LINE_BYTES).await?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || method.is_empty()
            || target.is_empty()
            || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid HTTP proxy request line: {request_line}"),
            ));
        }

        let mut header_bytes = 0usize;
        let mut authenticated_user = None;
        let mut host_header = None;
        let mut forwarded_headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut proxy_keep_alive = false;
        let mut proxy_connection_seen = false;
        let mut request_content_length = None;
        let mut request_transfer_encoding = false;
        let mut chunked_transfer_encoding = false;
        loop {
            let line = read_http_line(&mut server_stream, MAX_HEADER_BYTES).await?;
            header_bytes = header_bytes.saturating_add(line.len() + 2);
            if header_bytes > MAX_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP proxy headers exceed 16384 bytes",
                ));
            }
            if line.is_empty() {
                break;
            }

            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("proxy-authorization") {
                authenticated_user = self.authenticate_basic(value);
                continue;
            }
            if name.eq_ignore_ascii_case("proxy-connection") {
                if !proxy_connection_seen {
                    proxy_keep_alive = value.eq_ignore_ascii_case("keep-alive");
                    proxy_connection_seen = true;
                }
                continue;
            }
            if name.eq_ignore_ascii_case("proxy-authenticate")
                || name.eq_ignore_ascii_case("te")
                || name.eq_ignore_ascii_case("trailers")
                || name.eq_ignore_ascii_case("upgrade")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                connection_hop_headers.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_ascii_lowercase),
                );
                continue;
            }
            if name.eq_ignore_ascii_case("host") {
                host_header = Some(value.to_string());
            }
            if name.eq_ignore_ascii_case("content-length") {
                let length = value.parse::<u64>().map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP Content-Length {value}: {error}"),
                    )
                })?;
                match request_content_length {
                    Some(previous) if previous != length => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "conflicting HTTP Content-Length headers",
                        ));
                    }
                    Some(_) => continue,
                    None => request_content_length = Some(length),
                }
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if request_transfer_encoding
                    || !value.eq_ignore_ascii_case("chunked")
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unsupported HTTP Transfer-Encoding",
                    ));
                }
                request_transfer_encoding = true;
                chunked_transfer_encoding = true;
            }
            forwarded_headers.push(line);
        }

        if !self.accounts.is_empty() && authenticated_user.is_none() {
            let response = format!(
                "{version} 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
            );
            server_stream.write_all(response.as_bytes()).await?;
            server_stream.flush().await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "missing or invalid HTTP proxy authentication",
            ));
        }

        let traffic_context = Some(
            authenticated_user
                .map(|identity| {
                    TrafficContext::new("http")
                        .with_identity(identity)
                        .with_inbound_tag(self.inbound_tag.clone())
                })
                .unwrap_or_else(|| {
                    TrafficContext::new("http")
                        .with_inbound_tag(self.inbound_tag.clone())
                }),
        );

        if method.eq_ignore_ascii_case("CONNECT") {
            let remote_location =
                NetLocation::from_str(target, None).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP CONNECT authority {target}: {error}"),
                    )
                })?;
            let response = format!("{version} 200 Connection established\r\n\r\n")
                .into_bytes()
                .into_boxed_slice();
            return Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: server_stream,
                need_initial_flush: true,
                connection_success_response: Some(response),
                traffic_context,
            });
        }

        let (remote_location, origin_target, absolute_authority) = if target
            .starts_with("http://")
        {
            let (remote_location, origin_target, authority) =
                parse_absolute_http_target(target, "http://", 80)?;
            (remote_location, origin_target, Some(authority))
        } else if target.starts_with("https://") {
            let (remote_location, origin_target, authority) =
                parse_absolute_http_target(target, "https://", 443)?;
            (remote_location, origin_target, Some(authority))
        } else if self.allow_transparent && target.starts_with('/') {
            let host = host_header.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "transparent HTTP request requires a Host header",
                )
            })?;
            let remote_location =
                NetLocation::from_str(host, Some(80)).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP Host header {host}: {error}"),
                    )
                })?;
            (remote_location, target.to_string(), None)
        } else {
            let response = format!(
                "{version} 400 Bad Request\r\n\
                 Connection: close\r\n\
                 Proxy-Connection: close\r\n\
                 Content-Length: 0\r\n\r\n"
            );
            server_stream.write_all(response.as_bytes()).await?;
            server_stream.flush().await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTP proxy request must use an absolute http:// URI unless allowTransparent is enabled",
            ));
        };

        let http_10_chunked = version == "HTTP/1.0" && chunked_transfer_encoding;
        let forwarded_version = if http_10_chunked { "HTTP/1.1" } else { version };
        let mut initial_request =
            format!("{method} {origin_target} {forwarded_version}\r\n");
        if let Some(authority) = absolute_authority.as_deref() {
            initial_request.push_str("Host: ");
            initial_request.push_str(authority);
            initial_request.push_str("\r\n");
        }
        for line in forwarded_headers {
            let header_name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if (absolute_authority.is_some() && header_name == "host")
                || connection_hop_headers
                    .iter()
                    .any(|name| name == &header_name)
                || (chunked_transfer_encoding && header_name == "content-length")
                || (http_10_chunked && header_name == "transfer-encoding")
            {
                continue;
            }
            initial_request.push_str(&line);
            initial_request.push_str("\r\n");
        }
        if http_10_chunked {
            initial_request.push_str("Content-Length: 0\r\n");
        }
        initial_request.push_str("Connection: close\r\n\r\n");

        let bodyless_plain_request = request_content_length.unwrap_or(0) == 0
            && !request_transfer_encoding
            && (method.eq_ignore_ascii_case("GET")
                || method.eq_ignore_ascii_case("HEAD"));
        if http_10_chunked || (proxy_keep_alive && bodyless_plain_request) {
            return Ok(TcpServerSetupResult::HttpPlainForward {
                remote_location,
                stream: server_stream,
                request_head: initial_request.into_bytes().into_boxed_slice(),
                request_method: method.to_string(),
                keep_alive: proxy_keep_alive,
                next_handler: Box::new(self.clone()),
                traffic_context,
            });
        }

        let stream: Box<dyn AsyncStream> = if chunked_transfer_encoding {
            Box::new(FirstChunkValidatedStream::new(
                initial_request.into_bytes(),
                server_stream,
            ))
        } else {
            Box::new(PrefixedStream::new(
                initial_request.into_bytes(),
                server_stream,
            ))
        };
        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream,
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
    }
}

struct FirstChunkValidatedStream {
    prefix: Box<[u8]>,
    prefix_offset: usize,
    first_chunk_line: Vec<u8>,
    first_chunk_validated: bool,
    inner: Box<dyn AsyncStream>,
}

impl FirstChunkValidatedStream {
    fn new(prefix: Vec<u8>, inner: Box<dyn AsyncStream>) -> Self {
        Self {
            prefix: prefix.into_boxed_slice(),
            prefix_offset: 0,
            first_chunk_line: Vec::new(),
            first_chunk_validated: false,
            inner,
        }
    }

    fn remaining_prefix(&self) -> &[u8] {
        &self.prefix[self.prefix_offset..]
    }
}

impl AsyncRead for FirstChunkValidatedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.first_chunk_validated {
            loop {
                let mut byte = [0u8; 1];
                let mut read_buf = ReadBuf::new(&mut byte);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "HTTP chunked body ended before first chunk size",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        this.first_chunk_line.push(byte[0]);
                        if this.first_chunk_line.len() > MAX_REQUEST_LINE_BYTES {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "HTTP chunk size line is too long",
                            )));
                        }
                        if this.first_chunk_line.ends_with(b"\r\n") {
                            validate_chunk_size_line(
                                &this.first_chunk_line
                                    [..this.first_chunk_line.len() - 2],
                            )?;
                            let mut prefix = this.prefix.to_vec();
                            prefix.extend_from_slice(&this.first_chunk_line);
                            this.prefix = prefix.into_boxed_slice();
                            this.first_chunk_validated = true;
                            break;
                        }
                    }
                }
            }
        }

        let remaining = this.remaining_prefix();
        if !remaining.is_empty() {
            let to_copy = remaining.len().min(buf.remaining());
            if to_copy > 0 {
                buf.put_slice(&remaining[..to_copy]);
                this.prefix_offset += to_copy;
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FirstChunkValidatedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncPing for FirstChunkValidatedStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl AsyncStream for FirstChunkValidatedStream {}

fn validate_chunk_size_line(line: &[u8]) -> std::io::Result<()> {
    let mut size = line.split(|byte| *byte == b';').next().unwrap_or_default();
    while matches!(size.last(), Some(b' ' | b'\t')) {
        size = &size[..size.len() - 1];
    }
    if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP chunk size",
        ));
    }
    Ok(())
}

fn parse_absolute_http_target(
    target: &str,
    scheme: &str,
    default_port: u16,
) -> std::io::Result<(NetLocation, String, String)> {
    let remainder = target.strip_prefix(scheme).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("HTTP proxy target must start with {scheme}"),
        )
    })?;
    validate_percent_escapes(remainder)?;
    let split = remainder
        .char_indices()
        .find_map(|(index, value)| matches!(value, '/' | '?').then_some(index));
    let (authority, path) = match split {
        Some(index) => {
            let tail = &remainder[index..];
            let path = if tail.starts_with('?') {
                format!("/{tail}")
            } else {
                let (path, query) = tail
                    .split_once('?')
                    .map(|(path, query)| (path, Some(query)))
                    .unwrap_or((tail, None));
                let mut path = path.replace('#', "%23");
                if let Some(query) = query {
                    path.push('?');
                    path.push_str(query);
                }
                path
            };
            (&remainder[..index], path)
        }
        None => (remainder, "/".to_string()),
    };
    let host_authority = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if host_authority.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP absolute URI is missing an authority",
        ));
    }
    if !host_authority.starts_with('[') && host_authority.contains('%') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid URL escape in HTTP absolute URI host",
        ));
    }
    let remote_location =
        parse_absolute_http_authority(host_authority, default_port)?;
    Ok((remote_location, path, host_authority.to_string()))
}

fn parse_absolute_http_authority(
    authority: &str,
    default_port: u16,
) -> std::io::Result<NetLocation> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (literal, suffix) = bracketed.split_once(']').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid HTTP absolute URI authority {authority}"),
            )
        })?;
        let address = literal.parse::<std::net::Ipv6Addr>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid HTTP absolute URI IPv6 authority {authority}: {error}"
                ),
            )
        })?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            let raw_port = suffix.strip_prefix(':').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid HTTP absolute URI authority {authority}"),
                )
            })?;
            raw_port.parse::<u16>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "invalid HTTP absolute URI port in {authority}: {error}"
                    ),
                )
            })?
        };
        return Ok(NetLocation::from_ip_addr(
            std::net::IpAddr::V6(address),
            port,
        ));
    }

    NetLocation::from_str(authority, Some(default_port)).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP absolute URI authority {authority}: {error}"),
        )
    })
}

fn validate_percent_escapes(value: &str) -> std::io::Result<()> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || !bytes[index + 1].is_ascii_hexdigit()
            || !bytes[index + 2].is_ascii_hexdigit()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid URL escape in HTTP absolute URI",
            ));
        }
        index += 3;
    }
    Ok(())
}

impl HttpTcpServerHandler {
    fn authenticate_basic(&self, value: &str) -> Option<String> {
        let token = value.strip_prefix("Basic ")?;
        let decoded = BASE64.decode(token).ok()?;
        let decoded = std::str::from_utf8(&decoded).ok()?;
        let (username, password) = decoded.split_once(':')?;
        self.accounts
            .iter()
            .find(|account| {
                account.username == username && account.password == password
            })
            .map(|account| account.username.clone())
    }
}

async fn read_http_line<S>(
    stream: &mut S,
    max_bytes: usize,
) -> std::io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        line.push(byte);
        if line.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy line is too long",
            ));
        }
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("HTTP proxy line is not UTF-8: {error}"),
                )
            });
        }
    }
}

pub(crate) async fn relay_plain_http_response<R, W>(
    upstream: &mut R,
    downstream: &mut W,
    request_method: &str,
) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let status_line =
            read_http_line(upstream, MAX_RESPONSE_HEADER_BYTES).await?;
        let status_code = parse_http_status_code(&status_line)?;
        let mut header_bytes = 0usize;
        let mut headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut content_length = None;
        let mut content_length_valid = true;
        let mut transfer_encoding = false;

        loop {
            let line = read_http_line(upstream, MAX_RESPONSE_HEADER_BYTES).await?;
            header_bytes = header_bytes.saturating_add(line.len() + 2);
            if header_bytes > MAX_RESPONSE_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP proxy response headers exceed 65536 bytes",
                ));
            }
            if line.is_empty() {
                break;
            }

            let Some((name, value)) = line.split_once(':') else {
                headers.push((String::new(), line));
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "connection" {
                connection_hop_headers.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_ascii_lowercase),
                );
            } else if name == "content-length" {
                match value.parse::<u64>() {
                    Ok(length) => match content_length {
                        Some(previous) if previous != length => {
                            content_length_valid = false;
                        }
                        None => content_length = Some(length),
                        _ => {}
                    },
                    Err(_) => content_length_valid = false,
                }
            } else if name == "transfer-encoding" {
                transfer_encoding = true;
            }
            headers.push((name, line));
        }

        if (100..200).contains(&status_code) {
            write_http_header_block(downstream, &status_line, &headers).await?;
            continue;
        }

        let no_body = request_method.eq_ignore_ascii_case("HEAD")
            || matches!(status_code, 204 | 304);
        let body_length = if no_body {
            Some(0)
        } else if !transfer_encoding && content_length_valid {
            content_length
        } else {
            None
        };

        let mut response_head = format!("{status_line}\r\n");
        for (name, line) in headers {
            let strip_static = matches!(
                name.as_str(),
                "proxy-connection"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
                    | "upgrade"
            ) || (name == "transfer-encoding"
                && body_length.is_some());
            if name == "connection"
                || (body_length.is_some() && name == "keep-alive")
                || strip_static
                || connection_hop_headers.iter().any(|hop| hop == &name)
            {
                continue;
            }
            response_head.push_str(&line);
            response_head.push_str("\r\n");
        }
        if body_length.is_some() {
            response_head.push_str(
                "Connection: keep-alive\r\n\
                 Keep-Alive: timeout=60\r\n\
                 Proxy-Connection: keep-alive\r\n",
            );
        } else {
            response_head.push_str("Connection: close\r\n");
        }
        response_head.push_str("\r\n");
        downstream.write_all(response_head.as_bytes()).await?;

        if let Some(length) = body_length {
            let mut body = upstream.take(length);
            let copied = tokio::io::copy(&mut body, downstream).await?;
            if copied != length {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP proxy upstream response body ended early",
                ));
            }
        } else {
            tokio::io::copy(upstream, downstream).await?;
        }
        downstream.flush().await?;
        return Ok(body_length.is_some());
    }
}

fn parse_http_status_code(status_line: &str) -> std::io::Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid HTTP proxy upstream status line: {status_line}"),
        ));
    }
    status.parse::<u16>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid HTTP proxy upstream status code {status}: {error}"),
        )
    })
}

async fn write_http_header_block<W>(
    writer: &mut W,
    status_line: &str,
    headers: &[(String, String)],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(status_line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    for (_, line) in headers {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\r\n").await?;
    }
    writer.write_all(b"\r\n").await
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use crate::{
        async_stream::{AsyncPing, AsyncStream},
        config::server_config::HttpUser,
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::{HttpTcpServerHandler, relay_plain_http_response};

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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

    #[tokio::test]
    async fn connect_preserves_early_tunnel_bytes() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-in");
        let request =
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nearly";
        let (mut client, server) = duplex(1024);
        client.write_all(request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("CONNECT should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("HTTP CONNECT returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:443");
        assert_eq!(
            connection_success_response.as_deref(),
            Some(b"HTTP/1.1 200 Connection established\r\n\r\n".as_slice())
        );
        assert_eq!(
            traffic_context.unwrap().inbound_tag.as_deref(),
            Some("http-in")
        );
        let mut early = [0u8; 5];
        stream.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
    }

    #[tokio::test]
    async fn basic_auth_sets_user_identity() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-auth",
        );
        let token = BASE64.encode("alice:secret");
        let request = format!(
            "CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("authenticated CONNECT should succeed");
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = result
        else {
            panic!("HTTP CONNECT returned non-TCP result");
        };
        assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn basic_auth_matches_xray_scheme_and_spacing() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-auth",
        );
        let token = BASE64.encode("alice:secret");

        for authorization in [
            format!("basic {token}"),
            format!("Basic  {token}"),
            format!("Basic\t{token}"),
        ] {
            let request = format!(
                "CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: {authorization}\r\n\r\n"
            );
            let (mut client, server) = duplex(1024);
            client.write_all(request.as_bytes()).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects non-canonical Basic authorization"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(
                response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required")
            );
        }
    }

    #[tokio::test]
    async fn absolute_form_request_is_rewritten_and_proxy_headers_are_removed() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-forward",
        );
        let token = BASE64.encode("alice:secret");
        let request = format!(
            "POST http://example.com:8080/upload?q=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             Proxy-Authorization: Basic {token}\r\n\
             Proxy-Authenticate: Basic realm=\"upstream\"\r\n\
             TE: trailers\r\n\
             Trailers: X-Checksum\r\n\
             Upgrade: websocket\r\n\
             X-Remove-Early: hidden\r\n\
             Proxy-Connection: keep-alive\r\n\
             Connection: keep-alive, X-Remove-Early, x-remove-late\r\n\
             X-Test: forwarded\r\n\
             X-Remove-Late: hidden-too\r\n\r\nbody"
        );
        let (mut client, server) = duplex(4096);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("absolute-form HTTP proxy request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("HTTP forward returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:8080");
        assert!(connection_success_response.is_none());
        assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "POST /upload?q=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             X-Test: forwarded\r\n\
             Connection: close\r\n\r\nbody"
        );
    }

    #[tokio::test]
    async fn https_absolute_form_uses_default_https_semantics_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-https");
        let request = b"GET https://example.com/secure?q=1 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\
X-Test: forwarded\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("HTTPS absolute-form HTTP proxy request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("HTTPS absolute-form request returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:443");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /secure?q=1 HTTP/1.1\r\n\
Host: example.com\r\n\
X-Test: forwarded\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn absolute_form_path_hashes_are_escaped_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-fragment");
        let request = b"GET http://example.com/path#frag?x=#query HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("absolute-form path hash should be normalized like Xray");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("absolute-form path hash returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:80");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /path%23frag?x=#query HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn absolute_form_rejects_invalid_percent_escapes_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-percent");
        for target in [
            "http://example.com/a%zz",
            "http://example.com/a%",
            "http://example.com/a%2",
            "http://example.com/ok?q=%zz",
        ] {
            let request =
                format!("GET {target} HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n");
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => {
                    panic!("invalid percent escape should be rejected: {target}")
                }
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("invalid URL escape"));
        }
    }

    #[tokio::test]
    async fn absolute_form_rejects_percent_escaped_host_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-host-escape");
        for target in [
            "http://exa%6dple.invalid/a",
            "http://127.0.0.1%40evil.invalid/a",
        ] {
            let request =
                format!("GET {target} HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n");
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("percent-escaped host should be rejected: {target}"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("invalid URL escape"));
        }
    }

    #[tokio::test]
    async fn absolute_form_accepts_percent_escaped_userinfo_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-userinfo-escape");
        let request = b"GET http://user%40name:pass@example.com/a HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("percent-escaped userinfo should remain accepted");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("percent-escaped userinfo returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:80");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /a HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn absolute_form_preserves_valid_percent_escapes_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-percent");
        let request = b"GET http://example.com/a%2Fb?q=%25 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("valid percent escapes should remain accepted");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("valid percent escapes returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /a%2Fb?q=%25 HTTP/1.1\r\n\
Host: example.com\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn absolute_form_ipv6_authority_is_forwarded_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-ipv6");
        let request = b"GET http://[2001:db8::1]:8080/ipv6?q=1 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("bracketed IPv6 absolute-form request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("IPv6 absolute-form request returned non-TCP result");
        };
        assert_eq!(remote_location.address().to_string(), "2001:db8::1");
        assert_eq!(remote_location.port(), 8080);
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /ipv6?q=1 HTTP/1.1\r\n\
Host: [2001:db8::1]:8080\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn absolute_form_ipv6_userinfo_uses_default_port_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-ipv6-user");
        let request = b"GET http://user:pass@[2001:db8::2]/secret HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("IPv6 userinfo absolute-form request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("IPv6 userinfo absolute-form request returned non-TCP result");
        };
        assert_eq!(remote_location.address().to_string(), "2001:db8::2");
        assert_eq!(remote_location.port(), 80);
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /secret HTTP/1.1\r\n\
Host: [2001:db8::2]\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn absolute_form_userinfo_is_not_forwarded_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-userinfo");
        let request =
            b"GET http://user:pass@example.com:8080/secret?q=1 HTTP/1.1\r\n\
Host: ignored.invalid\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("absolute-form userinfo should be accepted like Xray");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("absolute-form userinfo returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:8080");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /secret?q=1 HTTP/1.1\r\n\
Host: example.com:8080\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn chunked_request_drops_conflicting_content_length_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-chunked");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 99\r\n\
Transfer-Encoding: chunked\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("chunked HTTP proxy request should succeed");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding: chunked\r\n\
Connection: close\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn invalid_first_chunk_size_fails_before_forwarding_bytes() {
        for chunk_size in ["Z", "0x4", "+4", " 4", "00000000000000000"] {
            let handler =
                HttpTcpServerHandler::new(Vec::new(), false, "http-chunk-size");
            let request = format!(
                "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: chunked\r\n\r\n\
                 {chunk_size}\r\ntest\r\n0\r\n\r\n"
            );
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("chunk syntax validation is deferred until relay starts");
            let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
                panic!("chunked HTTP request returned non-TCP result");
            };
            let mut forwarded = Vec::new();
            let error = stream.read_to_end(&mut forwarded).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(forwarded.is_empty());
        }
    }

    #[tokio::test]
    async fn supported_first_chunk_size_variants_still_stream() {
        for chunk_size in ["4 ", "4;foo=bar"] {
            let handler =
                HttpTcpServerHandler::new(Vec::new(), false, "http-chunk-size");
            let request = format!(
                "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: chunked\r\n\r\n\
                 {chunk_size}\r\ntest\r\n0\r\n\r\n"
            );
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray-compatible first chunk size should succeed");
            let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
                panic!("chunked HTTP request returned non-TCP result");
            };
            let mut forwarded = Vec::new();
            stream.read_to_end(&mut forwarded).await.unwrap();
            assert!(
                forwarded.ends_with(
                    format!("{chunk_size}\r\ntest\r\n0\r\n\r\n").as_bytes()
                )
            );
        }
    }

    #[tokio::test]
    async fn http_10_chunked_body_is_ignored_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-10-chunked");
        let request = b"POST http://example.com/upload HTTP/1.0\r\n\
Host: ignored.invalid\r\n\
Transfer-Encoding: chunked\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("HTTP/1.0 chunked request should succeed");
        let TcpServerSetupResult::HttpPlainForward {
            request_head,
            keep_alive,
            ..
        } = result
        else {
            panic!("HTTP/1.0 chunked request returned non-plain-HTTP result");
        };
        assert!(!keep_alive);
        assert_eq!(
            request_head.as_ref(),
            b"POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn unsupported_transfer_encoding_is_rejected_like_xray() {
        for transfer_encoding in [
            "gzip",
            "chunked, gzip",
            "gzip, chunked",
            "chunked\r\nTransfer-Encoding: chunked",
        ] {
            let handler = HttpTcpServerHandler::new(
                Vec::new(),
                false,
                "http-transfer-encoding",
            );
            let request = format!(
                "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: {transfer_encoding}\r\n\r\n\
                 4\r\ntest\r\n0\r\n\r\n"
            );
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!(
                    "unsupported Transfer-Encoding {transfer_encoding:?} must be rejected"
                ),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                error
                    .to_string()
                    .contains("unsupported HTTP Transfer-Encoding")
            );
        }
    }

    #[tokio::test]
    async fn duplicate_content_length_is_collapsed_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Content-Length: 4\r\n\r\nbody";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("matching duplicate Content-Length should succeed");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Connection: close\r\n\r\nbody"
        );
    }

    #[tokio::test]
    async fn conflicting_content_length_is_rejected_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Content-Length: 5\r\n\r\nbody";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("conflicting Content-Length must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("conflicting HTTP Content-Length")
        );
    }

    #[tokio::test]
    async fn keep_alive_get_uses_plain_http_forward() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-keepalive");
        let request = b"GET http://example.com/one HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Proxy-Connection: keep-alive\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("keep-alive GET should use the plain HTTP relay");
        let TcpServerSetupResult::HttpPlainForward {
            remote_location,
            request_head,
            request_method,
            keep_alive,
            traffic_context,
            ..
        } = result
        else {
            panic!("keep-alive GET returned non-HTTP plain result");
        };
        assert_eq!(remote_location.to_string(), "example.com:80");
        assert_eq!(request_method, "GET");
        assert!(keep_alive);
        assert_eq!(
            traffic_context.unwrap().inbound_tag.as_deref(),
            Some("http-keepalive")
        );
        assert_eq!(
            request_head.as_ref(),
            b"GET /one HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn plain_http_response_with_content_length_is_reusable() {
        let upstream_response = b"HTTP/1.1 100 Continue\r\nX-Early: yes\r\n\r\n\
                                  HTTP/1.1 200 OK\r\n\
                                  Content-Length: 5\r\n\
                                  Connection: close, X-Remove\r\n\
                                  Keep-Alive: timeout=5\r\n\
                                  X-Remove: hidden\r\n\
                                  X-Keep: visible\r\n\r\nhello";
        let (mut upstream_client, mut upstream_server) = duplex(4096);
        upstream_client.write_all(upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(4096);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 100 Continue\r\nX-Early: yes\r\n\r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 5\r\n\
             X-Keep: visible\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn plain_http_response_without_length_closes_connection() {
        let upstream_response = b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nhello";
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client.write_all(upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 200 OK\r\nX-Test: yes\r\nConnection: close\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn transparent_origin_form_uses_host_header() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), true, "http-transparent");
        let request = b"GET /health HTTP/1.1\r\nHost: example.com:8081\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("transparent HTTP request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("transparent HTTP returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:8081");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /health HTTP/1.1\r\n\
             Host: example.com:8081\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn origin_form_requires_allow_transparent() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-proxy");
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("origin-form request must require transparent mode"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("allowTransparent"));
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 400 Bad Request\r\n\
              Connection: close\r\n\
              Proxy-Connection: close\r\n\
              Content-Length: 0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn missing_auth_returns_407() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-auth",
        );
        let (mut client, server) = duplex(2048);
        client
            .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("missing auth must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
        );
    }
}
