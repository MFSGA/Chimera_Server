use std::{
    collections::{BTreeMap, BTreeSet},
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::HttpUser,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
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
    user_level: u32,
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
            user_level: 0,
        }
    }

    pub fn with_user_level(mut self, user_level: u32) -> Self {
        self.user_level = user_level;
        self
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_inner(server_stream).await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        let Some(runtime) = context.runtime.as_ref() else {
            return self.setup_server_stream_inner(server_stream).await;
        };
        let timeout = runtime.xray_handshake_timeout_for_level(self.user_level);
        tokio::time::timeout(timeout, self.setup_server_stream_inner(server_stream))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP handshake timed out",
                )
            })?
    }
}

impl HttpTcpServerHandler {
    async fn setup_server_stream_inner(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let request_line =
            read_http_line(&mut server_stream, MAX_REQUEST_LINE_BYTES).await?;
        let (method, target, version) = parse_http_request_line(&request_line)?;

        let mut header_bytes = 0usize;
        let mut authenticated_user = None;
        let mut proxy_authorization_seen = false;
        let mut host_header = None;
        let mut host_header_seen = false;
        let mut forwarded_headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut proxy_keep_alive = false;
        let mut proxy_connection_seen = false;
        let mut request_content_length = None;
        let mut request_transfer_encoding = false;
        let mut chunked_transfer_encoding = false;
        let mut request_trailer_values = Vec::new();
        let mut header_lines: Vec<String> = Vec::new();
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
            if line.starts_with([' ', '\t']) {
                let previous = header_lines.last_mut().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "HTTP header continuation has no preceding field",
                    )
                })?;
                previous.push(' ');
                previous.push_str(line.trim());
            } else {
                header_lines.push(line);
            }
        }

        for line in header_lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "malformed HTTP header line",
                ));
            };
            if !is_http_header_name(name) {
                continue;
            }
            if has_invalid_http_header_value(value) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid control character in HTTP header value",
                ));
            }
            let value = value.trim();
            if name.eq_ignore_ascii_case("proxy-authorization") {
                if !proxy_authorization_seen {
                    authenticated_user = self.authenticate_basic(value);
                    proxy_authorization_seen = true;
                }
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
            if name.eq_ignore_ascii_case("trailer") {
                request_trailer_values.push(value.to_string());
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
                if host_header_seen {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "multiple HTTP Host headers",
                    ));
                }
                host_header_seen = true;
                host_header = Some(value.to_string());
            }
            if name.eq_ignore_ascii_case("content-length") {
                let length = parse_http_content_length(value)?;
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
                forwarded_headers.push(format!("Content-Length: {length}"));
                continue;
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

        let request_trailer_names = if chunked_transfer_encoding {
            let mut names = BTreeSet::new();
            for value in request_trailer_values {
                names.extend(parse_http_request_trailer_names(&value)?);
            }
            names
        } else {
            BTreeSet::new()
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
        } else if chunked_transfer_encoding && !request_trailer_names.is_empty() {
            initial_request.push_str("Trailer: ");
            initial_request.push_str(
                &request_trailer_names
                    .iter()
                    .map(|name| canonical_http_header_name(name))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            initial_request.push_str("\r\n");
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
            Box::new(ChunkedRequestStream::new(
                initial_request.into_bytes(),
                server_stream,
                request_trailer_names.into_iter().collect(),
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

enum ChunkedRequestState {
    ChunkSize {
        line: Vec<u8>,
        first: bool,
    },
    ChunkData {
        remaining: u64,
    },
    ChunkDataTerminator {
        bytes: [u8; 2],
        filled: usize,
    },
    Trailers {
        line: Vec<u8>,
        lines: Vec<String>,
        header_bytes: usize,
    },
    Finished,
}

struct ChunkedRequestStream {
    request_head: Option<Box<[u8]>>,
    trailer_names: Vec<String>,
    decoded: Vec<u8>,
    output: Vec<u8>,
    output_offset: usize,
    pending_error: Option<std::io::Error>,
    state: ChunkedRequestState,
    inner: Box<dyn AsyncStream>,
}

impl ChunkedRequestStream {
    const REENCODE_BUFFER_SIZE: usize = 32 * 1024;

    fn new(
        request_head: Vec<u8>,
        inner: Box<dyn AsyncStream>,
        trailer_names: Vec<String>,
    ) -> Self {
        Self {
            request_head: Some(request_head.into_boxed_slice()),
            trailer_names,
            decoded: Vec::with_capacity(Self::REENCODE_BUFFER_SIZE),
            output: Vec::new(),
            output_offset: 0,
            pending_error: None,
            state: ChunkedRequestState::ChunkSize {
                line: Vec::new(),
                first: true,
            },
            inner,
        }
    }

    fn queue_bytes(&mut self, bytes: &[u8]) {
        if self.output_offset == self.output.len() {
            self.output.clear();
            self.output_offset = 0;
        }
        self.output.extend_from_slice(bytes);
    }

    fn queue_decoded_chunk(&mut self) {
        if self.decoded.is_empty() {
            return;
        }
        self.queue_bytes(format!("{:x}\r\n", self.decoded.len()).as_bytes());
        let decoded = std::mem::take(&mut self.decoded);
        self.queue_bytes(&decoded);
        self.queue_bytes(b"\r\n");
        self.decoded = Vec::with_capacity(Self::REENCODE_BUFFER_SIZE);
    }

    fn queue_request_head(&mut self) {
        if let Some(head) = self.request_head.take() {
            self.queue_bytes(&head);
        }
    }

    fn fail_after_decoded(&mut self, error: std::io::Error) {
        self.queue_decoded_chunk();
        self.pending_error = Some(error);
        self.state = ChunkedRequestState::Finished;
    }

    fn drain_output(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.output[self.output_offset..];
        if remaining.is_empty() || buf.remaining() == 0 {
            return false;
        }
        let to_copy = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..to_copy]);
        self.output_offset += to_copy;
        true
    }

    fn finish_trailers(&mut self, lines: Vec<String>) -> std::io::Result<()> {
        let trailers =
            normalize_chunked_request_trailers(lines, &self.trailer_names)?;
        self.queue_bytes(b"0\r\n");
        for trailer in trailers {
            self.queue_bytes(trailer.as_bytes());
            self.queue_bytes(b"\r\n");
        }
        self.queue_bytes(b"\r\n");
        self.state = ChunkedRequestState::Finished;
        Ok(())
    }
}

impl AsyncRead for ChunkedRequestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.drain_output(buf) {
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = this.pending_error.take() {
                return Poll::Ready(Err(error));
            }

            match &mut this.state {
                ChunkedRequestState::ChunkSize { line, first } => {
                    let mut byte = [0u8; 1];
                    let mut read_buf = ReadBuf::new(&mut byte);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "HTTP chunked request ended before chunk size",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            line.push(byte[0]);
                            if line.len() > MAX_REQUEST_LINE_BYTES {
                                let error = std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "HTTP chunk size line is too long",
                                );
                                if *first {
                                    return Poll::Ready(Err(error));
                                }
                                this.fail_after_decoded(error);
                                continue;
                            }
                            if !line.ends_with(b"\r\n") {
                                continue;
                            }
                            let size =
                                match parse_chunk_size_line(&line[..line.len() - 2])
                                {
                                    Ok(size) => size,
                                    Err(error) if *first => {
                                        return Poll::Ready(Err(error));
                                    }
                                    Err(error) => {
                                        this.fail_after_decoded(error);
                                        continue;
                                    }
                                };
                            if *first {
                                this.queue_request_head();
                            }
                            if size == 0 {
                                this.queue_decoded_chunk();
                                this.state = ChunkedRequestState::Trailers {
                                    line: Vec::new(),
                                    lines: Vec::new(),
                                    header_bytes: 0,
                                };
                            } else {
                                this.state = ChunkedRequestState::ChunkData {
                                    remaining: size,
                                };
                            }
                        }
                    }
                }
                ChunkedRequestState::ChunkData { remaining } => {
                    let available = Self::REENCODE_BUFFER_SIZE - this.decoded.len();
                    let read_len = available.min((*remaining).min(8192) as usize);
                    let mut bytes = [0u8; 8192];
                    let mut read_buf = ReadBuf::new(&mut bytes[..read_len]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.fail_after_decoded(error);
                        }
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            this.fail_after_decoded(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "HTTP chunked request body ended early",
                            ));
                        }
                        Poll::Ready(Ok(())) => {
                            this.decoded.extend_from_slice(read_buf.filled());
                            *remaining -= read_buf.filled().len() as u64;
                            let chunk_complete = *remaining == 0;
                            let buffer_full =
                                this.decoded.len() == Self::REENCODE_BUFFER_SIZE;
                            if buffer_full {
                                this.queue_decoded_chunk();
                            }
                            if chunk_complete {
                                this.state =
                                    ChunkedRequestState::ChunkDataTerminator {
                                        bytes: [0u8; 2],
                                        filled: 0,
                                    };
                            }
                        }
                    }
                }
                ChunkedRequestState::ChunkDataTerminator { bytes, filled } => {
                    let mut read_buf = ReadBuf::new(&mut bytes[*filled..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => this.fail_after_decoded(error),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            this.fail_after_decoded(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "HTTP chunked request data terminator ended early",
                            ));
                        }
                        Poll::Ready(Ok(())) => {
                            *filled += read_buf.filled().len();
                            if *filled != 2 {
                                continue;
                            }
                            if *bytes != *b"\r\n" {
                                this.fail_after_decoded(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid HTTP chunk data terminator",
                                ));
                            } else {
                                this.state = ChunkedRequestState::ChunkSize {
                                    line: Vec::new(),
                                    first: false,
                                };
                            }
                        }
                    }
                }
                ChunkedRequestState::Trailers {
                    line,
                    lines,
                    header_bytes,
                } => {
                    let mut byte = [0u8; 1];
                    let mut read_buf = ReadBuf::new(&mut byte);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "HTTP chunked request trailers ended early",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            line.push(byte[0]);
                            if !line.ends_with(b"\r\n") {
                                continue;
                            }
                            *header_bytes = header_bytes.saturating_add(line.len());
                            if *header_bytes > MAX_HEADER_BYTES {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "HTTP chunked request trailers exceed 16384 bytes",
                                )));
                            }
                            let raw = std::mem::take(line);
                            let value = match String::from_utf8(
                                raw[..raw.len() - 2].to_vec(),
                            ) {
                                Ok(value) => value,
                                Err(error) => {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        format!(
                                            "HTTP request trailer is not UTF-8: {error}"
                                        ),
                                    )));
                                }
                            };
                            if value.is_empty() {
                                let lines = std::mem::take(lines);
                                if let Err(error) = this.finish_trailers(lines) {
                                    return Poll::Ready(Err(error));
                                }
                                continue;
                            }
                            if value.starts_with([' ', '\t']) {
                                let Some(previous) = lines.last_mut() else {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "HTTP request trailer continuation has no preceding field",
                                    )));
                                };
                                previous.push(' ');
                                previous.push_str(value.trim());
                            } else {
                                lines.push(value);
                            }
                        }
                    }
                }
                ChunkedRequestState::Finished => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for ChunkedRequestStream {
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

impl AsyncPing for ChunkedRequestStream {
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

impl AsyncStream for ChunkedRequestStream {}

fn parse_http_content_length(value: &str) -> std::io::Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP Content-Length {value}"),
        ));
    }
    let length = value.parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP Content-Length {value}: {error}"),
        )
    })?;
    if length > i64::MAX as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP Content-Length {value}"),
        ));
    }
    Ok(length)
}

fn has_invalid_http_header_value(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
}

fn is_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
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
}

fn parse_http_request_line(
    request_line: &str,
) -> std::io::Result<(&str, &str, &str)> {
    let Some((method, remainder)) = request_line.split_once(' ') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP proxy request line: {request_line}"),
        ));
    };
    let Some((target, version)) = remainder.split_once(' ') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP proxy request line: {request_line}"),
        ));
    };
    if method.is_empty()
        || target.is_empty()
        || method.bytes().any(|byte| byte.is_ascii_whitespace())
        || target.bytes().any(|byte| byte.is_ascii_whitespace())
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP proxy request line: {request_line}"),
        ));
    }
    Ok((method, target, version))
}

fn validate_chunk_size_line(line: &[u8]) -> std::io::Result<()> {
    parse_chunk_size_line(line).map(|_| ())
}

fn parse_chunk_size_line(line: &[u8]) -> std::io::Result<u64> {
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
    u64::from_str_radix(
        std::str::from_utf8(size).expect("validated chunk size is ASCII"),
        16,
    )
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP chunk size",
        )
    })
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
            parse_xray_http_port(raw_port, default_port, authority)?
        };
        return Ok(NetLocation::from_ip_addr(
            std::net::IpAddr::V6(address),
            port,
        ));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, raw_port)) => {
            let port = parse_xray_http_port(raw_port, default_port, authority)?;
            (host, port)
        }
        None => (authority, default_port),
    };
    let address = Address::from(host).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP absolute URI authority {authority}: {error}"),
        )
    })?;
    Ok(NetLocation::new(address, port))
}

fn parse_xray_http_port(
    raw_port: &str,
    default_port: u16,
    authority: &str,
) -> std::io::Result<u16> {
    if raw_port.is_empty() {
        return Ok(default_port);
    }
    if !raw_port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP absolute URI port in {authority}"),
        ));
    }
    let port = raw_port.parse::<usize>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid HTTP absolute URI port in {authority}: {error}"),
        )
    })?;
    Ok(port as u16)
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
        let mut header_lines: Vec<String> = Vec::new();
        let mut headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut content_length = None;
        let mut transfer_encoding = false;
        let mut transfer_encoding_seen = false;
        let mut trailer_names = Vec::new();

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
            if line.starts_with([' ', '\t']) {
                let previous = header_lines.last_mut().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP response header continuation has no preceding field",
                    )
                })?;
                previous.push(' ');
                previous.push_str(line.trim());
            } else {
                header_lines.push(line);
            }
        }

        for line in header_lines {
            let Some((name, value)) = line.split_once(':') else {
                write_http_service_unavailable(downstream).await?;
                return Ok(false);
            };
            if !is_http_header_name(name) {
                continue;
            }
            if has_invalid_http_header_value(value) {
                write_http_service_unavailable(downstream).await?;
                return Ok(false);
            }
            let name = name.to_ascii_lowercase();
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
                let length = match parse_http_content_length(value) {
                    Ok(length) => length,
                    Err(_) => {
                        write_http_service_unavailable(downstream).await?;
                        return Ok(false);
                    }
                };
                match content_length {
                    Some(previous) if previous != length => {
                        write_http_service_unavailable(downstream).await?;
                        return Ok(false);
                    }
                    Some(_) => continue,
                    None => content_length = Some(length),
                }
                headers.push((name, format!("Content-Length: {length}")));
                continue;
            } else if name == "transfer-encoding" {
                if transfer_encoding_seen || !value.eq_ignore_ascii_case("chunked") {
                    write_http_service_unavailable(downstream).await?;
                    return Ok(false);
                }
                transfer_encoding_seen = true;
                transfer_encoding = true;
            } else if name == "trailer" {
                match parse_http_trailer_names(value) {
                    Ok(names) => trailer_names.extend(names),
                    Err(_) => {
                        write_http_service_unavailable(downstream).await?;
                        return Ok(false);
                    }
                }
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
        } else if !transfer_encoding {
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
                || name == "trailer"
                || (body_length.is_some() && name == "keep-alive")
                || (transfer_encoding && name == "content-length")
                || strip_static
                || connection_hop_headers.iter().any(|hop| hop == &name)
            {
                continue;
            }
            response_head.push_str(&line);
            response_head.push_str("\r\n");
        }
        if transfer_encoding && !trailer_names.is_empty() {
            let names = trailer_names
                .iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|name| canonical_http_header_name(name))
                .collect::<Vec<_>>()
                .join(",");
            response_head.push_str("Trailer: ");
            response_head.push_str(&names);
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
        } else if transfer_encoding {
            relay_chunked_http_response_body(upstream, downstream, &trailer_names)
                .await?;
        } else {
            tokio::io::copy(upstream, downstream).await?;
        }
        downstream.flush().await?;
        return Ok(body_length.is_some());
    }
}

async fn relay_chunked_http_response_body<R, W>(
    upstream: &mut R,
    downstream: &mut W,
    trailer_names: &[String],
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const REENCODE_BUFFER_SIZE: usize = 32 * 1024;

    let mut decoded = Vec::with_capacity(REENCODE_BUFFER_SIZE);
    loop {
        let chunk_size_line =
            match read_http_line(upstream, MAX_REQUEST_LINE_BYTES).await {
                Ok(line) => line,
                Err(error) => {
                    write_reencoded_chunk(downstream, &mut decoded).await?;
                    return Err(error);
                }
            };
        let chunk_size = match parse_chunk_size_line(chunk_size_line.as_bytes()) {
            Ok(size) => size,
            Err(error) => {
                write_reencoded_chunk(downstream, &mut decoded).await?;
                return Err(error);
            }
        };

        if chunk_size == 0 {
            write_reencoded_chunk(downstream, &mut decoded).await?;
            let trailers =
                read_chunked_response_trailers(upstream, trailer_names).await?;
            downstream.write_all(b"0\r\n").await?;
            for trailer in trailers {
                downstream.write_all(trailer.as_bytes()).await?;
                downstream.write_all(b"\r\n").await?;
            }
            downstream.write_all(b"\r\n").await?;
            return Ok(());
        }

        let mut remaining = chunk_size;
        while remaining != 0 {
            let available = REENCODE_BUFFER_SIZE - decoded.len();
            let read_len = available.min(remaining.min(usize::MAX as u64) as usize);
            let start = decoded.len();
            decoded.resize(start + read_len, 0);
            let read = upstream.read(&mut decoded[start..]).await?;
            if read == 0 {
                decoded.truncate(start);
                write_reencoded_chunk(downstream, &mut decoded).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP chunked response body ended early",
                ));
            }
            decoded.truncate(start + read);
            remaining -= read as u64;
            if decoded.len() == REENCODE_BUFFER_SIZE {
                write_reencoded_chunk(downstream, &mut decoded).await?;
            }
        }

        let mut chunk_terminator = [0u8; 2];
        if let Err(error) = upstream.read_exact(&mut chunk_terminator).await {
            write_reencoded_chunk(downstream, &mut decoded).await?;
            return Err(error);
        }
        if chunk_terminator != *b"\r\n" {
            write_reencoded_chunk(downstream, &mut decoded).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP chunk data terminator",
            ));
        }
    }
}

fn parse_http_request_trailer_names(value: &str) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for name in value.split(',').map(str::trim) {
        if !is_http_header_name(name)
            || matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length" | "transfer-encoding" | "trailer"
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid HTTP request trailer declaration",
            ));
        }
        names.push(name.to_ascii_lowercase());
    }
    Ok(names)
}

fn normalize_chunked_request_trailers(
    trailers: Vec<String>,
    trailer_names: &[String],
) -> std::io::Result<Vec<String>> {
    let mut forwarded: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for trailer in trailers {
        let Some((name, value)) = trailer.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTP request trailer line",
            ));
        };
        if !is_http_header_name(name) {
            continue;
        }
        if has_invalid_http_header_value(value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid control character in HTTP request trailer value",
            ));
        }
        if trailer_names
            .iter()
            .any(|declared| declared.eq_ignore_ascii_case(name))
        {
            forwarded
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
    }
    Ok(forwarded
        .into_iter()
        .flat_map(|(name, values)| {
            let name = canonical_http_header_name(&name);
            values
                .into_iter()
                .map(move |value| format!("{name}: {value}"))
        })
        .collect())
}

fn parse_http_trailer_names(value: &str) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for name in value.split(',').map(str::trim) {
        if !is_http_header_name(name)
            || matches!(
                name.to_ascii_lowercase().as_str(),
                "content-length" | "transfer-encoding" | "trailer"
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP response trailer declaration",
            ));
        }
        names.push(name.to_ascii_lowercase());
    }
    Ok(names)
}

async fn read_chunked_response_trailers<R>(
    upstream: &mut R,
    trailer_names: &[String],
) -> std::io::Result<Vec<String>>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = 0usize;
    let mut trailers: Vec<String> = Vec::new();
    loop {
        let line = read_http_line(upstream, MAX_HEADER_BYTES).await?;
        header_bytes = header_bytes.saturating_add(line.len() + 2);
        if header_bytes > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP chunked response trailers exceed 16384 bytes",
            ));
        }
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            let previous = trailers.last_mut().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP response trailer continuation has no preceding field",
                )
            })?;
            previous.push(' ');
            previous.push_str(line.trim());
        } else {
            trailers.push(line);
        }
    }

    let mut forwarded: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for trailer in trailers {
        let Some((name, value)) = trailer.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTP response trailer line",
            ));
        };
        if !is_http_header_name(name) {
            continue;
        }
        if has_invalid_http_header_value(value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid control character in HTTP response trailer value",
            ));
        }
        if trailer_names
            .iter()
            .any(|declared| declared.eq_ignore_ascii_case(name))
        {
            forwarded
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
    }
    Ok(forwarded
        .into_iter()
        .flat_map(|(name, values)| {
            let name = canonical_http_header_name(&name);
            values
                .into_iter()
                .map(move |value| format!("{name}: {value}"))
        })
        .collect())
}

fn canonical_http_header_name(name: &str) -> String {
    let mut upper_next = true;
    name.bytes()
        .map(|byte| {
            let byte = if upper_next {
                byte.to_ascii_uppercase()
            } else {
                byte.to_ascii_lowercase()
            };
            upper_next = byte == b'-';
            byte as char
        })
        .collect()
}

async fn write_reencoded_chunk<W>(
    downstream: &mut W,
    decoded: &mut Vec<u8>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if decoded.is_empty() {
        return Ok(());
    }
    downstream
        .write_all(format!("{:x}\r\n", decoded.len()).as_bytes())
        .await?;
    downstream.write_all(decoded).await?;
    downstream.write_all(b"\r\n").await?;
    decoded.clear();
    Ok(())
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

async fn write_http_service_unavailable<W>(writer: &mut W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\n\
              Connection: close\r\n\
              Proxy-Connection: close\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    writer.flush().await
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
        collections::HashMap,
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
        config::{
            def::{PolicyConfig, PolicyLevelConfig},
            server_config::HttpUser,
        },
        handler::tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
        runtime::RuntimeState,
    };

    use super::{
        HttpTcpServerHandler, parse_absolute_http_authority,
        parse_http_request_line, relay_plain_http_response,
    };

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
    async fn http_handshake_policy_covers_first_byte_like_xray() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let mut levels = HashMap::new();
        levels.insert(
            7,
            Some(PolicyLevelConfig {
                handshake: Some(0),
                ..PolicyLevelConfig::default()
            }),
        );
        runtime.replace_policy(Some(&PolicyConfig {
            levels,
            ..PolicyConfig::default()
        }));

        let (_client, server) = duplex(1024);
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-policy")
            .with_user_level(7);
        let result = handler
            .setup_server_stream_with_context(
                Box::new(TestStream(server)),
                TcpServerConnectionContext {
                    runtime: Some(runtime),
                    ..TcpServerConnectionContext::default()
                },
            )
            .await;
        let error = match result {
            Ok(_) => panic!(
                "zero-second Xray HTTP handshake policy must time out before first byte"
            ),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn request_line_spacing_matches_xray() {
        assert_eq!(
            parse_http_request_line("GET http://example.com/x HTTP/1.1").unwrap(),
            ("GET", "http://example.com/x", "HTTP/1.1")
        );
        for request_line in [
            "GET  http://example.com/x HTTP/1.1",
            "GET\thttp://example.com/x\tHTTP/1.1",
            " GET http://example.com/x HTTP/1.1",
            "GET http://example.com/x HTTP/1.1 ",
        ] {
            let error = parse_http_request_line(request_line)
                .expect_err("Xray rejects non-canonical request-line spacing");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[tokio::test]
    async fn malformed_header_lines_match_xray_rejection() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
        for request in [
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nNoColon\r\n\r\n"
                .as_slice(),
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nX-Test: a\x01b\r\n\r\n"
                .as_slice(),
            b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\nX-Test: a\x7fb\r\n\r\n"
                .as_slice(),
        ] {
            let (mut client, server) = duplex(1024);
            client.write_all(request).await.unwrap();
            client.shutdown().await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects malformed HTTP header framing"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    #[tokio::test]
    async fn duplicate_host_headers_are_rejected_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), true, "http-host");
        for headers in [
            "Host: example.com\r\nHost: example.com\r\n",
            "Host: example.com\r\nHost: example.net\r\n",
            "Host:\r\nHost: example.com\r\n",
            "Host: example.com\r\nHost:\r\n",
        ] {
            let request = format!("GET /x HTTP/1.1\r\n{headers}\r\n");
            let (mut client, server) = duplex(1024);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects multiple Host headers"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("multiple HTTP Host headers"));
        }
    }

    #[tokio::test]
    async fn absolute_form_allows_one_empty_host_header_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-host");
        let request = b"GET http://example.com/x HTTP/1.1\r\nHost:\r\n\r\n";
        let (mut client, server) = duplex(1024);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("absolute-form URL authority replaces one empty Host header");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("HTTP forward returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:80");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn folded_headers_are_unfolded_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
        for continuation in [" two", "\ttwo"] {
            let request = format!(
                "GET http://example.com/x HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 X-Test: one\r\n{continuation}\r\n\r\n"
            );
            let (mut client, server) = duplex(1024);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray unfolds obsolete header continuations");
            let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
                panic!("HTTP forward returned non-TCP result");
            };
            let mut forwarded = Vec::new();
            stream.read_to_end(&mut forwarded).await.unwrap();
            assert!(
                forwarded
                    .windows(b"X-Test: one two\r\n".len())
                    .any(|window| window == b"X-Test: one two\r\n")
            );
        }
    }

    #[tokio::test]
    async fn invalid_header_names_are_dropped_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
        for invalid_header in ["X-Test : hidden", "Bad Header: hidden"] {
            let request = format!(
                "GET http://example.com/x HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 {invalid_header}\r\n\
                 X-Keep: visible\r\n\r\n"
            );
            let (mut client, server) = duplex(1024);
            client.write_all(request.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray drops invalid HTTP field names without rejecting the request");
            let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
                panic!("HTTP forward returned non-TCP result");
            };
            let mut forwarded = Vec::new();
            stream.read_to_end(&mut forwarded).await.unwrap();
            assert!(
                !forwarded
                    .windows(b"hidden".len())
                    .any(|window| window == b"hidden")
            );
            assert!(
                forwarded
                    .windows(b"X-Keep: visible\r\n".len())
                    .any(|window| window == b"X-Keep: visible\r\n")
            );
        }
    }

    #[tokio::test]
    async fn header_value_tab_remains_accepted_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-headers");
        let request = b"GET http://example.com/x HTTP/1.1\r\n\
Host: example.com\r\n\
X-Test: a\tb\r\n\r\n";
        let (mut client, server) = duplex(1024);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray accepts horizontal tabs in HTTP header values");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded
                .windows(b"X-Test: a\tb\r\n".len())
                .any(|window| window == b"X-Test: a\tb\r\n")
        );
    }

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
    async fn duplicate_proxy_authorization_uses_first_value_like_xray() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-auth",
        );
        let valid = BASE64.encode("alice:secret");
        let invalid = BASE64.encode("alice:wrong");

        let request = format!(
            "CONNECT 127.0.0.1:80 HTTP/1.1\r\n\
             Proxy-Authorization: Basic {valid}\r\n\
             Proxy-Authorization: Basic {invalid}\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray accepts when the first authorization is valid");
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = result
        else {
            panic!("HTTP CONNECT returned non-TCP result");
        };
        assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));

        let request = format!(
            "CONNECT 127.0.0.1:80 HTTP/1.1\r\n\
             Proxy-Authorization: Basic {invalid}\r\n\
             Proxy-Authorization: Basic {valid}\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();
        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray rejects when the first authorization is invalid"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407 Proxy Authentication Required"));
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

    #[test]
    fn absolute_form_ports_match_xray_uint16_conversion() {
        let defaulted = parse_absolute_http_authority("example.com:", 80)
            .expect("empty HTTP port should use the scheme default");
        assert_eq!(defaulted.to_string(), "example.com:80");

        let wrapped_zero = parse_absolute_http_authority("example.com:65536", 80)
            .expect("Xray wraps numeric HTTP ports to uint16");
        assert_eq!(wrapped_zero.to_string(), "example.com:0");

        let wrapped = parse_absolute_http_authority("example.com:99999", 80)
            .expect("Xray wraps large numeric HTTP ports to uint16");
        assert_eq!(wrapped.to_string(), "example.com:34463");

        let ipv6 = parse_absolute_http_authority("[2001:db8::1]:65536", 80)
            .expect("bracketed IPv6 uses the same Xray port conversion");
        assert_eq!(ipv6.address().to_string(), "2001:db8::1");
        assert_eq!(ipv6.port(), 0);
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
    async fn chunked_request_trailers_match_xray_normalization() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-trailers");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding: chunked\r\n\
Trailer: x-foo, X-Foo\r\n\
Trailer: X-Bar\r\n\r\n\
4\r\ntest\r\n0\r\n\
X-Foo: one\r\nX-Unused: hidden\r\nX-Bar: two\r\nX-Foo: three\r\n\r\n";
        let (mut client, server) = duplex(4096);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("declared chunked trailers should succeed");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("chunked HTTP request returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        let forwarded = String::from_utf8(forwarded).unwrap();
        assert!(forwarded.contains("Trailer: X-Bar,X-Foo\r\n"));
        assert!(forwarded.ends_with(
            "4\r\ntest\r\n0\r\nX-Bar: two\r\nX-Foo: one\r\nX-Foo: three\r\n\r\n"
        ));
        assert!(!forwarded.contains("X-Unused"));

        let (mut client, server) = duplex(2048);
        client
            .write_all(
                b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("forbidden request trailer declaration must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
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
            assert!(forwarded.ends_with(b"4\r\ntest\r\n0\r\n\r\n"));
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
    async fn content_length_numeric_syntax_matches_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 0004\r\n\r\nbody";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("leading-zero Content-Length should succeed");
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

        for content_length in ["+4", "9223372036854775808"] {
            let request = format!(
                "POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: {content_length}\r\n\r\nbody"
            );
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => {
                    panic!("invalid Content-Length {content_length:?} must fail")
                }
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("invalid HTTP Content-Length"));
        }
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
    async fn plain_http_response_collapses_duplicate_content_length_like_xray() {
        let upstream_response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 02\r\nContent-Length: 2\r\n\r\nok";
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
        assert!(reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 2\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nok"
        );
    }

    #[tokio::test]
    async fn invalid_plain_http_response_content_length_returns_503_like_xray() {
        for content_lengths in [
            "Content-Length: nope",
            "Content-Length: +2",
            "Content-Length: 9223372036854775808",
            "Content-Length: 2\r\nContent-Length: 3",
        ] {
            let upstream_response =
                format!("HTTP/1.1 200 OK\r\n{content_lengths}\r\n\r\nok!");
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client
                .write_all(upstream_response.as_bytes())
                .await
                .unwrap();
            upstream_client.shutdown().await.unwrap();
            let (mut downstream_client, mut downstream_server) = duplex(2048);

            let reusable = relay_plain_http_response(
                &mut upstream_server,
                &mut downstream_server,
                "GET",
            )
            .await
            .unwrap();
            assert!(!reusable, "{content_lengths:?} must close");
            downstream_server.shutdown().await.unwrap();

            let mut response = Vec::new();
            downstream_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
                "{content_lengths:?}"
            );
        }
    }

    #[tokio::test]
    async fn chunked_plain_http_response_drops_content_length_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\
                                  Content-Length: 99\r\n\
                                  X-Test: yes\r\n\r\n\
                                  2\r\nok\r\n0\r\n\r\n";
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
            "HTTP/1.1 200 OK\r\n\
             Transfer-Encoding: chunked\r\n\
             X-Test: yes\r\n\
             Connection: close\r\n\r\n\
             2\r\nok\r\n0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn chunked_plain_http_response_reencodes_payload_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\r\n\
                                  4;foo=bar\r\ntest\r\n3\r\nxyz\r\n0\r\n\r\n";
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
            response,
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n\
              7\r\ntestxyz\r\n0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn late_invalid_response_chunks_flush_decoded_payload_like_xray() {
        for body in [
            b"4\r\ntest\r\nZ\r\noops\r\n".as_slice(),
            b"5\r\ntest".as_slice(),
            b"4\r\ntestX\r\n0\r\n\r\n".as_slice(),
        ] {
            let mut upstream_response =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            upstream_response.extend_from_slice(body);
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client.write_all(&upstream_response).await.unwrap();
            upstream_client.shutdown().await.unwrap();
            let (mut downstream_client, mut downstream_server) = duplex(2048);

            relay_plain_http_response(
                &mut upstream_server,
                &mut downstream_server,
                "GET",
            )
            .await
            .expect_err("malformed later chunk framing must terminate relay");
            downstream_server.shutdown().await.unwrap();

            let mut response = Vec::new();
            downstream_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 200 OK\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  4\r\ntest\r\n",
                "{body:?}"
            );
        }
    }

    #[tokio::test]
    async fn chunked_response_trailers_are_stripped_like_xray() {
        for trailer in [
            b"X-Trailer: yes\r\n".as_slice(),
            b"Bad Header: yes\r\n".as_slice(),
            b"X-Trailer: one\r\n two\r\n".as_slice(),
        ] {
            let mut upstream_response =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"
                    .to_vec();
            upstream_response.extend_from_slice(trailer);
            upstream_response.extend_from_slice(b"\r\n");
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client.write_all(&upstream_response).await.unwrap();
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
                response,
                b"HTTP/1.1 200 OK\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  2\r\nok\r\n0\r\n\r\n",
                "{trailer:?}"
            );
        }
    }

    #[tokio::test]
    async fn declared_chunked_response_trailer_is_forwarded_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\
                                  Trailer: X-Foo\r\n\r\n\
                                  2\r\nok\r\n0\r\nX-Foo: bar\r\n\r\n";
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
            response,
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Trailer: X-Foo\r\n\
              Connection: close\r\n\r\n\
              2\r\nok\r\n0\r\nX-Foo: bar\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn response_trailers_are_canonicalized_and_sorted_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\
                                  Trailer: x-foo, X-Foo\r\n\
                                  Trailer: X-Bar\r\n\r\n\
                                  2\r\nok\r\n0\r\n\
                                  X-Foo: one\r\n\
                                  X-Bar: two\r\n\
                                  x-foo: three\r\n\r\n";
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
            response,
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Trailer: X-Bar,X-Foo\r\n\
              Connection: close\r\n\r\n\
              2\r\nok\r\n0\r\n\
              X-Bar: two\r\n\
              X-Foo: one\r\n\
              X-Foo: three\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn forbidden_response_trailer_declarations_return_503_like_xray() {
        for trailer_name in ["Content-Length", "Transfer-Encoding", "Trailer"] {
            let upstream_response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Trailer: {trailer_name}\r\n\r\n\
                 2\r\nok\r\n0\r\n\r\n"
            );
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client
                .write_all(upstream_response.as_bytes())
                .await
                .unwrap();
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
                response,
                b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
                "{trailer_name}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_chunked_response_trailer_stops_before_terminal_chunk_like_xray()
     {
        for trailer in [
            b"NoColon\r\n".as_slice(),
            b"X-Trailer: a\x01b\r\n".as_slice(),
        ] {
            let mut upstream_response =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"
                    .to_vec();
            upstream_response.extend_from_slice(trailer);
            upstream_response.extend_from_slice(b"\r\n");
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client.write_all(&upstream_response).await.unwrap();
            upstream_client.shutdown().await.unwrap();
            let (mut downstream_client, mut downstream_server) = duplex(2048);

            relay_plain_http_response(
                &mut upstream_server,
                &mut downstream_server,
                "GET",
            )
            .await
            .expect_err("malformed response trailer must terminate relay");
            downstream_server.shutdown().await.unwrap();

            let mut response = Vec::new();
            downstream_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 200 OK\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  2\r\nok\r\n",
                "{trailer:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_first_response_chunk_size_stops_after_headers_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\n\
                                  Transfer-Encoding: chunked\r\n\r\n\
                                  Z\r\nok\r\n0\r\n\r\n";
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client.write_all(upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let error = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .expect_err("invalid first response chunk size must terminate relay");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn invalid_plain_http_response_transfer_encoding_returns_503_like_xray() {
        for transfer_encoding in [
            "Transfer-Encoding: gzip",
            "Transfer-Encoding: chunked, gzip",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
        ] {
            let upstream_response = format!(
                "HTTP/1.1 200 OK\r\n{transfer_encoding}\r\n\r\n2\r\nok\r\n0\r\n\r\n"
            );
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client
                .write_all(upstream_response.as_bytes())
                .await
                .unwrap();
            upstream_client.shutdown().await.unwrap();
            let (mut downstream_client, mut downstream_server) = duplex(2048);

            let reusable = relay_plain_http_response(
                &mut upstream_server,
                &mut downstream_server,
                "GET",
            )
            .await
            .unwrap();
            assert!(!reusable, "{transfer_encoding:?} must close");
            downstream_server.shutdown().await.unwrap();

            let mut response = Vec::new();
            downstream_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
                "{transfer_encoding:?}"
            );
        }
    }

    #[tokio::test]
    async fn plain_http_response_unfolds_headers_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: one\r\n two\r\nConnection: close\r\n\r\nok";
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
        assert!(reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 2\r\n\
             X-Test: one two\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nok"
        );
    }

    #[tokio::test]
    async fn plain_http_response_drops_invalid_header_names_like_xray() {
        let upstream_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nBad Header: hidden\r\nX-Keep: visible\r\n\r\nok";
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
        assert!(reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 2\r\n\
             X-Keep: visible\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nok"
        );
    }

    #[tokio::test]
    async fn malformed_plain_http_response_headers_return_503_like_xray() {
        for invalid_header in ["NoColon", "X-Test: a\u{1}b", "X-Test: a\u{7f}b"] {
            let upstream_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{invalid_header}\r\n\r\nok"
            );
            let (mut upstream_client, mut upstream_server) = duplex(2048);
            upstream_client
                .write_all(upstream_response.as_bytes())
                .await
                .unwrap();
            upstream_client.shutdown().await.unwrap();
            let (mut downstream_client, mut downstream_server) = duplex(2048);

            let reusable = relay_plain_http_response(
                &mut upstream_server,
                &mut downstream_server,
                "GET",
            )
            .await
            .unwrap();
            assert!(!reusable, "invalid header {invalid_header:?} must close");
            downstream_server.shutdown().await.unwrap();

            let mut response = Vec::new();
            downstream_client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 503 Service Unavailable\r\n\
                  Connection: close\r\n\
                  Proxy-Connection: close\r\n\
                  Content-Length: 0\r\n\r\n",
                "invalid header {invalid_header:?}"
            );
        }
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
