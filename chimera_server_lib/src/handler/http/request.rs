use std::{
    collections::BTreeMap,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
};

use super::{MAX_HEADER_BYTES, MAX_REQUEST_LINE_BYTES};

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

pub(super) struct ChunkedRequestStream {
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

    pub(super) fn new(
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

pub(super) fn parse_http_content_length(value: &str) -> std::io::Result<u64> {
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

pub(super) fn has_invalid_http_header_value(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
}

pub(super) fn is_http_header_name(name: &str) -> bool {
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

pub(super) fn parse_http_request_line(
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

pub(super) fn parse_chunk_size_line(line: &[u8]) -> std::io::Result<u64> {
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

pub(super) fn parse_absolute_http_target(
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

pub(super) fn parse_absolute_http_authority(
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

pub(super) fn parse_http_request_trailer_names(
    value: &str,
) -> std::io::Result<Vec<String>> {
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

pub(super) fn canonical_http_header_name(name: &str) -> String {
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
