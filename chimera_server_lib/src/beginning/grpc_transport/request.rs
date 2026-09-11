use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::mpsc,
    task::AbortHandle,
};
use tokio_util::io::ReaderStream;
use tracing::debug;

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    beginning::process_stream_with_sniffing_and_local_addr,
    config::server_config::InboundSniffingConfig,
    handler::tcp::tcp_handler::TcpServerHandler,
    resolver::Resolver,
    runtime::DataPlaneRuntime,
};

mod wire;

pub(super) use wire::decode_grpc_message_view;
use wire::{
    GrpcCompressedMessage, GrpcInvalidProtobuf, GrpcMessageTooLarge,
    GrpcUnexpectedPayloadFormat,
};
#[cfg(test)]
pub(super) use wire::{
    PROTOBUF_MAX_FIELD_NUMBER, decode_grpc_message, encode_varint,
};
pub(crate) use wire::{decode_grpc_message_payloads, encode_grpc_message};

const GRPC_PIPE_CAPACITY: usize = 64 * 1024;
pub(super) type ResponseBody = UnsyncBoxBody<Bytes, h2::Error>;

#[derive(Debug)]
pub(super) struct GrpcUploadStatus {
    pub(super) code: u8,
    pub(super) message: String,
}

#[derive(Debug, Clone)]
pub(super) struct GrpcPeerContext {
    pub(super) peer_addr: SocketAddr,
    pub(super) local_addr: SocketAddr,
    pub(super) trusted_x_forwarded_for: Arc<Vec<String>>,
    pub(super) sniffing: Option<InboundSniffingConfig>,
}

pub(super) async fn handle_request(
    request: Request<Incoming>,
    tun_service_path: String,
    tun_multi_service_path: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    peer_context: GrpcPeerContext,
) -> Result<Response<ResponseBody>, Infallible> {
    let (logical_peer_addr, logical_local_addr) =
        grpc_logical_addrs(request.headers(), &peer_context);
    let sniffing = peer_context.sniffing.clone();
    if let Some(message) =
        grpc_duplicate_host_error(request.headers(), request.uri())
    {
        return Ok(grpc_duplicate_host_response(&message));
    }
    if let Err(content_type) = grpc_content_type(request.headers()) {
        return Ok(grpc_invalid_content_type_response(&content_type));
    }
    if let Some(message) = grpc_malformed_binary_metadata(request.headers()) {
        return Ok(grpc_malformed_binary_metadata_response(&message));
    }
    let grpc_timeout = match grpc_timeout_duration(request.headers()) {
        Ok(timeout) => timeout,
        Err(message) => return Ok(grpc_malformed_timeout_response(&message)),
    };
    let grpc_deadline =
        grpc_timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    if request.method() != Method::POST {
        return Ok(grpc_method_not_allowed_response(request.method()));
    }
    if grpc_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now())
    {
        return Ok(grpc_deadline_exceeded_response());
    }
    let request_path = request.uri().path();
    let multi_mode = match request_path {
        path if path == tun_service_path => false,
        path if path == tun_multi_service_path => true,
        _ => {
            return Ok(grpc_unimplemented_path_response(
                request_path,
                &tun_service_path,
            ));
        }
    };
    if let Some(encoding) = grpc_unsupported_encoding(request.headers()) {
        return Ok(grpc_status_response(
            12,
            &format!(
                "grpc: Decompressor is not installed for grpc-encoding \"{encoding}\""
            ),
        ));
    }

    let (handler_stream, transport_stream) = duplex(GRPC_PIPE_CAPACITY);
    let (transport_read, mut transport_write) = tokio::io::split(transport_stream);
    let timed_out = Arc::new(AtomicBool::new(false));
    let stream_task = tokio::spawn(async move {
        if let Err(error) = process_stream_with_sniffing_and_local_addr(
            GrpcLogicalStream(handler_stream),
            server_handler,
            resolver,
            logical_peer_addr,
            Some(logical_local_addr),
            runtime,
            sniffing,
        )
        .await
        {
            debug!("gRPC logical stream {logical_peer_addr} ended: {error}");
        }
    });
    let stream_abort = stream_task.abort_handle();
    let upload_stream_abort = stream_abort.clone();
    let (upload_status_tx, upload_status_rx) = mpsc::unbounded_channel();
    let mut body = request.into_body();
    let upload_task = tokio::spawn(async move {
        match decode_request_body(&mut body, &mut transport_write, multi_mode).await
        {
            Ok(()) => {
                // grpc-go keeps the logical transport open after request END_STREAM;
                // only RPC cancellation or the logical stream ending closes it.
                futures::future::pending::<()>().await;
            }
            Err(error) => {
                debug!("gRPC upload decode failed: {error}");
                if let Some(status) = grpc_upload_status_from_error(&error) {
                    let _ = upload_status_tx.send(status);
                }
                upload_stream_abort.abort();
            }
        }
    });
    let upload_abort = upload_task.abort_handle();
    let deadline_abort = grpc_deadline.map(|deadline| {
        let upload_abort = upload_abort.clone();
        let stream_abort = stream_abort.clone();
        let timed_out = timed_out.clone();
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            timed_out.store(true, Ordering::Release);
            upload_abort.abort();
            stream_abort.abort();
        })
        .abort_handle()
    });
    let task_guard = GrpcStreamTaskGuard {
        upload_abort,
        stream_abort,
        deadline_abort,
    };

    Ok(grpc_stream_response(
        transport_read,
        multi_mode,
        timed_out,
        Some(upload_status_rx),
        Some(task_guard),
    ))
}

pub(super) fn grpc_timeout_duration(
    headers: &hyper::HeaderMap,
) -> Result<Option<Duration>, String> {
    let mut values = headers.get_all("grpc-timeout").iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let first_timeout = parse_grpc_timeout_value(first)?;
    for value in values {
        parse_grpc_timeout_value(value)?;
    }
    Ok(Some(first_timeout))
}

fn parse_grpc_timeout_value(
    value: &hyper::header::HeaderValue,
) -> Result<Duration, String> {
    let value = value.to_str().map_err(|_| {
        "malformed grpc-timeout: transport: timeout contains non-ASCII bytes"
            .to_string()
    })?;
    let size = value.len();
    if size < 2 {
        return Err(format!(
            "malformed grpc-timeout: transport: timeout string is too short: \"{value}\""
        ));
    }
    if size > 9 {
        return Err(format!(
            "malformed grpc-timeout: transport: timeout string is too long: \"{value}\""
        ));
    }

    let (digits, unit_text) = value.split_at(size - 1);
    let unit = match unit_text.as_bytes()[0] {
        b'H' => Duration::from_secs(60 * 60),
        b'M' => Duration::from_secs(60),
        b'S' => Duration::from_secs(1),
        b'm' => Duration::from_millis(1),
        b'u' => Duration::from_micros(1),
        b'n' => Duration::from_nanos(1),
        _ => {
            return Err(format!(
                "malformed grpc-timeout: transport: timeout unit is not recognized: \"{value}\""
            ));
        }
    };
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "malformed grpc-timeout: strconv.ParseUint: parsing \"{digits}\": invalid syntax"
        ));
    }
    let amount = digits
        .bytes()
        .fold(0_u64, |value, byte| value * 10 + u64::from(byte - b'0'));
    let timeout = if unit_text == "H" {
        const MAX_HOURS: u64 = i64::MAX as u64 / (60 * 60 * 1_000_000_000);
        if amount > MAX_HOURS {
            Duration::from_nanos(i64::MAX as u64)
        } else {
            unit * amount as u32
        }
    } else {
        unit * amount as u32
    };
    Ok(timeout)
}

pub(super) fn grpc_encode_message(message: &str) -> String {
    let mut encoded = String::with_capacity(message.len());
    for byte in message.bytes() {
        if (0x20..=0x7e).contains(&byte) && byte != b'%' {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}")
                .expect("writing to String cannot fail");
        }
    }
    encoded
}

pub(super) fn grpc_malformed_binary_metadata(
    headers: &hyper::HeaderMap,
) -> Option<String> {
    for (name, value) in headers {
        if !name.as_str().ends_with("-bin") {
            continue;
        }
        let bytes = value.as_bytes();
        let Some(offset) = grpc_invalid_base64_offset(bytes) else {
            continue;
        };
        let value = String::from_utf8_lossy(bytes);
        return Some(format!(
            "malformed binary metadata \"{value}\" in header \"{name}\": illegal base64 data at input byte {offset}"
        ));
    }
    None
}

pub(super) fn grpc_invalid_base64_offset(value: &[u8]) -> Option<usize> {
    let mut symbols = 0usize;
    let mut padding_start = None;
    let mut padding = 0usize;

    for (index, byte) in value.iter().copied().enumerate() {
        let is_symbol = byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/');
        if is_symbol {
            if let Some(start) = padding_start {
                return Some(start);
            }
            symbols += 1;
        } else if byte == b'=' {
            padding_start.get_or_insert(index);
            padding += 1;
        } else {
            return Some(index);
        }
    }

    if let Some(start) = padding_start {
        let expected_padding = match symbols % 4 {
            0 => 0,
            2 => 2,
            3 => 1,
            1 => return Some(start),
            _ => unreachable!(),
        };
        if padding != expected_padding || !(symbols + padding).is_multiple_of(4) {
            return Some(start);
        }
    } else if symbols % 4 == 1 {
        return Some(symbols.saturating_sub(1));
    }

    None
}

pub(super) fn grpc_duplicate_host_error(
    headers: &hyper::HeaderMap,
    uri: &hyper::Uri,
) -> Option<String> {
    let authority_count = usize::from(uri.authority().is_some());
    let host_count = headers.get_all(header::HOST).iter().count();
    (authority_count > 1 || host_count > 1).then(|| {
        format!(
            "num values of :authority: {authority_count}, num values of host: {host_count}, both must only have 1 value as per HTTP/2 spec"
        )
    })
}

pub(super) fn grpc_duplicate_host_response(message: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

pub(super) fn grpc_malformed_binary_metadata_response(
    message: &str,
) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

pub(super) fn grpc_malformed_timeout_response(
    message: &str,
) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

pub(super) fn grpc_deadline_exceeded_response() -> Response<ResponseBody> {
    grpc_status_response(4, "context deadline exceeded")
}

fn empty_grpc_body() -> ResponseBody {
    BodyExt::boxed_unsync(
        Empty::<Bytes>::new().map_err(|never| -> h2::Error { match never {} }),
    )
}

pub(super) fn grpc_content_type(headers: &hyper::HeaderMap) -> Result<&str, String> {
    let mut last_invalid = String::new();
    for value in headers.get_all(header::CONTENT_TYPE) {
        let Ok(content_type) = value.to_str() else {
            continue;
        };
        if grpc_content_type_is_valid(content_type) {
            return Ok(content_type);
        }
        last_invalid.clear();
        last_invalid.push_str(content_type);
    }
    Err(last_invalid)
}

pub(super) fn grpc_content_type_is_valid(content_type: &str) -> bool {
    const BASE: &str = "application/grpc";
    content_type == BASE
        || content_type
            .strip_prefix(BASE)
            .is_some_and(|suffix| suffix.starts_with('+') || suffix.starts_with(';'))
}

pub(super) fn grpc_invalid_content_type_response(
    content_type: &str,
) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "3")
        .header(
            "grpc-message",
            grpc_encode_message(&format!(
                "invalid gRPC request content-type \"{content_type}\""
            )),
        )
        .body(empty_grpc_body())
        .unwrap()
}

pub(super) fn grpc_method_not_allowed_response(
    method: &Method,
) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header(
            "grpc-message",
            grpc_encode_message(&format!(
                "Received a HEADERS frame with :method \"{method}\" which should be POST"
            )),
        )
        .body(empty_grpc_body())
        .unwrap()
}

pub(super) fn grpc_unimplemented_path_response(
    request_path: &str,
    tun_service_path: &str,
) -> Response<ResponseBody> {
    let registered_service = tun_service_path
        .strip_prefix('/')
        .and_then(|path| path.rsplit_once('/'))
        .map(|(service, _)| service)
        .unwrap_or_default();
    let (requested_service, requested_method) = request_path
        .strip_prefix('/')
        .and_then(|path| path.rsplit_once('/'))
        .unwrap_or((request_path.trim_start_matches('/'), ""));

    if requested_service == registered_service {
        grpc_status_response(
            12,
            &format!(
                "unknown method {requested_method} for service {registered_service}"
            ),
        )
    } else {
        grpc_status_response(12, &format!("unknown service {requested_service}"))
    }
}

pub(super) fn grpc_unsupported_encoding(headers: &hyper::HeaderMap) -> Option<&str> {
    headers
        .get_all("grpc-encoding")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .filter(|encoding| !encoding.is_empty() && *encoding != "identity")
}

pub(super) fn grpc_logical_addrs(
    headers: &hyper::HeaderMap,
    peer_context: &GrpcPeerContext,
) -> (SocketAddr, SocketAddr) {
    (
        grpc_logical_peer_addr(
            headers,
            peer_context.peer_addr,
            &peer_context.trusted_x_forwarded_for,
        ),
        peer_context.local_addr,
    )
}

pub(super) fn grpc_logical_peer_addr(
    headers: &hyper::HeaderMap,
    peer_addr: std::net::SocketAddr,
    trusted_x_forwarded_for: &[String],
) -> std::net::SocketAddr {
    let Some(value) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    else {
        return peer_addr;
    };
    if trusted_x_forwarded_for.is_empty()
        || !trusted_x_forwarded_for
            .iter()
            .any(|header| headers.contains_key(header.as_str()))
    {
        return peer_addr;
    }
    let value = value.split_once(',').map_or(value, |(first, _)| first);
    let value = if value.starts_with('[') && value.ends_with(']') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let value = if value
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || value
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        value.trim()
    } else {
        value
    };
    value
        .parse::<std::net::IpAddr>()
        .map(|ip| match ip {
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V6(ip)),
            ip => ip,
        })
        .map(|ip| std::net::SocketAddr::new(ip, 0))
        .unwrap_or(peer_addr)
}

async fn decode_request_body(
    body: &mut Incoming,
    writer: &mut tokio::io::WriteHalf<DuplexStream>,
    multi_mode: bool,
) -> io::Result<()> {
    let mut buffered = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })?;
        if let Some(data) = frame.data_ref() {
            buffered.extend_from_slice(data);
            while let Some(message) =
                decode_grpc_message_view(&mut buffered, multi_mode)?
            {
                for range in message.payloads {
                    writer.write_all(&message.data[range]).await?;
                }
            }
        }
    }
    if !buffered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated gRPC message",
        ));
    }
    Ok(())
}

pub(super) struct GrpcStreamTaskGuard {
    pub(super) upload_abort: AbortHandle,
    pub(super) stream_abort: AbortHandle,
    pub(super) deadline_abort: Option<AbortHandle>,
}

impl Drop for GrpcStreamTaskGuard {
    fn drop(&mut self) {
        self.upload_abort.abort();
        self.stream_abort.abort();
        if let Some(deadline_abort) = &self.deadline_abort {
            deadline_abort.abort();
        }
    }
}

pub(super) fn grpc_upload_status_from_error(
    error: &io::Error,
) -> Option<GrpcUploadStatus> {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        return Some(GrpcUploadStatus {
            code: 13,
            message: "unexpected EOF".to_string(),
        });
    }

    let source = error.get_ref()?;
    if let Some(too_large) = source.downcast_ref::<GrpcMessageTooLarge>() {
        return Some(GrpcUploadStatus {
            code: 8,
            message: too_large.to_string(),
        });
    }
    if let Some(compressed) = source.downcast_ref::<GrpcCompressedMessage>() {
        return Some(GrpcUploadStatus {
            code: 13,
            message: compressed.to_string(),
        });
    }
    if let Some(format) = source.downcast_ref::<GrpcUnexpectedPayloadFormat>() {
        return Some(GrpcUploadStatus {
            code: 13,
            message: format.to_string(),
        });
    }
    source
        .downcast_ref::<GrpcInvalidProtobuf>()
        .map(|invalid| GrpcUploadStatus {
            code: 13,
            message: invalid.to_string(),
        })
}

pub(super) fn grpc_stream_response(
    reader: tokio::io::ReadHalf<DuplexStream>,
    multi_mode: bool,
    timed_out: Arc<AtomicBool>,
    upload_status: Option<mpsc::UnboundedReceiver<GrpcUploadStatus>>,
    task_guard: Option<GrpcStreamTaskGuard>,
) -> Response<ResponseBody> {
    let stream = futures::stream::unfold(
        (
            ReaderStream::new(reader),
            timed_out,
            false,
            upload_status,
            task_guard,
        ),
        move |(mut reader, timed_out, finished, mut upload_status, task_guard)| async move {
            if finished {
                return None;
            }
            loop {
                if timed_out.load(Ordering::Acquire) {
                    return Some((
                        Err(h2::Error::from(h2::Reason::CANCEL)),
                        (reader, timed_out, true, upload_status, task_guard),
                    ));
                }
                tokio::select! {
                    biased;
                    status = async {
                        match upload_status.as_mut() {
                            Some(receiver) => receiver.recv().await,
                            None => futures::future::pending().await,
                        }
                    } => {
                        if let Some(status) = status {
                            let mut trailers = hyper::HeaderMap::new();
                            trailers.insert(
                                "grpc-status",
                                header::HeaderValue::from_str(&status.code.to_string())
                                    .expect("valid gRPC status"),
                            );
                            trailers.insert(
                                "grpc-message",
                                header::HeaderValue::from_str(&grpc_encode_message(&status.message))
                                    .expect("valid gRPC status message"),
                            );
                            return Some((
                                Ok(Frame::trailers(trailers)),
                                (reader, timed_out, true, upload_status, task_guard),
                            ));
                        }
                        upload_status = None;
                        continue;
                    }
                    next = reader.next() => match next {
                        Some(Ok(data)) if data.is_empty() => continue,
                        Some(Ok(data)) => {
                            return Some((
                                Ok(Frame::data(encode_grpc_message(&data, multi_mode))),
                                (reader, timed_out, false, upload_status, task_guard),
                            ));
                        }
                        Some(Err(error)) => {
                            debug!("gRPC response read failed: {error}");
                            return Some((
                                Err(h2::Error::from(h2::Reason::INTERNAL_ERROR)),
                                (reader, timed_out, true, upload_status, task_guard),
                            ));
                        }
                        None if timed_out.load(Ordering::Acquire) => {
                            return Some((
                                Err(h2::Error::from(h2::Reason::CANCEL)),
                                (reader, timed_out, true, upload_status, task_guard),
                            ));
                        }
                        None => {
                            let mut trailers = hyper::HeaderMap::new();
                            trailers.insert(
                                "grpc-status",
                                header::HeaderValue::from_static("0"),
                            );
                            trailers.insert(
                                "grpc-message",
                                header::HeaderValue::from_static(""),
                            );
                            return Some((
                                Ok(Frame::trailers(trailers)),
                                (reader, timed_out, true, upload_status, task_guard),
                            ));
                        }
                    }
                }
            }
        },
    );
    let body = StreamBody::new(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .body(BodyExt::boxed_unsync(body))
        .unwrap_or_else(|_| grpc_status_response(13, "internal response error"))
}

fn grpc_status_response(status: u8, message: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", status.to_string())
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

struct GrpcLogicalStream(DuplexStream);

impl AsyncRead for GrpcLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl AsyncWrite for GrpcLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncPing for GrpcLogicalStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for GrpcLogicalStream {}
