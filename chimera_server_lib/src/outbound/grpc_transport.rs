#[cfg(feature = "grpc_transport")]
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

#[cfg(feature = "grpc_transport")]
use bytes::BytesMut;
#[cfg(feature = "grpc_transport")]
use futures::StreamExt as _;
#[cfg(feature = "grpc_transport")]
use http_body_util::{BodyExt as _, StreamBody};
#[cfg(feature = "grpc_transport")]
use hyper::{
    Method, Request, body::Frame, client::conn::http2 as client_http2, header,
};
#[cfg(feature = "grpc_transport")]
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
#[cfg(feature = "grpc_transport")]
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, duplex},
    task::AbortHandle,
};
#[cfg(feature = "grpc_transport")]
use tokio_util::io::ReaderStream;

#[cfg(feature = "grpc_transport")]
use super::OutboundGrpcClientSettings;
#[cfg(feature = "grpc_transport")]
use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    beginning::grpc_transport::{
        decode_grpc_message_payloads, encode_grpc_message, grpc_service_paths,
    },
};

#[cfg(feature = "grpc_transport")]
pub(super) struct GrpcOutboundStream {
    inner: DuplexStream,
    shared_error: Arc<Mutex<Option<(std::io::ErrorKind, String)>>>,
    connection_abort: AbortHandle,
    response_abort: AbortHandle,
}

#[cfg(feature = "grpc_transport")]
impl Drop for GrpcOutboundStream {
    fn drop(&mut self) {
        self.response_abort.abort();
        self.connection_abort.abort();
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncRead for GrpcOutboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() == before => {
                match take_grpc_outbound_error(&self.shared_error) {
                    Some(error) => Poll::Ready(Err(error)),
                    None => Poll::Ready(Ok(())),
                }
            }
            other => other,
        }
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncWrite for GrpcOutboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(error) = clone_grpc_outbound_error(&self.shared_error) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(error) = clone_grpc_outbound_error(&self.shared_error) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "grpc_transport")]
impl AsyncPing for GrpcOutboundStream {
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

#[cfg(feature = "grpc_transport")]
impl AsyncStream for GrpcOutboundStream {}

#[cfg(feature = "grpc_transport")]
fn set_grpc_outbound_error(
    shared: &Mutex<Option<(std::io::ErrorKind, String)>>,
    kind: std::io::ErrorKind,
    message: String,
) {
    let mut guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.is_none() {
        *guard = Some((kind, message));
    }
}

#[cfg(feature = "grpc_transport")]
fn clone_grpc_outbound_error(
    shared: &Mutex<Option<(std::io::ErrorKind, String)>>,
) -> Option<std::io::Error> {
    let guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard
        .as_ref()
        .map(|(kind, message)| std::io::Error::new(*kind, message.clone()))
}

#[cfg(feature = "grpc_transport")]
fn take_grpc_outbound_error(
    shared: &Mutex<Option<(std::io::ErrorKind, String)>>,
) -> Option<std::io::Error> {
    let mut guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard
        .take()
        .map(|(kind, message)| std::io::Error::new(kind, message))
}

#[cfg(feature = "grpc_transport")]
pub(super) fn grpc_initial_stream_window(
    settings: &OutboundGrpcClientSettings,
) -> u32 {
    u32::try_from(settings.initial_windows_size)
        .ok()
        .filter(|size| *size >= 65_535)
        .unwrap_or(65_535)
}

#[cfg(feature = "grpc_transport")]
pub(super) fn grpc_keepalive_params(
    settings: &OutboundGrpcClientSettings,
) -> Option<(Duration, Duration, bool)> {
    if settings.idle_timeout <= 0
        && settings.health_check_timeout <= 0
        && !settings.permit_without_stream
    {
        return None;
    }
    let interval_secs = u64::try_from(settings.idle_timeout.max(10)).unwrap_or(10);
    let timeout_secs = if settings.health_check_timeout > 0 {
        u64::try_from(settings.health_check_timeout).unwrap_or(20)
    } else {
        20
    };
    Some((
        Duration::from_secs(interval_secs),
        Duration::from_secs(timeout_secs),
        settings.permit_without_stream,
    ))
}

#[cfg(feature = "grpc_transport")]
pub(super) async fn connect_grpc_transport(
    stream: Box<dyn AsyncStream>,
    settings: &OutboundGrpcClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    reality_transport: bool,
) -> std::io::Result<GrpcOutboundStream> {
    const PIPE_CAPACITY: usize = 64 * 1024;

    let authority = grpc_outbound_authority(
        settings,
        server,
        tls_server_name,
        reality_transport,
    );
    let (tun_path, tun_multi_path) = grpc_service_paths(&settings.service_name);
    let path = if settings.multi_mode {
        tun_multi_path
    } else {
        tun_path
    };
    let uri_text = match authority.as_deref() {
        Some(authority) => format!("http://{authority}{path}"),
        None => path,
    };
    let uri = uri_text.parse::<hyper::Uri>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid gRPC outbound authority/path: {error}"),
        )
    })?;

    let mut builder = client_http2::Builder::new(TokioExecutor::new());
    builder.initial_stream_window_size(grpc_initial_stream_window(settings));
    builder.initial_connection_window_size(65_535);
    if let Some((interval, timeout, permit_without_stream)) =
        grpc_keepalive_params(settings)
    {
        builder.timer(TokioTimer::new());
        builder.keep_alive_interval(Some(interval));
        builder.keep_alive_timeout(timeout);
        builder.keep_alive_while_idle(permit_without_stream);
    }
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("gRPC outbound HTTP/2 handshake failed: {error}"),
            )
        })?;

    let shared_error = Arc::new(Mutex::new(None));
    let connection_error = shared_error.clone();
    let connection_task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            set_grpc_outbound_error(
                &connection_error,
                std::io::ErrorKind::ConnectionAborted,
                format!("gRPC outbound HTTP/2 connection failed: {error}"),
            );
        }
    });
    let connection_abort = connection_task.abort_handle();
    drop(connection_task);

    let (app_stream, transport_stream) = duplex(PIPE_CAPACITY);
    let (upload_read, mut download_write) = tokio::io::split(transport_stream);
    let multi_mode = settings.multi_mode;
    let body_stream = ReaderStream::new(upload_read).map(move |chunk| {
        chunk.map(|data| Frame::data(encode_grpc_message(&data, multi_mode)))
    });
    let body = StreamBody::new(body_stream);
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers");
    if !settings.user_agent.trim().is_empty() {
        request = request.header(header::USER_AGENT, settings.user_agent.trim());
    }
    let request = match request.body(body) {
        Ok(request) => request,
        Err(error) => {
            connection_abort.abort();
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("failed to build gRPC outbound request: {error}"),
            ));
        }
    };

    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            connection_abort.abort();
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("gRPC outbound request failed: {error}"),
            ));
        }
    };
    if response.status() != hyper::StatusCode::OK {
        connection_abort.abort();
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("gRPC outbound returned HTTP status {}", response.status()),
        ));
    }
    if let Err(error) = validate_grpc_outbound_content_type(response.headers()) {
        connection_abort.abort();
        return Err(error);
    }
    let initial_status = match grpc_outbound_status(response.headers()) {
        Ok(status) => status,
        Err(error) => {
            connection_abort.abort();
            return Err(error);
        }
    };
    if let Some(status) = initial_status
        && status != 0
    {
        connection_abort.abort();
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("gRPC outbound rejected with grpc-status {status}"),
        ));
    }

    let response_error = shared_error.clone();
    let mut body = response.into_body();
    let response_task = tokio::spawn(async move {
        let result = async {
            let mut buffered = BytesMut::new();
            let mut saw_status = initial_status.is_some();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("gRPC outbound response body failed: {error}"),
                    )
                })?;
                if let Some(data) = frame.data_ref() {
                    buffered.extend_from_slice(data);
                    while let Some(payloads) =
                        decode_grpc_message_payloads(&mut buffered, multi_mode)?
                    {
                        for payload in payloads {
                            download_write.write_all(&payload).await?;
                        }
                    }
                }
                if let Some(trailers) = frame.trailers_ref() {
                    let status = grpc_outbound_status(trailers)?.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "gRPC outbound trailers are missing grpc-status",
                        )
                    })?;
                    saw_status = true;
                    if status != 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            format!(
                                "gRPC outbound stream ended with grpc-status {status}"
                            ),
                        ));
                    }
                }
            }
            if !buffered.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "gRPC outbound response ended with a truncated message",
                ));
            }
            if !saw_status {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "gRPC outbound response ended without grpc-status",
                ));
            }
            std::io::Result::Ok(())
        }
        .await;
        if let Err(error) = result {
            set_grpc_outbound_error(
                &response_error,
                error.kind(),
                error.to_string(),
            );
        }
        let _ = download_write.shutdown().await;
    });
    let response_abort = response_task.abort_handle();
    drop(response_task);

    Ok(GrpcOutboundStream {
        inner: app_stream,
        shared_error,
        connection_abort,
        response_abort,
    })
}

#[cfg(feature = "grpc_transport")]
fn grpc_outbound_authority(
    settings: &OutboundGrpcClientSettings,
    server: &NetLocation,
    tls_server_name: Option<&str>,
    reality_transport: bool,
) -> Option<String> {
    if !settings.authority.trim().is_empty() {
        return Some(settings.authority.trim().to_string());
    }
    if let Some(server_name) =
        tls_server_name.filter(|value| !value.trim().is_empty())
    {
        return Some(server_name.trim().to_string());
    }
    if reality_transport {
        return None;
    }
    match server.address() {
        Address::Hostname(hostname) => Some(hostname.clone()),
        Address::Ipv4(_) | Address::Ipv6(_) => None,
    }
}

#[cfg(feature = "grpc_transport")]
fn validate_grpc_outbound_content_type(
    headers: &hyper::HeaderMap,
) -> std::io::Result<()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type == "application/grpc"
        || content_type.starts_with("application/grpc+")
        || content_type.starts_with("application/grpc;")
    {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("gRPC outbound returned invalid content-type {content_type:?}"),
    ))
}

#[cfg(feature = "grpc_transport")]
fn grpc_outbound_status(headers: &hyper::HeaderMap) -> std::io::Result<Option<u32>> {
    let Some(value) = headers.get("grpc-status") else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "gRPC outbound grpc-status is not ASCII",
        )
    })?;
    value.parse::<u32>().map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("gRPC outbound grpc-status is invalid: {value:?}"),
        )
    })
}
