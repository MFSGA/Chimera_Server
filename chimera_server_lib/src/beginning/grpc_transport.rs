use std::{
    convert::Infallible,
    future::Future,
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

use bytes::{Buf, Bytes, BytesMut};
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Frame, Incoming},
    header,
    server::conn::http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::mpsc,
    task::{AbortHandle, JoinHandle},
    time::{Instant, Sleep},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info};

use crate::{
    address::BindLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::{
        GrpcServerConfig, InboundSniffingConfig, ServerConfig, ServerProxyConfig,
    },
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::RuntimeState,
};
#[cfg(feature = "reality")]
use crate::{
    config::server_config::RealityTransportConfig,
    handler::reality::accept_reality_stream,
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TlsServerConfig, handler::tls::build_server_config,
};

const GRPC_PIPE_CAPACITY: usize = 64 * 1024;
const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const GRPC_MAX_HEADER_LIST_BYTES: u32 = 16 * 1024 * 1024;
const GRPC_CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const HTTP2_CLIENT_PREFACE_LEN: usize = 24;
const HTTP2_FRAME_HEADER_LEN: usize = 9;

type ResponseBody = UnsyncBoxBody<Bytes, h2::Error>;

#[derive(Debug)]
struct GrpcMessageTooLarge {
    received: usize,
}

impl std::fmt::Display for GrpcMessageTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "grpc: received message larger than max ({} vs. {})",
            self.received, MAX_GRPC_MESSAGE_BYTES
        )
    }
}

impl std::error::Error for GrpcMessageTooLarge {}

#[derive(Debug)]
struct GrpcCompressedMessage;

impl std::fmt::Display for GrpcCompressedMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .write_str("grpc: compressed flag set with identity or empty encoding")
    }
}

impl std::error::Error for GrpcCompressedMessage {}

#[derive(Debug)]
struct GrpcUnexpectedPayloadFormat(u8);

impl std::fmt::Display for GrpcUnexpectedPayloadFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "grpc: received unexpected payload format {}",
            self.0
        )
    }
}

impl std::error::Error for GrpcUnexpectedPayloadFormat {}

#[derive(Debug)]
struct GrpcInvalidProtobuf;

impl std::fmt::Display for GrpcInvalidProtobuf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data",
        )
    }
}

impl std::error::Error for GrpcInvalidProtobuf {}

#[derive(Debug)]
struct GrpcUploadStatus {
    code: u8,
    message: String,
}

#[derive(Debug, Clone, Copy)]
struct GrpcKeepalive {
    idle_timeout: u32,
    health_check_timeout: u32,
}

#[derive(Debug, Clone)]
struct GrpcConnectionContext {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    setup_deadline: Instant,
    trusted_x_forwarded_for: Arc<Vec<String>>,
    sniffing: Option<InboundSniffingConfig>,
}

#[derive(Debug, Clone)]
struct GrpcPeerContext {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    trusted_x_forwarded_for: Arc<Vec<String>>,
    sniffing: Option<InboundSniffingConfig>,
}

#[derive(Debug)]
enum GrpcSetupState {
    Preface(usize),
    FrameHeader {
        bytes: [u8; HTTP2_FRAME_HEADER_LEN],
        filled: usize,
    },
    FramePayload(usize),
    Complete,
}

struct GrpcSetupTimeoutIo<IO> {
    inner: IO,
    deadline: Pin<Box<Sleep>>,
    state: GrpcSetupState,
}

impl<IO> GrpcSetupTimeoutIo<IO> {
    fn new(inner: IO, deadline: Instant) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            state: GrpcSetupState::Preface(0),
        }
    }

    fn observe_read(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            match &mut self.state {
                GrpcSetupState::Preface(read) => {
                    let take = (HTTP2_CLIENT_PREFACE_LEN - *read).min(bytes.len());
                    *read += take;
                    bytes = &bytes[take..];
                    if *read == HTTP2_CLIENT_PREFACE_LEN {
                        self.state = GrpcSetupState::FrameHeader {
                            bytes: [0; HTTP2_FRAME_HEADER_LEN],
                            filled: 0,
                        };
                    }
                }
                GrpcSetupState::FrameHeader {
                    bytes: header,
                    filled,
                } => {
                    let take = (HTTP2_FRAME_HEADER_LEN - *filled).min(bytes.len());
                    header[*filled..*filled + take].copy_from_slice(&bytes[..take]);
                    *filled += take;
                    bytes = &bytes[take..];
                    if *filled == HTTP2_FRAME_HEADER_LEN {
                        let payload_len = (usize::from(header[0]) << 16)
                            | (usize::from(header[1]) << 8)
                            | usize::from(header[2]);
                        self.state = if payload_len == 0 {
                            GrpcSetupState::Complete
                        } else {
                            GrpcSetupState::FramePayload(payload_len)
                        };
                    }
                }
                GrpcSetupState::FramePayload(remaining) => {
                    let take = (*remaining).min(bytes.len());
                    *remaining -= take;
                    bytes = &bytes[take..];
                    if *remaining == 0 {
                        self.state = GrpcSetupState::Complete;
                    }
                }
                GrpcSetupState::Complete => break,
            }
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for GrpcSetupTimeoutIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !matches!(self.state, GrpcSetupState::Complete)
            && self.deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "gRPC HTTP/2 connection setup timed out",
            )));
        }

        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                if after > before {
                    self.observe_read(&buf.filled()[before..after]);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for GrpcSetupTimeoutIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
enum GrpcSecurity {
    Plain,
    #[cfg(feature = "tls")]
    Tls(Arc<rustls::ServerConfig>),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
}

pub(super) async fn start_grpc_server(
    config: ServerConfig,
    runtime: RuntimeState,
) -> io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        sniffing,
        ..
    } = config;
    let (grpc_config, inner_protocol, security) = parse_listener_protocol(protocol)?;
    let mut rules_stack = Vec::new();
    let server_handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(
        create_tcp_server_handler(inner_protocol, &tag, &mut rules_stack)?,
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let listen_addr = match bind_location {
        BindLocation::Address(location) => location.to_socket_addr()?,
    };
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(
        service = %grpc_config.service_name,
        multi_mode = grpc_config.multi_mode,
        address = %listen_addr,
        "Starting gRPC transport server"
    );
    let (tun_service_path, tun_multi_service_path) =
        grpc_service_paths(&grpc_config.service_name);

    let handle = tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    error!("gRPC transport accept failed: {error}");
                    continue;
                }
            };
            let local_addr = match stream.local_addr() {
                Ok(value) => value,
                Err(error) => {
                    error!("gRPC transport local address lookup failed: {error}");
                    continue;
                }
            };
            let tun_service_path = tun_service_path.clone();
            let tun_multi_service_path = tun_multi_service_path.clone();
            let keepalive = GrpcKeepalive {
                idle_timeout: grpc_config.idle_timeout,
                health_check_timeout: grpc_config.health_check_timeout,
            };
            let trusted_x_forwarded_for =
                Arc::new(grpc_config.trusted_x_forwarded_for.clone());
            let server_handler = server_handler.clone();
            let resolver = resolver.clone();
            let runtime = runtime.clone();
            let sniffing = sniffing.clone();
            match &security {
                GrpcSecurity::Plain => {
                    tokio::spawn(serve_grpc_connection(
                        stream,
                        GrpcConnectionContext {
                            peer_addr,
                            local_addr,
                            setup_deadline: Instant::now()
                                + GRPC_CONNECTION_SETUP_TIMEOUT,
                            trusted_x_forwarded_for,
                            sniffing,
                        },
                        (tun_service_path, tun_multi_service_path),
                        keepalive,
                        server_handler,
                        resolver,
                        runtime,
                    ));
                }
                #[cfg(feature = "tls")]
                GrpcSecurity::Tls(server_config) => {
                    let acceptor = TlsAcceptor::from(server_config.clone());
                    tokio::spawn(async move {
                        let setup_deadline =
                            Instant::now() + GRPC_CONNECTION_SETUP_TIMEOUT;
                        match tokio::time::timeout_at(
                            setup_deadline,
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                serve_grpc_connection(
                                    stream,
                                    GrpcConnectionContext {
                                        peer_addr,
                                        local_addr,
                                        setup_deadline,
                                        trusted_x_forwarded_for,
                                        sniffing,
                                    },
                                    (tun_service_path, tun_multi_service_path),
                                    keepalive,
                                    server_handler,
                                    resolver,
                                    runtime,
                                )
                                .await;
                            }
                            Ok(Err(error)) => {
                                debug!("gRPC TLS handshake failed: {error}");
                            }
                            Err(_) => {
                                debug!("gRPC TLS handshake timed out");
                            }
                        }
                    });
                }
                #[cfg(feature = "reality")]
                GrpcSecurity::Reality(reality_config) => {
                    let reality_config = reality_config.clone();
                    tokio::spawn(async move {
                        match accept_reality_stream(
                            Box::new(stream),
                            &reality_config,
                        )
                        .await
                        {
                            Ok(stream) => {
                                serve_grpc_connection(
                                    stream,
                                    GrpcConnectionContext {
                                        peer_addr,
                                        local_addr,
                                        setup_deadline: Instant::now()
                                            + GRPC_CONNECTION_SETUP_TIMEOUT,
                                        trusted_x_forwarded_for,
                                        sniffing,
                                    },
                                    (tun_service_path, tun_multi_service_path),
                                    keepalive,
                                    server_handler,
                                    resolver,
                                    runtime,
                                )
                                .await;
                            }
                            Err(error) => {
                                debug!("gRPC REALITY handshake failed: {error}");
                            }
                        }
                    });
                }
            }
        }
    });
    Ok(vec![handle])
}

fn parse_listener_protocol(
    protocol: ServerProxyConfig,
) -> io::Result<(GrpcServerConfig, ServerProxyConfig, GrpcSecurity)> {
    match protocol {
        ServerProxyConfig::Grpc(config) => {
            let inner = (*config.inner).clone();
            Ok((config, inner, GrpcSecurity::Plain))
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            let TlsServerConfig {
                certificates,
                mut alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
                server_name: _,
                inner,
            } = tls_config;
            let ServerProxyConfig::Grpc(config) = *inner else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS gRPC listener requires Grpc as the inner protocol",
                ));
            };
            if !alpn_protocols.iter().any(|value| value == "h2") {
                alpn_protocols.push("h2".to_string());
            }
            let server_config = build_server_config(
                &certificates,
                &alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version.as_deref(),
                max_version.as_deref(),
            )?;
            let inner = (*config.inner).clone();
            Ok((config, inner, GrpcSecurity::Tls(Arc::new(server_config))))
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            let ServerProxyConfig::Grpc(config) = reality_config.inner.as_ref()
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY gRPC listener requires Grpc as the inner protocol",
                ));
            };
            let config = config.clone();
            let inner = (*config.inner).clone();
            Ok((config, inner, GrpcSecurity::Reality(reality_config)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid protocol for gRPC transport server: {other}"),
        )),
    }
}

fn grpc_service_paths(service_name: &str) -> (String, String) {
    let (service, tun, tun_multi) = grpc_service_parts(service_name);
    (
        format!("/{service}/{tun}"),
        format!("/{service}/{tun_multi}"),
    )
}

fn grpc_service_parts(service_name: &str) -> (String, String, String) {
    if !service_name.starts_with('/') {
        return (
            grpc_path_escape(service_name),
            "Tun".to_string(),
            "TunMulti".to_string(),
        );
    }

    let last_slash = service_name.rfind('/').unwrap_or(0);
    let service = if last_slash <= 1 {
        String::new()
    } else {
        service_name[1..last_slash]
            .split('/')
            .map(grpc_path_escape)
            .collect::<Vec<_>>()
            .join("/")
    };
    let ending = &service_name[last_slash + 1..];
    let mut stream_names = ending.split('|');
    let tun = grpc_path_escape(stream_names.next().unwrap_or_default());
    let tun_multi = grpc_path_escape(stream_names.next().unwrap_or(ending));
    (service, tun, tun_multi)
}

fn grpc_path_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'~' | b'$' | b'&' | b'+' | b':' | b'=' | b'@'
            )
        {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write as _;
            write!(&mut escaped, "%{byte:02X}")
                .expect("writing to String cannot fail");
        }
    }
    escaped
}

fn grpc_http2_builder(keepalive: GrpcKeepalive) -> http2::Builder<TokioExecutor> {
    let mut builder = http2::Builder::new(TokioExecutor::new());
    // grpc-go leaves HTTP/2 flow control at the RFC defaults, so Xray neither
    // advertises SETTINGS_INITIAL_WINDOW_SIZE nor sends an initial connection
    // WINDOW_UPDATE. Hyper defaults both receive windows to 1 MiB.
    builder.initial_stream_window_size(65_535);
    builder.initial_connection_window_size(65_535);
    // grpc-go does not configure MaxConcurrentStreams by default, so Xray does not
    // advertise a SETTINGS_MAX_CONCURRENT_STREAMS limit. Hyper defaults to 200.
    builder.max_concurrent_streams(None);
    // grpc-go v1.78 defaults to a 16 MiB inbound header-list limit when Xray does
    // not configure MaxHeaderListSize. Hyper defaults to 16 KiB, which rejects
    // valid Xray gRPC metadata long before grpc-go would.
    builder.max_header_list_size(GRPC_MAX_HEADER_LIST_BYTES);
    if keepalive.idle_timeout > 0 || keepalive.health_check_timeout > 0 {
        builder.timer(TokioTimer::new());
        builder.keep_alive_interval(Duration::from_secs(
            if keepalive.idle_timeout > 0 {
                u64::from(keepalive.idle_timeout)
            } else {
                2 * 60 * 60
            },
        ));
        builder.keep_alive_timeout(Duration::from_secs(
            if keepalive.health_check_timeout > 0 {
                u64::from(keepalive.health_check_timeout)
            } else {
                20
            },
        ));
    }
    builder
}

async fn serve_grpc_connection<IO>(
    io: IO,
    connection: GrpcConnectionContext,
    service_paths: (String, String),
    keepalive: GrpcKeepalive,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let builder = grpc_http2_builder(keepalive);
    let GrpcConnectionContext {
        peer_addr,
        local_addr,
        setup_deadline,
        trusted_x_forwarded_for,
        sniffing,
    } = connection;
    let (tun_service_path, tun_multi_service_path) = service_paths;
    let service = service_fn(move |request| {
        handle_request(
            request,
            tun_service_path.clone(),
            tun_multi_service_path.clone(),
            server_handler.clone(),
            resolver.clone(),
            runtime.clone(),
            GrpcPeerContext {
                peer_addr,
                local_addr,
                trusted_x_forwarded_for: trusted_x_forwarded_for.clone(),
                sniffing: sniffing.clone(),
            },
        )
    });
    let io = GrpcSetupTimeoutIo::new(io, setup_deadline);
    if let Err(error) = builder.serve_connection(TokioIo::new(io), service).await {
        debug!("gRPC transport connection {peer_addr} ended: {error}");
    }
}

async fn handle_request(
    request: Request<Incoming>,
    tun_service_path: String,
    tun_multi_service_path: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
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
        if let Err(error) = super::process_stream_with_sniffing_and_local_addr(
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

fn grpc_timeout_duration(
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

fn grpc_encode_message(message: &str) -> String {
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

fn grpc_malformed_binary_metadata(headers: &hyper::HeaderMap) -> Option<String> {
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

fn grpc_invalid_base64_offset(value: &[u8]) -> Option<usize> {
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

fn grpc_duplicate_host_error(
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

fn grpc_duplicate_host_response(message: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

fn grpc_malformed_binary_metadata_response(message: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

fn grpc_malformed_timeout_response(message: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", "13")
        .header("grpc-message", grpc_encode_message(message))
        .body(empty_grpc_body())
        .unwrap()
}

fn grpc_deadline_exceeded_response() -> Response<ResponseBody> {
    grpc_status_response(4, "context deadline exceeded")
}

fn empty_grpc_body() -> ResponseBody {
    BodyExt::boxed_unsync(
        Empty::<Bytes>::new().map_err(|never| -> h2::Error { match never {} }),
    )
}

fn grpc_content_type(headers: &hyper::HeaderMap) -> Result<&str, String> {
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

fn grpc_content_type_is_valid(content_type: &str) -> bool {
    const BASE: &str = "application/grpc";
    content_type == BASE
        || content_type
            .strip_prefix(BASE)
            .is_some_and(|suffix| suffix.starts_with('+') || suffix.starts_with(';'))
}

fn grpc_invalid_content_type_response(content_type: &str) -> Response<ResponseBody> {
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

fn grpc_method_not_allowed_response(method: &Method) -> Response<ResponseBody> {
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

fn grpc_unimplemented_path_response(
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

fn grpc_unsupported_encoding(headers: &hyper::HeaderMap) -> Option<&str> {
    headers
        .get_all("grpc-encoding")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .filter(|encoding| !encoding.is_empty() && *encoding != "identity")
}

fn grpc_logical_addrs(
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

fn grpc_logical_peer_addr(
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
            while let Some(payloads) =
                decode_grpc_message(&mut buffered, multi_mode)?
            {
                for payload in payloads {
                    writer.write_all(&payload).await?;
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

struct GrpcStreamTaskGuard {
    upload_abort: AbortHandle,
    stream_abort: AbortHandle,
    deadline_abort: Option<AbortHandle>,
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

fn grpc_upload_status_from_error(error: &io::Error) -> Option<GrpcUploadStatus> {
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

fn grpc_stream_response(
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

fn decode_grpc_message(
    buffer: &mut BytesMut,
    multi_mode: bool,
) -> io::Result<Option<Vec<Vec<u8>>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    match buffer[0] {
        0 => {}
        1 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                GrpcCompressedMessage,
            ));
        }
        format => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                GrpcUnexpectedPayloadFormat(format),
            ));
        }
    }
    let message_len =
        u32::from_be_bytes(buffer[1..5].try_into().expect("gRPC length")) as usize;
    if message_len > MAX_GRPC_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            GrpcMessageTooLarge {
                received: message_len,
            },
        ));
    }
    if buffer.len() < 5 + message_len {
        return Ok(None);
    }
    buffer.advance(5);
    let message = buffer.split_to(message_len);
    decode_data_fields(&message, multi_mode)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, GrpcInvalidProtobuf))
}

fn decode_data_fields(message: &[u8], multi_mode: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut offset = 0;
    let mut payloads = Vec::new();
    while offset < message.len() {
        let (key, key_len) = decode_varint(&message[offset..])?;
        offset += key_len;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        if field_number == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protobuf field number cannot be zero",
            ));
        }

        if field_number == 1 && wire_type == 2 {
            let (length, varint_len) = decode_varint(&message[offset..])?;
            offset += varint_len;
            let end = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "gRPC payload length overflow",
                )
            })?;
            if end > message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated gRPC protobuf payload",
                ));
            }
            let payload = message[offset..end].to_vec();
            offset = end;
            if multi_mode {
                payloads.push(payload);
            } else if let Some(existing) = payloads.first_mut() {
                *existing = payload;
            } else {
                payloads.push(payload);
            }
            continue;
        }

        // Generated protobuf decoders treat a known field with the wrong wire
        // type as an unknown field. Xray therefore skips it instead of failing.
        offset = skip_protobuf_field(message, offset, field_number, wire_type)?;
    }

    if payloads.is_empty() {
        payloads.push(Vec::new());
    }
    Ok(payloads)
}

fn skip_protobuf_field(
    message: &[u8],
    mut offset: usize,
    field_number: usize,
    wire_type: usize,
) -> io::Result<usize> {
    match wire_type {
        0 => {
            let (_, len) = decode_varint(&message[offset..])?;
            offset += len;
        }
        1 => {
            offset = offset.checked_add(8).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        2 => {
            let (length, len) = decode_varint(&message[offset..])?;
            offset += len;
            offset = offset.checked_add(length).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        3 => loop {
            if offset >= message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated protobuf group",
                ));
            }
            let (key, key_len) = decode_varint(&message[offset..])?;
            offset += key_len;
            let nested_field_number = key >> 3;
            let nested_wire_type = key & 0x07;
            if nested_field_number == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field number cannot be zero",
                ));
            }
            if nested_wire_type == 4 {
                if nested_field_number != field_number {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "protobuf group end field mismatch",
                    ));
                }
                break;
            }
            offset = skip_protobuf_field(
                message,
                offset,
                nested_field_number,
                nested_wire_type,
            )?;
        },
        4 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected protobuf end group",
            ));
        }
        5 => {
            offset = offset.checked_add(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protobuf field length overflow",
                )
            })?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported protobuf wire type",
            ));
        }
    }
    if offset > message.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated protobuf field",
        ));
    }
    Ok(offset)
}

fn encode_grpc_message(data: &[u8], _multi_mode: bool) -> Bytes {
    // Hunk and MultiHunk both encode their data using protobuf field 1. A single
    // field is a valid repeated-field encoding, so replies can use the same wire form.
    let mut protobuf = Vec::with_capacity(data.len() + 6);
    protobuf.push(0x0a);
    encode_varint(data.len(), &mut protobuf);
    protobuf.extend_from_slice(data);
    let mut frame = Vec::with_capacity(protobuf.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    Bytes::from(frame)
}

fn decode_varint(data: &[u8]) -> io::Result<(usize, usize)> {
    let mut value = 0usize;
    for (index, byte) in data.iter().copied().enumerate().take(10) {
        if index == 9 && byte > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protobuf varint",
            ));
        }
        value |= ((byte & 0x7f) as usize) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid protobuf varint",
    ))
}

fn encode_varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
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

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use bytes::{Bytes, BytesMut};
    use http_body_util::{Empty, Full};
    use hyper::{
        HeaderMap, Request, Response, client::conn::http2 as client_http2,
        service::service_fn,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::Instant,
    };

    use super::{
        GrpcKeepalive, GrpcPeerContext, GrpcSetupTimeoutIo, GrpcStreamTaskGuard,
        decode_grpc_message, encode_grpc_message, grpc_content_type,
        grpc_content_type_is_valid, grpc_deadline_exceeded_response,
        grpc_duplicate_host_error, grpc_duplicate_host_response,
        grpc_encode_message, grpc_http2_builder, grpc_invalid_base64_offset,
        grpc_invalid_content_type_response, grpc_logical_addrs,
        grpc_logical_peer_addr, grpc_malformed_binary_metadata,
        grpc_malformed_binary_metadata_response, grpc_malformed_timeout_response,
        grpc_method_not_allowed_response, grpc_service_paths, grpc_stream_response,
        grpc_timeout_duration, grpc_unimplemented_path_response,
        grpc_unsupported_encoding, grpc_upload_status_from_error,
    };

    #[tokio::test]
    async fn grpc_setup_timeout_expires_before_http2_handshake() {
        let (_client, server) = tokio::io::duplex(64);
        let mut server = GrpcSetupTimeoutIo::new(
            server,
            Instant::now() + Duration::from_millis(20),
        );

        let error = server.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn grpc_setup_timeout_includes_initial_settings_frame() {
        let (mut client, server) = tokio::io::duplex(128);
        let mut server = GrpcSetupTimeoutIo::new(
            server,
            Instant::now() + Duration::from_millis(30),
        );
        let reader = tokio::spawn(async move {
            let mut setup = [0u8; 33];
            server.read_exact(&mut setup).await.unwrap();
            server.read_u8().await
        });

        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x06\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();

        let error = reader.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn grpc_setup_timeout_clears_after_preface_and_settings() {
        let (mut client, server) = tokio::io::duplex(128);
        let deadline = Instant::now() + Duration::from_millis(40);
        let mut server = GrpcSetupTimeoutIo::new(server, deadline);
        let reader = tokio::spawn(async move {
            let mut setup = [0u8; 33];
            server.read_exact(&mut setup).await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            server.read_u8().await.unwrap()
        });

        let mut setup = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        setup.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        client.write_all(&setup).await.unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
        client.write_u8(0x7f).await.unwrap();

        assert_eq!(reader.await.unwrap(), 0x7f);
    }

    #[tokio::test]
    async fn grpc_server_does_not_advertise_hyper_stream_limit_like_xray_v26_2_6() {
        let (mut client, server) = tokio::io::duplex(4096);
        let builder = grpc_http2_builder(GrpcKeepalive {
            idle_timeout: 0,
            health_check_timeout: 0,
        });
        let server = tokio::spawn(async move {
            let service = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
            });
            builder
                .serve_connection(TokioIo::new(server), service)
                .await
        });

        let mut header = [0u8; 9];
        client.read_exact(&mut header).await.unwrap();
        let payload_len = (usize::from(header[0]) << 16)
            | (usize::from(header[1]) << 8)
            | usize::from(header[2]);
        assert_eq!(header[3], 0x04, "first HTTP/2 frame must be SETTINGS");
        let mut payload = vec![0u8; payload_len];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload.len() % 6, 0);
        assert!(
            payload
                .as_chunks::<6>()
                .0
                .iter()
                .all(|setting| u16::from_be_bytes([setting[0], setting[1]]) != 0x03),
            "Xray/grpc-go does not advertise SETTINGS_MAX_CONCURRENT_STREAMS by default"
        );

        drop(client);
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn grpc_server_uses_xray_default_flow_control_windows() {
        let (mut client, server) = tokio::io::duplex(4096);
        let builder = grpc_http2_builder(GrpcKeepalive {
            idle_timeout: 0,
            health_check_timeout: 0,
        });
        let server = tokio::spawn(async move {
            let service = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
            });
            builder
                .serve_connection(TokioIo::new(server), service)
                .await
        });

        let mut header = [0u8; 9];
        client.read_exact(&mut header).await.unwrap();
        let payload_len = (usize::from(header[0]) << 16)
            | (usize::from(header[1]) << 8)
            | usize::from(header[2]);
        assert_eq!(header[3], 0x04, "first HTTP/2 frame must be SETTINGS");
        let mut payload = vec![0u8; payload_len];
        client.read_exact(&mut payload).await.unwrap();
        for setting in payload.as_chunks::<6>().0 {
            if u16::from_be_bytes([setting[0], setting[1]]) == 0x04 {
                assert_eq!(
                    u32::from_be_bytes([
                        setting[2], setting[3], setting[4], setting[5]
                    ]),
                    65_535,
                    "Hyper may advertise the RFC-default stream window explicitly"
                );
            }
        }

        let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        client.write_all(&preface).await.unwrap();

        let next = tokio::time::timeout(Duration::from_millis(100), async {
            let mut frame = [0u8; 9];
            loop {
                client.read_exact(&mut frame).await.unwrap();
                let payload_len = (usize::from(frame[0]) << 16)
                    | (usize::from(frame[1]) << 8)
                    | usize::from(frame[2]);
                let mut payload = vec![0u8; payload_len];
                client.read_exact(&mut payload).await.unwrap();
                if frame[3] != 0x04 || frame[4] & 0x01 == 0 {
                    return frame[3];
                }
            }
        })
        .await;
        assert!(
            next.is_err(),
            "Xray/grpc-go does not send an initial connection WINDOW_UPDATE"
        );

        drop(client);
        let _ = server.await.unwrap();
    }

    #[tokio::test]
    async fn grpc_server_accepts_xray_sized_metadata_headers() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let builder = grpc_http2_builder(GrpcKeepalive {
            idle_timeout: 0,
            health_check_timeout: 0,
        });
        let server = tokio::spawn(async move {
            let service = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
            });
            builder
                .serve_connection(TokioIo::new(server), service)
                .await
        });
        let (mut sender, connection) =
            client_http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(client))
                .await
                .unwrap();
        let client = tokio::spawn(connection);
        let request = Request::builder()
            .method("POST")
            .uri("http://localhost/GunService/Tun")
            .header("content-type", "application/grpc")
            .header("x-large-metadata", "x".repeat(40 * 1024))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);

        drop(sender);
        client.abort();
        server.abort();
    }

    #[tokio::test]
    async fn grpc_server_rejects_http1_like_xray_v26_2_6() {
        let (mut client, server) = tokio::io::duplex(4096);
        let builder = grpc_http2_builder(GrpcKeepalive {
            idle_timeout: 0,
            health_check_timeout: 0,
        });
        let server = tokio::spawn(async move {
            let service = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"unexpected HTTP/1 response",
                ))))
            });
            builder
                .serve_connection(TokioIo::new(server), service)
                .await
        });

        client
            .write_all(
                b"POST /svc/Tun HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(server.await.unwrap().is_err());
        assert!(
            !response.starts_with(b"HTTP/1.1 200"),
            "gRPC transport must stay HTTP/2-only"
        );
    }

    #[test]
    fn grpc_server_exposes_tun_and_tun_multi_like_xray_v26_2_6() {
        let (tun, tun_multi) = grpc_service_paths("GunService");
        assert_eq!(tun, "/GunService/Tun");
        assert_eq!(tun_multi, "/GunService/TunMulti");
    }

    #[test]
    fn grpc_custom_service_paths_match_xray_v26_2_6() {
        let (tun, tun_multi) = grpc_service_paths("");
        assert_eq!(tun, "//Tun");
        assert_eq!(tun_multi, "//TunMulti");

        let (tun, tun_multi) =
            grpc_service_paths("/my/sample path/tun service|multi service");
        assert_eq!(tun, "/my/sample%20path/tun%20service");
        assert_eq!(tun_multi, "/my/sample%20path/multi%20service");

        let (tun, tun_multi) = grpc_service_paths("hello/world!");
        assert_eq!(tun, "/hello%2Fworld%21/Tun");
        assert_eq!(tun_multi, "/hello%2Fworld%21/TunMulti");
    }

    #[test]
    fn grpc_duplicate_host_validation_matches_xray_v26_2_6() {
        let uri: hyper::Uri = "http://proxy.example/NoService/Tun".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.append(hyper::header::HOST, "a.example".parse().unwrap());
        assert_eq!(grpc_duplicate_host_error(&headers, &uri), None);

        headers.append(hyper::header::HOST, "b.example".parse().unwrap());
        let message = grpc_duplicate_host_error(&headers, &uri)
            .expect("duplicate Host headers must be rejected before gRPC dispatch");
        assert_eq!(
            message,
            "num values of :authority: 1, num values of host: 2, both must only have 1 value as per HTTP/2 spec"
        );
        let response = grpc_duplicate_host_response(&message);
        assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        assert_eq!(response.headers()["grpc-status"], "13");
        assert_eq!(response.headers()["grpc-message"], message);
    }

    #[test]
    fn grpc_content_type_validation_matches_xray_v26_2_6() {
        for valid in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+xml",
            "application/grpc; charset=utf-8",
        ] {
            assert!(grpc_content_type_is_valid(valid), "{valid}");
        }
        for invalid in [
            "",
            "application/grpcfoo",
            "application/grpcx+proto",
            "application/grpc ",
            "application/grpc/",
            "APPLICATION/GRPC",
            "text/plain",
        ] {
            assert!(!grpc_content_type_is_valid(invalid), "{invalid}");
        }

        let mut headers = HeaderMap::new();
        headers.append("content-type", "text/plain".parse().unwrap());
        headers.append("content-type", "application/grpc".parse().unwrap());
        assert_eq!(grpc_content_type(&headers), Ok("application/grpc"));

        let mut headers = HeaderMap::new();
        headers.append("content-type", "application/grpc".parse().unwrap());
        headers.append("content-type", "application/grpcfoo".parse().unwrap());
        assert_eq!(grpc_content_type(&headers), Ok("application/grpc"));

        let mut headers = HeaderMap::new();
        headers.append("content-type", "text/plain".parse().unwrap());
        headers.append("content-type", "application/grpcfoo".parse().unwrap());
        assert_eq!(
            grpc_content_type(&headers),
            Err("application/grpcfoo".into())
        );

        let response = grpc_invalid_content_type_response("application/grpcfoo");
        assert_eq!(response.status(), hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        assert_eq!(response.headers()["grpc-status"], "3");
        assert_eq!(
            response.headers()["grpc-message"],
            "invalid gRPC request content-type \"application/grpcfoo\""
        );

        let response = grpc_invalid_content_type_response("application/grpc%foo");
        assert_eq!(
            response.headers()["grpc-message"],
            "invalid gRPC request content-type \"application/grpc%25foo\""
        );
    }

    #[test]
    fn grpc_binary_metadata_validation_matches_xray_v26_2_6() {
        for valid in [b"".as_slice(), b"AQI=", b"AQI", b"AB", b"AB=="] {
            assert_eq!(grpc_invalid_base64_offset(valid), None, "{valid:?}");
        }
        for (invalid, offset) in [
            (b"A".as_slice(), 0),
            (b"A=".as_slice(), 1),
            (b"A===".as_slice(), 1),
            (b"AQI==".as_slice(), 3),
            (b"AQI*".as_slice(), 3),
            (b"!!!".as_slice(), 0),
        ] {
            assert_eq!(grpc_invalid_base64_offset(invalid), Some(offset));
        }

        let mut headers = HeaderMap::new();
        headers.insert("x-test-bin", "!!!".parse().unwrap());
        let message = grpc_malformed_binary_metadata(&headers)
            .expect("invalid binary metadata must be rejected");
        assert_eq!(
            message,
            "malformed binary metadata \"!!!\" in header \"x-test-bin\": illegal base64 data at input byte 0"
        );
        let response = grpc_malformed_binary_metadata_response(&message);
        assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["grpc-status"], "13");
        assert_eq!(response.headers()["grpc-message"], message);
    }

    #[test]
    fn grpc_non_post_response_matches_xray_v26_2_6() {
        for method in [hyper::Method::GET, hyper::Method::PUT] {
            let response = grpc_method_not_allowed_response(&method);
            assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["content-type"], "application/grpc");
            assert_eq!(response.headers()["grpc-status"], "13");
            assert_eq!(
                response.headers()["grpc-message"],
                format!(
                    "Received a HEADERS frame with :method \"{method}\" which should be POST"
                )
            );
        }
    }

    #[test]
    fn grpc_unknown_service_and_method_match_xray_v26_2_6() {
        let tun_path = "/GunService/Tun";

        let response = grpc_unimplemented_path_response("/NoService/Tun", tun_path);
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(response.headers()["grpc-status"], "12");
        assert_eq!(
            response.headers()["grpc-message"],
            "unknown service NoService"
        );

        let response =
            grpc_unimplemented_path_response("/GunService/Nope", tun_path);
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(response.headers()["grpc-status"], "12");
        assert_eq!(
            response.headers()["grpc-message"],
            "unknown method Nope for service GunService"
        );

        let response =
            grpc_unimplemented_path_response("/No%25Service/Tun", tun_path);
        assert_eq!(response.headers()["grpc-status"], "12");
        assert_eq!(
            response.headers()["grpc-message"],
            "unknown service No%2525Service"
        );
    }

    #[test]
    fn grpc_message_encoding_matches_grpc_go() {
        assert_eq!(grpc_encode_message("plain text"), "plain text");
        assert_eq!(grpc_encode_message("50% done"), "50%25 done");
        assert_eq!(grpc_encode_message("line\nbreak"), "line%0Abreak");
        assert_eq!(grpc_encode_message("é"), "%C3%A9");
    }

    #[tokio::test]
    async fn grpc_invalid_protobuf_reports_internal_like_xray_v26_2_6() {
        let protobuf = [0x00_u8];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let error = decode_grpc_message(&mut buffer, false)
            .expect_err("invalid protobuf wire format must be rejected");
        let status = grpc_upload_status_from_error(&error)
            .expect("invalid protobuf wire format must map to a status");
        assert_eq!(status.code, 13);
        assert_eq!(
            status.message,
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
        );

        let (transport_stream, handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        drop(handler_stream);
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
        status_tx.send(status).unwrap();
        drop(status_tx);

        let response = grpc_stream_response(
            transport_read,
            false,
            Arc::new(AtomicBool::new(false)),
            Some(status_rx),
            None,
        );
        let collected = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect invalid-protobuf response");
        let trailers = collected.trailers().expect("invalid-protobuf trailers");
        assert_eq!(trailers["grpc-status"], "13");
        assert_eq!(
            trailers["grpc-message"],
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
        );
    }

    #[test]
    fn grpc_rejects_overflowing_protobuf_varints_like_xray_v26_2_6() {
        let protobuf = [
            0x10_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
            0x0a, 0x02, b'o', b'k',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());

        let error = decode_grpc_message(&mut buffer, false)
            .expect_err("protobuf varints wider than uint64 must be rejected");
        let status = grpc_upload_status_from_error(&error)
            .expect("overflowing protobuf varint must map to an internal status");
        assert_eq!(status.code, 13);
        assert_eq!(
            status.message,
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
        );

        let protobuf = [
            0x10_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x0a, 0x02, b'o', b'k',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        assert_eq!(
            decode_grpc_message(&mut buffer, false).unwrap(),
            Some(vec![b"ok".to_vec()])
        );
    }

    #[tokio::test]
    async fn grpc_truncated_message_reports_unexpected_eof_like_xray_v26_2_6() {
        let error = std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated gRPC message",
        );
        let status = grpc_upload_status_from_error(&error)
            .expect("truncated gRPC message must map to a status");
        assert_eq!(status.code, 13);
        assert_eq!(status.message, "unexpected EOF");

        let (transport_stream, handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        drop(handler_stream);
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
        status_tx.send(status).unwrap();
        drop(status_tx);

        let response = grpc_stream_response(
            transport_read,
            false,
            Arc::new(AtomicBool::new(false)),
            Some(status_rx),
            None,
        );
        let collected = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect truncated-message response");
        let trailers = collected.trailers().expect("truncated-message trailers");
        assert_eq!(trailers["grpc-status"], "13");
        assert_eq!(trailers["grpc-message"], "unexpected EOF");
    }

    #[tokio::test]
    async fn grpc_compressed_flag_reports_internal_like_xray_v26_2_6() {
        let mut buffer = BytesMut::from(&[1_u8, 0, 0, 0, 0][..]);
        let error = decode_grpc_message(&mut buffer, false).expect_err(
            "compressed gRPC message must be rejected without a decompressor",
        );
        let status = grpc_upload_status_from_error(&error)
            .expect("compressed gRPC message must map to a status");
        assert_eq!(status.code, 13);
        assert_eq!(
            status.message,
            "grpc: compressed flag set with identity or empty encoding"
        );

        let (transport_stream, handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        drop(handler_stream);
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
        status_tx.send(status).unwrap();
        drop(status_tx);

        let response = grpc_stream_response(
            transport_read,
            false,
            Arc::new(AtomicBool::new(false)),
            Some(status_rx),
            None,
        );
        let collected = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect compressed-message response");
        let trailers = collected.trailers().expect("compressed-message trailers");
        assert_eq!(trailers["grpc-status"], "13");
        assert_eq!(
            trailers["grpc-message"],
            "grpc: compressed flag set with identity or empty encoding"
        );
    }

    #[tokio::test]
    async fn grpc_invalid_payload_format_reports_internal_like_xray_v26_2_6() {
        for format in [2_u8, u8::MAX] {
            let mut buffer = BytesMut::from(&[format, 0, 0, 0, 0][..]);
            let error = decode_grpc_message(&mut buffer, false)
                .expect_err("unsupported gRPC payload format must be rejected");
            let status = grpc_upload_status_from_error(&error)
                .expect("unsupported gRPC payload format must map to a status");
            assert_eq!(status.code, 13);
            assert_eq!(
                status.message,
                format!("grpc: received unexpected payload format {format}")
            );
        }
    }

    #[tokio::test]
    async fn grpc_oversized_message_reports_resource_exhausted_like_xray_v26_2_6() {
        let mut buffer = BytesMut::from(&[0_u8, 0, 0x40, 0, 1][..]);
        let error = decode_grpc_message(&mut buffer, false)
            .expect_err("4 MiB + 1 gRPC message must be rejected");
        let status = grpc_upload_status_from_error(&error)
            .expect("oversized gRPC message must map to a status");
        assert_eq!(status.code, 8);
        assert_eq!(
            status.message,
            "grpc: received message larger than max (4194305 vs. 4194304)"
        );

        let (transport_stream, handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        drop(handler_stream);
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
        status_tx.send(status).unwrap();
        drop(status_tx);

        let response = grpc_stream_response(
            transport_read,
            false,
            Arc::new(AtomicBool::new(false)),
            Some(status_rx),
            None,
        );
        let collected = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect resource exhausted response");
        let trailers = collected.trailers().expect("resource exhausted trailers");
        assert_eq!(trailers["grpc-status"], "8");
        assert_eq!(
            trailers["grpc-message"],
            "grpc: received message larger than max (4194305 vs. 4194304)"
        );
    }

    #[tokio::test]
    async fn grpc_success_metadata_matches_xray_v26_2_6() {
        let (transport_stream, handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        drop(handler_stream);

        let response = grpc_stream_response(
            transport_read,
            false,
            Arc::new(AtomicBool::new(false)),
            None,
            None,
        );
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        assert!(!response.headers().contains_key("grpc-encoding"));
        assert!(!response.headers().contains_key("grpc-accept-encoding"));

        let collected = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect gRPC response");
        let trailers = collected.trailers().expect("gRPC success trailers");
        assert_eq!(trailers["grpc-status"], "0");
        assert_eq!(trailers["grpc-message"], "");
    }

    #[tokio::test]
    async fn dropping_grpc_response_aborts_logical_stream_tasks() {
        let (transport_stream, _handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        let upload_task = tokio::spawn(futures::future::pending::<()>());
        let stream_task = tokio::spawn(futures::future::pending::<()>());
        let upload_abort = upload_task.abort_handle();
        let stream_abort = stream_task.abort_handle();
        let guard = GrpcStreamTaskGuard {
            upload_abort,
            stream_abort,
            deadline_abort: None,
        };

        let response = grpc_stream_response(
            transport_read,
            false,
            Arc::new(AtomicBool::new(false)),
            None,
            Some(guard),
        );
        drop(response);

        assert!(
            upload_task
                .await
                .expect_err("upload task must be aborted")
                .is_cancelled()
        );
        assert!(
            stream_task
                .await
                .expect_err("logical stream task must be aborted")
                .is_cancelled()
        );
    }

    #[tokio::test]
    async fn grpc_deadline_ends_stream_without_success_trailers() {
        let (transport_stream, handler_stream) = tokio::io::duplex(64);
        let (transport_read, _transport_write) = tokio::io::split(transport_stream);
        drop(handler_stream);
        let timed_out = Arc::new(AtomicBool::new(true));

        let response =
            grpc_stream_response(transport_read, false, timed_out, None, None);
        let error = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect_err("expired gRPC stream must end with a body error");
        assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
    }

    #[test]
    fn grpc_timeout_parser_matches_grpc_go_syntax() {
        let mut headers = HeaderMap::new();
        assert_eq!(grpc_timeout_duration(&headers).unwrap(), None);

        headers.insert("grpc-timeout", "1S".parse().unwrap());
        assert_eq!(
            grpc_timeout_duration(&headers).unwrap(),
            Some(std::time::Duration::from_secs(1))
        );

        headers.insert("grpc-timeout", "250m".parse().unwrap());
        assert_eq!(
            grpc_timeout_duration(&headers).unwrap(),
            Some(std::time::Duration::from_millis(250))
        );

        headers.insert("grpc-timeout", "nope".parse().unwrap());
        let message = grpc_timeout_duration(&headers).unwrap_err();
        assert_eq!(
            message,
            "malformed grpc-timeout: transport: timeout unit is not recognized: \"nope\""
        );
        let response = grpc_malformed_timeout_response(&message);
        assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["grpc-status"], "13");
        assert_eq!(response.headers()["grpc-message"], message);

        headers.insert("grpc-timeout", "xS".parse().unwrap());
        let message = grpc_timeout_duration(&headers).unwrap_err();
        assert_eq!(
            message,
            "malformed grpc-timeout: strconv.ParseUint: parsing \"x\": invalid syntax"
        );
        let response = grpc_malformed_timeout_response(&message);
        assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["grpc-status"], "13");
        assert_eq!(response.headers()["grpc-message"], message);
    }

    #[test]
    fn grpc_expired_deadline_uses_xray_status() {
        let response = grpc_deadline_exceeded_response();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(response.headers()["grpc-status"], "4");
        assert_eq!(
            response.headers()["grpc-message"],
            "context deadline exceeded"
        );
    }

    #[test]
    fn grpc_duplicate_timeouts_validate_all_values_but_use_first_like_xray_v26_2_6()
    {
        let mut headers = HeaderMap::new();
        headers.append("grpc-timeout", "1S".parse().unwrap());
        headers.append("grpc-timeout", "2S".parse().unwrap());
        assert_eq!(
            grpc_timeout_duration(&headers).unwrap(),
            Some(std::time::Duration::from_secs(1))
        );

        headers.append("grpc-timeout", "nope".parse().unwrap());
        assert_eq!(
            grpc_timeout_duration(&headers).unwrap_err(),
            "malformed grpc-timeout: transport: timeout unit is not recognized: \"nope\""
        );
    }

    #[test]
    fn grpc_rejects_non_identity_encoding_like_xray_v26_2_6() {
        let mut headers = HeaderMap::new();
        assert_eq!(grpc_unsupported_encoding(&headers), None);

        headers.insert("grpc-encoding", "identity".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), None);

        headers.insert("grpc-encoding", "".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), None);

        headers.insert("grpc-encoding", "gzip".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), Some("gzip"));

        headers.insert("grpc-encoding", "deflate".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), Some("deflate"));

        headers.clear();
        headers.append("grpc-encoding", "identity".parse().unwrap());
        headers.append("grpc-encoding", "gzip".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), Some("gzip"));

        headers.clear();
        headers.append("grpc-encoding", "gzip".parse().unwrap());
        headers.append("grpc-encoding", "identity".parse().unwrap());
        assert_eq!(grpc_unsupported_encoding(&headers), None);
    }

    #[test]
    fn grpc_trusted_x_forwarded_for_matches_current_xray() {
        let peer_addr = "127.0.0.1:34567".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.9, 198.51.100.2".parse().unwrap(),
        );
        assert_eq!(grpc_logical_peer_addr(&headers, peer_addr, &[]), peer_addr);
        assert_eq!(
            grpc_logical_peer_addr(
                &headers,
                peer_addr,
                &["X-Trusted-CDN".to_string()]
            ),
            peer_addr
        );

        headers.insert("x-trusted-cdn", "".parse().unwrap());
        assert_eq!(
            grpc_logical_peer_addr(
                &headers,
                peer_addr,
                &["X-Trusted-CDN".to_string()]
            ),
            "203.0.113.9:0".parse().unwrap()
        );

        assert_eq!(
            grpc_logical_peer_addr(
                &headers,
                peer_addr,
                &["X-Forwarded-For".to_string()]
            ),
            "203.0.113.9:0".parse().unwrap()
        );

        headers.insert("x-real-ip", "192.0.2.10".parse().unwrap());
        headers.remove("x-forwarded-for");
        assert_eq!(
            grpc_logical_peer_addr(
                &headers,
                peer_addr,
                &["X-Trusted-CDN".to_string()]
            ),
            peer_addr
        );
    }

    #[test]
    fn grpc_logical_addrs_preserve_accepted_local_addr() {
        let peer_addr = "127.0.0.1:34567".parse().unwrap();
        let local_addr = "127.0.0.1:8443".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.insert("x-trusted-cdn", "".parse().unwrap());
        let context = GrpcPeerContext {
            peer_addr,
            local_addr,
            trusted_x_forwarded_for: Arc::new(vec!["X-Trusted-CDN".to_string()]),
            sniffing: None,
        };

        let (logical_peer_addr, logical_local_addr) =
            grpc_logical_addrs(&headers, &context);

        assert_eq!(logical_peer_addr, "203.0.113.9:0".parse().unwrap());
        assert_eq!(logical_local_addr, local_addr);
    }

    #[test]
    fn hunk_round_trip_handles_large_payload() {
        let payload = (0..70_000).map(|value| value as u8).collect::<Vec<_>>();
        let encoded = encode_grpc_message(&payload, false);
        let mut buffer = BytesMut::from(encoded.as_ref());
        let decoded = decode_grpc_message(&mut buffer, false)
            .expect("decode Hunk")
            .expect("complete Hunk");
        assert_eq!(decoded, vec![payload]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn multi_hunk_decodes_repeated_data_fields_in_order() {
        let protobuf = [
            0x0a, 0x05, b'h', b'e', b'l', b'l', b'o', 0x0a, 0x05, b'w', b'o', b'r',
            b'l', b'd',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, true)
            .expect("decode MultiHunk")
            .expect("complete MultiHunk");
        assert_eq!(decoded, vec![b"hello".to_vec(), b"world".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_decoder_matches_protobuf_unknown_and_duplicate_field_semantics() {
        let protobuf = [
            0x10, 0x01, // unknown varint field 2
            0x0a, 0x05, b'f', b'i', b'r', b's', b't', 0x1a, 0x03, b'x', b'y',
            b'z', // unknown bytes field 3
            0x0a, 0x04, b'l', b'a', b's', b't',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, false)
            .expect("decode Hunk with protobuf-compatible unknown fields")
            .expect("complete Hunk");
        assert_eq!(decoded, vec![b"last".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_skips_unknown_group_fields_like_xray_v26_2_6() {
        let protobuf = [
            0x13, // unknown field 2, start group
            0x18, 0x01, // nested unknown varint field 3
            0x14, // field 2, end group
            0x0a, 0x02, b'o', b'k',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, false)
            .expect("unknown protobuf group is skipped by generated decoder")
            .expect("complete Hunk");
        assert_eq!(decoded, vec![b"ok".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_ignores_known_data_field_with_wrong_wire_type_like_xray_v26_2_6() {
        let protobuf = [0x08_u8, 0x01];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, false)
            .expect("wrong-wire data field is skipped by generated protobuf decoder")
            .expect("complete Hunk");
        assert_eq!(decoded, vec![Vec::<u8>::new()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn multi_hunk_ignores_unknown_fields_and_keeps_all_data_fields() {
        let protobuf = [
            0x0a, 0x03, b'o', b'n', b'e', 0x2d, 0x01, 0x02, 0x03,
            0x04, // unknown fixed32 field 5
            0x0a, 0x03, b't', b'w', b'o',
        ];
        let mut frame = vec![0];
        frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&protobuf);
        let mut buffer = BytesMut::from(frame.as_slice());
        let decoded = decode_grpc_message(&mut buffer, true)
            .expect("decode MultiHunk with protobuf-compatible unknown fields")
            .expect("complete MultiHunk");
        assert_eq!(decoded, vec![b"one".to_vec(), b"two".to_vec()]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn hunk_decoder_waits_for_complete_frame() {
        let encoded = encode_grpc_message(b"hello", false);
        let mut buffer = BytesMut::from(&encoded[..4]);
        assert!(decode_grpc_message(&mut buffer, false).unwrap().is_none());
    }
}
