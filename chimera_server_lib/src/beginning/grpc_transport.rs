use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hyper::{server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    task::JoinHandle,
    time::{Instant, Sleep},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

#[cfg(feature = "reality")]
use crate::handler::reality::accept_reality_stream;
#[cfg(feature = "tls")]
use crate::handler::tls::build_server_config;
use crate::{
    address::BindLocation,
    config::server_config::{InboundSniffingConfig, ServerConfig},
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::{DataPlaneRuntime, RuntimeState},
};

use super::transport_plan::{GrpcListenerPlan, ListenerSecurityPlan};

const GRPC_MAX_HEADER_LIST_BYTES: u32 = 16 * 1024 * 1024;
const GRPC_CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const HTTP2_CLIENT_PREFACE_LEN: usize = 24;
const HTTP2_FRAME_HEADER_LEN: usize = 9;

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
    Reality(crate::config::server_config::RealityTransportConfig),
}

pub(super) async fn start_grpc_server(
    config: ServerConfig,
    runtime: RuntimeState,
    plan: GrpcListenerPlan,
) -> io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol: _,
        sniffing,
        tcp_socket_policy,
        ..
    } = config;
    let GrpcListenerPlan {
        config: grpc_config,
        protocol: inner_protocol,
        security,
    } = plan;
    let security = prepare_grpc_security(security)?;
    let mut rules_stack = Vec::new();
    let server_handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(
        create_tcp_server_handler(inner_protocol, &tag, &mut rules_stack)?,
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let data_plane = runtime.data_plane();
    let listen_addr = match bind_location {
        BindLocation::Address(location) => location.to_socket_addr()?,
    };
    let listener =
        super::create_tcp_listener(listen_addr, tcp_socket_policy.as_ref()).await?;
    info!(
        service = %grpc_config.service_name,
        multi_mode = grpc_config.multi_mode,
        address = %listen_addr,
        "Starting gRPC transport server"
    );
    let (tun_service_path, tun_multi_service_path) =
        grpc_service_paths(&grpc_config.service_name);

    let handle = tokio::spawn(async move {
        let mut accept_health = super::TcpAcceptHealth::default();
        loop {
            let (stream, peer_addr) = match super::accept_tcp_with_health(
                &listener,
                &mut accept_health,
                "grpc_transport",
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    error!("gRPC transport listener stopped: {error}");
                    return;
                }
            };
            if let Some(policy) = tcp_socket_policy.as_ref()
                && let Err(error) = super::apply_tcp_socket_policy(
                    &stream,
                    listen_addr,
                    peer_addr,
                    policy,
                )
            {
                error!(
                    "gRPC transport TCP socket policy for {peer_addr} failed: {error}"
                );
                continue;
            }
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
            let runtime = data_plane.clone();
            let connection_runtime = runtime.clone();
            let sniffing = sniffing.clone();
            match &security {
                GrpcSecurity::Plain => {
                    runtime.spawn_inbound_connection(serve_grpc_connection(
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
                        connection_runtime,
                    ));
                }
                #[cfg(feature = "tls")]
                GrpcSecurity::Tls(server_config) => {
                    let acceptor = TlsAcceptor::from(server_config.clone());
                    runtime.spawn_inbound_connection(async move {
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
                                    connection_runtime,
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
                    runtime.spawn_inbound_connection(async move {
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
                                    connection_runtime,
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

fn prepare_grpc_security(
    security: ListenerSecurityPlan,
) -> io::Result<GrpcSecurity> {
    match security {
        ListenerSecurityPlan::None => Ok(GrpcSecurity::Plain),
        #[cfg(feature = "tls")]
        ListenerSecurityPlan::Tls(tls_config) => {
            let crate::config::server_config::TlsServerConfig {
                certificates,
                mut alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
                ..
            } = tls_config;
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
            Ok(GrpcSecurity::Tls(Arc::new(server_config)))
        }
        #[cfg(feature = "reality")]
        ListenerSecurityPlan::Reality(reality_config) => {
            Ok(GrpcSecurity::Reality(reality_config))
        }
    }
}

pub(crate) fn grpc_service_paths(service_name: &str) -> (String, String) {
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
    runtime: DataPlaneRuntime,
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

mod request;

use request::{GrpcPeerContext, handle_request};
#[cfg(test)]
use request::{
    GrpcStreamTaskGuard, PROTOBUF_MAX_FIELD_NUMBER, decode_grpc_message,
    decode_grpc_message_view, encode_varint, grpc_content_type,
    grpc_content_type_is_valid, grpc_deadline_exceeded_response,
    grpc_duplicate_host_error, grpc_duplicate_host_response, grpc_encode_message,
    grpc_invalid_base64_offset, grpc_invalid_content_type_response,
    grpc_logical_addrs, grpc_logical_peer_addr, grpc_malformed_binary_metadata,
    grpc_malformed_binary_metadata_response, grpc_malformed_timeout_response,
    grpc_method_not_allowed_response, grpc_stream_response, grpc_timeout_duration,
    grpc_unimplemented_path_response, grpc_unsupported_encoding,
    grpc_upload_status_from_error,
};
pub(crate) use request::{decode_grpc_message_payloads, encode_grpc_message};

#[cfg(test)]
mod tests;
