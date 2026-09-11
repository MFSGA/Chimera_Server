use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use futures::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Frame},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use rand::RngExt;
#[cfg(feature = "tls")]
use tokio::task::JoinSet;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, duplex},
    time::{Duration, sleep},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

#[cfg(all(feature = "tls", target_os = "linux"))]
use std::os::fd::AsRawFd;
#[cfg(all(feature = "tls", feature = "hysteria"))]
use std::sync::atomic::AtomicU64;

#[cfg(feature = "reality")]
use crate::handler::reality::accept_reality_stream;
#[cfg(feature = "tls")]
use crate::handler::tls::build_server_config;
use crate::{
    address::BindLocation,
    async_stream::AsyncStream,
    config::server_config::{
        InboundSniffingConfig, ServerConfig, ServerProxyConfig, TcpSocketPolicy,
        XhttpDataPlacement, XhttpMode, XhttpPaddingMethod, XhttpPaddingPlacement,
        XhttpPlacement, XhttpServerConfig,
    },
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::{DataPlaneRuntime, RuntimeState},
};

use super::{
    process_stream_with_sniffing_and_local_addr,
    transport_plan::{ListenerSecurityPlan, XhttpListenerPlan},
};

mod session;

use session::{
    IncomingBodyReader, SessionCleanupGuard, SessionStore, XhttpLogicalStream,
};
#[cfg(test)]
use session::{
    SessionTtlPlan, SessionTtlSnapshot, SharedUploadReader, UploadPayloadPlan,
    UploadReassemblyPlan, UploadReassemblySnapshot, XhttpSession, XhttpUploadReader,
    plan_session_ttl, plan_upload_payload, plan_upload_reassembly,
};

const XHTTP_PIPE_CAPACITY: usize = 64 * 1024;
const XHTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(4);

type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;
type H3BidiRequestStream =
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3SendRequestStream =
    h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvRequestStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Adapts the receive half of an HTTP/3 request stream to the `http_body::Body`
/// interface used by the transport-neutral XHTTP request dispatcher.
#[allow(dead_code)]
struct H3RequestBody {
    stream: H3RecvRequestStream,
}

#[allow(dead_code)]
impl H3RequestBody {
    fn new(stream: H3RecvRequestStream) -> Self {
        Self { stream }
    }
}

impl Body for H3RequestBody {
    type Data = Bytes;
    type Error = h3::error::StreamError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut data))) => {
                let len = data.remaining();
                Poll::Ready(Some(Ok(Frame::data(data.copy_to_bytes(len)))))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Splits an accepted H3 request so XHTTP can consume the request body while
/// retaining the send half for the HTTP/3 response path.
#[allow(dead_code)]
fn split_h3_request_stream(
    stream: H3BidiRequestStream,
) -> (H3SendRequestStream, H3RequestBody) {
    let (send, recv) = stream.split();
    (send, H3RequestBody::new(recv))
}

/// Bridges an accepted HTTP/3 request into the transport-neutral XHTTP
/// dispatcher and streams its response back over the retained H3 send half.
#[allow(dead_code)]
async fn handle_h3_request_stream(
    request: Request<()>,
    stream: H3BidiRequestStream,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Result<(), h3::error::StreamError> {
    let (send, body) = split_h3_request_stream(stream);
    let (parts, ()) = request.into_parts();
    let request = Request::from_parts(parts, body);
    let response = match handle_request(request, state, peer_addr, local_addr).await
    {
        Ok(response) => response,
        Err(infallible) => match infallible {},
    };

    send_h3_response(send, response).await
}

#[allow(dead_code)]
async fn send_h3_response(
    mut stream: H3SendRequestStream,
    response: Response<ResponseBody>,
) -> Result<(), h3::error::StreamError> {
    let (parts, mut body) = response.into_parts();
    stream
        .send_response(Response::from_parts(parts, ()))
        .await?;

    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(infallible) => match infallible {},
        };
        let frame = match frame.into_data() {
            Ok(data) => {
                stream.send_data(data).await?;
                continue;
            }
            Err(frame) => frame,
        };
        if let Ok(trailers) = frame.into_trailers() {
            stream.send_trailers(trailers).await?;
        }
    }

    stream.finish().await
}

pub async fn start_xhttp_server(
    config: ServerConfig,
    runtime: RuntimeState,
    plan: XhttpListenerPlan,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol: _,
        sniffing,
        tcp_socket_policy,
        ..
    } = config;

    let listener_config = prepare_xhttp_listener(plan)?;

    let bind_addr = match bind_location {
        BindLocation::Address(address) => address.to_socket_addr()?,
    };

    let mut rules_stack = vec![];
    let server_handler = Arc::new(create_tcp_server_handler(
        listener_config.inner,
        &tag,
        &mut rules_stack,
    )?);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let shutdown = CancellationToken::new();
    #[cfg(feature = "tls")]
    let h3_transport_config =
        build_xhttp_h3_transport_config(&listener_config.xhttp_config)?;
    let state = Arc::new(AppState::new(
        listener_config.xhttp_config,
        server_handler,
        resolver,
        runtime.data_plane(),
        sniffing,
        shutdown.clone(),
    ));
    #[cfg(feature = "tls")]
    if let XhttpSecurityLayer::H3Tls(server_config) = listener_config.security {
        if tcp_socket_policy
            .as_ref()
            .is_some_and(TcpSocketPolicy::has_tcp_only_options)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TCP-only sockopt fields are not applicable to XHTTP HTTP/3",
            ));
        }
        return start_xhttp_h3_server(
            bind_addr,
            server_config,
            h3_transport_config,
            state,
            tcp_socket_policy,
        )
        .await;
    }

    let listener =
        super::create_tcp_listener(bind_addr, tcp_socket_policy.as_ref()).await?;
    let security = listener_config.security.clone();

    let handle = tokio::spawn(async move {
        let mut accept_health = super::TcpAcceptHealth::default();
        loop {
            let (stream, peer_addr) = match super::accept_tcp_with_health(
                &listener,
                &mut accept_health,
                "xhttp_tcp",
            )
            .await
            {
                Ok(pair) => pair,
                Err(err) => {
                    error!("xhttp TCP listener stopped: {err}");
                    return;
                }
            };
            let _ = stream.set_nodelay(true);
            if let Some(policy) = tcp_socket_policy.as_ref()
                && let Err(err) = super::apply_tcp_socket_policy(
                    &stream, bind_addr, peer_addr, policy,
                )
            {
                error!("xhttp TCP socket policy for {} failed: {}", peer_addr, err);
                continue;
            }
            let local_addr = match stream.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    error!("xhttp local address for {} failed: {}", peer_addr, err);
                    continue;
                }
            };

            let state = state.clone();
            let security = security.clone();
            let connection_runtime = state.runtime.clone();
            connection_runtime.spawn_inbound_connection(async move {
                let stream: Box<dyn AsyncStream> = Box::new(stream);
                let wrapped_stream: std::io::Result<Box<dyn AsyncStream>> =
                    match security {
                        XhttpSecurityLayer::None => Ok(stream),
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::Tls(acceptor) => {
                            accept_xhttp_tls(acceptor, stream).await
                        }
                        #[cfg(feature = "tls")]
                        XhttpSecurityLayer::H3Tls(_) => unreachable!(
                            "HTTP/3 XHTTP listener is dispatched before TCP accept"
                        ),
                        #[cfg(feature = "reality")]
                        XhttpSecurityLayer::Reality(config) => {
                            accept_reality_stream(stream, &config).await.map(
                                |stream| Box::new(stream) as Box<dyn AsyncStream>,
                            )
                        }
                    };

                match wrapped_stream {
                    Ok(stream) => {
                        serve_http_connection(stream, state, peer_addr, local_addr)
                            .await
                    }
                    Err(err) => {
                        error!("xhttp accept {} failed: {}", peer_addr, err);
                    }
                }
            });
        }
    });

    Ok(vec![handle])
}

struct XhttpListenerConfig {
    xhttp_config: XhttpServerConfig,
    inner: ServerProxyConfig,
    security: XhttpSecurityLayer,
}

#[derive(Clone)]
enum XhttpSecurityLayer {
    None,
    #[cfg(feature = "tls")]
    Tls(TlsAcceptor),
    #[cfg(feature = "tls")]
    H3Tls(Arc<rustls::ServerConfig>),
    #[cfg(feature = "reality")]
    Reality(crate::config::server_config::RealityTransportConfig),
}

#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_INITIAL_MTU: u16 = 1280;
#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_MAX_FIELD_SECTION_SIZE: u64 = 1 << 20;
#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_BBR_INITIAL_WINDOW: u64 = 32 * XRAY_XHTTP_H3_INITIAL_MTU as u64;
#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_INITIAL_CONNECTION_RECEIVE_WINDOW: u64 = 3 * 1024 * 1024;

#[cfg(feature = "tls")]
fn apply_xray_xhttp_h3_initial_mtu(transport: &mut quinn::TransportConfig) {
    // Current Xray uses quic-go's 1280-byte InitialPacketSize for XHTTP/3.
    transport.initial_mtu(XRAY_XHTTP_H3_INITIAL_MTU);
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XhttpH3CongestionMode {
    Reno,
    Bbr,
    ForceBrutal,
}

#[cfg(feature = "tls")]
fn configured_xhttp_h3_congestion_mode(
    congestion: Option<&str>,
) -> XhttpH3CongestionMode {
    match congestion {
        Some("reno") => XhttpH3CongestionMode::Reno,
        None | Some("") | Some("bbr") => XhttpH3CongestionMode::Bbr,
        Some("force-brutal") => XhttpH3CongestionMode::ForceBrutal,
        Some(_) => unreachable!("validated XHTTP congestion mode"),
    }
}

#[cfg(feature = "tls")]
fn build_xhttp_h3_transport_config(
    config: &XhttpServerConfig,
) -> std::io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    // Xray leaves quic-go's Reno controller in place for explicit `reno`, and
    // switches accepted XHTTP/3 connections to BBR for the default / `bbr`.
    match configured_xhttp_h3_congestion_mode(config.xray_congestion.as_deref()) {
        XhttpH3CongestionMode::Reno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        XhttpH3CongestionMode::Bbr => {
            let mut bbr = quinn::congestion::BbrConfig::default();
            // Xray's BBR starts at 32 packets and XHTTP/3 uses quic-go's
            // 1280-byte InitialPacketSize, for a 40,960-byte initial CWND.
            bbr.initial_window(XRAY_XHTTP_H3_BBR_INITIAL_WINDOW);
            transport.congestion_controller_factory(Arc::new(bbr));
        }
        XhttpH3CongestionMode::ForceBrutal => {
            #[cfg(feature = "hysteria")]
            {
                let tx_bps = config
                    .xray_brutal_up
                    .expect("validated XHTTP force-brutal bandwidth");
                transport.congestion_controller_factory(Arc::new(
                    crate::handler::hysteria2::congestion::BrutalConfig::new(
                        Arc::new(AtomicU64::new(tx_bps)),
                    ),
                ));
            }
            #[cfg(not(feature = "hysteria"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "XHTTP force-brutal requires the hysteria feature",
                ));
            }
        }
    }
    apply_xray_xhttp_h3_initial_mtu(&mut transport);
    if let Some(max_idle_timeout_secs) = config.xray_max_idle_timeout_secs {
        let idle_timeout = std::time::Duration::from_secs(max_idle_timeout_secs)
            .try_into()
            .map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
            })?;
        transport.max_idle_timeout(Some(idle_timeout));
    }
    if let Some(max_incoming_streams) = config.xray_max_incoming_streams {
        let max_incoming_streams = quinn::VarInt::from_u64(max_incoming_streams)
            .map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
            })?;
        transport.max_concurrent_bidi_streams(max_incoming_streams);
    }
    // Quinn exposes the receive credit advertised on the wire, but not quic-go's
    // separate auto-tuning ceiling. Match Xray's initial flow-control windows here;
    // using max*ReceiveWindow would advertise Xray's ceiling as the initial credit.
    let stream_receive_window = configured_xhttp_receive_window(
        config.xray_init_stream_receive_window,
        XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW,
    )?;
    transport.stream_receive_window(stream_receive_window);
    let connection_receive_window = configured_xhttp_receive_window(
        config.xray_init_connection_receive_window,
        XRAY_XHTTP_H3_INITIAL_CONNECTION_RECEIVE_WINDOW,
    )?;
    transport.receive_window(connection_receive_window);
    let platform_supports_path_mtu_discovery = cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    ));
    if config.xray_disable_path_mtu_discovery == Some(true)
        || !platform_supports_path_mtu_discovery
    {
        transport.mtu_discovery_config(None);
    }
    Ok(transport)
}

#[cfg(feature = "tls")]
fn configured_xhttp_receive_window(
    value: Option<u64>,
    xray_default: u64,
) -> std::io::Result<quinn::VarInt> {
    let value = value.filter(|value| *value != 0).unwrap_or(xray_default);
    quinn::VarInt::from_u64(value)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
}

#[cfg(feature = "tls")]
async fn start_xhttp_h3_server(
    bind_addr: std::net::SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    transport_config: quinn::TransportConfig,
    state: Arc<AppState>,
    socket_policy: Option<TcpSocketPolicy>,
) -> std::io::Result<Vec<tokio::task::JoinHandle<()>>> {
    let quic_crypto: quinn::crypto::rustls::QuicServerConfig =
        tls_config.try_into().map_err(std::io::Error::other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport_config));

    if socket_policy
        .as_ref()
        .is_some_and(|policy| policy.receive_original_destination)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "receiveOriginalDestAddress is not applicable to XHTTP HTTP/3",
        ));
    }
    let bind_interface = socket_policy
        .as_ref()
        .and_then(|policy| policy.bind_interface.clone());
    let socket = crate::util::socket::new_socket2_udp_socket_with_buffer_size(
        bind_addr.is_ipv6(),
        bind_interface,
        None,
        true,
        Some(8_625_000),
    )?;
    if socket_policy
        .as_ref()
        .is_some_and(|policy| policy.ipv6_only)
    {
        if !bind_addr.is_ipv6() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sockopt.v6only requires an IPv6 XHTTP HTTP/3 listener",
            ));
        }
        socket.set_only_v6(true)?;
    }
    #[cfg(target_os = "linux")]
    if let Some(policy) = socket_policy.as_ref() {
        let fd = socket.as_raw_fd();
        if let Some(mark) = policy.mark {
            crate::util::socket::configure_socket_mark(fd, mark)?;
        }
        if policy.transparent {
            crate::util::socket::configure_ip_transparent(fd)?;
        }
        crate::util::socket::configure_custom_sockopt(
            fd,
            if bind_addr.is_ipv6() { "udp6" } else { "udp4" },
            &policy.custom_sockopt,
        )?;
    }
    #[cfg(not(target_os = "linux"))]
    if socket_policy.as_ref().is_some_and(|policy| {
        policy.mark.is_some()
            || policy.transparent
            || !policy.custom_sockopt.is_empty()
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "configured XHTTP HTTP/3 listener socket options are unsupported on this platform",
        ));
    }
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.into(),
        Arc::new(quinn::TokioRuntime),
    )?;
    let listener_addr = endpoint.local_addr()?;

    let handle = tokio::spawn(async move {
        let _cancel_on_drop = CancelOnDrop(state.shutdown.clone());
        loop {
            let incoming =
                match super::accept_quic_with_health(&endpoint, "xhttp-http3").await
                {
                    Ok(incoming) => incoming,
                    Err(_) => return,
                };
            let state = state.clone();
            let runtime = state.runtime.clone();
            let shutdown = state.shutdown.clone();
            spawn_xhttp_h3_connection(&runtime, shutdown, async move {
                let local_addr = xhttp_h3_connection_local_addr(
                    listener_addr,
                    incoming.local_ip(),
                );
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(err) => {
                        debug!("xhttp H3 QUIC handshake failed: {}", err);
                        return;
                    }
                };
                let peer_addr = connection.remote_address();
                let h3_quinn_connection = h3_quinn::Connection::new(connection);
                let mut h3_builder = h3::server::builder();
                // Xray's quic-go HTTP/3 server uses Go's http.DefaultMaxHeaderBytes,
                // advertises extended CONNECT, and doesn't emit HTTP/3 GREASE values.
                h3_builder
                    .max_field_section_size(XRAY_XHTTP_H3_MAX_FIELD_SECTION_SIZE)
                    .enable_extended_connect(true)
                    .send_grease(false);
                let mut h3_connection =
                    match h3_builder.build(h3_quinn_connection).await {
                        Ok(connection) => connection,
                        Err(err) => {
                            debug!(
                                "xhttp H3 connection setup from {} failed: {}",
                                peer_addr, err
                            );
                            return;
                        }
                    };
                let mut requests = JoinSet::new();

                loop {
                    tokio::select! {
                        resolved = h3_connection.accept() => {
                            let resolver = match resolved {
                                Ok(Some(resolver)) => resolver,
                                Ok(None) => break,
                                Err(err) => {
                                    debug!(
                                        "xhttp H3 accept from {} failed: {}",
                                        peer_addr, err
                                    );
                                    break;
                                }
                            };
                            let (request, stream) = match resolver.resolve_request().await {
                                Ok(request) => request,
                                Err(err) => {
                                    debug!(
                                        "xhttp H3 request from {} failed: {}",
                                        peer_addr, err
                                    );
                                    continue;
                                }
                            };
                            let state = state.clone();
                            requests.spawn(async move {
                                if let Err(err) = handle_h3_request_stream(
                                    request, stream, state, peer_addr, local_addr,
                                )
                                .await
                                {
                                    debug!(
                                        "xhttp H3 response to {} failed: {}",
                                        peer_addr, err
                                    );
                                }
                            });
                        }
                        result = requests.join_next(), if !requests.is_empty() => {
                            if let Some(Err(err)) = result {
                                debug!("xhttp H3 request task failed: {}", err);
                            }
                        }
                    }
                }
            });
        }
    });

    Ok(vec![handle])
}

#[cfg(feature = "tls")]
fn spawn_xhttp_h3_connection<F>(
    runtime: &DataPlaneRuntime,
    shutdown: CancellationToken,
    future: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    runtime.spawn_inbound_connection(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = future => {}
        }
    });
}

#[cfg(feature = "tls")]
fn xhttp_h3_connection_local_addr(
    listener_addr: std::net::SocketAddr,
    local_ip: Option<std::net::IpAddr>,
) -> std::net::SocketAddr {
    local_ip
        .map(|local_ip| std::net::SocketAddr::new(local_ip, listener_addr.port()))
        .unwrap_or(listener_addr)
}

#[cfg(feature = "tls")]
async fn accept_xhttp_tls(
    acceptor: TlsAcceptor,
    stream: Box<dyn AsyncStream>,
) -> std::io::Result<Box<dyn AsyncStream>> {
    match tokio::time::timeout(XHTTP_HEADER_READ_TIMEOUT, acceptor.accept(stream))
        .await
    {
        Ok(result) => {
            result.map(|tls_stream| Box::new(tls_stream) as Box<dyn AsyncStream>)
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "xhttp tls handshake timeout",
        )),
    }
}

fn prepare_xhttp_listener(
    plan: XhttpListenerPlan,
) -> std::io::Result<XhttpListenerConfig> {
    let XhttpListenerPlan {
        config: xhttp_config,
        protocol: inner,
        security,
    } = plan;
    let security = match security {
        ListenerSecurityPlan::None => XhttpSecurityLayer::None,
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
            let is_h3 = alpn_protocols.as_slice() == ["h3"];
            if !is_h3 && !alpn_protocols.iter().any(|proto| proto == "h2") {
                alpn_protocols.push("h2".to_string());
            }
            let tls_config = Arc::new(build_server_config(
                &certificates,
                &alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version.as_deref(),
                max_version.as_deref(),
            )?);
            if is_h3 {
                XhttpSecurityLayer::H3Tls(tls_config)
            } else {
                XhttpSecurityLayer::Tls(TlsAcceptor::from(tls_config))
            }
        }
        #[cfg(feature = "reality")]
        ListenerSecurityPlan::Reality(reality_config) => {
            XhttpSecurityLayer::Reality(reality_config)
        }
    };
    Ok(XhttpListenerConfig {
        xhttp_config,
        inner,
        security,
    })
}

const XHTTP_HTTP1_HEADER_SLOP_BYTES: usize = 4096;
const XHTTP_HTTP2_HEADER_LIST_OVERHEAD_BYTES: usize = 320;
const XRAY_XHTTP_HTTP2_MAX_CONCURRENT_STREAMS: u32 = 250;
const XRAY_XHTTP_HTTP2_MAX_FRAME_SIZE: u32 = 1_048_576;

fn xray_http1_header_read_limit(server_max_header_bytes: usize) -> usize {
    server_max_header_bytes
        .saturating_add(XHTTP_HTTP1_HEADER_SLOP_BYTES)
        .max(8192)
}

fn xray_http2_header_list_limit(server_max_header_bytes: usize) -> u32 {
    server_max_header_bytes
        .saturating_add(XHTTP_HTTP2_HEADER_LIST_OVERHEAD_BYTES)
        .min(u32::MAX as usize) as u32
}

fn uses_http1_header_read_limit(version: hyper::Version) -> bool {
    matches!(version, hyper::Version::HTTP_10 | hyper::Version::HTTP_11)
}

fn xray_valid_http_host(request: &str, config: &str) -> bool {
    let request = request.to_ascii_lowercase();
    let config = config.to_ascii_lowercase();
    if !request.contains(':') {
        return request == config;
    }

    let host = if let Some(rest) = request.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return false;
        };
        if !suffix.starts_with(':') || suffix[1..].contains(':') {
            return false;
        }
        host
    } else {
        let Some((host, _port)) = request.rsplit_once(':') else {
            return false;
        };
        if host.contains(':') {
            return false;
        }
        host
    };

    host == config
}

fn configure_http_builder(
    builder: &mut auto::Builder<TokioExecutor>,
    server_max_header_bytes: usize,
) {
    // Go net/http reads MaxHeaderBytes plus 4 KiB of bufio slop before it
    // decides an HTTP/1 request header is too large. Xray wires the normalized
    // XHTTP serverMaxHeaderBytes directly into http.Server.MaxHeaderBytes.
    let http1_read_limit = xray_http1_header_read_limit(server_max_header_bytes);
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(XHTTP_HEADER_READ_TIMEOUT)
        .max_buf_size(http1_read_limit);
    // Go's bundled HTTP/2 server adjusts MaxHeaderBytes before advertising
    // SETTINGS_MAX_HEADER_LIST_SIZE. Xray v26.2.6 advertises 8512 for its
    // 8192-byte XHTTP MaxHeaderBytes value (8192 + 320 bytes of HTTP/2 field
    // accounting overhead), rather than the raw MaxHeaderBytes value.
    builder
        .http2()
        .max_header_list_size(xray_http2_header_list_limit(server_max_header_bytes))
        .max_concurrent_streams(XRAY_XHTTP_HTTP2_MAX_CONCURRENT_STREAMS)
        .max_frame_size(XRAY_XHTTP_HTTP2_MAX_FRAME_SIZE);
}

async fn serve_http_connection<IO>(
    io: IO,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(io);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    configure_http_builder(&mut builder, state.server_max_header_bytes);
    let service = service_fn(move |request| {
        handle_request(request, state.clone(), peer_addr, local_addr)
    });

    if let Err(err) = builder.serve_connection(io, service).await {
        error!("xhttp connection {} exited: {}", peer_addr, err);
    }
}

#[derive(Clone)]
struct AppState {
    mode: XhttpMode,
    host: Option<String>,
    base_path: String,
    trusted_x_forwarded_for: Vec<String>,
    min_padding: usize,
    max_padding: usize,
    max_each_post_bytes: i64,
    stream_up_server_secs: (usize, usize),
    server_max_header_bytes: usize,
    padding_obfs_mode: bool,
    padding_key: String,
    padding_header: String,
    padding_placement: XhttpPaddingPlacement,
    padding_method: XhttpPaddingMethod,
    no_sse_header: bool,
    uplink_http_method: String,
    session_placement: XhttpPlacement,
    session_key: String,
    seq_placement: XhttpPlacement,
    seq_key: String,
    uplink_data_placement: XhttpDataPlacement,
    uplink_data_key: String,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    sniffing: Option<InboundSniffingConfig>,
    shutdown: CancellationToken,
    sessions: SessionStore,
}

impl AppState {
    fn new(
        config: XhttpServerConfig,
        server_handler: Arc<Box<dyn TcpServerHandler>>,
        resolver: Arc<dyn Resolver>,
        runtime: DataPlaneRuntime,
        sniffing: Option<InboundSniffingConfig>,
        shutdown: CancellationToken,
    ) -> Self {
        let sessions = SessionStore::new(
            Duration::from_secs(config.session_ttl_secs),
            config.max_buffered_posts,
            shutdown.clone(),
            runtime.clone(),
        );
        Self {
            mode: config.mode,
            host: config.host,
            base_path: normalize_base_path(
                config.path,
                config.session_placement,
                config.seq_placement,
            ),
            trusted_x_forwarded_for: config.trusted_x_forwarded_for,
            min_padding: config.min_padding,
            max_padding: config.max_padding,
            max_each_post_bytes: config.max_each_post_bytes,
            stream_up_server_secs: config.stream_up_server_secs,
            server_max_header_bytes: config.server_max_header_bytes,
            padding_obfs_mode: config.padding_obfs_mode,
            padding_key: config.padding_key,
            padding_header: config.padding_header,
            padding_placement: config.padding_placement,
            padding_method: config.padding_method,
            no_sse_header: config.no_sse_header,
            uplink_http_method: config.uplink_http_method,
            session_placement: config.session_placement,
            session_key: config.session_key,
            seq_placement: config.seq_placement,
            seq_key: config.seq_key,
            uplink_data_placement: config.uplink_data_placement,
            uplink_data_key: config.uplink_data_key,
            server_handler,
            resolver,
            runtime,
            sniffing,
            shutdown,
            sessions,
        }
    }

    fn validate_host(&self, header_host: Option<&str>) -> bool {
        match (&self.host, header_host) {
            (None, _) => true,
            (Some(expected), Some(actual)) => xray_valid_http_host(actual, expected),
            _ => false,
        }
    }

    fn extract_meta<B>(
        &self,
        request: &Request<B>,
        decoded_path: &str,
    ) -> (Option<String>, Option<String>) {
        let trimmed_base_path = self.base_path.trim_end_matches('/');
        let path_tail = if decoded_path == trimmed_base_path {
            ""
        } else {
            decoded_path.strip_prefix(&self.base_path).unwrap_or("")
        };

        // Current Xray consumes path metadata in placement order. Each path
        // placement advances the path segment index independently, so mixed
        // path/query/header/cookie configurations remain valid.
        let mut path_part = 0usize;
        let session_id = match self.session_placement {
            XhttpPlacement::Path => xray_path_metadata_value_for_placement(
                path_tail,
                &mut path_part,
                self.session_placement,
            ),
            XhttpPlacement::Query => {
                query_value(request.uri().query(), &self.session_key)
            }
            XhttpPlacement::Header => {
                header_value(request.headers(), &self.session_key)
            }
            XhttpPlacement::Cookie => {
                cookie_value(request.headers(), &self.session_key)
            }
        };
        let seq = match self.seq_placement {
            XhttpPlacement::Path => xray_path_metadata_value_for_placement(
                path_tail,
                &mut path_part,
                self.seq_placement,
            ),
            XhttpPlacement::Query => {
                query_value(request.uri().query(), &self.seq_key)
            }
            XhttpPlacement::Header => header_value(request.headers(), &self.seq_key),
            XhttpPlacement::Cookie => cookie_value(request.headers(), &self.seq_key),
        };
        (session_id, seq)
    }

    fn validate_padding(
        &self,
        path_query: Option<&str>,
        headers: &hyper::HeaderMap,
    ) -> Option<bool> {
        let padding = extract_xray_request_padding(
            self.padding_obfs_mode,
            &self.padding_key,
            &self.padding_header,
            self.padding_placement,
            path_query,
            headers,
        )?;

        is_padding_valid(
            &padding,
            self.min_padding,
            self.max_padding,
            self.padding_method,
        )
        .then_some(self.padding_obfs_mode && !padding.is_empty())
    }

    fn decorate_response(
        &self,
        response: &mut Response<ResponseBody>,
        request_method: &Method,
        request_headers: &hyper::HeaderMap,
    ) {
        apply_xray_cors_headers(
            response.headers_mut(),
            request_method,
            request_headers,
            self.uses_cookie_request_metadata(),
        );
        apply_response_padding(response.headers_mut(), self);
    }

    fn uses_cookie_request_metadata(&self) -> bool {
        self.session_placement == XhttpPlacement::Cookie
            || self.seq_placement == XhttpPlacement::Cookie
            || self.padding_placement == XhttpPaddingPlacement::Cookie
            || self.uplink_data_placement == XhttpDataPlacement::Cookie
    }
}

async fn handle_request<B>(
    request: Request<B>,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Result<Response<ResponseBody>, Infallible>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let request_headers = request.headers().clone();

    let http1_header_limit =
        xray_http1_header_read_limit(state.server_max_header_bytes);
    if uses_http1_header_read_limit(request.version())
        && request_head_bytes(&request) > http1_header_limit
    {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            limit = http1_header_limit,
            "xhttp request rejected by HTTP/1 header size limit"
        );
        return Ok(simple_response(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE));
    }

    let host_header = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let authority_host = request.uri().authority().map(|value| value.as_str());
    let request_host = host_header.or(authority_host);

    if !state.validate_host(request_host) {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            host = ?request_host,
            "xhttp request rejected by host validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }

    let path = match decode_xray_url_path(request.uri().path()) {
        Ok(path) => path,
        Err(()) => {
            debug!(
                method = %request.method(),
                path = %request.uri().path(),
                "xhttp request rejected by malformed URL path escape"
            );
            return Ok(simple_response(StatusCode::BAD_REQUEST));
        }
    };
    if !matches_base_path(&path, &state.base_path) {
        debug!(
            method = %request.method(),
            path = %path,
            base_path = %state.base_path,
            "xhttp request rejected by path validation"
        );
        return Ok(simple_response(StatusCode::NOT_FOUND));
    }

    if request.method() == Method::OPTIONS {
        let mut response = simple_response(StatusCode::OK);
        state.decorate_response(&mut response, request.method(), request.headers());
        return Ok(response);
    }

    let Some(obfs_padding_accepted) =
        state.validate_padding(request.uri().query(), request.headers())
    else {
        debug!(
            method = %request.method(),
            path = %request.uri().path(),
            query = ?request.uri().query(),
            "xhttp request rejected by padding validation"
        );
        let mut response = simple_response(StatusCode::BAD_REQUEST);
        state.decorate_response(&mut response, request.method(), request.headers());
        return Ok(response);
    };

    let request_method = request.method().clone();
    let logical_peer_addr =
        trusted_forwarded_peer(&request_headers, &state.trusted_x_forwarded_for)
            .unwrap_or(peer_addr);
    // Current Xray keeps the legacy Referer compatibility marker, and also
    // enables stream-up padding when xPaddingObfsMode accepted non-empty padding.
    let stream_up_padding =
        stream_up_padding_enabled(&request_headers, obfs_padding_accepted);
    let (session_id, seq) = state.extract_meta(&request, &path);
    let is_downlink_method = request.method() == Method::GET;
    // Current Xray treats every non-GET request as uplink. GET is uplink only
    // when sequence metadata is present, which lets packet-up use GET without
    // relying on the configured client method or legacy upstream markers.
    let is_uplink_method = is_xray_uplink_request(request.method(), seq.is_some());
    let dispatch = classify_request(
        state.mode,
        is_downlink_method,
        is_uplink_method,
        session_id.is_some(),
        seq.is_some(),
    );
    let mut response = match dispatch {
        Ok(XhttpRequestDispatch::StreamDown) => {
            handle_stream_down(
                state.clone(),
                session_id.expect("stream-down requires a session id"),
                logical_peer_addr,
                local_addr,
            )
            .await
        }
        Ok(XhttpRequestDispatch::StreamOne) => {
            handle_stream_one(
                request.into_body(),
                state.clone(),
                logical_peer_addr,
                local_addr,
            )
            .await
        }
        Ok(XhttpRequestDispatch::StreamUp) => {
            let request_version = request.version();
            handle_stream_up(
                request.into_body(),
                request_version,
                state.clone(),
                session_id.expect("stream-up requires a session id"),
                stream_up_padding,
            )
            .await
        }
        Ok(XhttpRequestDispatch::PacketUp) => {
            handle_packet_up(
                request,
                state.clone(),
                session_id.expect("packet-up requires a session id"),
                seq.expect("packet-up requires a sequence"),
            )
            .await
        }
        Err(status) => simple_response(status),
    };

    state.decorate_response(&mut response, &request_method, &request_headers);
    Ok(response)
}

async fn handle_stream_one<B>(
    mut body: B,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: Send + 'static,
{
    let (client_upload, server_read) = duplex(XHTTP_PIPE_CAPACITY);
    let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
    let logical_stream = XhttpLogicalStream::new(server_read, server_write);

    spawn_handler_stream(logical_stream, state.clone(), peer_addr, local_addr);

    let mut upload_writer = client_upload;
    let shutdown = state.shutdown.clone();
    let runtime = state.runtime.clone();
    let _ = runtime.spawn_inbound_connection(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = async {
                while let Some(frame_result) = body.frame().await {
                    match frame_result {
                        Ok(frame) => {
                            if let Some(chunk) = frame.data_ref()
                                && upload_writer.write_all(chunk).await.is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            } => {}
        }
        let _ = upload_writer.shutdown().await;
    });

    reader_response(StatusCode::OK, client_download, state.no_sse_header)
}

fn stream_up_padding_enabled(
    headers: &hyper::HeaderMap,
    obfs_padding_accepted: bool,
) -> bool {
    header_value(headers, "referer").is_some() || obfs_padding_accepted
}

fn stream_up_can_flush_while_uploading(version: hyper::Version) -> bool {
    matches!(version, hyper::Version::HTTP_2 | hyper::Version::HTTP_3)
}

async fn handle_stream_up<B>(
    body: B,
    request_version: hyper::Version,
    state: Arc<AppState>,
    session_id: String,
    padding_enabled: bool,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let response_can_flush_while_uploading =
        stream_up_can_flush_while_uploading(request_version);
    let session = state.sessions.get_or_create(&session_id);
    let reader = IncomingBodyReader::new(body);
    if session
        .upload_queue
        .push_reader(Box::pin(reader))
        .await
        .is_err()
    {
        return simple_response(StatusCode::CONFLICT);
    }

    stream_up_response(
        session.closed.clone(),
        &state,
        padding_enabled && response_can_flush_while_uploading,
    )
    .await
}

async fn handle_stream_down(
    state: Arc<AppState>,
    session_id: String,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) -> Response<ResponseBody> {
    let session = state.sessions.get_or_create(&session_id);
    session.fully_connected.store(true, Ordering::Release);

    let (stream, reader) = session.new_downlink_connection();
    spawn_handler_stream(stream, state.clone(), peer_addr, local_addr);

    let cleanup = SessionCleanupGuard {
        sessions: state.sessions.clone(),
        session_id,
        session,
    };
    let body_stream = futures::stream::unfold(
        (ReaderStream::new(reader), cleanup),
        |(mut reader, cleanup)| async move {
            match reader.next().await {
                Some(Ok(bytes)) => Some((Ok(Frame::data(bytes)), (reader, cleanup))),
                Some(Err(err)) => {
                    error!("xhttp stream-down read failed: {}", err);
                    None
                }
                None => None,
            }
        },
    );

    stream_response(StatusCode::OK, body_stream.boxed(), state.no_sse_header)
}

async fn handle_packet_up<B>(
    request: Request<B>,
    state: Arc<AppState>,
    session_id: String,
    seq: String,
) -> Response<ResponseBody>
where
    B: Body<Data = Bytes> + Unpin,
{
    let Ok(seq) = seq.parse::<u64>() else {
        return simple_response(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let (parts, body) = request.into_parts();
    if declared_body_length_exceeds_post_limit(
        state.uplink_data_placement,
        &parts.headers,
        state.max_each_post_bytes,
    ) {
        return simple_response(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let header_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Header
    ) {
        match decode_chunked_header_payload(&parts.headers, &state.uplink_data_key) {
            Ok(payload) => payload,
            Err(_) => return simple_response(StatusCode::BAD_REQUEST),
        }
    } else {
        Vec::new()
    };
    let cookie_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Cookie
    ) {
        match decode_chunked_cookie_payload(&parts.headers, &state.uplink_data_key) {
            Ok(payload) => payload,
            Err(_) => return simple_response(StatusCode::BAD_REQUEST),
        }
    } else {
        Vec::new()
    };
    let body_payload = if matches!(
        state.uplink_data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) {
        match collect_body_limited(body, state.max_each_post_bytes.max(0) as usize)
            .await
        {
            Ok(payload) => payload,
            Err(status) => return simple_response(status),
        }
    } else {
        Vec::new()
    };

    let body_payload_is_empty = body_payload.is_empty();
    let payload = match state.uplink_data_placement {
        XhttpDataPlacement::Auto => {
            let mut payload = Vec::with_capacity(
                header_payload.len() + cookie_payload.len() + body_payload.len(),
            );
            payload.extend_from_slice(&header_payload);
            payload.extend_from_slice(&cookie_payload);
            payload.extend_from_slice(&body_payload);
            payload
        }
        XhttpDataPlacement::Body => body_payload,
        XhttpDataPlacement::Header => header_payload,
        XhttpDataPlacement::Cookie => cookie_payload,
    };
    if payload_exceeds_post_limit(payload.len(), state.max_each_post_bytes) {
        return simple_response(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let collected = Bytes::from(payload);

    let session = state.sessions.get_or_create(&session_id);
    match session.upload_queue.push_payload(seq, collected).await {
        Ok(()) => packet_up_success_response(body_payload_is_empty),
        Err(_) => simple_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn packet_up_success_response(
    body_payload_is_empty: bool,
) -> Response<ResponseBody> {
    let mut response = simple_response(StatusCode::OK);
    if body_payload_is_empty {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn wait_for_stream_up_response_start(
    session_closed: CancellationToken,
    padding_enabled: bool,
    min_padding: usize,
    max_padding: usize,
) -> Option<(CancellationToken, Bytes)> {
    if padding_enabled {
        let padding_len = random_xray_range(min_padding, max_padding);
        return Some((session_closed, Bytes::from(vec![b'X'; padding_len])));
    }

    session_closed.cancelled().await;
    None
}

async fn stream_up_response(
    session_closed: CancellationToken,
    state: &AppState,
    padding_enabled: bool,
) -> Response<ResponseBody> {
    let (min_secs, max_secs) = state.stream_up_server_secs;
    let padding_enabled = padding_enabled && max_secs > 0;

    let Some((session_closed, first_padding)) = wait_for_stream_up_response_start(
        session_closed,
        padding_enabled,
        state.min_padding,
        state.max_padding,
    )
    .await
    else {
        return stream_response(
            StatusCode::OK,
            futures::stream::empty::<Result<Frame<Bytes>, Infallible>>(),
            true,
        );
    };

    let min_padding = state.min_padding;
    let max_padding = state.max_padding;
    let shutdown = state.shutdown.clone();
    let body_stream = futures::stream::unfold(
        (session_closed, Some(first_padding)),
        move |(session_closed, first_padding)| {
            let shutdown = shutdown.clone();
            async move {
                if let Some(first_padding) = first_padding {
                    return Some((
                        Ok(Frame::data(first_padding)),
                        (session_closed, None),
                    ));
                }

                let delay_secs = random_xray_range(min_secs, max_secs);
                tokio::select! {
                    _ = session_closed.cancelled() => None,
                    _ = shutdown.cancelled() => None,
                    _ = sleep(Duration::from_secs(delay_secs as u64)) => {
                        let padding_len = random_xray_range(min_padding, max_padding);
                        Some((
                            Ok(Frame::data(Bytes::from(vec![b'X'; padding_len]))),
                            (session_closed, None),
                        ))
                    }
                }
            }
        },
    );

    stream_response(StatusCode::OK, body_stream, true)
}

fn spawn_handler_stream(
    stream: XhttpLogicalStream,
    state: Arc<AppState>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
) {
    let shutdown = state.shutdown.clone();
    let runtime = state.runtime.clone();
    let _ = runtime.spawn_inbound_connection(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            result = process_stream_with_sniffing_and_local_addr(
                stream,
                state.server_handler.clone(),
                state.resolver.clone(),
                peer_addr,
                Some(local_addr),
                state.runtime.clone(),
                state.sniffing.clone(),
            ) => {
                if let Err(err) = result {
                    error!("xhttp logical stream {} failed: {}", peer_addr, err);
                }
            }
        }
    });
}

fn reader_response(
    status: StatusCode,
    reader: DuplexStream,
    no_sse_header: bool,
) -> Response<ResponseBody> {
    let body_stream = ReaderStream::new(reader).filter_map(|result| async move {
        match result {
            Ok(bytes) => Some(Ok(Frame::data(bytes))),
            Err(err) => {
                error!("xhttp response read failed: {}", err);
                None
            }
        }
    });
    stream_response(status, body_stream.boxed(), no_sse_header)
}

fn stream_response<S>(
    status: StatusCode,
    body_stream: S,
    no_sse_header: bool,
) -> Response<ResponseBody>
where
    S: futures::Stream<Item = Result<Frame<Bytes>, Infallible>> + Send + 'static,
{
    let mut response = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-accel-buffering", "no");
    if !no_sse_header {
        response = response.header(header::CONTENT_TYPE, "text/event-stream");
    }
    response
        .body(BodyExt::boxed_unsync(StreamBody::new(body_stream)))
        .unwrap_or_else(|_| simple_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn simple_response(status: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .body(BodyExt::boxed_unsync(Empty::<Bytes>::new()))
        .unwrap()
}

fn normalize_base_path(
    mut path: String,
    session_placement: XhttpPlacement,
    seq_placement: XhttpPlacement,
) -> String {
    if let Some(query_index) = path.find('?') {
        path.truncate(query_index);
    }
    if path.is_empty() || !path.starts_with('/') {
        path.insert(0, '/');
    }
    if (session_placement == XhttpPlacement::Path
        || seq_placement == XhttpPlacement::Path)
        && !path.ends_with('/')
    {
        path.push('/');
    }
    path
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    for pair in query?.split('&') {
        // Go's url.ParseQuery rejects a value containing an unescaped semicolon
        // and URL.Query silently discards that malformed pair. Percent-encoded
        // semicolons remain valid data because the rejection happens first.
        if pair.contains(';') {
            continue;
        }
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(name) = decode_query_component(raw_name) else {
            continue;
        };
        if name != key {
            continue;
        }
        let Some(value) = decode_query_component(raw_value) else {
            continue;
        };
        return (!value.is_empty()).then_some(value);
    }
    None
}

fn decode_query_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn header_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn trusted_forwarded_peer(
    headers: &hyper::HeaderMap,
    trusted_x_forwarded_for: &[String],
) -> Option<std::net::SocketAddr> {
    if trusted_x_forwarded_for.is_empty()
        || !trusted_x_forwarded_for
            .iter()
            .any(|header| headers.contains_key(header))
    {
        return None;
    }

    let first = headers
        .get("x-forwarded-for")?
        .to_str()
        .ok()?
        .split(',')
        .next()?;
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

fn cookie_value(headers: &hyper::HeaderMap, key: &str) -> Option<String> {
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(header_value) = header_value.to_str() else {
            continue;
        };
        for cookie in header_value.split(';') {
            let Some((name, raw_value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name != key {
                continue;
            }
            let Some(value) = parse_cookie_value_like_go(raw_value) else {
                continue;
            };
            // Go's Request.Cookie returns the first successfully parsed cookie
            // with this name. An empty first value therefore means "missing"
            // to XHTTP and must not fall through to a later duplicate.
            return (!value.is_empty()).then_some(value);
        }
    }
    None
}

fn parse_cookie_value_like_go(raw: &str) -> Option<String> {
    let value = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(raw);
    if value.bytes().all(|byte| {
        (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b';' && byte != b'\\'
    }) {
        Some(value.to_string())
    } else {
        None
    }
}

fn has_uplink_marker(
    headers: &hyper::HeaderMap,
    placement: XhttpDataPlacement,
    key: &str,
) -> bool {
    match placement {
        XhttpDataPlacement::Header => {
            header_value(headers, &format!("{key}-Upstream")).as_deref() == Some("1")
        }
        XhttpDataPlacement::Cookie => {
            cookie_value(headers, &format!("{key}_upstream")).as_deref() == Some("1")
        }
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body => false,
    }
}

fn decode_chunked_header_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let header_name = format!("{key}-{index}");
        let Some(chunk) = header_value(headers, &header_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    decode_xhttp_payload(&encoded)
}

fn decode_chunked_cookie_payload(
    headers: &hyper::HeaderMap,
    key: &str,
) -> std::io::Result<Vec<u8>> {
    let mut encoded = String::new();
    for index in 0usize.. {
        let cookie_name = format!("{key}_{index}");
        let Some(chunk) = cookie_value(headers, &cookie_name) else {
            break;
        };
        encoded.push_str(&chunk);
    }
    decode_xhttp_payload(&encoded)
}

fn payload_exceeds_post_limit(payload_len: usize, max_bytes: i64) -> bool {
    i64::try_from(payload_len).unwrap_or(i64::MAX) > max_bytes
}

fn declared_body_length_exceeds_post_limit(
    data_placement: XhttpDataPlacement,
    headers: &hyper::HeaderMap,
    max_bytes: i64,
) -> bool {
    if !matches!(
        data_placement,
        XhttpDataPlacement::Auto | XhttpDataPlacement::Body
    ) {
        return false;
    }

    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| i128::from(length) > i128::from(max_bytes))
}

async fn collect_body_limited<B>(
    mut body: B,
    max_bytes: usize,
) -> Result<Vec<u8>, StatusCode>
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut payload = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(chunk) = frame.data_ref() {
            let next_len = payload.len().saturating_add(chunk.len());
            if next_len > max_bytes {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            payload.extend_from_slice(chunk);
        }
    }
    Ok(payload)
}

fn decode_xhttp_payload(encoded: &str) -> std::io::Result<Vec<u8>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid XHTTP uplink payload encoding: {error}"),
        )
    })
}

fn matches_base_path(request_path: &str, base_path: &str) -> bool {
    request_path.starts_with(base_path)
}

fn xray_path_metadata_value_for_placement(
    path_tail: &str,
    path_part: &mut usize,
    placement: XhttpPlacement,
) -> Option<String> {
    if placement != XhttpPlacement::Path {
        return None;
    }
    let value = xray_path_metadata_value(path_tail, *path_part);
    *path_part += 1;
    value
}

fn xray_path_metadata_value(path_tail: &str, index: usize) -> Option<String> {
    path_tail
        .split('/')
        .nth(index)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn decode_xray_url_path(raw_path: &str) -> Result<String, ()> {
    if !raw_path.as_bytes().contains(&b'%') {
        return Ok(raw_path.to_string());
    }

    let bytes = raw_path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let high = hex_value(bytes[index + 1]).ok_or(())?;
        let low = hex_value(bytes[index + 2]).ok_or(())?;
        decoded.push((high << 4) | low);
        index += 3;
    }

    String::from_utf8(decoded).or_else(|_| Ok(raw_path.to_string()))
}

fn extract_xray_request_padding(
    obfs_mode: bool,
    padding_key: &str,
    padding_header: &str,
    padding_placement: XhttpPaddingPlacement,
    path_query: Option<&str>,
    headers: &hyper::HeaderMap,
) -> Option<String> {
    if !obfs_mode {
        if let Some(referer) = header_value(headers, "referer") {
            // Xray v26.2.6 returns immediately when url.Parse succeeds, even
            // if Referer does not contain x_padding. Only a parse failure falls
            // through to the configurable cookie/header/query extraction below.
            if xray_url_parse_succeeds(&referer) {
                return query_value_from_url(&referer, "x_padding");
            }
        } else {
            return query_value(path_query, "x_padding");
        }
    }

    cookie_value(headers, padding_key)
        .or_else(|| {
            header_value(headers, padding_header).and_then(|value| {
                match padding_placement {
                    XhttpPaddingPlacement::Header => Some(value),
                    _ => query_value_from_url(&value, padding_key),
                }
            })
        })
        .or_else(|| query_value(path_query, padding_key))
}

fn xray_url_parse_succeeds(raw_url: &str) -> bool {
    let bytes = raw_url.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] < b' ' || bytes[index] == 0x7f {
            return false;
        }
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len()
            || hex_value(bytes[index + 1]).is_none()
            || hex_value(bytes[index + 2]).is_none()
        {
            return false;
        }
        index += 3;
    }
    true
}

fn query_value_from_url(raw_url: &str, key: &str) -> Option<String> {
    if !xray_url_parse_succeeds(raw_url) {
        return None;
    }
    let query = raw_url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    query_value(Some(query), key)
}

fn request_head_bytes<B>(request: &Request<B>) -> usize {
    // XHTTP's HTTP/1 paths use HTTP/1.0 or HTTP/1.1; both protocol tokens are
    // eight bytes long and count against Go net/http's MaxHeaderBytes budget.
    let request_line_bytes = request
        .method()
        .as_str()
        .len()
        .saturating_add(1)
        .saturating_add(request.uri().to_string().len())
        .saturating_add(1)
        .saturating_add(8)
        .saturating_add(2);

    request.headers().iter().fold(
        request_line_bytes.saturating_add(2),
        |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(2)
                .saturating_add(value.as_bytes().len())
                .saturating_add(2)
        },
    )
}

fn random_xray_range(from: usize, to: usize) -> usize {
    let low = from.min(to);
    let high = from.max(to);
    if low == high {
        low
    } else {
        // Xray's crypto.RandBetween swaps reversed bounds and samples [from, to).
        rand::rng().random_range(low..high)
    }
}

fn is_padding_valid(
    padding: &str,
    min_padding: usize,
    max_padding: usize,
    method: XhttpPaddingMethod,
) -> bool {
    if padding.is_empty() {
        return false;
    }

    match method {
        XhttpPaddingMethod::RepeatX => {
            padding.len() >= min_padding && padding.len() <= max_padding
        }
        XhttpPaddingMethod::Tokenish => {
            let encoded_len = hpack_huffman_encoded_len(padding);
            encoded_len >= min_padding.saturating_sub(2)
                && encoded_len <= max_padding.saturating_add(2)
        }
    }
}

fn generate_padding(method: XhttpPaddingMethod, target_len: usize) -> String {
    match method {
        XhttpPaddingMethod::RepeatX => "X".repeat(target_len),
        XhttpPaddingMethod::Tokenish => generate_tokenish_padding(target_len),
    }
}

fn generate_tokenish_padding(target_len: usize) -> String {
    const BASE62: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if target_len == 0 {
        return String::new();
    }

    let initial_len = target_len.saturating_mul(5).div_ceil(4).max(1);
    let mut rng = rand::rng();
    let mut padding = String::with_capacity(initial_len + 4);
    for _ in 0..initial_len {
        let index = rng.random_range(0..BASE62.len());
        padding.push(BASE62[index] as char);
    }
    drop(rng);

    let mut adjust_char = 'X';
    for _ in 0..150 {
        let current_len = hpack_huffman_encoded_len(&padding);
        if current_len.abs_diff(target_len) <= 2 {
            return padding;
        }
        if current_len < target_len {
            padding.push(adjust_char);
            adjust_char = if adjust_char == 'X' { 'Z' } else { 'X' };
        } else if padding.pop().is_none() {
            break;
        }
    }
    padding
}

fn hpack_huffman_encoded_len(value: &str) -> usize {
    let bits = value.bytes().fold(0usize, |total, byte| {
        total.saturating_add(hpack_huffman_bit_len(byte))
    });
    bits.div_ceil(8)
}

fn hpack_huffman_bit_len(byte: u8) -> usize {
    match byte {
        b'0' | b'1' | b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9'
        | b'A'
        | b'b'
        | b'd'
        | b'f'
        | b'g'
        | b'h'
        | b'l'
        | b'm'
        | b'n'
        | b'p'
        | b'r'
        | b'u' => 6,
        b'B'..=b'W' | b'Y' | b'j' | b'k' | b'q' | b'v'..=b'z' => 7,
        b'X' | b'Z' => 8,
        _ => 8,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XhttpRequestDispatch {
    StreamDown,
    StreamOne,
    StreamUp,
    PacketUp,
}

fn is_xray_uplink_request(method: &Method, has_seq: bool) -> bool {
    method != Method::GET || has_seq
}

fn classify_request(
    mode: XhttpMode,
    is_get: bool,
    is_uplink_method: bool,
    has_session_id: bool,
    has_seq: bool,
) -> Result<XhttpRequestDispatch, StatusCode> {
    if !has_session_id && mode == XhttpMode::PacketUp {
        return Err(StatusCode::BAD_REQUEST);
    }

    if is_uplink_method && has_session_id {
        if !has_seq {
            if !matches!(mode, XhttpMode::Auto | XhttpMode::StreamUp) {
                return Err(StatusCode::BAD_REQUEST);
            }
            return Ok(XhttpRequestDispatch::StreamUp);
        }

        if !matches!(mode, XhttpMode::Auto | XhttpMode::PacketUp) {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(XhttpRequestDispatch::PacketUp);
    }

    if is_get || !has_session_id {
        return Ok(if has_session_id {
            XhttpRequestDispatch::StreamDown
        } else {
            XhttpRequestDispatch::StreamOne
        });
    }

    Err(StatusCode::METHOD_NOT_ALLOWED)
}

fn apply_xray_cors_headers(
    headers: &mut hyper::HeaderMap,
    request_method: &Method,
    request_headers: &hyper::HeaderMap,
    allow_credentials: bool,
) {
    // Current Xray mirrors the browser request Origin when present because
    // wildcard origins cannot be combined with credentialed cookie requests.
    let allow_origin = request_headers
        .get(header::ORIGIN)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("*"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);

    if allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    if request_method == Method::OPTIONS {
        let allow_method = request_headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("*"));
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, allow_method);

        let allow_headers = request_headers
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("*"));
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers);
    }
}

fn apply_response_padding(headers: &mut hyper::HeaderMap, state: &AppState) {
    let padding_len = random_xray_range(state.min_padding, state.max_padding);
    apply_response_padding_value(
        headers,
        state.padding_obfs_mode,
        state.padding_placement,
        &state.padding_key,
        &state.padding_header,
        state.padding_method,
        padding_len,
    );
}

fn apply_response_padding_value(
    headers: &mut hyper::HeaderMap,
    padding_obfs_mode: bool,
    padding_placement: XhttpPaddingPlacement,
    padding_key: &str,
    padding_header: &str,
    padding_method: XhttpPaddingMethod,
    padding_len: usize,
) {
    if !padding_obfs_mode {
        if let Ok(value) =
            hyper::header::HeaderValue::from_str(&"X".repeat(padding_len))
        {
            headers.insert("x-padding", value);
        }
        return;
    }

    let padding = generate_padding(padding_method, padding_len);
    match padding_placement {
        XhttpPaddingPlacement::Cookie => {
            if !padding_key.is_empty()
                && !padding.is_empty()
                && let Ok(value) = hyper::header::HeaderValue::from_str(&format!(
                    "{padding_key}={padding}; Path=/"
                ))
            {
                headers.append(header::SET_COOKIE, value);
            }
        }
        // Current Xray has no response-side query padding representation.
        XhttpPaddingPlacement::Query => {}
        XhttpPaddingPlacement::Header => {
            if let Ok(name) =
                hyper::header::HeaderName::from_bytes(padding_header.as_bytes())
                && let Ok(value) = hyper::header::HeaderValue::from_str(&padding)
            {
                headers.insert(name, value);
            }
        }
        XhttpPaddingPlacement::QueryInHeader => {
            let value = format!("?{padding_key}={padding}");
            if let Ok(name) =
                hyper::header::HeaderName::from_bytes(padding_header.as_bytes())
                && let Ok(value) = hyper::header::HeaderValue::from_str(&value)
            {
                headers.insert(name, value);
            }
        }
    }
}

#[cfg(test)]
mod tests;
