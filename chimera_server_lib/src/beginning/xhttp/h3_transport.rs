use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::{
    Request, Response,
    body::{Body, Frame},
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::debug;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(feature = "hysteria")]
use std::sync::atomic::AtomicU64;

use crate::{
    config::server_config::{TcpSocketPolicy, XhttpServerConfig},
    runtime::DataPlaneRuntime,
};

use super::{AppState, ResponseBody, handle_request};

pub(super) type H3BidiRequestStream =
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub(super) type H3SendRequestStream =
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
pub(super) struct H3RequestBody {
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
pub(super) fn split_h3_request_stream(
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

#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_INITIAL_MTU: u16 = 1280;
#[cfg(feature = "tls")]
const XRAY_XHTTP_H3_MAX_FIELD_SECTION_SIZE: u64 = 1 << 20;
#[cfg(feature = "tls")]
pub(super) const XRAY_XHTTP_H3_BBR_INITIAL_WINDOW: u64 =
    32 * XRAY_XHTTP_H3_INITIAL_MTU as u64;
#[cfg(feature = "tls")]
pub(super) const XRAY_XHTTP_H3_INITIAL_STREAM_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024;
#[cfg(feature = "tls")]
pub(super) const XRAY_XHTTP_H3_INITIAL_CONNECTION_RECEIVE_WINDOW: u64 =
    3 * 1024 * 1024;

#[cfg(feature = "tls")]
pub(super) fn apply_xray_xhttp_h3_initial_mtu(
    transport: &mut quinn::TransportConfig,
) {
    // Current Xray uses quic-go's 1280-byte InitialPacketSize for XHTTP/3.
    transport.initial_mtu(XRAY_XHTTP_H3_INITIAL_MTU);
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum XhttpH3CongestionMode {
    Reno,
    Bbr,
    ForceBrutal,
}

#[cfg(feature = "tls")]
pub(super) fn configured_xhttp_h3_congestion_mode(
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
pub(super) fn build_xhttp_h3_transport_config(
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
pub(super) fn configured_xhttp_receive_window(
    value: Option<u64>,
    xray_default: u64,
) -> std::io::Result<quinn::VarInt> {
    let value = value.filter(|value| *value != 0).unwrap_or(xray_default);
    quinn::VarInt::from_u64(value)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
}

#[cfg(feature = "tls")]
pub(super) async fn start_xhttp_h3_server(
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
            let incoming = match super::super::accept_quic_with_health(
                &endpoint,
                "xhttp-http3",
            )
            .await
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
pub(super) fn spawn_xhttp_h3_connection<F>(
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
pub(super) fn xhttp_h3_connection_local_addr(
    listener_addr: std::net::SocketAddr,
    local_ip: Option<std::net::IpAddr>,
) -> std::net::SocketAddr {
    local_ip
        .map(|local_ip| std::net::SocketAddr::new(local_ip, listener_addr.port()))
        .unwrap_or(listener_addr)
}
