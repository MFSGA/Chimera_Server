use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncWriteExt;
use tracing::warn;

mod decode;
mod grpc_transport;
mod http_transport;
mod protocol;
mod routing;
mod static_config;
mod wire;
mod xhttp_transport;

#[cfg(all(test, feature = "vless-reverse"))]
use decode::decode_vless_reverse_bridge;
#[cfg(feature = "vless-reverse")]
use decode::maybe_decode_vless_reverse_bridge;
#[cfg(feature = "api")]
pub(crate) use decode::validate_outbound_sender_settings;
use decode::{
    decode_freedom_proxy_protocol, decode_outbound_transport, decode_socks_outbound,
    decode_trojan_outbound, decode_vless_outbound,
};
use wire::*;

#[cfg(feature = "grpc_transport")]
use grpc_transport::connect_grpc_transport;
#[cfg(all(test, feature = "grpc_transport"))]
use grpc_transport::{grpc_initial_stream_window, grpc_keepalive_params};

#[cfg(feature = "httpupgrade")]
use http_transport::connect_httpupgrade_transport;
#[cfg(feature = "ws")]
use http_transport::connect_websocket_transport;
#[cfg(all(test, feature = "ws"))]
use http_transport::websocket_accept_value;

#[cfg(feature = "vless-reverse")]
use protocol::vless_reverse_connect;
use protocol::{
    TcpProtocolHandshake, TrojanCommand, build_trojan_request, socks5_connect,
    trojan_connect, vless_tcp_connect,
};
use xhttp_transport::connect_xhttp_stream_up_h2;

#[cfg(any(feature = "hysteria", feature = "tuic"))]
pub(crate) use routing::connection_routing_input;
#[cfg(feature = "tuic")]
pub(crate) use routing::select_direct_outbound;
#[cfg(feature = "hysteria")]
pub(crate) use routing::select_direct_outbound_with_policy_identities;
pub(crate) use routing::{
    DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
    USER_DOMAIN_ACCESS_BLACKHOLE_TAG, select_direct_outbound_for_location,
};
use routing::{TcpRoutePlan, plan_tcp_route};

#[cfg(all(test, feature = "grpc_transport"))]
use static_config::{StaticOutboundGrpcSettings, encode_static_grpc_config};
pub(crate) use static_config::{compile_static_outbound, parse_xray_uuid};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    beginning::build_proxy_protocol_header,
    resolver::{Resolver, resolve_single_address},
    routing_state::OutboundObservation,
    runtime::{DataPlaneRuntime, OutboundSummary},
    util::socket::new_tcp_socket,
};

#[cfg(feature = "trojan")]
use crate::handler::trojan_udp::TrojanUdpStream;
#[cfg(feature = "reality")]
use crate::reality::{
    RealityClientConfig, RealityClientConnection, RealityTlsStream,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksOutboundEndpoint {
    server: NetLocation,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VlessOutboundEndpoint {
    server: NetLocation,
    user_id: [u8; 16],
    flow: String,
}

#[cfg(feature = "vless-reverse")]
#[derive(Debug, Clone)]
pub(crate) struct VlessReverseBridgeEndpoint {
    pub(crate) server: NetLocation,
    pub(crate) user_id: [u8; 16],
    pub(crate) flow: String,
    pub(crate) reverse_tag: String,
    pub(crate) routing_user: String,
    pub(crate) policy_identity: String,
    pub(crate) user_level: u32,
    pub(crate) sniffing: Option<crate::config::server_config::InboundSniffingConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrojanOutboundEndpoint {
    server: NetLocation,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum OutboundTransport {
    #[default]
    Raw,
    Tls(OutboundTlsClientSettings),
    Websocket {
        tls: Option<OutboundTlsClientSettings>,
        settings: OutboundWebsocketClientSettings,
    },
    HttpUpgrade {
        tls: Option<OutboundTlsClientSettings>,
        settings: OutboundHttpUpgradeClientSettings,
    },
    Xhttp {
        tls: OutboundTlsClientSettings,
        settings: OutboundXhttpClientSettings,
    },
    #[cfg(feature = "grpc_transport")]
    Grpc {
        tls: Option<OutboundTlsClientSettings>,
        reality: Option<OutboundRealityClientSettings>,
        settings: OutboundGrpcClientSettings,
    },
    Reality(OutboundRealityClientSettings),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundWebsocketClientSettings {
    host: String,
    path: String,
    headers: HashMap<String, String>,
    ed: u32,
    heartbeat_period: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundHttpUpgradeClientSettings {
    host: String,
    path: String,
    headers: HashMap<String, String>,
    ed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutboundXhttpSessionPlacement {
    Path,
    Query(String),
    Header(String),
    Cookie(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundXhttpXmuxSettings {
    max_concurrency: Option<(i32, i32)>,
    max_connections: Option<(i32, i32)>,
    c_max_reuse_times: Option<(i32, i32)>,
    h_max_request_times: Option<(i32, i32)>,
    h_max_reusable_secs: Option<(i32, i32)>,
    h_keep_alive_period: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundXhttpClientSettings {
    host: String,
    path: String,
    headers: HashMap<String, String>,
    padding_from: i32,
    padding_to: i32,
    padding_obfs_mode: bool,
    padding_key: String,
    padding_header: String,
    padding_placement: crate::config::server_config::XhttpPaddingPlacement,
    padding_method: crate::config::server_config::XhttpPaddingMethod,
    no_grpc_header: bool,
    uplink_http_method: String,
    session_placement: OutboundXhttpSessionPlacement,
    xmux: Option<OutboundXhttpXmuxSettings>,
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundGrpcClientSettings {
    authority: String,
    service_name: String,
    multi_mode: bool,
    idle_timeout: i32,
    health_check_timeout: i32,
    permit_without_stream: bool,
    initial_windows_size: i32,
    user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundTlsClientSettings {
    server_name: String,
    alpn: Vec<String>,
    disable_system_root: bool,
    custom_root_certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundRealityClientSettings {
    public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
}

pub(crate) struct TcpOutboundConnection {
    pub stream: Box<dyn AsyncStream>,
    pub outbound_tag: Option<String>,
}

#[cfg(feature = "vless-reverse")]
pub(crate) fn prepare_vless_reverse_bridge(
    outbound: &OutboundSummary,
) -> std::io::Result<Option<VlessReverseBridgeEndpoint>> {
    if !outbound.protocol.trim().eq_ignore_ascii_case("vless") {
        return Ok(None);
    }
    let Some(endpoint) = maybe_decode_vless_reverse_bridge(outbound)? else {
        return Ok(None);
    };
    match decode_outbound_transport(outbound)? {
        OutboundTransport::Raw => Ok(Some(endpoint)),
        OutboundTransport::Tls(_) => {
            #[cfg(feature = "tls")]
            {
                Ok(Some(endpoint))
            }
            #[cfg(not(feature = "tls"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge TLS requires the tls feature",
                ))
            }
        }
        OutboundTransport::Websocket { tls, settings } => {
            if settings.ed != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge WebSocket early data is not implemented yet",
                ));
            }
            #[cfg(not(feature = "ws"))]
            {
                let _ = (tls, settings);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge WebSocket requires the ws feature",
                ));
            }
            #[cfg(feature = "ws")]
            if tls.is_some() && !cfg!(feature = "tls") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge WebSocket TLS requires the tls feature",
                ));
            }
            #[cfg(feature = "ws")]
            Ok(Some(endpoint))
        }
        OutboundTransport::Xhttp { .. } => {
            #[cfg(feature = "tls")]
            {
                Ok(Some(endpoint))
            }
            #[cfg(not(feature = "tls"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge XHTTP stream-up requires the tls feature",
                ))
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "VLESS Reverse Bridge outbound {} uses an unsupported transport/security combination",
                outbound.tag
            ),
        )),
    }
}

#[cfg(feature = "vless-reverse")]
pub(crate) async fn connect_vless_reverse_bridge(
    resolver: &Arc<dyn Resolver>,
    outbound: &OutboundSummary,
    endpoint: &VlessReverseBridgeEndpoint,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let transport = decode_outbound_transport(outbound)?;
    let target = resolve_single_address(resolver, &endpoint.server).await?;
    let socket = new_tcp_socket(None, target.is_ipv6())?;
    let raw_stream = socket.connect(target).await?;
    if let Err(error) = raw_stream.set_nodelay(true) {
        warn!("Failed to set TCP no-delay on Reverse Bridge socket: {error}");
    }

    let mut stream: Box<dyn AsyncStream> = match transport {
        OutboundTransport::Raw => Box::new(raw_stream),
        OutboundTransport::Tls(settings) => {
            #[cfg(feature = "tls")]
            {
                Box::new(
                    connect_tls_transport(raw_stream, &settings, &endpoint.server)
                        .await?,
                )
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (raw_stream, settings);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge TLS requires the tls feature",
                ));
            }
        }
        OutboundTransport::Websocket { tls, settings } => {
            if settings.ed != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge WebSocket early data is not implemented yet",
                ));
            }
            #[cfg(feature = "ws")]
            {
                let tls_server_name = tls
                    .as_ref()
                    .map(|settings| settings.server_name.trim())
                    .filter(|server_name| !server_name.is_empty())
                    .map(str::to_string);
                let base_stream: Box<dyn AsyncStream> = match tls {
                    None => Box::new(raw_stream),
                    Some(settings) => {
                        #[cfg(feature = "tls")]
                        {
                            Box::new(
                                connect_tls_transport(
                                    raw_stream,
                                    &settings,
                                    &endpoint.server,
                                )
                                .await?,
                            )
                        }
                        #[cfg(not(feature = "tls"))]
                        {
                            let _ = (raw_stream, settings);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "VLESS Reverse Bridge WebSocket TLS requires the tls feature",
                            ));
                        }
                    }
                };
                Box::new(
                    connect_websocket_transport(
                        base_stream,
                        &settings,
                        &endpoint.server,
                        tls_server_name.as_deref(),
                        None,
                    )
                    .await?,
                )
            }
            #[cfg(not(feature = "ws"))]
            {
                let _ = (raw_stream, tls, settings);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge WebSocket requires the ws feature",
                ));
            }
        }
        OutboundTransport::Xhttp { tls, settings } => {
            #[cfg(feature = "tls")]
            {
                let tls_server_name = (!tls.server_name.trim().is_empty())
                    .then_some(tls.server_name.trim().to_string());
                let base_stream =
                    connect_tls_transport(raw_stream, &tls, &endpoint.server)
                        .await?;
                Box::new(
                    connect_xhttp_stream_up_h2(
                        Box::new(base_stream),
                        &settings,
                        &endpoint.server,
                        tls_server_name.as_deref(),
                    )
                    .await?,
                )
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (raw_stream, tls, settings);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VLESS Reverse Bridge XHTTP stream-up requires the tls feature",
                ));
            }
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "VLESS Reverse Bridge outbound {} currently supports only RAW TCP or TLS",
                    outbound.tag
                ),
            ));
        }
    };
    vless_reverse_connect(&mut *stream, endpoint).await?;
    Ok(stream)
}

#[cfg(any(test, feature = "tuic"))]
pub(crate) async fn connect_tcp_outbound(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    connect_tcp_outbound_with_vless_route(
        resolver,
        remote_location,
        runtime,
        inbound_tag,
        user,
        source_addr,
        InboundRoutingMetadata::default(),
    )
    .await
}

#[cfg(any(test, feature = "hysteria"))]
pub(crate) async fn connect_tcp_outbound_with_vless_route(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    connect_tcp_outbound_with_routing_metadata(
        resolver,
        remote_location,
        runtime,
        inbound_tag,
        user,
        source_addr,
        routing_metadata,
    )
    .await
}

pub(crate) async fn connect_tcp_outbound_with_routing_metadata(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    let Some(plan) = plan_tcp_route(
        resolver,
        remote_location,
        runtime,
        inbound_tag,
        user,
        source_addr,
        routing_metadata,
    )
    .await?
    else {
        return Ok(None);
    };

    connect_planned_tcp_outbound(resolver, runtime, plan, true, TrojanCommand::Tcp)
        .await
        .map(Some)
}

async fn connect_planned_tcp_outbound(
    resolver: &Arc<dyn Resolver>,
    runtime: &DataPlaneRuntime,
    plan: TcpRoutePlan,
    record_observation: bool,
    trojan_command: TrojanCommand,
) -> std::io::Result<TcpOutboundConnection> {
    #[cfg(feature = "vless-reverse")]
    if let TcpRoutePlan::VlessReverse {
        target,
        outbound_tag,
        source_addr,
        local_addr,
    } = &plan
    {
        let stream = runtime.open_reverse_tcp(
            outbound_tag,
            target.clone(),
            *source_addr,
            *local_addr,
        )?;
        return Ok(TcpOutboundConnection {
            stream: Box::new(stream),
            outbound_tag: Some(outbound_tag.clone()),
        });
    }

    let freedom_proxy_protocol = match &plan {
        TcpRoutePlan::Freedom {
            source_addr,
            proxy_protocol,
            ..
        } if *proxy_protocol != 0 => Some((*proxy_protocol, *source_addr)),
        _ => None,
    };
    let (target_addr, outbound_tag, transport, transport_server, handshake) =
        match plan {
            TcpRoutePlan::Freedom {
                target_addr,
                outbound_tag,
                ..
            } => (
                target_addr,
                outbound_tag,
                OutboundTransport::Raw,
                None,
                TcpProtocolHandshake::None,
            ),
            TcpRoutePlan::Socks { target, outbound } => {
                let transport = decode_outbound_transport(&outbound)?;
                let endpoint = decode_socks_outbound(&outbound)?;
                let server = endpoint.server.clone();
                let server_addr = resolve_single_address(resolver, &server).await?;
                (
                    server_addr,
                    Some(outbound.tag),
                    transport,
                    Some(server),
                    TcpProtocolHandshake::Socks { target, endpoint },
                )
            }
            TcpRoutePlan::Vless { target, outbound } => {
                let transport = decode_outbound_transport(&outbound)?;
                let endpoint = decode_vless_outbound(&outbound)?;
                let server = endpoint.server.clone();
                let server_addr = resolve_single_address(resolver, &server).await?;
                (
                    server_addr,
                    Some(outbound.tag),
                    transport,
                    Some(server),
                    TcpProtocolHandshake::Vless { target, endpoint },
                )
            }
            #[cfg(feature = "vless-reverse")]
            TcpRoutePlan::VlessReverse { .. } => {
                unreachable!("Reverse route is handled before socket setup")
            }
            TcpRoutePlan::Trojan { target, outbound } => {
                let transport = decode_outbound_transport(&outbound)?;
                let endpoint = decode_trojan_outbound(&outbound)?;
                let server = endpoint.server.clone();
                let server_addr = resolve_single_address(resolver, &server).await?;
                (
                    server_addr,
                    Some(outbound.tag),
                    transport,
                    Some(server),
                    TcpProtocolHandshake::Trojan { target, endpoint },
                )
            }
        };
    let record = |observation| {
        if record_observation {
            record_tcp_connect_observation(
                runtime,
                outbound_tag.as_deref(),
                observation,
            );
        }
    };
    let websocket_early_data = match (&transport, &handshake) {
        (
            OutboundTransport::Websocket { settings, .. },
            TcpProtocolHandshake::Trojan { target, endpoint },
        ) if settings.ed > 0 => {
            let request = build_trojan_request(endpoint, target, trojan_command)?;
            (request.len() <= settings.ed as usize).then_some(request)
        }
        _ => None,
    };
    let httpupgrade_early_data = match (&transport, &handshake) {
        (
            OutboundTransport::HttpUpgrade { settings, .. },
            TcpProtocolHandshake::Trojan { target, endpoint },
        ) if settings.ed > 0 => {
            Some(build_trojan_request(endpoint, target, trojan_command)?)
        }
        _ => None,
    };
    let handshake_sent_as_early_data =
        websocket_early_data.is_some() || httpupgrade_early_data.is_some();

    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let started = Instant::now();
    let attempted_at = unix_time_secs();
    let mut raw_stream = match tcp_socket.connect(target_addr).await {
        Ok(stream) => stream,
        Err(error) => {
            record(tcp_connect_observation(
                false,
                elapsed_millis(started),
                attempted_at,
                error.to_string(),
            ));
            return Err(error);
        }
    };
    if let Err(error) = raw_stream.set_nodelay(true) {
        warn!("Failed to set TCP no-delay on client socket: {}", error);
    }
    if let Some((proxy_protocol, source_addr)) = freedom_proxy_protocol {
        let prefix = build_proxy_protocol_header(
            proxy_protocol as u8,
            source_addr,
            Some(target_addr),
        )?;
        raw_stream.write_all(&prefix).await?;
    }

    let mut stream: Box<dyn AsyncStream> = match transport {
        OutboundTransport::Raw => Box::new(raw_stream),
        OutboundTransport::Tls(settings) => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other("TLS outbound is missing its server identity")
            })?;
            #[cfg(feature = "tls")]
            {
                match connect_tls_transport(raw_stream, &settings, server).await {
                    Ok(stream) => Box::new(stream),
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (raw_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TLS outbound requires the tls feature",
                ));
            }
        }
        OutboundTransport::Websocket { tls, settings } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "WebSocket outbound is missing its server identity",
                )
            })?;
            #[cfg(feature = "ws")]
            let tls_server_name = tls
                .as_ref()
                .map(|settings| settings.server_name.trim())
                .filter(|server_name| !server_name.is_empty())
                .map(str::to_string);
            let base_stream: Box<dyn AsyncStream> = match tls {
                None => Box::new(raw_stream),
                Some(settings) => {
                    #[cfg(feature = "tls")]
                    {
                        match connect_tls_transport(raw_stream, &settings, server)
                            .await
                        {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "WebSocket TLS outbound requires the tls feature",
                        ));
                    }
                }
            };
            #[cfg(feature = "ws")]
            {
                match connect_websocket_transport(
                    base_stream,
                    &settings,
                    server,
                    tls_server_name.as_deref(),
                    websocket_early_data.as_deref(),
                )
                .await
                {
                    Ok(stream) => Box::new(stream),
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "ws"))]
            {
                let _ = (base_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "WebSocket outbound requires the ws feature",
                ));
            }
        }
        OutboundTransport::HttpUpgrade { tls, settings } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "HTTPUpgrade outbound is missing its server identity",
                )
            })?;
            #[cfg(feature = "httpupgrade")]
            let tls_server_name = tls
                .as_ref()
                .map(|settings| settings.server_name.trim())
                .filter(|server_name| !server_name.is_empty())
                .map(str::to_string);
            let base_stream: Box<dyn AsyncStream> = match tls {
                None => Box::new(raw_stream),
                Some(settings) => {
                    #[cfg(feature = "tls")]
                    {
                        match connect_tls_transport(raw_stream, &settings, server)
                            .await
                        {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "HTTPUpgrade TLS outbound requires the tls feature",
                        ));
                    }
                }
            };
            #[cfg(feature = "httpupgrade")]
            {
                match connect_httpupgrade_transport(
                    base_stream,
                    &settings,
                    server,
                    tls_server_name.as_deref(),
                    httpupgrade_early_data.as_deref(),
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "httpupgrade"))]
            {
                let _ = (base_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "HTTPUpgrade outbound requires the httpupgrade feature",
                ));
            }
        }
        OutboundTransport::Xhttp { tls, settings } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "XHTTP outbound is missing its server identity",
                )
            })?;
            #[cfg(feature = "tls")]
            {
                let tls_server_name = (!tls.server_name.trim().is_empty())
                    .then_some(tls.server_name.trim().to_string());
                let base_stream =
                    match connect_tls_transport(raw_stream, &tls, server).await {
                        Ok(stream) => Box::new(stream) as Box<dyn AsyncStream>,
                        Err(error) => {
                            record(tcp_connect_observation(
                                false,
                                elapsed_millis(started),
                                attempted_at,
                                error.to_string(),
                            ));
                            return Err(error);
                        }
                    };
                match connect_xhttp_stream_up_h2(
                    base_stream,
                    &settings,
                    server,
                    tls_server_name.as_deref(),
                )
                .await
                {
                    Ok(stream) => Box::new(stream),
                    Err(error) => {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (raw_stream, tls, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "XHTTP outbound currently requires the tls feature",
                ));
            }
        }
        #[cfg(feature = "grpc_transport")]
        OutboundTransport::Grpc {
            tls,
            reality,
            settings,
        } => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other("gRPC outbound is missing its server identity")
            })?;
            let tls_server_name = tls
                .as_ref()
                .map(|settings| settings.server_name.trim())
                .filter(|server_name| !server_name.is_empty())
                .map(str::to_string);
            let reality_transport = reality.is_some();
            let base_stream: Box<dyn AsyncStream> = match (tls, reality) {
                (None, None) => Box::new(raw_stream),
                (Some(settings), None) => {
                    #[cfg(feature = "tls")]
                    {
                        match connect_tls_transport(raw_stream, &settings, server)
                            .await
                        {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "gRPC TLS outbound requires the tls feature",
                        ));
                    }
                }
                (None, Some(settings)) => {
                    #[cfg(feature = "reality")]
                    {
                        match connect_reality_transport(
                            raw_stream, &settings, server,
                        ) {
                            Ok(stream) => Box::new(stream),
                            Err(error) => {
                                record(tcp_connect_observation(
                                    false,
                                    elapsed_millis(started),
                                    attempted_at,
                                    error.to_string(),
                                ));
                                return Err(error);
                            }
                        }
                    }
                    #[cfg(not(feature = "reality"))]
                    {
                        let _ = (raw_stream, settings, server);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "gRPC REALITY outbound requires the reality feature",
                        ));
                    }
                }
                (Some(_), Some(_)) => {
                    unreachable!("one Xray stream has one security type")
                }
            };
            match connect_grpc_transport(
                base_stream,
                &settings,
                server,
                tls_server_name.as_deref(),
                reality_transport,
            )
            .await
            {
                Ok(stream) => Box::new(stream),
                Err(error) => {
                    record(tcp_connect_observation(
                        false,
                        elapsed_millis(started),
                        attempted_at,
                        error.to_string(),
                    ));
                    return Err(error);
                }
            }
        }
        OutboundTransport::Reality(settings) => {
            let server = transport_server.as_ref().ok_or_else(|| {
                std::io::Error::other(
                    "REALITY outbound is missing its server identity",
                )
            })?;
            #[cfg(feature = "reality")]
            {
                connect_reality_transport(raw_stream, &settings, server)
                    .inspect_err(|error| {
                        record(tcp_connect_observation(
                            false,
                            elapsed_millis(started),
                            attempted_at,
                            error.to_string(),
                        ));
                    })
                    .map(|stream| Box::new(stream) as Box<dyn AsyncStream>)?
            }
            #[cfg(not(feature = "reality"))]
            {
                let _ = (raw_stream, settings, server);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "REALITY outbound requires the reality feature",
                ));
            }
        }
    };

    let handshake_result = match handshake {
        TcpProtocolHandshake::None => Ok(()),
        TcpProtocolHandshake::Socks { target, endpoint } => {
            socks5_connect(&mut *stream, &endpoint, &target).await
        }
        TcpProtocolHandshake::Vless { target, endpoint } => {
            vless_tcp_connect(&mut *stream, &endpoint, &target).await
        }
        TcpProtocolHandshake::Trojan { .. } if handshake_sent_as_early_data => {
            Ok(())
        }
        TcpProtocolHandshake::Trojan { target, endpoint } => {
            trojan_connect(&mut *stream, &endpoint, &target, trojan_command).await
        }
    };
    if let Err(error) = handshake_result {
        record(tcp_connect_observation(
            false,
            elapsed_millis(started),
            attempted_at,
            error.to_string(),
        ));
        return Err(error);
    }

    record(tcp_connect_observation(
        true,
        elapsed_millis(started),
        attempted_at,
        String::new(),
    ));
    Ok(TcpOutboundConnection {
        stream,
        outbound_tag,
    })
}

pub(crate) async fn connect_tcp_via_outbound(
    resolver: &Arc<dyn Resolver>,
    target: &NetLocation,
    runtime: &DataPlaneRuntime,
    outbound: &OutboundSummary,
) -> std::io::Result<TcpOutboundConnection> {
    let plan = match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => {
            let target_addr = resolve_single_address(resolver, target).await?;
            let source_addr = if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0u8; 4], 0))
            };
            TcpRoutePlan::Freedom {
                target_addr,
                outbound_tag: Some(outbound.tag.clone()),
                source_addr,
                proxy_protocol: decode_freedom_proxy_protocol(outbound)?,
            }
        }
        "socks" => TcpRoutePlan::Socks {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        "vless" => TcpRoutePlan::Vless {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        "trojan" => TcpRoutePlan::Trojan {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        "blackhole" => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("outbound {} is blackhole", outbound.tag),
            ));
        }
        protocol => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "outbound {} protocol {} has no TCP connector",
                    outbound.tag, protocol
                ),
            ));
        }
    };
    connect_planned_tcp_outbound(resolver, runtime, plan, false, TrojanCommand::Tcp)
        .await
}

#[cfg(feature = "trojan")]
pub(crate) async fn connect_trojan_udp_via_outbound(
    resolver: &Arc<dyn Resolver>,
    target: &NetLocation,
    runtime: &DataPlaneRuntime,
    outbound: &OutboundSummary,
) -> std::io::Result<TrojanUdpStream> {
    if !outbound.protocol.trim().eq_ignore_ascii_case("trojan") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "outbound {} protocol {} is not Trojan",
                outbound.tag, outbound.protocol
            ),
        ));
    }
    let connection = connect_planned_tcp_outbound(
        resolver,
        runtime,
        TcpRoutePlan::Trojan {
            target: target.clone(),
            outbound: outbound.clone(),
        },
        true,
        TrojanCommand::Udp,
    )
    .await?;
    Ok(TrojanUdpStream::new(connection.stream))
}

pub(crate) fn reqwest_proxy_for_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<Option<reqwest::Proxy>> {
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(None),
        "socks" => {
            let endpoint = decode_socks_outbound(outbound)?;
            let (address, port) = endpoint.server.components();
            let host = match address {
                Address::Ipv4(ip) => ip.to_string(),
                Address::Ipv6(ip) => format!("[{ip}]"),
                Address::Hostname(domain) => domain.clone(),
            };
            let mut proxy = reqwest::Proxy::all(format!("socks5h://{host}:{port}"))
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "invalid SOCKS proxy URL for {}: {error}",
                            outbound.tag
                        ),
                    )
                })?;
            if let Some(username) = endpoint.username.as_deref() {
                proxy = proxy.basic_auth(
                    username,
                    endpoint.password.as_deref().unwrap_or_default(),
                );
            }
            Ok(Some(proxy))
        }
        protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "outbound {} protocol {} cannot be used as an HTTP probe transport",
                outbound.tag, protocol
            ),
        )),
    }
}

#[cfg(feature = "reality")]
fn connect_reality_transport(
    stream: tokio::net::TcpStream,
    settings: &OutboundRealityClientSettings,
    server: &NetLocation,
) -> std::io::Result<RealityTlsStream<tokio::net::TcpStream, RealityClientConnection>>
{
    let server_name = if settings.server_name.trim().is_empty() {
        match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => ip.to_string(),
        }
    } else {
        settings.server_name.trim().to_string()
    };
    let session = RealityClientConnection::new(RealityClientConfig {
        public_key: settings.public_key,
        short_id: settings.short_id,
        server_name,
        cipher_suites: Vec::new(),
    })?;
    Ok(RealityTlsStream::new(stream, session))
}

#[cfg(feature = "tls")]
async fn connect_tls_transport(
    stream: tokio::net::TcpStream,
    settings: &OutboundTlsClientSettings,
    server: &NetLocation,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut added_roots = 0usize;
    if !settings.disable_system_root {
        let native = rustls_native_certs::load_native_certs();
        let (added, _) = roots.add_parsable_certificates(native.certs);
        added_roots += added;
    }
    for certificate in &settings.custom_root_certificates {
        let mut cursor = std::io::Cursor::new(certificate.as_slice());
        let pem_certificates = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid outbound TLS CA certificate: {error}"),
                )
            })?;
        if pem_certificates.is_empty() {
            roots
                .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid outbound TLS CA certificate: {error}"),
                    )
                })?;
            added_roots += 1;
        } else {
            for certificate in pem_certificates {
                roots.add(certificate).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid outbound TLS CA certificate: {error}"),
                    )
                })?;
                added_roots += 1;
            }
        }
    }
    if added_roots == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no CA certificates were available for outbound TLS",
        ));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = settings
        .alpn
        .iter()
        .filter(|protocol| !protocol.is_empty())
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = if settings.server_name.trim().is_empty() {
        match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => ip.to_string(),
        }
    } else {
        settings.server_name.trim().to_string()
    };
    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid outbound TLS serverName {server_name}: {error}"),
        )
    })?;
    connector.connect(server_name, stream).await
}

fn elapsed_millis(started: Instant) -> i64 {
    started.elapsed().as_millis().min(i64::MAX as u128) as i64
}

fn tcp_connect_observation(
    alive: bool,
    delay_ms: i64,
    attempted_at: i64,
    last_error_reason: String,
) -> OutboundObservation {
    OutboundObservation {
        alive,
        delay_ms,
        last_error_reason,
        last_seen_time: if alive { attempted_at } else { 0 },
        last_try_time: attempted_at,
        ..OutboundObservation::default()
    }
}

fn record_tcp_connect_observation(
    runtime: &DataPlaneRuntime,
    outbound_tag: Option<&str>,
    observation: OutboundObservation,
) {
    if let Some(tag) = outbound_tag {
        runtime.record_passive_outbound_observation(tag, observation);
    }
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests;
