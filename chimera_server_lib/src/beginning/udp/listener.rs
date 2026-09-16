use std::{net::SocketAddr, sync::Arc};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(feature = "shadowsocks")]
use tokio::time::timeout;
use tokio::{net::UdpSocket, task::JoinHandle};
#[cfg(feature = "shadowsocks")]
use tracing::debug;
use tracing::{error, info};

#[cfg(target_os = "linux")]
use crate::util::socket::enable_udp_original_destination;
use crate::util::socket::new_socket2_udp_socket;
#[cfg(feature = "shadowsocks")]
use crate::{
    handler::shadowsocks::ShadowsocksUdpCodec,
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
};

#[cfg(all(feature = "shadowsocks", feature = "trojan"))]
use crate::outbound::connect_trojan_udp_via_outbound;

#[cfg(feature = "shadowsocks")]
use crate::resolver::Resolver;
use crate::{
    address::BindLocation,
    config::server_config::{ServerConfig, ServerProxyConfig, TcpSocketPolicy},
    resolver::resolve_single_address,
    runtime::DataPlaneRuntime,
};
#[cfg(feature = "shadowsocks")]
use crate::{
    address::NetLocation,
    traffic::{TrafficContext, record_transfer, record_transfer_ref},
};

#[cfg(all(feature = "shadowsocks", feature = "trojan"))]
use super::targeted_session::shutdown_targeted_message;
#[cfg(feature = "shadowsocks")]
use super::{UDP_BUFFER_SIZE, UDP_SESSION_IDLE_TIMEOUT};

pub(super) use super::dokodemo::run_dokodemo_udp_server;
#[cfg(test)]
pub(super) use super::dokodemo::{UdpOutboundAction, select_udp_outbound};

pub async fn start_udp_server(
    config: ServerConfig,
    runtime: DataPlaneRuntime,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        tcp_socket_policy,
        ..
    } = config;

    let dokodemo_config = match protocol {
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, identity } => {
            return start_shadowsocks_udp_server(
                bind_location,
                tag,
                users,
                identity,
                tcp_socket_policy,
                runtime.clone(),
            )
            .await;
        }
        ServerProxyConfig::DokodemoDoor { config } => config,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport=udp supports dokodemo-door and shadowsocks in this stage (got {other})"
                ),
            ));
        }
    };

    #[cfg(not(target_os = "linux"))]
    if dokodemo_config.follow_redirect {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dokodemo-door UDP followRedirect is supported only on Linux",
        ));
    }

    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let target_addr = if dokodemo_config.follow_redirect {
        None
    } else {
        let resolver = runtime.resolver();
        Some(resolve_single_address(&resolver, &dokodemo_config.target).await?)
    };

    if dokodemo_config.follow_redirect {
        info!(
            "Starting DokodemoDoor UDP server at {} with followRedirect",
            bind_location
        );
    } else {
        info!(
            "Starting DokodemoDoor UDP server at {} forwarding to {}",
            bind_location, dokodemo_config.target
        );
    }

    let socket = create_udp_listener(
        bind_addr,
        tcp_socket_policy.as_ref(),
        dokodemo_config.follow_redirect,
    )?;
    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_dokodemo_udp_server(
            socket,
            dokodemo_config,
            target_addr,
            tag,
            runtime,
        )
        .await
        {
            error!("UDP server stopped with error: {}", err);
        }
    })))
}

pub(crate) fn bind_location_to_socket_addr(
    bind_location: &BindLocation,
) -> std::io::Result<SocketAddr> {
    match bind_location {
        BindLocation::Address(location) => location.to_socket_addr(),
    }
}

pub(crate) fn create_udp_listener(
    bind_addr: SocketAddr,
    policy: Option<&TcpSocketPolicy>,
    force_original_destination: bool,
) -> std::io::Result<Arc<UdpSocket>> {
    let bind_interface = policy.and_then(|policy| policy.bind_interface.clone());
    let socket =
        new_socket2_udp_socket(bind_addr.is_ipv6(), bind_interface, None, true)?;

    if policy.is_some_and(|policy| policy.ipv6_only) {
        if !bind_addr.is_ipv6() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sockopt.v6only requires an IPv6 UDP listener",
            ));
        }
        socket.set_only_v6(true)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(policy) = policy {
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
    if policy.is_some_and(|policy| {
        policy.mark.is_some()
            || policy.transparent
            || !policy.custom_sockopt.is_empty()
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "configured inbound UDP listener socket options are unsupported on this platform",
        ));
    }

    let receive_original_destination = force_original_destination
        || policy.is_some_and(|policy| policy.receive_original_destination);
    if receive_original_destination {
        #[cfg(target_os = "linux")]
        enable_udp_original_destination(&socket, bind_addr.is_ipv6())?;
        #[cfg(not(target_os = "linux"))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP original destination is supported only on Linux",
        ));
    }

    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(Arc::new(UdpSocket::from_std(socket)?))
}

#[cfg(feature = "shadowsocks")]
async fn start_shadowsocks_udp_server(
    bind_location: BindLocation,
    inbound_tag: String,
    users: Vec<crate::config::server_config::ShadowsocksUser>,
    identity: Option<crate::config::server_config::ShadowsocksServerIdentity>,
    socket_policy: Option<TcpSocketPolicy>,
    runtime: DataPlaneRuntime,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let socket = create_udp_listener(bind_addr, socket_policy.as_ref(), false)?;
    let codec = Arc::new(ShadowsocksUdpCodec::new(users, identity)?);
    info!("Starting Shadowsocks UDP server at {}", bind_location);

    Ok(Some(tokio::spawn(run_shadowsocks_udp_server(
        socket,
        codec,
        inbound_tag,
        runtime,
    ))))
}

#[cfg(feature = "shadowsocks")]
pub(super) async fn run_shadowsocks_udp_server(
    socket: Arc<UdpSocket>,
    codec: Arc<ShadowsocksUdpCodec>,
    inbound_tag: String,
    runtime: DataPlaneRuntime,
) {
    let runtime_users = runtime.shadowsocks_user_store(&inbound_tag);
    let resolver = runtime.resolver();
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
    loop {
        let (len, client_addr) = match socket.recv_from(&mut buffer).await {
            Ok(value) => value,
            Err(error) => {
                error!("Shadowsocks UDP receive failed: {error}");
                break;
            }
        };
        let packet = buffer[..len].to_vec();
        let socket = socket.clone();
        let codec = runtime_users
            .as_ref()
            .map(|store| Arc::new(store.udp_codec(codec.as_ref())))
            .unwrap_or_else(|| codec.clone());
        let task_runtime = runtime.clone();
        let resolver = resolver.clone();
        let inbound_tag = inbound_tag.clone();
        runtime.spawn_inbound_connection(async move {
            if let Err(error) = relay_shadowsocks_udp_packet(
                socket,
                codec,
                resolver,
                task_runtime,
                inbound_tag,
                client_addr,
                packet,
            )
            .await
            {
                debug!(
                    "Shadowsocks UDP packet from {} failed: {}",
                    client_addr, error
                );
            }
        });
    }
}

#[cfg(feature = "shadowsocks")]
pub(super) async fn relay_shadowsocks_udp_packet(
    server_socket: Arc<UdpSocket>,
    codec: Arc<ShadowsocksUdpCodec>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    inbound_tag: String,
    client_addr: SocketAddr,
    packet: Vec<u8>,
) -> std::io::Result<()> {
    let request = codec.decrypt_packet(&packet)?;
    let (outbound_action, target_addr) = select_direct_outbound_for_location(
        &resolver,
        &request.target_location,
        &runtime,
        OutboundRoutingContext::new(
            &inbound_tag,
            &request.identity,
            client_addr,
            3,
            "udp",
            InboundRoutingMetadata {
                local_addr: server_socket.local_addr().ok(),
                inbound_protocol: Some("shadowsocks".to_string()),
                ..InboundRoutingMetadata::default()
            },
        ),
    )
    .await?;
    let mut traffic_context = TrafficContext::new("shadowsocks")
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_addr.ip())
        .with_user_level(request.user_level);
    if !request.identity.is_empty() {
        traffic_context = traffic_context.with_identity(request.identity.clone());
    }
    runtime.apply_traffic_stats_policy(&mut traffic_context);

    match outbound_action {
        DirectOutboundAction::Blackhole { tag } => {
            traffic_context = traffic_context.with_outbound_tag(tag);
            record_transfer(Some(traffic_context), request.payload.len() as u64, 0);
            Ok(())
        }
        DirectOutboundAction::Freedom { tag } => {
            if let Some(tag) = tag {
                traffic_context = traffic_context.with_outbound_tag(tag);
            }
            let target_addr = target_addr.ok_or_else(|| {
                std::io::Error::other(
                    "Shadowsocks UDP freedom route did not resolve target",
                )
            })?;
            let bind_addr = if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let outbound = UdpSocket::bind(bind_addr).await?;
            let sent = outbound.send_to(&request.payload, target_addr).await?;
            record_transfer_ref(Some(&traffic_context), sent as u64, 0);

            let mut response = vec![0u8; UDP_BUFFER_SIZE];
            let (response_len, response_addr) =
                timeout(UDP_SESSION_IDLE_TIMEOUT, outbound.recv_from(&mut response))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Shadowsocks UDP response timed out",
                        )
                    })??;
            let source =
                NetLocation::from_ip_addr(response_addr.ip(), response_addr.port());
            let encrypted = codec.encrypt_packet(
                &request,
                &source,
                &response[..response_len],
            )?;
            server_socket.send_to(&encrypted, client_addr).await?;
            record_transfer(Some(traffic_context), 0, response_len as u64);
            Ok(())
        }
        DirectOutboundAction::Trojan { outbound } => {
            #[cfg(feature = "trojan")]
            {
                traffic_context =
                    traffic_context.with_outbound_tag(outbound.tag.clone());
                let mut proxy = connect_trojan_udp_via_outbound(
                    &resolver,
                    &request.target_location,
                    &runtime,
                    &outbound,
                )
                .await?;
                proxy
                    .send_to(&request.target_location, &request.payload)
                    .await?;
                record_transfer_ref(
                    Some(&traffic_context),
                    request.payload.len() as u64,
                    0,
                );

                let mut response = vec![0u8; UDP_BUFFER_SIZE];
                let (source, response_len) = timeout(
                    UDP_SESSION_IDLE_TIMEOUT,
                    proxy.recv_from(&mut response),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Shadowsocks Trojan UDP response timed out",
                    )
                })??;
                let encrypted = codec.encrypt_packet(
                    &request,
                    &source,
                    &response[..response_len],
                )?;
                server_socket.send_to(&encrypted, client_addr).await?;
                record_transfer(Some(traffic_context), 0, response_len as u64);
                let _ = shutdown_targeted_message(&mut proxy).await;
                Ok(())
            }
            #[cfg(not(feature = "trojan"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "Trojan outbound {} requires the trojan feature",
                        outbound.tag
                    ),
                ))
            }
        }
        DirectOutboundAction::Socks { outbound }
        | DirectOutboundAction::Vless { outbound } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("TCP proxy outbound {} cannot be used for UDP", outbound.tag),
        )),
    }
}
