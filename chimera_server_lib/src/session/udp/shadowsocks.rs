use std::{net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, time::timeout};
use tracing::{debug, error};

#[cfg(feature = "trojan")]
use crate::outbound::connect_trojan_udp_via_outbound;
use crate::{
    address::NetLocation,
    handler::shadowsocks::ShadowsocksUdpCodec,
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{TrafficContext, record_transfer, record_transfer_ref},
};

#[cfg(feature = "trojan")]
use super::shutdown_targeted_message;
use super::{UDP_BUFFER_SIZE, UDP_SESSION_IDLE_TIMEOUT};

#[cfg(feature = "shadowsocks")]
pub(crate) async fn run_shadowsocks_udp_server(
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
pub(crate) async fn relay_shadowsocks_udp_packet(
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
        DirectOutboundAction::Freedom { tag, .. } => {
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
        #[cfg(feature = "vless-reverse")]
        DirectOutboundAction::VlessReverse { tag } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS Reverse outbound {tag} is TCP-only"),
        )),
    }
}
