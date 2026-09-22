use std::{collections::HashMap, net::SocketAddr, sync::Arc};

#[cfg(all(test, feature = "traffic"))]
use tokio::time::{MissedTickBehavior, interval};
use tokio::{io::AsyncReadExt, sync::Notify};

#[cfg(all(test, feature = "traffic"))]
use crate::config::server_config::SocksUserStore;
use crate::{
    async_stream::AsyncStream,
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{TrafficContext, record_transfer, register_connection},
};

#[cfg(all(test, feature = "traffic"))]
use super::UDP_TARGET_SESSION_ACTIVITY_CHECK;
use super::{MAX_UDP_DATAGRAM_SIZE, XRAY_SOCKS_UDP_PACKET_SIZE, parse_udp_address};

mod target_sessions;

#[cfg(test)]
pub(super) use target_sessions::XrayUdpActivityWindow;
#[cfg(test)]
pub(super) use target_sessions::prune_closed_udp_sessions;
use target_sessions::stop_udp_client_sessions;
#[cfg(feature = "trojan")]
use target_sessions::{
    SocksTrojanUdpClientSession, SocksTrojanUdpSessionStart,
    send_trojan_udp_target_payload, stop_trojan_udp_client_sessions,
};
pub(super) use target_sessions::{SocksUdpClientSession, send_udp_target_payload};

#[cfg(all(test, feature = "traffic"))]
pub(crate) async fn run_shared_udp_relay(
    udp_socket: Arc<tokio::net::UdpSocket>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    accounts: SocksUserStore,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let mut recv_buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    let mut client_sessions =
        HashMap::<(SocketAddr, bool), SocksUdpClientSession>::new();
    #[cfg(feature = "trojan")]
    let mut trojan_sessions =
        HashMap::<(SocketAddr, String), SocksTrojanUdpClientSession>::new();
    let mut session_cleanup = interval(UDP_TARGET_SESSION_ACTIVITY_CHECK);
    session_cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
    session_cleanup.tick().await;

    loop {
        let (len, client_addr) = tokio::select! {
            result = udp_socket.recv_from(&mut recv_buf) => result?,
            _ = session_cleanup.tick() => {
                prune_closed_udp_sessions(&mut client_sessions);
                #[cfg(feature = "trojan")]
                trojan_sessions.retain(|_, session| !session.sender.is_closed());
                continue;
            }
        };
        if accounts.auth_required()
            && !accounts.is_udp_ip_authorized(client_addr.ip())
        {
            tracing::debug!(
                "SOCKS5 shared UDP listener ignored unauthorized source {}",
                client_addr
            );
            continue;
        }

        // Winsock returns WSAEMSGSIZE instead of truncating an oversized UDP
        // datagram. Receive it in full, then apply Xray's 8 KiB buffer limit.
        let data = &recv_buf[..len.min(XRAY_SOCKS_UDP_PACKET_SIZE)];
        if data.len() < 4 || data[2] != 0 {
            continue;
        }
        let (target_location, payload_offset) = match parse_udp_address(data, 3) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let payload = &data[payload_offset..];
        if payload.is_empty() {
            continue;
        }
        let mut datagram_context = traffic_context
            .clone()
            .map(|context| context.with_client_ip(client_addr.ip()));
        let inbound_tag = datagram_context
            .as_ref()
            .and_then(|context| context.inbound_tag.as_deref())
            .unwrap_or_default();
        let identity = datagram_context
            .as_ref()
            .and_then(|context| context.identity.as_deref())
            .unwrap_or_default();
        let (action, target_addr) = select_direct_outbound_for_location(
            &resolver,
            &target_location,
            &runtime,
            OutboundRoutingContext::new(
                inbound_tag,
                identity,
                client_addr,
                3,
                "udp",
                InboundRoutingMetadata {
                    local_addr: udp_socket.local_addr().ok(),
                    inbound_protocol: datagram_context
                        .as_ref()
                        .map(|context| context.protocol.to_string()),
                    ..InboundRoutingMetadata::default()
                },
            ),
        )
        .await?;
        match action {
            DirectOutboundAction::Blackhole { tag } => {
                datagram_context = datagram_context
                    .map(|context| context.with_outbound_tag(tag.clone()));
                record_transfer(datagram_context, payload.len() as u64, 0);
                continue;
            }
            DirectOutboundAction::Freedom { tag: Some(tag) } => {
                datagram_context =
                    datagram_context.map(|context| context.with_outbound_tag(tag));
            }
            DirectOutboundAction::Freedom { tag: None } => {}
            DirectOutboundAction::Trojan { outbound } => {
                #[cfg(feature = "trojan")]
                {
                    datagram_context = datagram_context.map(|context| {
                        context.with_outbound_tag(outbound.tag.clone())
                    });
                    if let Err(error) = send_trojan_udp_target_payload(
                        &mut trojan_sessions,
                        target_location.clone(),
                        payload.to_vec(),
                        datagram_context,
                        SocksTrojanUdpSessionStart {
                            outbound,
                            resolver: resolver.clone(),
                            runtime: runtime.clone(),
                            client_endpoint: client_addr,
                            client_socket: udp_socket.clone(),
                            association_activity: None,
                        },
                    )
                    .await
                    {
                        tracing::warn!(
                            "SOCKS5 shared Trojan UDP forwarding failed: {}",
                            error
                        );
                    }
                    continue;
                }
                #[cfg(not(feature = "trojan"))]
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!(
                            "Trojan outbound {} requires the trojan feature",
                            outbound.tag
                        ),
                    ));
                }
            }
            DirectOutboundAction::Socks { outbound }
            | DirectOutboundAction::Vless { outbound } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "TCP proxy outbound {} cannot be used for UDP",
                        outbound.tag
                    ),
                ));
            }
            #[cfg(feature = "vless-reverse")]
            DirectOutboundAction::VlessReverse { tag } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("VLESS Reverse outbound {tag} is TCP-only"),
                ));
            }
        }
        let target_addr = target_addr.ok_or_else(|| {
            std::io::Error::other(
                "SOCKS5 shared UDP freedom route did not resolve target",
            )
        })?;
        if let Err(error) = send_udp_target_payload(
            &mut client_sessions,
            target_addr,
            client_addr,
            udp_socket.clone(),
            None,
            payload.to_vec(),
            datagram_context,
        )
        .await
        {
            tracing::warn!("SOCKS5 shared UDP forwarding failed: {}", error);
        }
    }
}

#[cfg(all(test, feature = "traffic"))]
pub(crate) async fn run_udp_relay(
    udp_socket: Arc<tokio::net::UdpSocket>,
    tcp_stream: Box<dyn AsyncStream>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    tcp_peer_addr: SocketAddr,
    restrict_client_ip_to_tcp_peer: bool,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let expected_client = restrict_client_ip_to_tcp_peer
        .then_some(SocketAddr::new(tcp_peer_addr.ip(), 0));
    run_udp_relay_with_expected_client(
        udp_socket,
        tcp_stream,
        resolver,
        runtime,
        expected_client,
        0,
        traffic_context,
    )
    .await
}

pub(crate) async fn run_udp_relay_with_expected_client(
    udp_socket: Arc<tokio::net::UdpSocket>,
    mut tcp_stream: Box<dyn AsyncStream>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    mut expected_client: Option<SocketAddr>,
    user_level: u32,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let udp_socket_clone = udp_socket.clone();
    let _connection_guard = register_connection(traffic_context.as_ref());
    let association_idle_timeout =
        runtime.xray_connection_idle_timeout_for_level(user_level);
    if association_idle_timeout.is_zero() {
        tracing::debug!("SOCKS5 UDP relay: zero Xray connIdle, terminating");
        return Ok(());
    }

    let mut tcp_monitor = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match tcp_stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    });

    // Xray v26.2.6 reads SOCKS UDP packets through an 8 KiB buf.Buffer.
    // Oversized datagrams are truncated to that packet size before decoding.
    let mut recv_buf = vec![0u8; MAX_UDP_DATAGRAM_SIZE];
    // Xray v26.2.6 full-cone UDP reuses an outbound mapping for different
    // targets from one client endpoint. Keep one socket per IP family so a
    // first IPv4 target cannot make a later IPv6 target unusable (or vice versa).
    let mut client_sessions =
        HashMap::<(SocketAddr, bool), SocksUdpClientSession>::new();
    #[cfg(feature = "trojan")]
    let mut trojan_sessions =
        HashMap::<(SocketAddr, String), SocksTrojanUdpClientSession>::new();
    let association_activity = Arc::new(Notify::new());
    let association_idle = tokio::time::sleep(association_idle_timeout);
    tokio::pin!(association_idle);
    let mut association_active = true;
    let mut tcp_monitor_finished = false;
    let result = loop {
        let (len, client_addr) = tokio::select! {
            _ = &mut tcp_monitor => {
                tcp_monitor_finished = true;
                tracing::debug!("SOCKS5 UDP relay: TCP connection closed, terminating");
                break Ok(());
            }
            _ = association_activity.notified() => {
                association_active = true;
                continue;
            }
            _ = &mut association_idle => {
                if association_active {
                    association_active = false;
                    association_idle
                        .as_mut()
                        .reset(tokio::time::Instant::now() + association_idle_timeout);
                    continue;
                }
                tracing::debug!("SOCKS5 UDP relay: association idle timeout, terminating");
                break Ok(());
            }
            result = udp_socket_clone.recv_from(&mut recv_buf) => {
                match result {
                    Ok(result) => result,
                    Err(error) => break Err(error),
                }
            }
        };

        if let Some(expected) = expected_client {
            if client_addr.ip() != expected.ip()
                || (expected.port() != 0 && client_addr.port() != expected.port())
            {
                tracing::warn!(
                    "SOCKS5 UDP relay ignored datagram from {}; expected source {}",
                    client_addr,
                    expected
                );
                continue;
            }
            if expected.port() == 0 {
                expected_client = Some(client_addr);
            }
        }
        association_active = true;
        let response_endpoint = client_addr;
        // Apply Xray's packet limit explicitly so Windows and Unix truncate
        // oversized datagrams identically.
        let data = &recv_buf[..len.min(XRAY_SOCKS_UDP_PACKET_SIZE)];

        // Parse SOCKS5 UDP request header: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT(2)
        if data.len() < 4 {
            continue;
        }

        let _rsv = &data[0..2];
        let frag = data[2];

        // We don't support fragmentation; per RFC 1928, drop FRAG != 0
        if frag != 0 {
            continue;
        }

        let (target_location, payload_offset) = match parse_udp_address(data, 3) {
            Ok((location, offset)) => (location, offset),
            Err(_) => continue,
        };

        let payload = &data[payload_offset..];
        // Xray v26.2.6 drops a successfully decoded SOCKS UDP packet when
        // there is no payload after the address header.
        if payload.is_empty() {
            continue;
        }
        let inbound_tag = traffic_context
            .as_ref()
            .and_then(|context| context.inbound_tag.as_deref())
            .unwrap_or_default();
        let identity = traffic_context
            .as_ref()
            .and_then(|context| context.identity.as_deref())
            .unwrap_or_default();
        let (action, target_addr) = match select_direct_outbound_for_location(
            &resolver,
            &target_location,
            &runtime,
            OutboundRoutingContext::new(
                inbound_tag,
                identity,
                client_addr,
                3,
                "udp",
                InboundRoutingMetadata {
                    local_addr: udp_socket_clone.local_addr().ok(),
                    inbound_protocol: traffic_context
                        .as_ref()
                        .map(|context| context.protocol.to_string()),
                    ..InboundRoutingMetadata::default()
                },
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(error) => break Err(error),
        };
        let mut datagram_context = traffic_context.clone();
        match action {
            DirectOutboundAction::Blackhole { tag } => {
                datagram_context = datagram_context
                    .map(|context| context.with_outbound_tag(tag.clone()));
                record_transfer(datagram_context, payload.len() as u64, 0);
                tracing::debug!(
                    "SOCKS5 UDP payload dropped by blackhole outbound {}",
                    tag
                );
                continue;
            }
            DirectOutboundAction::Freedom { tag: Some(tag) } => {
                datagram_context =
                    datagram_context.map(|context| context.with_outbound_tag(tag));
            }
            DirectOutboundAction::Freedom { tag: None } => {}
            DirectOutboundAction::Trojan { outbound } => {
                #[cfg(feature = "trojan")]
                {
                    datagram_context = datagram_context.map(|context| {
                        context.with_outbound_tag(outbound.tag.clone())
                    });
                    if let Err(error) = send_trojan_udp_target_payload(
                        &mut trojan_sessions,
                        target_location.clone(),
                        payload.to_vec(),
                        datagram_context,
                        SocksTrojanUdpSessionStart {
                            outbound,
                            resolver: resolver.clone(),
                            runtime: runtime.clone(),
                            client_endpoint: response_endpoint,
                            client_socket: udp_socket_clone.clone(),
                            association_activity: Some(association_activity.clone()),
                        },
                    )
                    .await
                    {
                        tracing::warn!(
                            "SOCKS5 Trojan UDP forwarding failed: {}",
                            error
                        );
                    }
                    continue;
                }
                #[cfg(not(feature = "trojan"))]
                {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!(
                            "Trojan outbound {} requires the trojan feature",
                            outbound.tag
                        ),
                    ));
                }
            }
            DirectOutboundAction::Socks { outbound }
            | DirectOutboundAction::Vless { outbound } => {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "TCP proxy outbound {} cannot be used for UDP",
                        outbound.tag
                    ),
                ));
            }
            #[cfg(feature = "vless-reverse")]
            DirectOutboundAction::VlessReverse { tag } => {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("VLESS Reverse outbound {tag} is TCP-only"),
                ));
            }
        }

        let target_addr = match target_addr {
            Some(target_addr) => target_addr,
            None => {
                break Err(std::io::Error::other(
                    "SOCKS5 UDP freedom route did not resolve target",
                ));
            }
        };
        if let Err(error) = send_udp_target_payload(
            &mut client_sessions,
            target_addr,
            response_endpoint,
            udp_socket_clone.clone(),
            Some(&association_activity),
            payload.to_vec(),
            datagram_context,
        )
        .await
        {
            tracing::warn!(
                "SOCKS5 UDP relay: failed to send payload to target {}: {}",
                target_addr,
                error
            );
        }
    };

    stop_udp_client_sessions(&mut client_sessions).await;
    #[cfg(feature = "trojan")]
    stop_trojan_udp_client_sessions(&mut trojan_sessions).await;
    if !tcp_monitor_finished {
        tcp_monitor.abort();
        let _ = tcp_monitor.await;
    }
    result
}
