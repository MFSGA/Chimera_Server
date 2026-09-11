use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::{
    io::AsyncReadExt,
    sync::{Notify, mpsc},
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};

#[cfg(feature = "trojan")]
use crate::{
    address::NetLocation, outbound::connect_trojan_udp_via_outbound,
    runtime::OutboundSummary,
};
use crate::{
    async_stream::AsyncStream,
    config::server_config::SocksUserStore,
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{TrafficContext, record_transfer, register_connection},
};

#[cfg(feature = "trojan")]
use super::build_udp_response_packet_location;
use super::{
    MAX_UDP_DATAGRAM_SIZE, UDP_BUFFER_SIZE, UDP_TARGET_SESSION_ACTIVITY_CHECK,
    XRAY_SOCKS_UDP_PACKET_SIZE, build_udp_response_packet,
    create_udp_socket_for_target, parse_udp_address,
};

pub(super) struct SocksUdpClientSession {
    pub(super) sender: mpsc::Sender<(SocketAddr, Vec<u8>, Option<TrafficContext>)>,
    pub(super) task: Option<JoinHandle<()>>,
}

impl SocksUdpClientSession {
    async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for SocksUdpClientSession {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

#[cfg(feature = "trojan")]
struct SocksTrojanUdpClientSession {
    sender: mpsc::Sender<(NetLocation, Vec<u8>, Option<TrafficContext>)>,
    task: Option<JoinHandle<()>>,
}

#[cfg(feature = "trojan")]
#[derive(Clone)]
struct SocksTrojanUdpSessionStart {
    outbound: OutboundSummary,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    client_endpoint: SocketAddr,
    client_socket: Arc<tokio::net::UdpSocket>,
    association_activity: Option<Arc<Notify>>,
}

#[cfg(feature = "trojan")]
impl SocksTrojanUdpClientSession {
    async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(feature = "trojan")]
impl Drop for SocksTrojanUdpClientSession {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

#[derive(Debug)]
pub(super) struct XrayUdpActivityWindow {
    downstream_activity: bool,
}

impl XrayUdpActivityWindow {
    pub(super) fn new() -> Self {
        Self {
            downstream_activity: true,
        }
    }

    pub(super) fn record_downstream(&mut self) {
        self.downstream_activity = true;
    }

    pub(super) fn keep_alive_on_check(&mut self) -> bool {
        std::mem::replace(&mut self.downstream_activity, false)
    }
}

fn start_udp_client_session(
    initial_target_addr: SocketAddr,
    client_endpoint: SocketAddr,
    client_socket: Arc<tokio::net::UdpSocket>,
    association_activity: Option<Arc<Notify>>,
) -> std::io::Result<SocksUdpClientSession> {
    let target_socket = create_udp_socket_for_target(&initial_target_addr)?;
    let (sender, mut receiver) =
        mpsc::channel::<(SocketAddr, Vec<u8>, Option<TrafficContext>)>(32);
    let task = tokio::spawn(async move {
        let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
        let mut activity_checks = interval(UDP_TARGET_SESSION_ACTIVITY_CHECK);
        activity_checks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Tokio intervals tick immediately; Xray's ActivityTimer first checks
        // after one full timeout period.
        activity_checks.tick().await;
        let mut activity = XrayUdpActivityWindow::new();
        let mut response_contexts =
            HashMap::<SocketAddr, Option<TrafficContext>>::new();

        loop {
            tokio::select! {
                message = receiver.recv() => {
                    let Some((target_addr, payload, traffic_context)) = message else {
                        return;
                    };
                    match target_socket.send_to(&payload, target_addr).await {
                        Ok(sent) => {
                            record_transfer(traffic_context.clone(), sent as u64, 0);
                            response_contexts.insert(target_addr, traffic_context);
                        }
                        Err(error) => {
                            tracing::warn!("SOCKS5 UDP relay: failed to send to target: {}", error);
                        }
                    }
                }
                result = target_socket.recv_from(&mut response_buf) => {
                    match result {
                        Ok((resp_len, resp_addr)) => {
                            // Xray updates its UDP ActivityTimer as soon as a
                            // downstream packet is read, before the SOCKS
                            // response callback writes it to the client.
                            activity.record_downstream();
                            if let Some(activity) = association_activity.as_ref() {
                                activity.notify_one();
                            }
                            let socks5_response =
                                build_udp_response_packet(resp_addr, &response_buf[..resp_len]);
                            let forwarded_payload_len = if socks5_response.is_empty() {
                                0
                            } else {
                                resp_len
                            };
                            if let Err(error) = client_socket.send_to(&socks5_response, client_endpoint).await {
                                tracing::warn!(
                                    "SOCKS5 UDP relay: failed to send response to client: {}",
                                    error
                                );
                            } else {
                                record_transfer(
                                    response_contexts.get(&resp_addr).cloned().flatten(),
                                    0,
                                    forwarded_payload_len as u64,
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!("SOCKS5 UDP relay: failed to receive from target: {}", error);
                            return;
                        }
                    }
                }
                _ = activity_checks.tick() => {
                    if !activity.keep_alive_on_check() {
                        return;
                    }
                }
            }
        }
    });

    Ok(SocksUdpClientSession {
        sender,
        task: Some(task),
    })
}

#[cfg(feature = "trojan")]
async fn start_trojan_udp_client_session(
    initial_target: NetLocation,
    start: SocksTrojanUdpSessionStart,
) -> std::io::Result<SocksTrojanUdpClientSession> {
    let mut proxy = connect_trojan_udp_via_outbound(
        &start.resolver,
        &initial_target,
        &start.runtime,
        &start.outbound,
    )
    .await?;
    let (sender, mut receiver) =
        mpsc::channel::<(NetLocation, Vec<u8>, Option<TrafficContext>)>(32);
    let SocksTrojanUdpSessionStart {
        outbound,
        client_endpoint,
        client_socket,
        association_activity,
        ..
    } = start;
    let task = tokio::spawn(async move {
        let mut response_buf = vec![0u8; XRAY_SOCKS_UDP_PACKET_SIZE];
        let mut activity_checks = interval(UDP_TARGET_SESSION_ACTIVITY_CHECK);
        activity_checks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        activity_checks.tick().await;
        let mut activity = XrayUdpActivityWindow::new();
        let mut response_contexts =
            HashMap::<NetLocation, Option<TrafficContext>>::new();
        let mut last_context = None::<TrafficContext>;

        loop {
            tokio::select! {
                message = receiver.recv() => {
                    let Some((target, payload, traffic_context)) = message else {
                        return;
                    };
                    if let Err(error) = proxy.send_to(&target, &payload).await {
                        tracing::warn!(
                            "SOCKS5 Trojan UDP relay: failed to send to {} via {}: {}",
                            target,
                            outbound.tag,
                            error
                        );
                        return;
                    }
                    record_transfer(
                        traffic_context.clone(),
                        payload.len() as u64,
                        0,
                    );
                    if let Some(context) = traffic_context.clone() {
                        last_context = Some(context);
                    }
                    response_contexts.insert(target, traffic_context);
                }
                result = proxy.recv_from(&mut response_buf) => {
                    let (source, resp_len) = match result {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::warn!(
                                "SOCKS5 Trojan UDP relay: failed to receive via {}: {}",
                                outbound.tag,
                                error
                            );
                            return;
                        }
                    };
                    activity.record_downstream();
                    if let Some(activity) = association_activity.as_ref() {
                        activity.notify_one();
                    }
                    let socks5_response = match build_udp_response_packet_location(
                        &source,
                        &response_buf[..resp_len],
                    ) {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::warn!(
                                "SOCKS5 Trojan UDP relay: invalid response source {}: {}",
                                source,
                                error
                            );
                            return;
                        }
                    };
                    let forwarded_payload_len = if socks5_response.is_empty() {
                        0
                    } else {
                        resp_len
                    };
                    if let Err(error) = client_socket
                        .send_to(&socks5_response, client_endpoint)
                        .await
                    {
                        tracing::warn!(
                            "SOCKS5 Trojan UDP relay: failed to send response to client: {}",
                            error
                        );
                    } else {
                        let context = response_contexts
                            .get(&source)
                            .cloned()
                            .flatten()
                            .or_else(|| last_context.clone());
                        record_transfer(
                            context,
                            0,
                            forwarded_payload_len as u64,
                        );
                    }
                }
                _ = activity_checks.tick() => {
                    if !activity.keep_alive_on_check() {
                        return;
                    }
                }
            }
        }
    });

    Ok(SocksTrojanUdpClientSession {
        sender,
        task: Some(task),
    })
}

#[cfg(feature = "trojan")]
async fn send_trojan_udp_target_payload(
    client_sessions: &mut HashMap<(SocketAddr, String), SocksTrojanUdpClientSession>,
    target: NetLocation,
    payload: Vec<u8>,
    traffic_context: Option<TrafficContext>,
    start: SocksTrojanUdpSessionStart,
) -> std::io::Result<()> {
    let session_key = (start.client_endpoint, start.outbound.tag.clone());
    let message = (target.clone(), payload, traffic_context);
    for attempt in 0..2 {
        if let std::collections::hash_map::Entry::Vacant(entry) =
            client_sessions.entry(session_key.clone())
        {
            entry.insert(
                start_trojan_udp_client_session(target.clone(), start.clone())
                    .await?,
            );
        }

        let sender = &client_sessions
            .get(&session_key)
            .expect("SOCKS5 Trojan UDP client session exists after insertion")
            .sender;
        match sender.send(message.clone()).await {
            Ok(()) => return Ok(()),
            Err(_) if attempt == 0 => {
                if let Some(session) = client_sessions.remove(&session_key) {
                    session.stop().await;
                }
            }
            Err(_) => {
                if let Some(session) = client_sessions.remove(&session_key) {
                    session.stop().await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "SOCKS5 Trojan UDP client session closed before payload was sent",
                ));
            }
        }
    }
    unreachable!("SOCKS5 Trojan UDP target payload retry loop is bounded")
}

pub(super) async fn send_udp_target_payload(
    client_sessions: &mut HashMap<(SocketAddr, bool), SocksUdpClientSession>,
    target_addr: SocketAddr,
    client_endpoint: SocketAddr,
    client_socket: Arc<tokio::net::UdpSocket>,
    association_activity: Option<&Arc<Notify>>,
    payload: Vec<u8>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let message = (target_addr, payload, traffic_context);
    let session_key = (client_endpoint, target_addr.is_ipv6());
    for attempt in 0..2 {
        if let std::collections::hash_map::Entry::Vacant(entry) =
            client_sessions.entry(session_key)
        {
            entry.insert(start_udp_client_session(
                target_addr,
                client_endpoint,
                client_socket.clone(),
                association_activity.cloned(),
            )?);
        }

        let sender = &client_sessions
            .get(&session_key)
            .expect("SOCKS5 UDP client session exists after insertion")
            .sender;
        match sender.send(message.clone()).await {
            Ok(()) => return Ok(()),
            Err(_) if attempt == 0 => {
                if let Some(session) = client_sessions.remove(&session_key) {
                    session.stop().await;
                }
            }
            Err(_) => {
                if let Some(session) = client_sessions.remove(&session_key) {
                    session.stop().await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "SOCKS5 UDP client session closed before payload was sent",
                ));
            }
        }
    }
    unreachable!("SOCKS5 UDP target payload retry loop is bounded")
}

pub(super) fn prune_closed_udp_sessions(
    client_sessions: &mut HashMap<(SocketAddr, bool), SocksUdpClientSession>,
) {
    client_sessions.retain(|_, session| !session.sender.is_closed());
}

async fn stop_udp_client_sessions(
    client_sessions: &mut HashMap<(SocketAddr, bool), SocksUdpClientSession>,
) {
    for (_, session) in client_sessions.drain() {
        session.stop().await;
    }
}

#[cfg(feature = "trojan")]
async fn stop_trojan_udp_client_sessions(
    client_sessions: &mut HashMap<(SocketAddr, String), SocksTrojanUdpClientSession>,
) {
    for (_, session) in client_sessions.drain() {
        session.stop().await;
    }
}

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
