use std::{
    collections::{HashMap, hash_map::Entry},
    io::{Error, ErrorKind},
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use lru::LruCache;
use rand::RngExt;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use super::{
    AuthContext, MAX_ADDRESS_LEN, decode_varint_from_slice,
    hysteria2_traffic_context, push_varint,
};
use crate::{
    address::NetLocation,
    outbound::{
        DirectOutboundAction, connection_routing_input, select_direct_outbound,
    },
    resolver::{Resolver, resolve_single_address},
    runtime::DataPlaneRuntime,
    traffic::{
        ConnectionGuard, TrafficContext, record_transfer, register_connection,
    },
    util::socket::new_socket2_udp_socket,
};

const XRAY_UDP_IDLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const SHOES_UDP_IDLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
pub(super) const MAX_FRAGMENT_CACHE_SIZE: usize = 256;

pub(super) async fn drive_udp_datagrams(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    auth_ctx: &AuthContext,
    inbound_tag: Arc<String>,
    runtime: DataPlaneRuntime,
    udp_idle_timeout: Option<Duration>,
) -> std::io::Result<()> {
    let mut sessions: HashMap<u32, UdpSession> = HashMap::new();
    let cleanup_period = udp_idle_cleanup_interval(auth_ctx.xray_compat);
    let mut cleanup_interval = udp_idle_timeout.map(|_| {
        let start = tokio::time::Instant::now() + cleanup_period;
        let mut interval = tokio::time::interval_at(start, cleanup_period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval
    });
    let peer_addr = connection.remote_address();
    let identity = auth_ctx
        .client
        .email
        .clone()
        .unwrap_or(auth_ctx.client.password.clone());
    let base_context = hysteria2_traffic_context(
        &auth_ctx.client,
        inbound_tag.as_str(),
        peer_addr,
        &runtime,
    );

    loop {
        let data_result = loop {
            if let (Some(interval), Some(timeout)) =
                (cleanup_interval.as_mut(), udp_idle_timeout)
            {
                tokio::select! {
                    result = connection.read_datagram() => break result,
                    _ = interval.tick() => {
                        prune_idle_udp_sessions(
                            &mut sessions,
                            Instant::now(),
                            timeout,
                        );
                    }
                }
            } else {
                break connection.read_datagram().await;
            }
        };

        let data = match data_result {
            Ok(data) => data,
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed { .. }) => return Ok(()),
            Err(err) => return Err(Error::other(err)),
        };

        let (address_start, payload_start) =
            match udp_datagram_address_bounds(&data, auth_ctx.xray_compat) {
                Ok(bounds) => bounds,
                Err(err) => {
                    debug!("Ignoring malformed hysteria2 UDP datagram: {}", err);
                    continue;
                }
            };

        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let address_bytes = data.slice(address_start..payload_start);
        let payload_fragment = data.slice(payload_start..);

        let address_str = match std::str::from_utf8(&address_bytes) {
            Ok(addr) => addr,
            Err(err) => {
                warn!("Ignoring hysteria2 UDP packet with invalid UTF-8: {}", err);
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(address_str, None) {
            Ok(loc) => loc,
            Err(err) => {
                warn!(
                    "Failed to parse hysteria2 UDP address {}: {}",
                    address_str, err
                );
                continue;
            }
        };

        let session = match sessions.entry(session_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let remote_addr = match resolve_single_address(
                    &resolver,
                    &remote_location,
                )
                .await
                {
                    Ok(addr) => addr,
                    Err(err) => {
                        warn!(
                            "Failed to resolve hysteria2 UDP destination {}: {}",
                            remote_location, err
                        );
                        continue;
                    }
                };
                let session = create_udp_session(
                    session_id,
                    remote_location.clone(),
                    remote_addr,
                    connection.clone(),
                    base_context.clone(),
                    auth_ctx.xray_compat,
                )
                .await?;
                entry.insert(session)
            }
        };
        if refresh_udp_activity_on_datagram(auth_ctx.xray_compat) {
            // Xray refreshes InterConn activity as soon as a session datagram is
            // read, before UDP parsing/defragmentation completes. In particular,
            // a stream of partial fragments must keep an active session alive.
            session.mark_active();
        }
        let (complete_payload, completed_location) = if fragment_count <= 1 {
            // Xray's Defragger treats FragCount 0 and 1 as complete datagrams.
            // Keep accepting the legacy zero value in Xray compatibility mode,
            // while shoes/native mode retains shoes' stricter zero-fragment rejection.
            if !accept_unfragmented_udp_datagram(
                fragment_count,
                auth_ctx.xray_compat,
            ) {
                warn!(
                    "Ignoring hysteria2 UDP packet {} with zero fragments",
                    session_id
                );
                continue;
            }
            (payload_fragment, remote_location)
        } else {
            if fragment_id as usize >= fragment_count as usize {
                warn!(
                    "Ignoring hysteria2 UDP packet {} with invalid fragment id {}",
                    session_id, fragment_id
                );
                continue;
            }

            prepare_fragment_cache(
                &mut session.fragments,
                packet_id,
                fragment_count,
                auth_ctx.xray_compat,
            );

            if !session.fragments.contains(&packet_id) {
                session.fragments.put(
                    packet_id,
                    FragmentedPacket {
                        fragment_count,
                        fragment_received: 0,
                        packet_len: 0,
                        received: vec![None; fragment_count as usize],
                        remote_location: remote_location.clone(),
                    },
                );
            }

            let entry = session
                .fragments
                .get_mut(&packet_id)
                .expect("inserted hysteria2 fragment must be cached");

            if entry.fragment_count != fragment_count {
                warn!(
                    "Mismatched fragment count for hysteria2 UDP packet {}",
                    session_id
                );
                session.fragments.pop(&packet_id);
                continue;
            }

            if entry.received[fragment_id as usize].is_some() {
                warn!(
                    "Duplicate fragment {} for hysteria2 UDP packet {}",
                    fragment_id, session_id
                );
                handle_duplicate_fragment(
                    &mut session.fragments,
                    packet_id,
                    auth_ctx.xray_compat,
                );
                continue;
            }

            entry.fragment_received += 1;
            entry.packet_len += payload_fragment.len();
            entry.received[fragment_id as usize] = Some(payload_fragment);

            if entry.fragment_received != entry.fragment_count {
                continue;
            }

            let FragmentedPacket {
                remote_location: remembered_location,
                received,
                packet_len,
                ..
            } = completed_fragment_packet(
                &mut session.fragments,
                packet_id,
                auth_ctx.xray_compat,
            )
            .expect("completed hysteria2 fragment packet must be cached");
            let completed_location = fragment_completion_location(
                remembered_location,
                remote_location,
                auth_ctx.xray_compat,
            );

            let mut assembled = BytesMut::with_capacity(packet_len);
            for bytes in received.into_iter().flatten() {
                assembled.extend_from_slice(&bytes);
            }

            (assembled.freeze(), completed_location)
        };

        // Both shoes and Xray hand a destination to the forwarding path only
        // after defragmentation completes. Incomplete fragments must not resolve
        // or mutate the session destination on their own.
        if completed_location != session.last_location {
            let updated_addr = match resolve_single_address(
                &resolver,
                &completed_location,
            )
            .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(
                        "Failed to resolve updated hysteria2 UDP destination {}: {}",
                        completed_location, err
                    );
                    continue;
                }
            };
            session.last_location = completed_location;
            session.last_socket_addr = updated_addr;
        }

        let mut route_input = connection_routing_input(
            inbound_tag.as_str(),
            &identity,
            3,
            peer_addr,
            session.last_socket_addr,
            &session.last_location,
        );
        route_input.vless_route = auth_ctx.vless_route;
        let action = match select_direct_outbound(&runtime, &route_input, "udp") {
            Ok(action) => action,
            Err(err) => {
                warn!(
                    "Failed to route hysteria2 UDP payload for session {}: {}",
                    session_id, err
                );
                continue;
            }
        };
        let mut traffic_context = session.base_context.clone();

        match action {
            DirectOutboundAction::Blackhole { tag } => {
                traffic_context = traffic_context.with_outbound_tag(tag.clone());
                record_transfer(
                    Some(traffic_context),
                    complete_payload.len() as u64,
                    0,
                );
                debug!(
                    "hysteria2 UDP payload for session {} dropped by blackhole outbound {}",
                    session_id, tag
                );
                continue;
            }
            DirectOutboundAction::Freedom { tag: Some(tag) } => {
                traffic_context = traffic_context.with_outbound_tag(tag);
            }
            DirectOutboundAction::Freedom { tag: None } => {}
            DirectOutboundAction::Socks { outbound }
            | DirectOutboundAction::Vless { outbound }
            | DirectOutboundAction::Trojan { outbound } => {
                warn!("hysteria2 UDP outbound {} is not implemented", outbound.tag);
                continue;
            }
        }

        session
            .response_contexts
            .write()
            .expect("hysteria2 UDP contexts lock poisoned")
            .insert(
                session.last_socket_addr,
                UdpResponseContext {
                    traffic_context: traffic_context.clone(),
                    client_location: session.last_location.clone(),
                },
            );

        match session
            .socket
            .send_to(
                complete_payload.as_ref(),
                hysteria2_udp_send_addr(session.last_socket_addr),
            )
            .await
        {
            Ok(sent) => {
                record_transfer(Some(traffic_context), sent as u64, 0);
            }
            Err(err) => {
                warn!(
                    "Failed to forward hysteria2 UDP payload for session {}: {}",
                    session_id, err
                );
                sessions.remove(&session_id);
            }
        }
    }
}

pub(super) fn prune_idle_udp_sessions(
    sessions: &mut HashMap<u32, UdpSession>,
    now: Instant,
    timeout: Duration,
) {
    sessions.retain(|session_id, session| {
        let active = !udp_session_is_idle(session.last_active(), now, timeout);
        if !active {
            debug!(
                "hysteria2 UDP session {} expired after {:?} of inactivity",
                session_id, timeout
            );
        }
        active
    });
}

pub(super) fn udp_idle_cleanup_interval(xray_compat: bool) -> Duration {
    if xray_compat {
        XRAY_UDP_IDLE_CLEANUP_INTERVAL
    } else {
        SHOES_UDP_IDLE_CLEANUP_INTERVAL
    }
}

pub(super) fn refresh_udp_activity_on_datagram(xray_compat: bool) -> bool {
    xray_compat
}

pub(super) fn refresh_udp_activity_on_response(xray_compat: bool) -> bool {
    xray_compat
}

pub(super) fn udp_session_is_idle(
    last_active: Instant,
    now: Instant,
    timeout: Duration,
) -> bool {
    now.saturating_duration_since(last_active) > timeout
}

pub(super) struct UdpSession {
    socket: Arc<UdpSocket>,
    fragments: LruCache<u16, FragmentedPacket>,
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    last_active: Arc<RwLock<Instant>>,
    base_context: TrafficContext,
    response_contexts: Arc<RwLock<HashMap<SocketAddr, UdpResponseContext>>>,
    remote_task: tokio::task::JoinHandle<()>,
    _connection_guard: ConnectionGuard,
}

impl UdpSession {
    fn mark_active(&self) {
        *self
            .last_active
            .write()
            .expect("hysteria2 UDP activity lock poisoned") = Instant::now();
    }

    fn last_active(&self) -> Instant {
        *self
            .last_active
            .read()
            .expect("hysteria2 UDP activity lock poisoned")
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.remote_task.abort();
    }
}

#[derive(Clone)]
pub(super) struct UdpResponseContext {
    traffic_context: TrafficContext,
    client_location: NetLocation,
}

#[derive(Clone)]
pub(super) struct FragmentedPacket {
    pub(super) fragment_count: u8,
    pub(super) fragment_received: u8,
    pub(super) packet_len: usize,
    pub(super) received: Vec<Option<Bytes>>,
    pub(super) remote_location: NetLocation,
}

pub(super) fn hysteria2_fragment_cache() -> LruCache<u16, FragmentedPacket> {
    LruCache::new(NonZeroUsize::new(MAX_FRAGMENT_CACHE_SIZE).unwrap())
}

pub(super) fn fragment_completion_location(
    remembered_location: NetLocation,
    current_location: NetLocation,
    xray_compat: bool,
) -> NetLocation {
    // Xray's Defragger returns the fragment that completes the packet after
    // replacing only its Data field, so the completed message keeps that
    // fragment's address. Shoes explicitly retains the first fragment's address.
    if xray_compat {
        current_location
    } else {
        remembered_location
    }
}

pub(super) fn completed_fragment_packet(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    packet_id: u16,
    xray_compat: bool,
) -> Option<FragmentedPacket> {
    // Xray's Defragger keeps completed state until a different packet ID or
    // fragment count replaces it. Shoes removes completed packets immediately.
    if xray_compat {
        fragments.peek(&packet_id).cloned()
    } else {
        fragments.pop(&packet_id)
    }
}

pub(super) fn handle_duplicate_fragment(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    packet_id: u16,
    xray_compat: bool,
) {
    // Xray's Defragger ignores a duplicate fragment and retains the partial
    // packet. Shoes discards the entire partial packet on a duplicate.
    if !xray_compat {
        fragments.pop(&packet_id);
    }
}

pub(super) fn prepare_fragment_cache(
    fragments: &mut LruCache<u16, FragmentedPacket>,
    packet_id: u16,
    fragment_count: u8,
    xray_compat: bool,
) {
    if !xray_compat {
        return;
    }

    let current_matches = fragments
        .peek(&packet_id)
        .is_some_and(|packet| packet.fragment_count == fragment_count);
    if !current_matches {
        // Xray's Defragger tracks only one in-flight packet per UDP session.
        // A new packet ID or fragment count replaces any partial assembly.
        fragments.clear();
    }
}

pub(super) fn new_hysteria2_socket2_udp_socket() -> std::io::Result<socket2::Socket>
{
    let socket = new_socket2_udp_socket(true, None, None, false)?;
    socket.set_only_v6(false)?;
    let bind_addr: SocketAddr =
        "[::]:0".parse().expect("valid IPv6 wildcard address");
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    Ok(socket)
}

pub(super) fn new_hysteria2_udp_socket() -> std::io::Result<UdpSocket> {
    let std_socket: std::net::UdpSocket = new_hysteria2_socket2_udp_socket()?.into();
    UdpSocket::from_std(std_socket)
}

pub(super) fn hysteria2_udp_send_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(addr) => {
            SocketAddr::from((addr.ip().to_ipv6_mapped(), addr.port()))
        }
        SocketAddr::V6(_) => addr,
    }
}

pub(super) fn normalize_hysteria2_udp_peer_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::from((ip, addr.port())))
            .unwrap_or(SocketAddr::V6(addr)),
        SocketAddr::V4(_) => addr,
    }
}

pub(super) async fn create_udp_session(
    session_id: u32,
    remote_location: NetLocation,
    remote_addr: SocketAddr,
    connection: quinn::Connection,
    base_context: TrafficContext,
    xray_compat: bool,
) -> std::io::Result<UdpSession> {
    // Match shoes: one Hysteria UDP session can change destination address
    // families, so keep a dual-stack socket instead of binding to the family
    // of the first destination.
    let socket = Arc::new(new_hysteria2_udp_socket()?);
    let socket_for_task = socket.clone();
    let connection_for_task = connection.clone();
    let response_contexts = Arc::new(RwLock::new(HashMap::new()));
    let contexts_for_task = response_contexts.clone();
    let last_active = Arc::new(RwLock::new(Instant::now()));
    let activity_for_task = last_active.clone();
    let fallback_context = base_context.clone();
    let connection_guard = register_connection(Some(&base_context));

    let remote_task = tokio::spawn(async move {
        if let Err(err) = run_udp_remote_to_local_loop(
            session_id,
            connection_for_task,
            socket_for_task,
            contexts_for_task,
            activity_for_task,
            fallback_context,
            xray_compat,
        )
        .await
        {
            debug!(
                "hysteria2 UDP remote-to-local loop for session {} ended: {}",
                session_id, err
            );
        }
    });

    Ok(UdpSession {
        socket,
        fragments: hysteria2_fragment_cache(),
        last_location: remote_location,
        last_socket_addr: remote_addr,
        last_active,
        base_context,
        response_contexts,
        remote_task,
        _connection_guard: connection_guard,
    })
}

pub(super) async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    response_contexts: Arc<RwLock<HashMap<SocketAddr, UdpResponseContext>>>,
    last_active: Arc<RwLock<Instant>>,
    fallback_context: TrafficContext,
    xray_compat: bool,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| Error::other("peer does not support datagrams"))?;

    let mut next_packet_id: u16 = 0;
    let mut buf = vec![0u8; 65535];
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) =
            socket.recv_from(&mut buf).await.map_err(|err| {
                Error::other(format!(
                    "failed to receive hysteria2 UDP payload: {}",
                    err
                ))
            })?;
        let src_addr = normalize_hysteria2_udp_peer_addr(src_addr);
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }
        let response_context = response_contexts
            .read()
            .expect("hysteria2 UDP contexts lock poisoned")
            .get(&src_addr)
            .cloned();
        let (traffic_context, client_address) = match response_context {
            Some(context) => {
                (context.traffic_context, context.client_location.to_string())
            }
            None => (fallback_context.clone(), src_addr.to_string()),
        };

        let address_bytes = Bytes::from(client_address.into_bytes());
        let mut address_len_buf = Vec::with_capacity(8);
        push_varint(&mut address_len_buf, address_bytes.len() as u64)?;
        let address_len_bytes = Bytes::from(address_len_buf);

        let header_overhead =
            4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();
        if header_overhead >= max_datagram_size {
            warn!(
                "hysteria2 UDP datagram header larger than max datagram size ({} >= {})",
                header_overhead, max_datagram_size
            );
            continue;
        }

        let available_payload = max_datagram_size - header_overhead;
        if available_payload == 0 {
            warn!("hysteria2 UDP available payload is zero, skipping packet");
            continue;
        }

        if payload_len <= available_payload {
            let packet_id =
                udp_response_packet_id(&mut next_packet_id, false, xray_compat);
            let mut datagram =
                BytesMut::with_capacity(header_overhead + payload_len);
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&[0, 1]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection
                .send_datagram(datagram.freeze())
                .map_err(Error::other)?;
        } else {
            let fragment_count = payload_len.div_ceil(available_payload);
            if fragment_count > u8::MAX as usize {
                warn!(
                    "hysteria2 UDP packet too large to fragment ({} fragments)",
                    fragment_count
                );
                continue;
            }

            let packet_id =
                udp_response_packet_id(&mut next_packet_id, true, xray_compat);
            for fragment_id in 0..fragment_count {
                let start = fragment_id * available_payload;
                let end = std::cmp::min(start + available_payload, payload_len);

                let mut datagram =
                    BytesMut::with_capacity(header_overhead + (end - start));
                datagram.extend_from_slice(&session_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram
                    .extend_from_slice(&[fragment_id as u8, fragment_count as u8]);
                datagram.extend_from_slice(&address_len_bytes);
                datagram.extend_from_slice(&address_bytes);
                datagram.extend_from_slice(&buf[start..end]);

                connection
                    .send_datagram(datagram.freeze())
                    .map_err(Error::other)?;
            }
        }

        if refresh_udp_activity_on_response(xray_compat) {
            *last_active
                .write()
                .expect("hysteria2 UDP activity lock poisoned") = Instant::now();
        }
        record_transfer(Some(traffic_context), 0, payload_len as u64);
    }
}

pub(super) fn udp_response_packet_id(
    next_packet_id: &mut u16,
    fragmented: bool,
    xray_compat: bool,
) -> u16 {
    if xray_compat {
        if fragmented {
            rand::rng().random_range(1..=u16::MAX)
        } else {
            0
        }
    } else {
        let packet_id = *next_packet_id;
        *next_packet_id = next_packet_id.wrapping_add(1);
        packet_id
    }
}

pub(super) fn accept_unfragmented_udp_datagram(
    fragment_count: u8,
    xray_compat: bool,
) -> bool {
    fragment_count == 1 || (fragment_count == 0 && xray_compat)
}

pub(super) fn udp_datagram_address_bounds(
    data: &[u8],
    xray_compat: bool,
) -> std::io::Result<(usize, usize)> {
    if data.len() < 9 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "hysteria2 datagram too short",
        ));
    }

    let (address_len, varint_len) = decode_varint_from_slice(&data[8..])?;
    if address_len == 0 || address_len > MAX_ADDRESS_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid hysteria2 UDP address length: {address_len}"),
        ));
    }

    let address_start = 8 + varint_len;
    let payload_start = address_start.checked_add(address_len).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "hysteria2 UDP address length overflow",
        )
    })?;
    if data.len() < payload_start {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "hysteria2 datagram truncated before payload",
        ));
    }
    if xray_compat && data.len() == payload_start {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "xray hysteria2 UDP datagram requires a non-empty payload",
        ));
    }

    Ok((address_start, payload_start))
}
