use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use tokio::{io::AsyncReadExt, net::UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::{
    address::NetLocation,
    outbound::{
        DirectOutboundAction, connection_routing_input, select_direct_outbound,
    },
    resolver::{Resolver, resolve_single_address},
    traffic::{
        ConnectionGuard, TrafficContext, record_transfer, register_connection,
    },
    util::{allocate_vec, socket::new_socket2_udp_socket_with_buffer_size},
};

use super::{
    CLEANUP_INTERVAL, COMMAND_TYPE_DISSOCIATE, COMMAND_TYPE_PACKET, IDLE_TIMEOUT,
    MAX_HEADER_LEN, TUIC_VERSION, TuicConnectionTaskOwner, TuicFlowContext,
    read_address,
};

mod codec;

pub(super) use codec::serialize_socket_addr;
use codec::{
    FragmentAssembler, ParsedDatagram, parse_datagram, validate_fragment_header,
};

pub(super) type UdpSessionMap = Arc<DashMap<u16, UdpSession>>;

struct TuicUdpTaskScope<'a> {
    parent_cancel_token: &'a CancellationToken,
    child_tasks: &'a TuicConnectionTaskOwner,
}

pub(super) struct UdpSession {
    pub(super) send_socket: Arc<UdpSocket>,
    pub(super) last_location: NetLocation,
    pub(super) last_socket_addr: SocketAddr,
    pub(super) last_activity: Instant,
    pub(super) cancel_token: CancellationToken,
    pub(super) base_context: TrafficContext,
    pub(super) response_contexts: Arc<DashMap<SocketAddr, TrafficContext>>,
    pub(super) _connection_guard: ConnectionGuard,
}

impl UdpSession {
    fn start_with_send_stream(
        assoc_id: u16,
        send_stream: quinn::SendStream,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        base_context: TrafficContext,
        task_scope: TuicUdpTaskScope<'_>,
    ) -> std::io::Result<Self> {
        let session_cancel_token = task_scope.parent_cancel_token.child_token();
        let response_contexts = Arc::new(DashMap::new());
        let connection_guard = register_connection(Some(&base_context));

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            last_activity: Instant::now(),
            cancel_token: session_cancel_token.clone(),
            base_context: base_context.clone(),
            response_contexts: response_contexts.clone(),
            _connection_guard: connection_guard,
        };

        if !task_scope.child_tasks.spawn(async move {
            if let Err(e) = run_udp_remote_to_local_stream_loop(
                assoc_id,
                send_stream,
                client_socket,
                session_cancel_token,
                response_contexts,
                base_context,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        }) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "server is no longer accepting TUIC connection tasks",
            ));
        }

        Ok(session)
    }

    fn start_with_datagram(
        assoc_id: u16,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        base_context: TrafficContext,
        task_scope: TuicUdpTaskScope<'_>,
    ) -> std::io::Result<Self> {
        let session_cancel_token = task_scope.parent_cancel_token.child_token();
        let response_contexts = Arc::new(DashMap::new());
        let connection_guard = register_connection(Some(&base_context));

        let session = UdpSession {
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            last_activity: Instant::now(),
            cancel_token: session_cancel_token.clone(),
            base_context: base_context.clone(),
            response_contexts: response_contexts.clone(),
            _connection_guard: connection_guard,
        };

        if !task_scope.child_tasks.spawn(async move {
            if let Err(e) = run_udp_remote_to_local_datagram_loop(
                assoc_id,
                connection,
                client_socket,
                session_cancel_token,
                response_contexts,
                base_context,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        }) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "server is no longer accepting TUIC connection tasks",
            ));
        }

        Ok(session)
    }

    async fn resolve_address(
        &self,
        location: &NetLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<(SocketAddr, bool)> {
        if location == &self.last_location {
            Ok((self.last_socket_addr, false))
        } else {
            let updated_address = resolve_single_address(resolver, location).await?;
            Ok((updated_address, true))
        }
    }

    fn update_last_location(
        &mut self,
        location: NetLocation,
        socket_addr: SocketAddr,
    ) {
        self.last_location = location;
        self.last_socket_addr = socket_addr;
    }
}

async fn run_udp_remote_to_local_stream_loop(
    assoc_id: u16,
    mut send_stream: quinn::SendStream,
    socket: Arc<UdpSocket>,
    cancel_token: CancellationToken,
    response_contexts: Arc<DashMap<SocketAddr, TrafficContext>>,
    fallback_context: TrafficContext,
) -> std::io::Result<()> {
    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(MAX_HEADER_LEN + 65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) =
            match socket.try_recv_from(&mut buf[MAX_HEADER_LEN..]) {
                Ok(res) => res,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            return Ok(());
                        }
                        result = socket.readable() => {
                            result?;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "failed to receive from UDP socket: {e}"
                    )));
                }
            };

        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);
        let traffic_context = response_contexts
            .get(&src_addr)
            .map(|entry| entry.value().clone())
            .unwrap_or_else(|| fallback_context.clone());

        let address_bytes = serialize_socket_addr(&src_addr);
        let address_bytes_len = address_bytes.len();

        // assoc_id(2) + packet_id(2) + fragment total(1) + fragment id(1) + payload size (2)
        // + address bytes
        let header_len = 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        let start_offset = MAX_HEADER_LEN - header_len;
        let end_offset = MAX_HEADER_LEN + payload_len;

        buf[start_offset] = (assoc_id >> 8) as u8;
        buf[start_offset + 1] = assoc_id as u8;
        buf[start_offset + 2] = (packet_id >> 8) as u8;
        buf[start_offset + 3] = packet_id as u8;
        buf[start_offset + 4] = 1;
        buf[start_offset + 5] = 0;
        buf[start_offset + 6] = (payload_len >> 8) as u8;
        buf[start_offset + 7] = payload_len as u8;
        buf[start_offset + 8..start_offset + 8 + address_bytes_len]
            .copy_from_slice(&address_bytes);

        let mut i = start_offset;
        while i < end_offset {
            let count = tokio::select! {
                _ = cancel_token.cancelled() => return Ok(()),
                result = send_stream.write(&buf[i..end_offset]) => {
                    result.map_err(std::io::Error::other)?
                }
            };
            i += count;
        }
        record_transfer(Some(traffic_context), 0, payload_len as u64);
    }
}

async fn run_udp_remote_to_local_datagram_loop(
    assoc_id: u16,
    connection: quinn::Connection,
    client_socket: Arc<UdpSocket>,
    cancel_token: CancellationToken,
    response_contexts: Arc<DashMap<SocketAddr, TrafficContext>>,
    fallback_context: TrafficContext,
) -> std::io::Result<()> {
    let max_datagram_size = connection.max_datagram_size().ok_or_else(|| {
        std::io::Error::other("datagram not supported by remote endpoint")
    })?;

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535).into_boxed_slice();
    let mut loop_count: u8 = 0;

    loop {
        let (payload_len, src_addr) = match client_socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = client_socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);
        let traffic_context = response_contexts
            .get(&src_addr)
            .map(|entry| entry.value().clone())
            .unwrap_or_else(|| fallback_context.clone());

        let address_bytes = serialize_socket_addr(&src_addr);
        let address_bytes_len = address_bytes.len();

        // tuic_version (1) + command (1) + assoc_id (2) + packet_id (2)
        // + frag_total (1) + frag_id (1) + payload_size (2) + address bytes
        let header_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + address_bytes_len;

        if header_overhead + payload_len <= max_datagram_size {
            let mut datagram =
                BytesMut::with_capacity(header_overhead + payload_len);
            datagram.put_u8(TUIC_VERSION);
            datagram.put_u8(COMMAND_TYPE_PACKET);
            datagram.extend_from_slice(&assoc_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.put_u8(1);
            datagram.put_u8(0);
            datagram.extend_from_slice(&(payload_len as u16).to_be_bytes());
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[..payload_len]);

            connection.send_datagram(datagram.freeze()).map_err(|e| {
                std::io::Error::other(format!("Failed to send datagram: {e}"))
            })?;
        } else {
            let first_overhead = header_overhead;
            let other_overhead = 1 + 1 + 2 + 2 + 1 + 1 + 2 + 1;
            let first_capacity = max_datagram_size - first_overhead;
            let other_capacity = max_datagram_size - other_overhead;

            let remaining = payload_len.saturating_sub(first_capacity);
            let additional_fragments = remaining.div_ceil(other_capacity);
            let fragment_count = 1 + additional_fragments;

            let mut offset = 0;
            for fragment_id in 0..fragment_count {
                let (fragment_payload_len, header_size) = if fragment_id == 0 {
                    let len = std::cmp::min(first_capacity, payload_len);
                    (len, first_overhead)
                } else {
                    let len = std::cmp::min(other_capacity, payload_len - offset);
                    (len, other_overhead)
                };

                let mut datagram =
                    BytesMut::with_capacity(header_size + fragment_payload_len);
                datagram.extend_from_slice(&[TUIC_VERSION, COMMAND_TYPE_PACKET]);
                datagram.extend_from_slice(&assoc_id.to_be_bytes());
                datagram.extend_from_slice(&packet_id.to_be_bytes());
                datagram
                    .extend_from_slice(&[fragment_count as u8, fragment_id as u8]);
                datagram
                    .extend_from_slice(&(fragment_payload_len as u16).to_be_bytes());
                if fragment_id == 0 {
                    datagram.extend_from_slice(&address_bytes);
                } else {
                    datagram.put_u8(0xff);
                }
                datagram
                    .extend_from_slice(&buf[offset..offset + fragment_payload_len]);
                connection.send_datagram(datagram.freeze()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to send datagram fragment {fragment_id}: {e}"
                    ))
                })?;
                offset += fragment_payload_len;
            }
        }
        record_transfer(Some(traffic_context), 0, payload_len as u64);
    }
}

pub(super) async fn run_unidirectional_loop(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
    context: TuicFlowContext,
    child_tasks: TuicConnectionTaskOwner,
) -> std::io::Result<()> {
    let cleanup_session_map = udp_session_map.clone();
    let cleanup_cancel_token = cancel_token.clone();
    if !child_tasks.spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = cleanup_cancel_token.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    cleanup_session_map.retain(|assoc_id, session| {
                        if session.last_activity.elapsed() > IDLE_TIMEOUT {
                            session.cancel_token.cancel();
                            debug!("Removing inactive UDP session {assoc_id}");
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
    }) {
        return Ok(());
    }

    loop {
        let recv_stream = match connection.accept_uni().await {
            Ok(recv_stream) => recv_stream,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept unidirectional stream: {e}"
                )));
            }
        };

        let connection = connection.clone();
        let resolver = resolver.clone();
        let udp_session_map = udp_session_map.clone();
        let cancel_token = cancel_token.clone();
        let context = context.clone();
        let stream_child_tasks = child_tasks.clone();
        if !child_tasks.spawn(async move {
            match process_uni_stream(
                &connection,
                resolver,
                recv_stream,
                udp_session_map,
                cancel_token,
                context,
                stream_child_tasks,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    error!("Error processing uni stream, closing connection: {e}");
                    connection.close(0u32.into(), b"");
                }
            }
        }) {
            return Ok(());
        }
    }
    Ok(())
}

async fn process_uni_stream(
    connection: &quinn::Connection,
    resolver: Arc<dyn Resolver>,
    mut recv_stream: quinn::RecvStream,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
    context: TuicFlowContext,
    child_tasks: TuicConnectionTaskOwner,
) -> std::io::Result<()> {
    let tuic_version = recv_stream.read_u8().await?;
    if tuic_version != TUIC_VERSION {
        return Err(std::io::Error::other(format!(
            "invalid tuic version: {tuic_version}"
        )));
    }
    let command_type = recv_stream.read_u8().await?;

    if command_type == COMMAND_TYPE_DISSOCIATE {
        let assoc_id = recv_stream.read_u16().await?;
        if let Some((_, session)) = udp_session_map.remove(&assoc_id) {
            session.cancel_token.cancel();
        }
        return Ok(());
    }

    if command_type != COMMAND_TYPE_PACKET {
        return Err(std::io::Error::other(format!(
            "invalid uni stream command type: {command_type}"
        )));
    }

    let assoc_id = recv_stream.read_u16().await?;
    let packet_id = recv_stream.read_u16().await?;
    let frag_total = recv_stream.read_u8().await?;
    let frag_id = recv_stream.read_u8().await?;
    let payload_size = recv_stream.read_u16().await? as usize;
    let remote_location = read_address(&mut recv_stream).await?;

    let mut payload_fragment = allocate_vec(payload_size);
    recv_stream
        .read_exact(&mut payload_fragment)
        .await
        .map_err(std::io::Error::other)?;

    let mut fragments = FragmentAssembler::new();

    process_udp_packet(
        connection,
        &resolver,
        &udp_session_map,
        &mut fragments,
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        &payload_fragment,
        true,
        &cancel_token,
        &context,
        &child_tasks,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn process_udp_packet(
    connection: &quinn::Connection,
    resolver: &Arc<dyn Resolver>,
    udp_session_map: &UdpSessionMap,
    fragments: &mut FragmentAssembler,
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    remote_location: Option<NetLocation>,
    payload_fragment: &[u8],
    is_uni_stream: bool,
    cancel_token: &CancellationToken,
    context: &TuicFlowContext,
    child_tasks: &TuicConnectionTaskOwner,
) -> std::io::Result<()> {
    validate_fragment_header(frag_total, frag_id)?;

    let session = match udp_session_map.get(&assoc_id) {
        Some(s) => s,
        None => {
            if remote_location.is_none() {
                return Err(std::io::Error::other(
                    "ignoring packet with unknown session and empty address",
                ));
            }

            let remote_location = remote_location
                .clone()
                .ok_or_else(|| std::io::Error::other("missing initial address"))?;
            let resolved_address =
                resolve_single_address(resolver, &remote_location).await?;

            let bind_addr: SocketAddr = if resolved_address.is_ipv6() {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            };
            let socket = new_udp_socket(bind_addr, None)?;
            let base_context = context.traffic_context();

            let session = if is_uni_stream {
                let send_stream =
                    connection.open_uni().await.map_err(std::io::Error::other)?;
                UdpSession::start_with_send_stream(
                    assoc_id,
                    send_stream,
                    Arc::new(socket),
                    remote_location,
                    resolved_address,
                    base_context.clone(),
                    TuicUdpTaskScope {
                        parent_cancel_token: cancel_token,
                        child_tasks,
                    },
                )?
            } else {
                UdpSession::start_with_datagram(
                    assoc_id,
                    connection.clone(),
                    Arc::new(socket),
                    remote_location,
                    resolved_address,
                    base_context,
                    TuicUdpTaskScope {
                        parent_cancel_token: cancel_token,
                        child_tasks,
                    },
                )?
            };

            udp_session_map.insert(assoc_id, session);
            udp_session_map
                .get(&assoc_id)
                .expect("udp session should exist")
        }
    };

    let Some((remote_location, complete_payload)) = fragments.assemble(
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        remote_location,
        payload_fragment,
    )?
    else {
        return Ok(());
    };

    let (socket_addr, is_updated) =
        session.resolve_address(&remote_location, resolver).await?;
    let keep_session = forward_udp_payload(
        &session,
        context,
        assoc_id,
        &remote_location,
        socket_addr,
        &complete_payload,
    )
    .await?;

    drop(session);
    if !keep_session {
        udp_session_map.remove(&assoc_id);
        return Ok(());
    }
    if let Some(mut session) = udp_session_map.get_mut(&assoc_id) {
        session.last_activity = Instant::now();
        if is_updated {
            session.update_last_location(remote_location, socket_addr);
        }
    }

    Ok(())
}

pub(super) async fn forward_udp_payload(
    session: &UdpSession,
    context: &TuicFlowContext,
    assoc_id: u16,
    remote_location: &NetLocation,
    socket_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<bool> {
    let mut route_input = connection_routing_input(
        context.connection.inbound_tag.as_str(),
        context.connection.identity.as_str(),
        3,
        context.peer_addr,
        socket_addr,
        remote_location,
    );
    route_input.protocol = "tuic".to_string();
    let action =
        select_direct_outbound(&context.connection.runtime, &route_input, "udp")?;
    let mut traffic_context = session.base_context.clone();

    match action {
        DirectOutboundAction::Blackhole { tag } => {
            traffic_context = traffic_context.with_outbound_tag(tag.clone());
            record_transfer(Some(traffic_context), payload.len() as u64, 0);
            debug!(
                "TUIC UDP payload for session {} dropped by blackhole outbound {}",
                assoc_id, tag
            );
            return Ok(true);
        }
        DirectOutboundAction::Freedom { tag: Some(tag) } => {
            traffic_context = traffic_context.with_outbound_tag(tag);
        }
        DirectOutboundAction::Freedom { tag: None } => {}
        DirectOutboundAction::Socks { outbound }
        | DirectOutboundAction::Vless { outbound }
        | DirectOutboundAction::Trojan { outbound } => {
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

    session
        .response_contexts
        .insert(socket_addr, traffic_context.clone());
    match session.send_socket.send_to(payload, socket_addr).await {
        Ok(sent) => {
            record_transfer(Some(traffic_context), sent as u64, 0);
            Ok(true)
        }
        Err(err) => {
            error!("Failed to forward UDP payload for session {assoc_id}: {err}");
            Ok(false)
        }
    }
}

pub(super) async fn run_datagram_loop(
    connection: quinn::Connection,
    resolver: Arc<dyn Resolver>,
    udp_session_map: UdpSessionMap,
    cancel_token: CancellationToken,
    context: TuicFlowContext,
    child_tasks: TuicConnectionTaskOwner,
) -> std::io::Result<()> {
    let mut fragments = FragmentAssembler::new();
    let mut last_cleanup = Instant::now();

    loop {
        let now = Instant::now();
        if (now - last_cleanup) > CLEANUP_INTERVAL {
            udp_session_map.retain(|assoc_id, session| {
                if session.last_activity.elapsed() > IDLE_TIMEOUT {
                    session.cancel_token.cancel();
                    debug!("Removing inactive UDP session {assoc_id}");
                    false
                } else {
                    true
                }
            });
            last_cleanup = now;
        }

        let data = connection.read_datagram().await.map_err(|err| {
            std::io::Error::other(format!("failed to read datagram: {err}"))
        })?;

        let ParsedDatagram::Packet(packet) = parse_datagram(&data)? else {
            continue;
        };

        if let Err(e) = process_udp_packet(
            &connection,
            &resolver,
            &udp_session_map,
            &mut fragments,
            packet.assoc_id,
            packet.packet_id,
            packet.frag_total,
            packet.frag_id,
            packet.remote_location,
            packet.payload_fragment,
            false,
            &cancel_token,
            &context,
            &child_tasks,
        )
        .await
        {
            error!("Failed to process datagram UDP packet: {e}");
        }
    }
}

fn new_udp_socket(
    bind_address: SocketAddr,
    buffer_size: Option<usize>,
) -> std::io::Result<UdpSocket> {
    let socket2_socket = new_socket2_udp_socket_with_buffer_size(
        bind_address.is_ipv6(),
        None,
        Some(bind_address),
        false,
        buffer_size,
    )?;
    let std_socket: std::net::UdpSocket = socket2_socket.into();
    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}
