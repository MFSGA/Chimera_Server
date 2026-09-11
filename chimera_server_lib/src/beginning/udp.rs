use std::{
    collections::HashMap, future::poll_fn, net::SocketAddr, pin::Pin, sync::Arc,
    time::Duration,
};

#[cfg(test)]
use crate::xudp_registry::XUDP_GLOBAL_REATTACH_TTL;
#[cfg(test)]
use tokio::sync::{Notify, RwLock};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::{Instant, sleep},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, warn};

#[cfg(feature = "trojan")]
use crate::{
    handler::trojan_udp::TrojanUdpStream, outbound::connect_trojan_udp_via_outbound,
    resolver::NativeResolver,
};

use crate::{
    address::NetLocation,
    async_stream::{
        AsyncMessageStream, AsyncSessionMessageStream, AsyncTargetedMessageStream,
        SessionMessage,
    },
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        apply_routing_metadata, connection_routing_input, select_direct_outbound,
        select_direct_outbound_for_location,
    },
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{TrafficContext, record_transfer, register_connection},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const VMESS_UDP_MESSAGE_BUFFER_SIZE: usize = 8192;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_CHANNEL_CAPACITY: usize = 64;

mod global_xudp;
use global_xudp::*;
mod session_worker;
use session_worker::*;
mod targeted_session;
#[cfg(test)]
use targeted_session::run_multi_directional_udp_with_tasks;
#[cfg(feature = "trojan")]
use targeted_session::shutdown_targeted_message;
mod listener;
pub use listener::start_udp_server;
#[cfg(test)]
use listener::{
    UdpOutboundAction, bind_location_to_socket_addr, create_udp_listener,
    run_dokodemo_udp_server, select_udp_outbound,
};
#[cfg(all(test, feature = "shadowsocks"))]
use listener::{relay_shadowsocks_udp_packet, run_shadowsocks_udp_server};

pub(crate) async fn shutdown_global_xudp_workers() -> usize {
    global_xudp::shutdown_workers().await
}
// UDP routing supports freedom/blackhole plus Trojan proxy outbounds. SOCKS and
// VLESS remain TCP-only here; GlobalID XUDP + Trojan is intentionally fail-closed
// until a proxy tunnel can survive XUDP detach/reattach semantics correctly.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TargetedUdpSessionKey {
    target_addr: SocketAddr,
    outbound_tag: Option<String>,
}

struct SessionUdpResponse {
    session_id: u16,
    generation: u64,
    source: SocketAddr,
    payload: Vec<u8>,
    traffic_context: Option<TrafficContext>,
}

enum SessionUdpEvent {
    Data(SessionUdpResponse),
    End {
        session_id: u16,
        generation: u64,
        has_error: bool,
    },
}

struct LocalUdpPayload {
    target_addr: SocketAddr,
    payload: Vec<u8>,
}

pub(crate) async fn run_bidirectional_udp(
    mut server_stream: Box<dyn AsyncMessageStream>,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let inbound_tag = traffic_context
        .as_ref()
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default();
    let identity = traffic_context
        .as_ref()
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default();
    let (action, target_addr) = select_direct_outbound_for_location(
        &resolver,
        &remote_location,
        &runtime,
        OutboundRoutingContext::new(
            inbound_tag,
            identity,
            peer_addr,
            3,
            "udp",
            InboundRoutingMetadata {
                local_addr,
                ..InboundRoutingMetadata::default()
            },
        ),
    )
    .await?;
    let mut traffic_context =
        traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));

    let result = match action {
        DirectOutboundAction::Blackhole { tag } => {
            traffic_context = traffic_context
                .map(|context| context.with_outbound_tag(tag.clone()));
            let _connection_guard = register_connection(traffic_context.as_ref());
            consume_blackholed_udp_messages(
                &mut *server_stream,
                traffic_context,
                &remote_location,
                &tag,
            )
            .await
        }
        DirectOutboundAction::Freedom { tag } => {
            if let Some(tag) = tag {
                traffic_context =
                    traffic_context.map(|context| context.with_outbound_tag(tag));
            }
            let target_addr = target_addr.ok_or_else(|| {
                std::io::Error::other("UDP freedom route did not resolve target")
            })?;
            let bind_addr = if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let socket = UdpSocket::bind(bind_addr).await?;
            socket.connect(target_addr).await?;
            let _connection_guard = register_connection(traffic_context.as_ref());
            copy_bidirectional_udp_messages(
                &mut *server_stream,
                &socket,
                traffic_context,
            )
            .await
        }
        DirectOutboundAction::Trojan { outbound } => {
            #[cfg(feature = "trojan")]
            {
                traffic_context = traffic_context
                    .map(|context| context.with_outbound_tag(outbound.tag.clone()));
                let _connection_guard =
                    register_connection(traffic_context.as_ref());
                let mut proxy = connect_trojan_udp_via_outbound(
                    &resolver,
                    &remote_location,
                    &runtime,
                    &outbound,
                )
                .await?;
                let result = copy_bidirectional_trojan_udp_messages(
                    &mut *server_stream,
                    &mut proxy,
                    &remote_location,
                    traffic_context,
                )
                .await;
                let _ = shutdown_targeted_message(&mut proxy).await;
                result
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
    };

    let _ = shutdown_message(&mut *server_stream).await;
    result
}

pub(crate) async fn run_multi_directional_udp(
    server_stream: Box<dyn AsyncTargetedMessageStream>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    targeted_session::run_multi_directional_udp_with_tasks(
        server_stream,
        resolver,
        runtime,
        peer_addr,
        local_addr,
        traffic_context,
        TaskTracker::new(),
    )
    .await
}

pub(crate) async fn run_session_based_udp(
    mut server_stream: Box<dyn AsyncSessionMessageStream>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let traffic_context =
        traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));
    let inbound_tag = traffic_context
        .as_ref()
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default()
        .to_string();
    let identity = traffic_context
        .as_ref()
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default()
        .to_string();
    let _connection_guard = register_connection(traffic_context.as_ref());
    #[cfg(feature = "trojan")]
    let trojan_resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let (response_sender, mut response_receiver) =
        mpsc::channel::<SessionUdpEvent>(UDP_SESSION_CHANNEL_CAPACITY);
    let mut sessions = HashMap::<u16, SessionUdpWorker>::new();
    let mut next_generation = 1u64;
    let mut client_buffer = vec![0u8; UDP_BUFFER_SIZE];

    let result = loop {
        tokio::select! {
            request = read_session_message(&mut *server_stream, &mut client_buffer) => {
                let (
                    session_id,
                    target_addr,
                    global_id,
                    is_new,
                    payload_length,
                ) = match request {
                    Ok((SessionMessage::Data {
                        session_id,
                        target,
                        global_id,
                        is_new,
                    }, payload_length)) => {
                        (session_id, target, global_id, is_new, payload_length)
                    }
                    Ok((SessionMessage::End { session_id }, _)) => {
                        expire_session_udp_worker(&mut sessions, session_id).await;
                        debug!("session udp {} ended by peer", session_id);
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        break Ok(());
                    }
                    Err(error) => break Err(error),
                };
                if is_new && sessions.contains_key(&session_id) {
                    expire_session_udp_worker(&mut sessions, session_id).await;
                }
                let payload = client_buffer[..payload_length].to_vec();
                let target_location =
                    NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());
                let route_input = apply_routing_metadata(
                    connection_routing_input(
                        &inbound_tag,
                        &identity,
                        3,
                        peer_addr,
                        target_addr,
                        &target_location,
                    ),
                    InboundRoutingMetadata {
                        local_addr,
                        ..InboundRoutingMetadata::default()
                    },
                );
                let action = match select_direct_outbound(&runtime, &route_input, "udp") {
                    Ok(action) => action,
                    Err(error) => break Err(error),
                };

                match action {
                    DirectOutboundAction::Blackhole { tag } => {
                        let packet_context = traffic_context
                            .clone()
                            .map(|context| context.with_outbound_tag(tag.clone()));
                        record_transfer(packet_context, payload_length as u64, 0);
                        debug!(
                            "session udp packet {} to {} dropped by blackhole outbound {}",
                            session_id, target_location, tag
                        );
                    }
                    DirectOutboundAction::Freedom { tag } => {
                        let packet_context = match &tag {
                            Some(tag) => traffic_context
                                .clone()
                                .map(|context| context.with_outbound_tag(tag.clone())),
                            None => traffic_context.clone(),
                        };
                        let key = TargetedUdpSessionKey {
                            target_addr,
                            outbound_tag: tag,
                        };
                        let sender = match plan_session_udp_worker(
                            sessions.get(&session_id),
                            &key,
                            global_id,
                        ) {
                            SessionUdpWorkerPlan::Reuse(sender) => sender,
                            SessionUdpWorkerPlan::Replace => {
                                match replace_session_udp_worker(
                                    &mut sessions,
                                    session_id,
                                    &mut next_generation,
                                    SessionUdpWorkerStart {
                                        key: key.clone(),
                                        response_sender: response_sender.clone(),
                                        traffic_context: packet_context.clone(),
                                        global_id,
                                        idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                    },
                                )
                                .await
                                {
                                    Ok(sender) => sender,
                                    Err(error) => break Err(error),
                                }
                            }
                        };

                        if let Err(retry_payload) = sender.send_to(payload, target_addr).await {
                            let retry_sender = match replace_session_udp_worker(
                                &mut sessions,
                                session_id,
                                &mut next_generation,
                                SessionUdpWorkerStart {
                                    key,
                                    response_sender: response_sender.clone(),
                                    traffic_context: packet_context,
                                    global_id,
                                    idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                },
                            )
                            .await
                            {
                                Ok(sender) => sender,
                                Err(error) => break Err(error),
                            };
                            if retry_sender
                                .send_to(retry_payload, target_addr)
                                .await
                                .is_err()
                            {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "session udp socket closed before payload was sent",
                                ));
                            }
                        }
                    }
                    DirectOutboundAction::Trojan { outbound } => {
                        #[cfg(feature = "trojan")]
                        {
                            if global_id.is_some() {
                                break Err(std::io::Error::new(
                                    std::io::ErrorKind::Unsupported,
                                    "Trojan outbound for GlobalID XUDP is not implemented yet",
                                ));
                            }
                            let packet_context = traffic_context
                                .clone()
                                .map(|context| context.with_outbound_tag(outbound.tag.clone()));
                            let key = TargetedUdpSessionKey {
                                target_addr,
                                outbound_tag: Some(outbound.tag.clone()),
                            };
                            let sender = match plan_session_udp_worker(
                                sessions.get(&session_id),
                                &key,
                                None,
                            ) {
                                SessionUdpWorkerPlan::Reuse(sender) => sender,
                                SessionUdpWorkerPlan::Replace => {
                                    match replace_trojan_session_udp_worker(
                                        &mut sessions,
                                        session_id,
                                        &mut next_generation,
                                        TrojanSessionUdpWorkerStart {
                                            key: key.clone(),
                                            response_sender: response_sender.clone(),
                                            traffic_context: packet_context.clone(),
                                            resolver: trojan_resolver.clone(),
                                            runtime: runtime.clone(),
                                            outbound: outbound.clone(),
                                            global_id: None,
                                            idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                        },
                                    )
                                    .await
                                    {
                                        Ok(sender) => sender,
                                        Err(error) => break Err(error),
                                    }
                                }
                            };

                            if let Err(retry_payload) = sender.send_to(payload, target_addr).await {
                                let retry_sender = match replace_trojan_session_udp_worker(
                                    &mut sessions,
                                    session_id,
                                    &mut next_generation,
                                    TrojanSessionUdpWorkerStart {
                                        key,
                                        response_sender: response_sender.clone(),
                                        traffic_context: packet_context,
                                        resolver: trojan_resolver.clone(),
                                        runtime: runtime.clone(),
                                        outbound,
                                        global_id: None,
                                        idle_timeout: UDP_SESSION_IDLE_TIMEOUT,
                                    },
                                )
                                .await
                                {
                                    Ok(sender) => sender,
                                    Err(error) => break Err(error),
                                };
                                if retry_sender
                                    .send_to(retry_payload, target_addr)
                                    .await
                                    .is_err()
                                {
                                    break Err(std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "Trojan session UDP tunnel closed before payload was sent",
                                    ));
                                }
                            }
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
                            format!("TCP proxy outbound {} cannot be used for UDP", outbound.tag),
                        ));
                    }
                }
            }
            event = response_receiver.recv() => {
                let Some(event) = event else {
                    break Ok(());
                };
                match event {
                    SessionUdpEvent::Data(response) => {
                        if !is_current_session_udp_response(&sessions, &response) {
                            debug!(
                                "dropping stale session udp response for session {} generation {}",
                                response.session_id, response.generation
                            );
                            continue;
                        }
                        if let Err(error) = write_session_message(
                            &mut *server_stream,
                            response.session_id,
                            &response.payload,
                            &response.source,
                        )
                        .await
                        {
                            break Err(error);
                        }
                        if let Err(error) =
                            flush_session_message(&mut *server_stream).await
                        {
                            break Err(error);
                        }
                        record_transfer(
                            response.traffic_context,
                            0,
                            response.payload.len() as u64,
                        );
                    }
                    SessionUdpEvent::End {
                        session_id,
                        generation,
                        has_error,
                    } => {
                        if !is_current_session_udp_generation(
                            &sessions,
                            session_id,
                            generation,
                        ) {
                            debug!(
                                "dropping stale session udp End for session {} generation {}",
                                session_id, generation
                            );
                            continue;
                        }
                        expire_session_udp_worker(&mut sessions, session_id).await;
                        if let Err(error) = write_session_end(
                            &mut *server_stream,
                            session_id,
                            has_error,
                        )
                        .await
                        {
                            break Err(error);
                        }
                        if let Err(error) =
                            flush_session_message(&mut *server_stream).await
                        {
                            break Err(error);
                        }
                    }
                }
            }
        }
    };

    for (_, worker) in sessions.drain() {
        detach_session_udp_worker(worker).await;
    }
    let _ = shutdown_session_message(&mut *server_stream).await;
    result
}

async fn read_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
    buffer: &mut [u8],
) -> std::io::Result<(SessionMessage, usize)> {
    poll_fn(|cx| {
        let mut read_buffer = ReadBuf::new(buffer);
        match Pin::new(&mut *stream).poll_read_session_message(cx, &mut read_buffer)
        {
            std::task::Poll::Ready(Ok(message)) => {
                std::task::Poll::Ready(Ok((message, read_buffer.filled().len())))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

async fn write_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
    session_id: u16,
    payload: &[u8],
    source: &SocketAddr,
) -> std::io::Result<()> {
    poll_fn(|cx| {
        Pin::new(&mut *stream)
            .poll_write_session_message(cx, session_id, payload, source)
    })
    .await
}

async fn write_session_end(
    stream: &mut dyn AsyncSessionMessageStream,
    session_id: u16,
    has_error: bool,
) -> std::io::Result<()> {
    poll_fn(|cx| {
        Pin::new(&mut *stream).poll_write_session_end(cx, session_id, has_error)
    })
    .await
}

async fn flush_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
}

async fn shutdown_session_message(
    stream: &mut dyn AsyncSessionMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_shutdown_message(cx)).await
}

async fn consume_blackholed_udp_messages(
    stream: &mut dyn AsyncMessageStream,
    traffic_context: Option<TrafficContext>,
    remote_location: &NetLocation,
    outbound_tag: &str,
) -> std::io::Result<()> {
    let mut buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
    loop {
        let len = read_message(stream, &mut buffer).await?;
        if len == 0 {
            return Ok(());
        }
        record_transfer(traffic_context.clone(), len as u64, 0);
        debug!(
            "udp message to {} dropped by blackhole outbound {}",
            remote_location, outbound_tag
        );
    }
}

#[cfg(feature = "trojan")]
async fn copy_bidirectional_trojan_udp_messages(
    stream: &mut dyn AsyncMessageStream,
    proxy: &mut TrojanUdpStream,
    target: &NetLocation,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let mut client_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
    let mut target_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];

    loop {
        tokio::select! {
            result = read_message(stream, &mut client_buffer) => {
                let len = result?;
                if len == 0 {
                    return Ok(());
                }
                proxy.send_to(target, &client_buffer[..len]).await?;
                record_transfer(traffic_context.clone(), len as u64, 0);
            }
            result = proxy.recv_from(&mut target_buffer) => {
                let (_source, len) = result?;
                write_message(stream, &target_buffer[..len]).await?;
                flush_message(stream).await?;
                record_transfer(traffic_context.clone(), 0, len as u64);
            }
        }
    }
}

async fn copy_bidirectional_udp_messages(
    stream: &mut dyn AsyncMessageStream,
    socket: &UdpSocket,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let mut client_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
    let mut target_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];

    loop {
        tokio::select! {
            result = read_message(stream, &mut client_buffer) => {
                let len = result?;
                if len == 0 {
                    return Ok(());
                }
                let written = socket.send(&client_buffer[..len]).await?;
                if written != len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!("udp message was truncated: wrote {written} of {len} bytes"),
                    ));
                }
                record_transfer(traffic_context.clone(), len as u64, 0);
            }
            result = socket.recv(&mut target_buffer) => {
                let len = result?;
                write_message(stream, &target_buffer[..len]).await?;
                flush_message(stream).await?;
                record_transfer(traffic_context.clone(), 0, len as u64);
            }
        }
    }
}

async fn read_message(
    stream: &mut dyn AsyncMessageStream,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buffer);
        match Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf) {
            std::task::Poll::Ready(Ok(())) => {
                std::task::Poll::Ready(Ok(read_buf.filled().len()))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

async fn write_message(
    stream: &mut dyn AsyncMessageStream,
    buffer: &[u8],
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, buffer)).await
}

async fn flush_message(stream: &mut dyn AsyncMessageStream) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
}

async fn shutdown_message(
    stream: &mut dyn AsyncMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_shutdown_message(cx)).await
}

#[cfg(test)]
mod tests;
