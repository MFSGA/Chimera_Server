use std::{
    collections::HashMap, future::poll_fn, net::SocketAddr, pin::Pin, sync::Arc,
};

use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    sync::mpsc,
    time::{Instant, sleep},
};
use tokio_util::task::TaskTracker;
use tracing::{debug, warn};

#[cfg(feature = "trojan")]
use crate::outbound::connect_trojan_udp_via_outbound;
use crate::{
    address::NetLocation,
    async_stream::AsyncTargetedMessageStream,
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{TrafficContext, record_transfer, register_connection},
};

#[cfg(feature = "trojan")]
use crate::resolver::resolve_single_address;

#[cfg(feature = "trojan")]
use super::VMESS_UDP_MESSAGE_BUFFER_SIZE;
use super::{
    TargetedUdpSessionKey, UDP_BUFFER_SIZE, UDP_SESSION_CHANNEL_CAPACITY,
    UDP_SESSION_IDLE_TIMEOUT,
};

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TrojanUdpSessionKey {
    target: NetLocation,
    outbound_tag: String,
}

struct TargetedUdpResponse {
    source: SocketAddr,
    payload: Vec<u8>,
    traffic_context: Option<TrafficContext>,
}

pub(super) async fn run_multi_directional_udp_with_tasks(
    mut server_stream: Box<dyn AsyncTargetedMessageStream>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
    session_tasks: TaskTracker,
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
    let (response_sender, mut response_receiver) =
        mpsc::channel::<TargetedUdpResponse>(UDP_SESSION_CHANNEL_CAPACITY);
    let mut sessions =
        HashMap::<TargetedUdpSessionKey, mpsc::Sender<Vec<u8>>>::new();
    #[cfg(feature = "trojan")]
    let mut trojan_sessions =
        HashMap::<TrojanUdpSessionKey, mpsc::Sender<Vec<u8>>>::new();
    let mut client_buffer = vec![0u8; UDP_BUFFER_SIZE];

    let result: std::io::Result<()> = async {
        loop {
            tokio::select! {
            request = read_targeted_message(&mut *server_stream, &mut client_buffer) => {
                let (target_location, payload_length) = match request {
                    Ok(request) => request,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        break Ok(());
                    }
                    Err(error) => break Err(error),
                };
                let payload = client_buffer[..payload_length].to_vec();
                let (action, target_addr) = match select_direct_outbound_for_location(
                    &resolver,
                    &target_location,
                    &runtime,
                    OutboundRoutingContext::new(
                        &inbound_tag,
                        &identity,
                        peer_addr,
                        3,
                        "udp",
                        InboundRoutingMetadata {
                            local_addr,
                            ..InboundRoutingMetadata::default()
                        },
                    ),
                )
                .await
                {
                    Ok(selection) => selection,
                    Err(error) => break Err(error),
                };

                match action {
                    DirectOutboundAction::Blackhole { tag } => {
                        let packet_context = traffic_context
                            .clone()
                            .map(|context| context.with_outbound_tag(tag.clone()));
                        record_transfer(packet_context, payload_length as u64, 0);
                        debug!(
                            "targeted udp packet to {} dropped by blackhole outbound {}",
                            target_location, tag
                        );
                    }
                    DirectOutboundAction::Freedom { tag } => {
                        let target_addr = target_addr.ok_or_else(|| {
                            std::io::Error::other(
                                "targeted UDP freedom route did not resolve target",
                            )
                        })?;
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
                        let sender = match sessions.get(&key) {
                            Some(sender) if !sender.is_closed() => sender.clone(),
                            _ => {
                                let sender = start_targeted_udp_session(
                                    &session_tasks,
                                    key.clone(),
                                    response_sender.clone(),
                                    packet_context.clone(),
                                )
                                .await?;
                                sessions.insert(key.clone(), sender.clone());
                                sender
                            }
                        };

                        if sender.send(payload).await.is_err() {
                            sessions.remove(&key);
                            let sender = start_targeted_udp_session(
                                &session_tasks,
                                key.clone(),
                                response_sender.clone(),
                                packet_context,
                            )
                            .await?;
                            sender.send(client_buffer[..payload_length].to_vec()).await.map_err(
                                |_| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "targeted udp session closed before payload was sent",
                                    )
                                },
                            )?;
                            sessions.insert(key, sender);
                        }
                    }
                    DirectOutboundAction::Trojan { outbound } => {
                        #[cfg(feature = "trojan")]
                        {
                            let packet_context = traffic_context
                                .clone()
                                .map(|context| context.with_outbound_tag(outbound.tag.clone()));
                            let key = TrojanUdpSessionKey {
                                target: target_location.clone(),
                                outbound_tag: outbound.tag.clone(),
                            };
                            let sender = match trojan_sessions.get(&key) {
                                Some(sender) if !sender.is_closed() => sender.clone(),
                                _ => {
                                    let sender = start_trojan_targeted_udp_session(
                                        &session_tasks,
                                        resolver.clone(),
                                        runtime.clone(),
                                        key.clone(),
                                        outbound.clone(),
                                        response_sender.clone(),
                                        packet_context.clone(),
                                    )
                                    .await?;
                                    trojan_sessions.insert(key.clone(), sender.clone());
                                    sender
                                }
                            };

                            if sender.send(payload).await.is_err() {
                                trojan_sessions.remove(&key);
                                let sender = start_trojan_targeted_udp_session(
                                    &session_tasks,
                                    resolver.clone(),
                                    runtime.clone(),
                                    key.clone(),
                                    outbound,
                                    response_sender.clone(),
                                    packet_context,
                                )
                                .await?;
                                sender
                                    .send(client_buffer[..payload_length].to_vec())
                                    .await
                                    .map_err(|_| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::BrokenPipe,
                                            "Trojan targeted UDP session closed before payload was sent",
                                        )
                                    })?;
                                trojan_sessions.insert(key, sender);
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
                response = response_receiver.recv() => {
                    let Some(response) = response else {
                        break Ok(());
                    };
                    write_sourced_message(
                        &mut *server_stream,
                        &response.payload,
                        &response.source,
                    )
                    .await?;
                    flush_targeted_message(&mut *server_stream).await?;
                    record_transfer(
                        response.traffic_context,
                        0,
                        response.payload.len() as u64,
                    );
                }
            }
        }
    }
    .await;

    drop(sessions);
    #[cfg(feature = "trojan")]
    drop(trojan_sessions);
    drop(response_sender);
    drop(response_receiver);
    session_tasks.close();
    session_tasks.wait().await;
    let _ = shutdown_targeted_message(&mut *server_stream).await;
    result
}

#[cfg(feature = "trojan")]
async fn start_trojan_targeted_udp_session(
    session_tasks: &TaskTracker,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    key: TrojanUdpSessionKey,
    outbound: crate::runtime::OutboundSummary,
    response_sender: mpsc::Sender<TargetedUdpResponse>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    let mut proxy =
        connect_trojan_udp_via_outbound(&resolver, &key.target, &runtime, &outbound)
            .await?;
    let (sender, mut receiver) =
        mpsc::channel::<Vec<u8>>(UDP_SESSION_CHANNEL_CAPACITY);

    session_tasks.spawn(async move {
        let mut response_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
        let mut idle = Box::pin(sleep(UDP_SESSION_IDLE_TIMEOUT));
        loop {
            tokio::select! {
                _ = idle.as_mut() => break,
                payload = receiver.recv() => {
                    let Some(payload) = payload else {
                        break;
                    };
                    if let Err(error) = proxy.send_to(&key.target, &payload).await {
                        debug!(
                            "Trojan targeted UDP write to {} via {} failed: {}",
                            key.target, key.outbound_tag, error
                        );
                        break;
                    }
                    record_transfer(
                        traffic_context.clone(),
                        payload.len() as u64,
                        0,
                    );
                    idle.as_mut().reset(
                        Instant::now() + UDP_SESSION_IDLE_TIMEOUT,
                    );
                }
                response = proxy.recv_from(&mut response_buffer) => {
                    let (source_location, length) = match response {
                        Ok(response) => response,
                        Err(error) => {
                            debug!(
                                "Trojan targeted UDP receive via {} failed: {}",
                                key.outbound_tag, error
                            );
                            break;
                        }
                    };
                    let source = match source_location.to_socket_addr_nonblocking() {
                        Some(source) => source,
                        None => match resolve_single_address(&resolver, &source_location).await {
                            Ok(source) => source,
                            Err(error) => {
                                debug!(
                                    "Trojan targeted UDP response source {} did not resolve: {}",
                                    source_location, error
                                );
                                break;
                            }
                        },
                    };
                    let response = TargetedUdpResponse {
                        source,
                        payload: response_buffer[..length].to_vec(),
                        traffic_context: traffic_context.clone(),
                    };
                    if response_sender.send(response).await.is_err() {
                        break;
                    }
                    idle.as_mut().reset(
                        Instant::now() + UDP_SESSION_IDLE_TIMEOUT,
                    );
                }
            }
        }
        let _ = shutdown_targeted_message(&mut proxy).await;
    });

    Ok(sender)
}

async fn start_targeted_udp_session(
    session_tasks: &TaskTracker,
    key: TargetedUdpSessionKey,
    response_sender: mpsc::Sender<TargetedUdpResponse>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    let bind_addr = if key.target_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let (sender, mut receiver) =
        mpsc::channel::<Vec<u8>>(UDP_SESSION_CHANNEL_CAPACITY);

    session_tasks.spawn(async move {
        let mut response_buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut idle = Box::pin(sleep(UDP_SESSION_IDLE_TIMEOUT));
        loop {
            tokio::select! {
                _ = idle.as_mut() => break,
                payload = receiver.recv() => {
                    let Some(payload) = payload else {
                        break;
                    };
                    match socket.send_to(&payload, key.target_addr).await {
                        Ok(written) if written == payload.len() => {
                            record_transfer(
                                traffic_context.clone(),
                                written as u64,
                                0,
                            );
                            idle.as_mut().reset(
                                Instant::now() + UDP_SESSION_IDLE_TIMEOUT,
                            );
                        }
                        Ok(written) => {
                            warn!(
                                "targeted udp write to {} was truncated: {} of {} bytes",
                                key.target_addr,
                                written,
                                payload.len()
                            );
                            break;
                        }
                        Err(error) => {
                            debug!(
                                "targeted udp write to {} failed: {}",
                                key.target_addr, error
                            );
                            break;
                        }
                    }
                }
                response = socket.recv_from(&mut response_buffer) => {
                    let (length, source) = match response {
                        Ok(response) => response,
                        Err(error) => {
                            debug!(
                                "targeted udp receive for {} failed: {}",
                                key.target_addr, error
                            );
                            break;
                        }
                    };
                    let response = TargetedUdpResponse {
                        source,
                        payload: response_buffer[..length].to_vec(),
                        traffic_context: traffic_context.clone(),
                    };
                    if response_sender.send(response).await.is_err() {
                        break;
                    }
                    idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
                }
            }
        }
    });

    Ok(sender)
}

async fn read_targeted_message(
    stream: &mut dyn AsyncTargetedMessageStream,
    buffer: &mut [u8],
) -> std::io::Result<(NetLocation, usize)> {
    poll_fn(|cx| {
        let mut read_buffer = ReadBuf::new(buffer);
        match Pin::new(&mut *stream).poll_read_targeted_message(cx, &mut read_buffer)
        {
            std::task::Poll::Ready(Ok(target)) => {
                std::task::Poll::Ready(Ok((target, read_buffer.filled().len())))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

async fn write_sourced_message(
    stream: &mut dyn AsyncTargetedMessageStream,
    payload: &[u8],
    source: &SocketAddr,
) -> std::io::Result<()> {
    poll_fn(|cx| {
        Pin::new(&mut *stream).poll_write_sourced_message(cx, payload, source)
    })
    .await
}

async fn flush_targeted_message(
    stream: &mut dyn AsyncTargetedMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
}

pub(super) async fn shutdown_targeted_message(
    stream: &mut dyn AsyncTargetedMessageStream,
) -> std::io::Result<()> {
    poll_fn(|cx| Pin::new(&mut *stream).poll_shutdown_message(cx)).await
}
