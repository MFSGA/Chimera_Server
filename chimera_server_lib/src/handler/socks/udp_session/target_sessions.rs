use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::{
    sync::{Notify, mpsc},
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};

use crate::traffic::{TrafficContext, record_transfer};
#[cfg(feature = "trojan")]
use crate::{
    address::NetLocation,
    outbound::connect_trojan_udp_via_outbound,
    resolver::Resolver,
    runtime::{DataPlaneRuntime, OutboundSummary},
};

use super::super::{
    UDP_BUFFER_SIZE, UDP_TARGET_SESSION_ACTIVITY_CHECK, build_udp_response_packet,
    create_udp_socket_for_target,
};
#[cfg(feature = "trojan")]
use super::super::{XRAY_SOCKS_UDP_PACKET_SIZE, build_udp_response_packet_location};

pub(in crate::handler::socks) struct SocksUdpClientSession {
    pub(in crate::handler::socks) sender:
        mpsc::Sender<(SocketAddr, Vec<u8>, Option<TrafficContext>)>,
    pub(in crate::handler::socks) task: Option<JoinHandle<()>>,
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
pub(super) struct SocksTrojanUdpClientSession {
    pub(super) sender: mpsc::Sender<(NetLocation, Vec<u8>, Option<TrafficContext>)>,
    task: Option<JoinHandle<()>>,
}

#[cfg(feature = "trojan")]
#[derive(Clone)]
pub(super) struct SocksTrojanUdpSessionStart {
    pub(super) outbound: OutboundSummary,
    pub(super) resolver: Arc<dyn Resolver>,
    pub(super) runtime: DataPlaneRuntime,
    pub(super) client_endpoint: SocketAddr,
    pub(super) client_socket: Arc<tokio::net::UdpSocket>,
    pub(super) association_activity: Option<Arc<Notify>>,
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
pub(in crate::handler::socks) struct XrayUdpActivityWindow {
    downstream_activity: bool,
}

impl XrayUdpActivityWindow {
    pub(in crate::handler::socks) fn new() -> Self {
        Self {
            downstream_activity: true,
        }
    }

    pub(in crate::handler::socks) fn record_downstream(&mut self) {
        self.downstream_activity = true;
    }

    pub(in crate::handler::socks) fn keep_alive_on_check(&mut self) -> bool {
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
pub(super) async fn send_trojan_udp_target_payload(
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

pub(in crate::handler::socks) async fn send_udp_target_payload(
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

#[cfg(test)]
pub(in crate::handler::socks) fn prune_closed_udp_sessions(
    client_sessions: &mut HashMap<(SocketAddr, bool), SocksUdpClientSession>,
) {
    client_sessions.retain(|_, session| !session.sender.is_closed());
}

pub(super) async fn stop_udp_client_sessions(
    client_sessions: &mut HashMap<(SocketAddr, bool), SocksUdpClientSession>,
) {
    for (_, session) in client_sessions.drain() {
        session.stop().await;
    }
}

#[cfg(feature = "trojan")]
pub(super) async fn stop_trojan_udp_client_sessions(
    client_sessions: &mut HashMap<(SocketAddr, String), SocksTrojanUdpClientSession>,
) {
    for (_, session) in client_sessions.drain() {
        session.stop().await;
    }
}
