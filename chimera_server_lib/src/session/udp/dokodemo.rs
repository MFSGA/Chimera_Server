use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "vless-reverse")]
use tokio::sync::oneshot;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc},
    time::{Instant, sleep},
};
use tracing::{debug, warn};

#[cfg(feature = "vless")]
use crate::outbound::{VlessUdpSendOutcome, connect_vless_udp_via_outbound};
#[cfg(target_os = "linux")]
use crate::util::socket::recv_udp_with_original_destination;
use crate::{
    address::{Address, NetLocation},
    config::server_config::DokodemoDoorConfig,
    outbound::USER_DOMAIN_ACCESS_BLACKHOLE_TAG,
    routing_process::enrich_routing_input,
    routing_state::RoutingInput,
    runtime::{DataPlaneRuntime, OutboundSummary},
    traffic::{TrafficContext, record_transfer, record_transfer_ref},
    user_domain::UserDomainAccessAuditContext,
};
#[cfg(feature = "trojan")]
use crate::{
    handler::trojan_udp::TrojanUdpStream, outbound::connect_trojan_udp_via_outbound,
};

use super::{
    UDP_BUFFER_SIZE, UDP_SESSION_CHANNEL_CAPACITY, UDP_SESSION_IDLE_TIMEOUT,
};
#[cfg(feature = "trojan")]
use crate::session::udp::shutdown_targeted_message;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UdpOutboundAction {
    Freedom {
        tag: Option<String>,
    },
    Blackhole {
        tag: String,
    },
    Trojan {
        outbound: OutboundSummary,
    },
    #[cfg(feature = "vless")]
    Vless {
        outbound: OutboundSummary,
    },
    #[cfg(feature = "vless-reverse")]
    VlessReverse {
        tag: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpOutboundIdentity {
    Freedom(Option<String>),
    Blackhole(String),
    Trojan(String),
    #[cfg(feature = "vless")]
    Vless(String),
    #[cfg(feature = "vless-reverse")]
    VlessReverse(String),
}

impl UdpOutboundAction {
    fn identity(&self) -> UdpOutboundIdentity {
        match self {
            Self::Freedom { tag } => UdpOutboundIdentity::Freedom(tag.clone()),
            Self::Blackhole { tag } => UdpOutboundIdentity::Blackhole(tag.clone()),
            Self::Trojan { outbound } => {
                UdpOutboundIdentity::Trojan(outbound.tag.clone())
            }
            #[cfg(feature = "vless")]
            Self::Vless { outbound } => {
                UdpOutboundIdentity::Vless(outbound.tag.clone())
            }
            #[cfg(feature = "vless-reverse")]
            Self::VlessReverse { tag } => {
                UdpOutboundIdentity::VlessReverse(tag.clone())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    outbound_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: NetLocation,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DokodemoTrojanUdpSessionKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target: NetLocation,
    outbound_tag: String,
}

struct DokodemoUdpDatagram {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: NetLocation,
    payload: Vec<u8>,
}

#[cfg(feature = "vless-reverse")]
struct ReverseUdpPayload {
    payload: Vec<u8>,
    completion: oneshot::Sender<std::io::Result<()>>,
}

#[derive(Clone)]
enum UdpActiveRouteSender {
    Freedom(mpsc::Sender<Vec<u8>>),
    #[cfg(feature = "trojan")]
    Trojan(mpsc::Sender<Vec<u8>>),
    #[cfg(feature = "vless")]
    Vless(mpsc::Sender<Vec<u8>>),
    #[cfg(feature = "vless-reverse")]
    VlessReverse(mpsc::Sender<ReverseUdpPayload>),
}

impl UdpActiveRouteSender {
    fn is_closed(&self) -> bool {
        match self {
            Self::Freedom(sender) => sender.is_closed(),
            #[cfg(feature = "trojan")]
            Self::Trojan(sender) => sender.is_closed(),
            #[cfg(feature = "vless")]
            Self::Vless(sender) => sender.is_closed(),
            #[cfg(feature = "vless-reverse")]
            Self::VlessReverse(sender) => sender.is_closed(),
        }
    }

    fn same_channel(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Freedom(left), Self::Freedom(right)) => left.same_channel(right),
            #[cfg(feature = "trojan")]
            (Self::Trojan(left), Self::Trojan(right)) => left.same_channel(right),
            #[cfg(feature = "vless")]
            (Self::Vless(left), Self::Vless(right)) => left.same_channel(right),
            #[cfg(feature = "vless-reverse")]
            (Self::VlessReverse(left), Self::VlessReverse(right)) => {
                left.same_channel(right)
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
struct UdpActiveRoute {
    action: UdpOutboundAction,
    sender: UdpActiveRouteSender,
}

struct UdpRelayState {
    reply_sink: Arc<dyn UdpReplySink>,
    session_slots: Option<Arc<Semaphore>>,
    session_idle_timeout: Duration,
    active_routes: Mutex<HashMap<UdpFlowKey, UdpActiveRoute>>,
    sessions: Mutex<HashMap<UdpSessionKey, mpsc::Sender<Vec<u8>>>>,
    #[cfg(feature = "vless")]
    vless_sessions: Mutex<HashMap<UdpSessionKey, mpsc::Sender<Vec<u8>>>>,
    #[cfg(feature = "trojan")]
    trojan_sessions:
        Mutex<HashMap<DokodemoTrojanUdpSessionKey, mpsc::Sender<Vec<u8>>>>,
    #[cfg(feature = "vless-reverse")]
    reverse_sessions: Mutex<HashMap<UdpSessionKey, mpsc::Sender<ReverseUdpPayload>>>,
}

struct UdpSessionReceiver<T = Vec<u8>> {
    receiver: mpsc::Receiver<T>,
    session_sender: mpsc::Sender<T>,
    _session_permit: Option<OwnedSemaphorePermit>,
}

impl<T> UdpSessionReceiver<T> {
    fn new(
        receiver: mpsc::Receiver<T>,
        session_permit: Option<OwnedSemaphorePermit>,
        session_sender: mpsc::Sender<T>,
    ) -> Self {
        Self {
            receiver,
            session_sender,
            _session_permit: session_permit,
        }
    }

    async fn recv(&mut self) -> Option<T> {
        self.receiver.recv().await
    }
}

async fn remove_udp_session_if_current<K, T>(
    sessions: &Mutex<HashMap<K, mpsc::Sender<T>>>,
    key: &K,
    sender: &mpsc::Sender<T>,
) where
    K: Eq + std::hash::Hash,
{
    let mut sessions = sessions.lock().await;
    if sessions
        .get(key)
        .is_some_and(|current| current.same_channel(sender))
    {
        sessions.remove(key);
    }
}

impl UdpRelayState {
    fn new(reply_sink: Arc<dyn UdpReplySink>, max_sessions: Option<usize>) -> Self {
        Self::with_idle_timeout(reply_sink, max_sessions, UDP_SESSION_IDLE_TIMEOUT)
    }

    fn with_idle_timeout(
        reply_sink: Arc<dyn UdpReplySink>,
        max_sessions: Option<usize>,
        session_idle_timeout: Duration,
    ) -> Self {
        Self {
            reply_sink,
            session_slots: max_sessions.map(|limit| Arc::new(Semaphore::new(limit))),
            session_idle_timeout,
            active_routes: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "vless")]
            vless_sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "trojan")]
            trojan_sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "vless-reverse")]
            reverse_sessions: Mutex::new(HashMap::new()),
        }
    }

    fn acquire_session_slot(&self) -> std::io::Result<Option<OwnedSemaphorePermit>> {
        let Some(slots) = &self.session_slots else {
            return Ok(None);
        };
        slots.clone().try_acquire_owned().map(Some).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "dokodemo-door UDP session limit reached",
            )
        })
    }

    async fn active_route(&self, flow: &UdpFlowKey) -> Option<UdpOutboundAction> {
        let mut routes = self.active_routes.lock().await;
        let route = routes.get(flow)?;
        if !route.sender.is_closed() {
            return Some(route.action.clone());
        }
        routes.remove(flow);
        None
    }
}

async fn remove_active_route_if_current(
    relay_state: &UdpRelayState,
    flow: &UdpFlowKey,
    identity: UdpOutboundIdentity,
    sender: UdpActiveRouteSender,
) {
    let mut routes = relay_state.active_routes.lock().await;
    if routes.get(flow).is_some_and(|route| {
        route.action.identity() == identity && route.sender.same_channel(&sender)
    }) {
        routes.remove(flow);
    }
}

async fn remember_active_route(
    relay_state: &UdpRelayState,
    flow: UdpFlowKey,
    action: UdpOutboundAction,
    sender: UdpActiveRouteSender,
) {
    if !sender.is_closed() {
        relay_state
            .active_routes
            .lock()
            .await
            .insert(flow, UdpActiveRoute { action, sender });
    }
}

#[async_trait::async_trait]
pub(crate) trait UdpReplySink: Send + Sync {
    fn local_addr(&self) -> Option<SocketAddr>;

    fn local_addr_for(&self, _client_addr: SocketAddr) -> Option<SocketAddr> {
        self.local_addr()
    }

    async fn send_response(
        &self,
        payload: &[u8],
        client_addr: SocketAddr,
        source_addr: SocketAddr,
    ) -> std::io::Result<usize>;
}

struct SocketUdpReplySink(Arc<UdpSocket>);

#[async_trait::async_trait]
impl UdpReplySink for SocketUdpReplySink {
    fn local_addr(&self) -> Option<SocketAddr> {
        self.0.local_addr().ok()
    }

    async fn send_response(
        &self,
        payload: &[u8],
        client_addr: SocketAddr,
        _source_addr: SocketAddr,
    ) -> std::io::Result<usize> {
        self.0.send_to(payload, client_addr).await
    }
}

#[cfg(all(feature = "tun-gateway", target_os = "linux"))]
pub(crate) struct TunUdpForwarder {
    relay_state: Arc<UdpRelayState>,
    inbound_tag: String,
    user_level: u32,
    runtime: DataPlaneRuntime,
}

#[cfg(all(feature = "tun-gateway", target_os = "linux"))]
impl TunUdpForwarder {
    pub(crate) fn new(
        inbound_tag: String,
        user_level: u32,
        runtime: DataPlaneRuntime,
        reply_sink: Arc<dyn UdpReplySink>,
        max_sessions: usize,
    ) -> Self {
        Self::with_session_idle_timeout(
            inbound_tag,
            user_level,
            runtime,
            reply_sink,
            max_sessions,
            UDP_SESSION_IDLE_TIMEOUT,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_idle_timeout(
        inbound_tag: String,
        user_level: u32,
        runtime: DataPlaneRuntime,
        reply_sink: Arc<dyn UdpReplySink>,
        max_sessions: usize,
        session_idle_timeout: Duration,
    ) -> Self {
        Self::with_session_idle_timeout(
            inbound_tag,
            user_level,
            runtime,
            reply_sink,
            max_sessions,
            session_idle_timeout,
        )
    }

    fn with_session_idle_timeout(
        inbound_tag: String,
        user_level: u32,
        runtime: DataPlaneRuntime,
        reply_sink: Arc<dyn UdpReplySink>,
        max_sessions: usize,
        session_idle_timeout: Duration,
    ) -> Self {
        Self {
            relay_state: Arc::new(UdpRelayState::with_idle_timeout(
                reply_sink,
                Some(max_sessions),
                session_idle_timeout,
            )),
            inbound_tag,
            user_level,
            runtime,
        }
    }

    pub(crate) async fn forward(
        &self,
        packet: watfaq_netstack::UdpPacket,
    ) -> std::io::Result<()> {
        let client_addr = packet.local_addr;
        let target_addr = packet.remote_addr;
        if client_addr.is_ipv4() != target_addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "tunGateway UDP packet has mismatched address families",
            ));
        }
        relay_dokodemo_udp_datagram(
            Arc::clone(&self.relay_state),
            self.inbound_tag.clone(),
            self.user_level,
            self.runtime.clone(),
            DokodemoUdpDatagram {
                client_addr,
                target_addr,
                target_location: NetLocation::from_ip_addr(
                    target_addr.ip(),
                    target_addr.port(),
                ),
                payload: packet.data().to_vec(),
            },
        )
        .await
    }
}

pub(crate) async fn run_dokodemo_udp_server(
    socket: Arc<UdpSocket>,
    config: DokodemoDoorConfig,
    target_addr: impl Into<Option<SocketAddr>> + Send,
    inbound_tag: String,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let target_addr = target_addr.into();
    let relay_state = Arc::new(UdpRelayState::new(
        Arc::new(SocketUdpReplySink(Arc::clone(&socket))),
        None,
    ));
    let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let (len, client_addr, datagram_target, target_location) =
            if config.follow_redirect {
                #[cfg(target_os = "linux")]
                {
                    let (len, client_addr, original_destination) =
                        recv_udp_with_original_destination(&socket, &mut recv_buf)
                            .await?;
                    (
                        len,
                        client_addr,
                        original_destination,
                        NetLocation::from_ip_addr(
                            original_destination.ip(),
                            original_destination.port(),
                        ),
                    )
                }
                #[cfg(not(target_os = "linux"))]
                unreachable!("non-Linux followRedirect returned before receive loop")
            } else {
                let (len, client_addr) = socket.recv_from(&mut recv_buf).await?;
                let target_addr = target_addr.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "dokodemo-door UDP fixed target is unavailable",
                    )
                })?;
                (len, client_addr, target_addr, config.target.clone())
            };
        let payload = recv_buf[..len].to_vec();
        let inbound_tag = inbound_tag.clone();
        let task_runtime = runtime.clone();
        let relay_state = relay_state.clone();

        runtime.spawn_inbound_connection(async move {
            if let Err(err) = relay_dokodemo_udp_datagram(
                relay_state,
                inbound_tag,
                config.user_level,
                task_runtime,
                DokodemoUdpDatagram {
                    client_addr,
                    target_addr: datagram_target,
                    target_location,
                    payload,
                },
            )
            .await
            {
                debug!(
                    "dokodemo-door udp relay for {} ended with error: {}",
                    client_addr, err
                );
            }
        });
    }
}

async fn relay_dokodemo_udp_datagram(
    relay_state: Arc<UdpRelayState>,
    inbound_tag: String,
    user_level: u32,
    runtime: DataPlaneRuntime,
    datagram: DokodemoUdpDatagram,
) -> std::io::Result<()> {
    let DokodemoUdpDatagram {
        client_addr,
        target_addr,
        target_location,
        payload,
    } = datagram;
    let flow_key = UdpFlowKey {
        client_addr,
        target_addr,
        target_location: target_location.clone(),
    };
    let outbound_action = match relay_state.active_route(&flow_key).await {
        Some(action) => action,
        None => {
            select_udp_outbound(
                &runtime,
                &inbound_tag,
                client_addr,
                relay_state.reply_sink.local_addr_for(client_addr),
                target_addr,
                &target_location,
            )
            .await?
        }
    };

    let mut traffic_context = TrafficContext::new("dokodemo-door")
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_addr.ip())
        .with_user_level(user_level);
    runtime.apply_traffic_stats_policy(&mut traffic_context);

    match outbound_action {
        UdpOutboundAction::Blackhole { tag } => {
            let traffic_context = traffic_context.with_outbound_tag(tag.clone());
            debug!(
                "dokodemo-door udp packet from {} to {} dropped by blackhole outbound {}",
                client_addr, target_location, tag
            );
            record_transfer(Some(traffic_context), payload.len() as u64, 0);
            Ok(())
        }
        UdpOutboundAction::Freedom { tag } => {
            let route_action = UdpOutboundAction::Freedom { tag: tag.clone() };
            let traffic_context = match &tag {
                Some(tag) => traffic_context.with_outbound_tag(tag.clone()),
                None => traffic_context,
            };
            let key = UdpSessionKey {
                client_addr,
                target_addr,
                outbound_tag: tag.clone(),
            };
            let sender = freedom_udp_session_sender(
                Arc::clone(&relay_state),
                key,
                target_location,
                tag,
                traffic_context,
                &runtime,
            )
            .await?;
            remember_active_route(
                &relay_state,
                flow_key,
                route_action,
                UdpActiveRouteSender::Freedom(sender.clone()),
            )
            .await;

            sender.send(payload).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dokodemo-door udp session closed before payload was sent",
                )
            })
        }
        #[cfg(feature = "vless")]
        UdpOutboundAction::Vless { outbound } => {
            let route_action = UdpOutboundAction::Vless {
                outbound: outbound.clone(),
            };
            let traffic_context =
                traffic_context.with_outbound_tag(outbound.tag.clone());
            let key = UdpSessionKey {
                client_addr,
                target_addr,
                outbound_tag: Some(outbound.tag.clone()),
            };
            let sender = vless_udp_session_sender(
                Arc::clone(&relay_state),
                key,
                target_location,
                outbound,
                traffic_context,
                runtime,
            )
            .await?;
            remember_active_route(
                &relay_state,
                flow_key,
                route_action,
                UdpActiveRouteSender::Vless(sender.clone()),
            )
            .await;
            sender.send(payload).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dokodemo-door VLESS UDP session closed before payload was sent",
                )
            })
        }
        #[cfg(feature = "vless-reverse")]
        UdpOutboundAction::VlessReverse { tag } => {
            let route_action = UdpOutboundAction::VlessReverse { tag: tag.clone() };
            let key = UdpSessionKey {
                client_addr,
                target_addr,
                outbound_tag: Some(tag.clone()),
            };
            let sender = reverse_udp_session_sender(
                Arc::clone(&relay_state),
                key.clone(),
                target_location.clone(),
                tag.clone(),
                traffic_context.clone().with_outbound_tag(tag.clone()),
                &runtime,
            )
            .await?;
            remember_active_route(
                &relay_state,
                flow_key.clone(),
                route_action.clone(),
                UdpActiveRouteSender::VlessReverse(sender.clone()),
            )
            .await;
            match send_reverse_udp_payload(&sender, payload).await {
                Ok(()) => Ok(()),
                Err((retry_payload, error))
                    if retryable_reverse_udp_error(&error) =>
                {
                    remove_udp_session_if_current(
                        &relay_state.reverse_sessions,
                        &key,
                        &sender,
                    )
                    .await;
                    let retry_sender = reverse_udp_session_sender(
                        Arc::clone(&relay_state),
                        key,
                        target_location,
                        tag.clone(),
                        traffic_context.with_outbound_tag(tag),
                        &runtime,
                    )
                    .await?;
                    remember_active_route(
                        &relay_state,
                        flow_key,
                        route_action,
                        UdpActiveRouteSender::VlessReverse(retry_sender.clone()),
                    )
                    .await;
                    send_reverse_udp_payload(&retry_sender, retry_payload)
                        .await
                        .map_err(|(_, error)| error)
                }
                Err((_, error)) => Err(error),
            }
        }
        UdpOutboundAction::Trojan { outbound } => {
            #[cfg(feature = "trojan")]
            {
                let route_action = UdpOutboundAction::Trojan {
                    outbound: outbound.clone(),
                };
                let traffic_context =
                    traffic_context.with_outbound_tag(outbound.tag.clone());
                let key = DokodemoTrojanUdpSessionKey {
                    client_addr,
                    target_addr,
                    target: target_location,
                    outbound_tag: outbound.tag.clone(),
                };
                let sender = trojan_dokodemo_udp_session_sender(
                    Arc::clone(&relay_state),
                    key,
                    outbound,
                    runtime,
                    traffic_context,
                )
                .await?;
                remember_active_route(
                    &relay_state,
                    flow_key,
                    route_action,
                    UdpActiveRouteSender::Trojan(sender.clone()),
                )
                .await;
                sender.send(payload).await.map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "dokodemo-door Trojan UDP session closed before payload was sent",
                    )
                })
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
    }
}

#[cfg(feature = "vless")]
async fn vless_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target: NetLocation,
    outbound: OutboundSummary,
    traffic_context: TrafficContext,
    runtime: DataPlaneRuntime,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    if let Some(sender) = relay_state
        .vless_sessions
        .lock()
        .await
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        return Ok(sender);
    }

    let session_permit = relay_state.acquire_session_slot()?;
    let resolver = runtime.resolver();
    let proxy =
        connect_vless_udp_via_outbound(&resolver, &target, &runtime, &outbound)
            .await?;
    let (sender, receiver) = mpsc::channel(UDP_SESSION_CHANNEL_CAPACITY);

    let mut sessions = relay_state.vless_sessions.lock().await;
    if let Some(existing) = sessions
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        drop(sessions);
        drop(proxy);
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    let cleanup_state = Arc::clone(&relay_state);
    let cleanup_key = key.clone();
    let cleanup_sender = sender.clone();
    if !runtime.spawn_inbound_connection(run_vless_udp_session(
        relay_state,
        key,
        target,
        outbound.tag,
        traffic_context,
        proxy,
        UdpSessionReceiver::new(receiver, session_permit, cleanup_sender.clone()),
    )) {
        remove_udp_session_if_current(
            &cleanup_state.vless_sessions,
            &cleanup_key,
            &cleanup_sender,
        )
        .await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "server is draining; cannot start dokodemo-door VLESS UDP session",
        ));
    }
    Ok(sender)
}

#[cfg(feature = "vless")]
async fn run_vless_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target: NetLocation,
    outbound_tag: String,
    traffic_context: TrafficContext,
    mut proxy: crate::outbound::VlessUdpOutboundStream,
    mut receiver: UdpSessionReceiver,
) {
    let flow_key = UdpFlowKey {
        client_addr: key.client_addr,
        target_addr: key.target_addr,
        target_location: target.clone(),
    };
    let mut response = vec![0u8; UDP_BUFFER_SIZE];
    let session_idle_timeout = relay_state.session_idle_timeout;
    let mut idle = Box::pin(sleep(session_idle_timeout));

    loop {
        tokio::select! {
            _ = idle.as_mut() => {
                debug!(
                    "dokodemo-door VLESS UDP session {} -> {} via {} expired after {:?}",
                    key.client_addr,
                    target,
                    outbound_tag,
                    session_idle_timeout
                );
                break;
            }
            maybe_payload = receiver.recv() => {
                let Some(payload) = maybe_payload else { break; };
                match proxy.send_to(&target, &payload).await {
                    Ok(VlessUdpSendOutcome::Written) => {
                        record_transfer_ref(Some(&traffic_context), payload.len() as u64, 0);
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Ok(VlessUdpSendOutcome::Skipped) => {
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Err(error) => {
                        debug!(
                            "dokodemo-door VLESS UDP send {} -> {} via {} failed: {}",
                            key.client_addr,
                            target,
                            outbound_tag,
                            error
                        );
                        break;
                    }
                }
            }
            result = proxy.recv_from(&mut response) => {
                let (_source, response_len) = match result {
                    Ok(result) => result,
                    Err(error) => {
                        debug!(
                            "dokodemo-door VLESS UDP receive from {} via {} failed: {}",
                            target,
                            outbound_tag,
                            error
                        );
                        break;
                    }
                };
                match relay_state
                    .reply_sink
                    .send_response(&response[..response_len], key.client_addr, key.target_addr)
                    .await
                {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Err(error) => {
                        debug!(
                            "dokodemo-door VLESS UDP response to {} via {} failed: {}",
                            key.client_addr,
                            outbound_tag,
                            error
                        );
                        break;
                    }
                }
            }
        }
    }

    remove_udp_session_if_current(
        &relay_state.vless_sessions,
        &key,
        &receiver.session_sender,
    )
    .await;
    remove_active_route_if_current(
        &relay_state,
        &flow_key,
        UdpOutboundIdentity::Vless(outbound_tag),
        UdpActiveRouteSender::Vless(receiver.session_sender.clone()),
    )
    .await;
}

#[cfg(feature = "vless-reverse")]
async fn reverse_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target: NetLocation,
    tag: String,
    traffic_context: TrafficContext,
    runtime: &DataPlaneRuntime,
) -> std::io::Result<mpsc::Sender<ReverseUdpPayload>> {
    if let Some(sender) = relay_state
        .reverse_sessions
        .lock()
        .await
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        return Ok(sender);
    }

    let session_permit = relay_state.acquire_session_slot()?;
    let mut session = runtime.open_reverse_udp(
        &tag,
        target.clone(),
        key.client_addr,
        relay_state.reply_sink.local_addr(),
    )?;
    let (sender, receiver) =
        mpsc::channel::<ReverseUdpPayload>(UDP_SESSION_CHANNEL_CAPACITY);
    let mut sessions = relay_state.reverse_sessions.lock().await;
    if let Some(existing) = sessions
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        drop(sessions);
        let _ = session.close().await;
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    let cleanup_state = Arc::clone(&relay_state);
    let cleanup_key = key.clone();
    let cleanup_sender = sender.clone();
    if !runtime.spawn_inbound_connection(run_reverse_udp_session(
        relay_state,
        key,
        target,
        tag,
        traffic_context,
        session,
        UdpSessionReceiver::new(receiver, session_permit, cleanup_sender.clone()),
    )) {
        remove_udp_session_if_current(
            &cleanup_state.reverse_sessions,
            &cleanup_key,
            &cleanup_sender,
        )
        .await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "server is draining; cannot start dokodemo-door Reverse UDP session",
        ));
    }
    Ok(sender)
}

#[cfg(feature = "vless-reverse")]
async fn run_reverse_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target: NetLocation,
    tag: String,
    traffic_context: TrafficContext,
    mut session: crate::handler::vless_reverse::worker::ReversePacketSession,
    mut receiver: UdpSessionReceiver<ReverseUdpPayload>,
) {
    let flow_key = UdpFlowKey {
        client_addr: key.client_addr,
        target_addr: key.target_addr,
        target_location: target.clone(),
    };
    let session_idle_timeout = relay_state.session_idle_timeout;
    let mut idle = Box::pin(sleep(session_idle_timeout));
    let send_failure = loop {
        tokio::select! {
            _ = idle.as_mut() => break None,
            maybe_payload = receiver.recv() => {
                let Some(request) = maybe_payload else { break None; };
                if let Err(error) = session.send(request.payload.clone().into(), None).await {
                    debug!("dokodemo-door Reverse UDP send {} -> {} via {} failed: {}", key.client_addr, target, tag, error);
                    break Some((request.completion, error));
                }
                record_transfer_ref(
                    Some(&traffic_context),
                    request.payload.len() as u64,
                    0,
                );
                let _ = request.completion.send(Ok(()));
                idle.as_mut().reset(Instant::now() + session_idle_timeout);
            }
            response = session.recv() => {
                let (payload, _target_override) = match response {
                    Ok(Some(response)) => response,
                    Ok(None) => break None,
                    Err(error) => {
                        debug!("dokodemo-door Reverse UDP receive from {} via {} failed: {}", target, tag, error);
                        break None;
                    }
                };
                match relay_state
                    .reply_sink
                    .send_response(&payload, key.client_addr, key.target_addr)
                    .await
                {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Err(error) => {
                        debug!("dokodemo-door Reverse UDP response to {} via {} failed: {}", key.client_addr, tag, error);
                        break None;
                    }
                }
            }
        }
    };
    let _ = session.close().await;
    remove_udp_session_if_current(
        &relay_state.reverse_sessions,
        &key,
        &receiver.session_sender,
    )
    .await;
    remove_active_route_if_current(
        &relay_state,
        &flow_key,
        UdpOutboundIdentity::VlessReverse(tag),
        UdpActiveRouteSender::VlessReverse(receiver.session_sender.clone()),
    )
    .await;
    drop(receiver);
    if let Some((completion, error)) = send_failure {
        let _ = completion.send(Err(error));
    }
}

#[cfg(feature = "vless-reverse")]
async fn send_reverse_udp_payload(
    sender: &mpsc::Sender<ReverseUdpPayload>,
    payload: Vec<u8>,
) -> Result<(), (Vec<u8>, std::io::Error)> {
    let retry_payload = payload.clone();
    let (completion, completed) = oneshot::channel();
    sender
        .send(ReverseUdpPayload {
            payload,
            completion,
        })
        .await
        .map_err(|error| {
            (
                error.0.payload,
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dokodemo-door Reverse UDP session receiver is closed",
                ),
            )
        })?;
    match completed.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err((retry_payload, error)),
        Err(_) => Err((
            retry_payload,
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "dokodemo-door Reverse UDP session ended before packet completion",
            ),
        )),
    }
}

#[cfg(feature = "vless-reverse")]
fn retryable_reverse_udp_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

#[cfg(feature = "trojan")]
async fn trojan_dokodemo_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: DokodemoTrojanUdpSessionKey,
    outbound: OutboundSummary,
    runtime: DataPlaneRuntime,
    traffic_context: TrafficContext,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    if let Some(sender) = relay_state
        .trojan_sessions
        .lock()
        .await
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        return Ok(sender);
    }

    let session_permit = relay_state.acquire_session_slot()?;
    let resolver = runtime.resolver();
    let mut proxy =
        connect_trojan_udp_via_outbound(&resolver, &key.target, &runtime, &outbound)
            .await?;
    let (sender, receiver) = mpsc::channel(UDP_SESSION_CHANNEL_CAPACITY);

    let mut sessions = relay_state.trojan_sessions.lock().await;
    if let Some(existing) = sessions
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        drop(sessions);
        let _ = shutdown_targeted_message(&mut proxy).await;
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    let cleanup_state = Arc::clone(&relay_state);
    let cleanup_key = key.clone();
    let cleanup_sender = sender.clone();
    if !runtime.spawn_inbound_connection(run_trojan_dokodemo_udp_session(
        relay_state,
        key,
        traffic_context,
        proxy,
        UdpSessionReceiver::new(receiver, session_permit, cleanup_sender.clone()),
    )) {
        remove_udp_session_if_current(
            &cleanup_state.trojan_sessions,
            &cleanup_key,
            &cleanup_sender,
        )
        .await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "server is draining; cannot start dokodemo-door Trojan UDP session",
        ));
    }
    Ok(sender)
}

#[cfg(feature = "trojan")]
async fn run_trojan_dokodemo_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: DokodemoTrojanUdpSessionKey,
    traffic_context: TrafficContext,
    mut proxy: TrojanUdpStream,
    mut receiver: UdpSessionReceiver,
) {
    let flow_key = UdpFlowKey {
        client_addr: key.client_addr,
        target_addr: key.target_addr,
        target_location: key.target.clone(),
    };
    let outbound_tag = key.outbound_tag.clone();
    let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
    let session_idle_timeout = relay_state.session_idle_timeout;
    let mut idle = Box::pin(sleep(session_idle_timeout));

    loop {
        tokio::select! {
            _ = idle.as_mut() => {
                debug!(
                    "dokodemo-door Trojan UDP session {} -> {} via {} expired after {:?}",
                    key.client_addr,
                    key.target,
                    key.outbound_tag,
                    session_idle_timeout
                );
                break;
            }
            maybe_payload = receiver.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                match proxy.send_to(&key.target, &payload).await {
                    Ok(()) => {
                        record_transfer_ref(
                            Some(&traffic_context),
                            payload.len() as u64,
                            0,
                        );
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Err(error) => {
                        debug!(
                            "dokodemo-door Trojan UDP send {} -> {} via {} failed: {}",
                            key.client_addr,
                            key.target,
                            key.outbound_tag,
                            error
                        );
                        break;
                    }
                }
            }
            response = proxy.recv_from(&mut response_buf) => {
                let (_source, response_len) = match response {
                    Ok(response) => response,
                    Err(error) => {
                        debug!(
                            "dokodemo-door Trojan UDP receive from {} via {} failed: {}",
                            key.target,
                            key.outbound_tag,
                            error
                        );
                        break;
                    }
                };
                match relay_state
                    .reply_sink
                    .send_response(
                        &response_buf[..response_len],
                        key.client_addr,
                        key.target_addr,
                    )
                    .await
                {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Err(error) => {
                        debug!(
                            "dokodemo-door Trojan UDP response to {} via {} failed: {}",
                            key.client_addr,
                            key.outbound_tag,
                            error
                        );
                        break;
                    }
                }
            }
        }
    }

    let _ = shutdown_targeted_message(&mut proxy).await;
    remove_udp_session_if_current(
        &relay_state.trojan_sessions,
        &key,
        &receiver.session_sender,
    )
    .await;
    remove_active_route_if_current(
        &relay_state,
        &flow_key,
        UdpOutboundIdentity::Trojan(outbound_tag),
        UdpActiveRouteSender::Trojan(receiver.session_sender.clone()),
    )
    .await;
}

async fn freedom_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
    runtime: &DataPlaneRuntime,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    if let Some(sender) = relay_state
        .sessions
        .lock()
        .await
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        return Ok(sender);
    }

    let session_permit = relay_state.acquire_session_slot()?;
    let bind_addr = if key.target_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let outbound_socket = UdpSocket::bind(bind_addr).await?;
    let (sender, receiver) = mpsc::channel(UDP_SESSION_CHANNEL_CAPACITY);

    let mut sessions = relay_state.sessions.lock().await;
    if let Some(existing) = sessions
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    let cleanup_state = Arc::clone(&relay_state);
    let cleanup_key = key.clone();
    let cleanup_sender = sender.clone();
    if !runtime.spawn_inbound_connection(run_freedom_udp_session(
        relay_state,
        key,
        target_location,
        outbound_tag,
        traffic_context,
        outbound_socket,
        UdpSessionReceiver::new(receiver, session_permit, cleanup_sender.clone()),
    )) {
        remove_udp_session_if_current(
            &cleanup_state.sessions,
            &cleanup_key,
            &cleanup_sender,
        )
        .await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "server is draining; cannot start dokodemo-door UDP session",
        ));
    }

    Ok(sender)
}

async fn run_freedom_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
    outbound_socket: UdpSocket,
    mut receiver: UdpSessionReceiver,
) {
    let flow_key = UdpFlowKey {
        client_addr: key.client_addr,
        target_addr: key.target_addr,
        target_location: target_location.clone(),
    };
    let route_identity = UdpOutboundIdentity::Freedom(outbound_tag.clone());
    let outbound_label = outbound_tag.as_deref().unwrap_or("implicit-freedom");
    let session_idle_timeout = relay_state.session_idle_timeout;
    let mut idle = Box::pin(sleep(session_idle_timeout));

    loop {
        let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
        tokio::select! {
            _ = idle.as_mut() => {
                debug!(
                    "dokodemo-door udp session {} -> {} via {} expired after {:?}",
                    key.client_addr,
                    target_location,
                    outbound_label,
                    session_idle_timeout
                );
                break;
            }
            maybe_payload = receiver.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                match outbound_socket.send_to(&payload, key.target_addr).await {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), sent as u64, 0);
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                    }
                    Err(err) => {
                        debug!(
                            "dokodemo-door udp send {} -> {} via {} failed: {}",
                            key.client_addr,
                            target_location,
                            outbound_label,
                            err
                        );
                        break;
                    }
                }
            }
            response = outbound_socket.recv_from(&mut response_buf) => {
                let (response_len, response_addr) = match response {
                    Ok(result) => result,
                    Err(err) => {
                        debug!(
                            "dokodemo-door udp recv from {} via {} failed: {}",
                            target_location,
                            outbound_label,
                            err
                        );
                        break;
                    }
                };

                if response_addr != key.target_addr {
                    warn!(
                        "dokodemo-door udp ignored response from unexpected {} for target {}",
                        response_addr,
                        target_location
                    );
                    continue;
                }

                let response = &response_buf[..response_len];
                match relay_state
                    .reply_sink
                    .send_response(response, key.client_addr, key.target_addr)
                    .await
                {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + session_idle_timeout);
                        debug!(
                            "dokodemo-door udp relay {} <- {} via {} forwarded {} bytes",
                            key.client_addr,
                            target_location,
                            outbound_label,
                            sent
                        );
                    }
                    Err(err) => {
                        debug!(
                            "dokodemo-door udp response to {} from {} via {} failed: {}",
                            key.client_addr,
                            target_location,
                            outbound_label,
                            err
                        );
                        break;
                    }
                }
            }
        }
    }

    remove_udp_session_if_current(
        &relay_state.sessions,
        &key,
        &receiver.session_sender,
    )
    .await;
    remove_active_route_if_current(
        &relay_state,
        &flow_key,
        route_identity,
        UdpActiveRouteSender::Freedom(receiver.session_sender.clone()),
    )
    .await;
}

pub(crate) async fn select_udp_outbound(
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    client_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> std::io::Result<UdpOutboundAction> {
    let mut route_input = RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network: 3,
        source_ips: vec![encode_ip(client_addr.ip())],
        target_ips: vec![encode_ip(target_addr.ip())],
        source_port: client_addr.port() as u32,
        target_port: target_addr.port() as u32,
        target_domain: target_domain(target_location),
        local_ips: local_addr
            .map(|address| vec![encode_ip(address.ip())])
            .unwrap_or_default(),
        local_port: local_addr.map_or(0, |address| address.port() as u32),
        ..RoutingInput::default()
    };
    let target_summary = target_location.to_string();
    let audit_context = UserDomainAccessAuditContext {
        inbound_tag,
        protocol: "dokodemo-door",
        network: "udp",
        target: &target_summary,
        routing_user: &route_input.user,
    };
    if !runtime.allows_user_domain_access_with_context(
        &route_input.user,
        &route_input.target_domain,
        audit_context,
    ) {
        return Ok(UdpOutboundAction::Blackhole {
            tag: USER_DOMAIN_ACCESS_BLACKHOLE_TAG.to_string(),
        });
    }
    if runtime.routing_needs_process_lookup(&route_input) {
        enrich_routing_input(&mut route_input).await;
    }

    let selected =
        runtime
            .select_outbound_checked(&route_input)
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
            })?;

    let Some(outbound) = selected else {
        return Ok(UdpOutboundAction::Freedom { tag: None });
    };

    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => {
            let needs_ip_check = crate::outbound::freedom_requires_target_ip_check(
                Some(&outbound),
                Some("dokodemo-door"),
            )?;
            let mut candidates = vec![target_addr];
            if needs_ip_check && target_location.address().hostname().is_some() {
                let resolved = runtime
                    .resolver()
                    .resolve_location(target_location)
                    .await
                    .inspect_err(|_| runtime.record_user_domain_dns_failure())?;
                if resolved.is_empty() {
                    runtime.record_user_domain_dns_failure();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "DNS lookup returned no addresses for Freedom finalRules",
                    ));
                }
                candidates.extend(resolved);
            }
            if !crate::outbound::freedom_allows_targets(
                Some(&outbound),
                Some("dokodemo-door"),
                3,
                &candidates,
            )? {
                return Ok(UdpOutboundAction::Blackhole {
                    tag: crate::outbound::FREEDOM_FINAL_RULES_BLACKHOLE_TAG
                        .to_string(),
                });
            }
            Ok(UdpOutboundAction::Freedom {
                tag: Some(outbound.tag),
            })
        }
        "blackhole" => Ok(UdpOutboundAction::Blackhole { tag: outbound.tag }),
        #[cfg(feature = "vless")]
        "vless" => Ok(UdpOutboundAction::Vless { outbound }),
        "trojan" => Ok(UdpOutboundAction::Trojan { outbound }),
        #[cfg(feature = "vless-reverse")]
        "vless-reverse" => Ok(UdpOutboundAction::VlessReverse { tag: outbound.tag }),
        protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "udp outbound {} uses unsupported protocol {}",
                outbound.tag, protocol
            ),
        )),
    }
}

fn encode_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn target_domain(target_location: &NetLocation) -> String {
    match target_location.address() {
        Address::Hostname(hostname) => hostname.clone(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "vless")]
    use super::run_vless_udp_session;
    use super::{
        DokodemoUdpDatagram, TrafficContext, UdpActiveRoute, UdpActiveRouteSender,
        UdpFlowKey, UdpOutboundAction, UdpRelayState, UdpReplySink, UdpSessionKey,
        UdpSessionReceiver, relay_dokodemo_udp_datagram,
        remove_active_route_if_current, remove_udp_session_if_current,
        run_freedom_udp_session,
    };
    use crate::{
        address::NetLocation,
        config::rule::{NetworkListConfig, RoutingConfig, RuleConfig},
        routing_state::RoutingState,
        runtime::{OutboundSummary, RuntimeState},
    };
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };
    use tokio::sync::{Mutex, mpsc};
    use tokio::{
        io::AsyncReadExt as _,
        net::UdpSocket,
        time::{advance, timeout},
    };

    struct TestUdpReplySink;

    #[async_trait::async_trait]
    impl UdpReplySink for TestUdpReplySink {
        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        async fn send_response(
            &self,
            payload: &[u8],
            _client_addr: SocketAddr,
            _source_addr: SocketAddr,
        ) -> std::io::Result<usize> {
            Ok(payload.len())
        }
    }

    #[test]
    fn configured_udp_session_limit_is_enforced() {
        let relay = UdpRelayState::new(Arc::new(TestUdpReplySink), Some(1));
        let permit = relay
            .acquire_session_slot()
            .expect("first session slot")
            .expect("limited state returns permit");
        let error = relay
            .acquire_session_slot()
            .expect_err("second session exceeds configured limit");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        drop(permit);
        assert!(relay.acquire_session_slot().is_ok());
    }

    #[cfg(feature = "vless")]
    #[tokio::test(start_paused = true)]
    async fn vless_udp_oversized_packet_does_not_end_the_worker() {
        const OVERSIZED_PAYLOAD_LENGTH: usize = 8 * 1024 - 1;

        let target =
            NetLocation::from_str("192.0.2.8:53", None).expect("parse UDP target");
        let target_addr = SocketAddr::from(([192, 0, 2, 8], 53));
        let relay = Arc::new(UdpRelayState::with_idle_timeout(
            Arc::new(TestUdpReplySink),
            None,
            Duration::from_secs(1),
        ));
        let key = UdpSessionKey {
            client_addr: SocketAddr::from(([192, 0, 2, 1], 45_555)),
            target_addr,
            outbound_tag: Some("vless-out".into()),
        };
        let (sender, receiver) = mpsc::channel(2);
        let (proxy_stream, mut peer_stream) = tokio::io::duplex(16 * 1024);
        let proxy = crate::outbound::VlessUdpOutboundStream::new(
            Box::new(proxy_stream),
            target.clone(),
        );
        let task = tokio::spawn(run_vless_udp_session(
            Arc::clone(&relay),
            key,
            target,
            "vless-out".into(),
            TrafficContext::new("dokodemo-door"),
            proxy,
            UdpSessionReceiver::new(receiver, None, sender.clone()),
        ));

        sender
            .send(vec![0; OVERSIZED_PAYLOAD_LENGTH])
            .await
            .expect("queue oversized UDP packet");
        sender
            .send(b"after oversized".to_vec())
            .await
            .expect("queue valid UDP packet after oversized packet");

        timeout(Duration::from_secs(1), async {
            let length = peer_stream
                .read_u16()
                .await
                .expect("read valid packet length");
            assert_eq!(length as usize, b"after oversized".len());
            let mut payload = vec![0; length as usize];
            peer_stream
                .read_exact(&mut payload)
                .await
                .expect("read valid packet after oversized packet");
            assert_eq!(payload, b"after oversized");
        })
        .await
        .expect("worker did not forward the valid packet after the oversized one");

        drop(sender);
        advance(Duration::from_secs(2)).await;
        task.await.expect("VLESS UDP worker task panicked");
    }

    #[tokio::test(start_paused = true)]
    async fn freedom_udp_idle_expiry_removes_session_and_releases_permit() {
        let relay =
            Arc::new(UdpRelayState::new(Arc::new(TestUdpReplySink), Some(1)));
        let client_addr = SocketAddr::from(([127, 0, 0, 1], 45_557));
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP target");
        let target_addr = target.local_addr().expect("UDP target address");
        let key = UdpSessionKey {
            client_addr,
            target_addr,
            outbound_tag: Some("direct".into()),
        };
        let (sender, receiver) = mpsc::channel(1);
        relay
            .sessions
            .lock()
            .await
            .insert(key.clone(), sender.clone());
        let permit = relay
            .acquire_session_slot()
            .expect("acquire the only slot")
            .expect("limited relay returns permit");
        let outbound_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind outbound UDP session socket");
        let session = tokio::spawn(run_freedom_udp_session(
            Arc::clone(&relay),
            key.clone(),
            NetLocation::from_ip_addr(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                target_addr.port(),
            ),
            Some("direct".into()),
            TrafficContext::new("dokodemo-door"),
            outbound_socket,
            UdpSessionReceiver::new(receiver, Some(permit), sender.clone()),
        ));

        tokio::task::yield_now().await;
        advance(super::UDP_SESSION_IDLE_TIMEOUT).await;
        session
            .await
            .expect("UDP session worker should finish on idle expiry");

        assert!(!relay.sessions.lock().await.contains_key(&key));
        assert!(
            relay
                .acquire_session_slot()
                .expect("idle expiry returns the configured slot")
                .is_some()
        );
    }

    #[tokio::test]
    async fn stale_udp_session_cleanup_keeps_replacement_channel() {
        let sessions = Mutex::new(HashMap::new());
        let key = "client-target-flow".to_string();
        let (stale_sender, stale_receiver) = mpsc::channel::<Vec<u8>>(1);
        drop(stale_receiver);
        let (current_sender, _current_receiver) = mpsc::channel::<Vec<u8>>(1);
        sessions
            .lock()
            .await
            .insert(key.clone(), current_sender.clone());

        remove_udp_session_if_current(&sessions, &key, &stale_sender).await;

        let sessions = sessions.lock().await;
        assert!(
            sessions
                .get(&key)
                .is_some_and(|sender| sender.same_channel(&current_sender))
        );
    }

    #[tokio::test]
    async fn stale_udp_worker_cleanup_keeps_replacement_route_pin() {
        let relay = UdpRelayState::new(Arc::new(TestUdpReplySink), None);
        let flow = UdpFlowKey {
            client_addr: SocketAddr::from(([127, 0, 0, 1], 45_557)),
            target_addr: SocketAddr::from(([127, 0, 0, 1], 53)),
            target_location: NetLocation::from_ip_addr(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                53,
            ),
        };
        let (old_sender, _old_receiver) = mpsc::channel::<Vec<u8>>(1);
        let (current_sender, _current_receiver) = mpsc::channel::<Vec<u8>>(1);
        let action = UdpOutboundAction::Freedom {
            tag: Some("direct".into()),
        };
        relay.active_routes.lock().await.insert(
            flow.clone(),
            UdpActiveRoute {
                action,
                sender: UdpActiveRouteSender::Freedom(current_sender.clone()),
            },
        );

        remove_active_route_if_current(
            &relay,
            &flow,
            super::UdpOutboundIdentity::Freedom(Some("direct".into())),
            UdpActiveRouteSender::Freedom(old_sender),
        )
        .await;

        let routes = relay.active_routes.lock().await;
        let current = routes.get(&flow).expect("replacement route remains");
        match &current.sender {
            UdpActiveRouteSender::Freedom(sender) => {
                assert!(sender.same_channel(&current_sender));
            }
            _ => panic!("replacement route uses a different worker kind"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn active_dokodemo_udp_flow_keeps_route_until_idle_cleanup() {
        const IDLE_TIMEOUT: Duration = Duration::from_millis(100);
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![
                OutboundSummary {
                    tag: "direct".into(),
                    protocol: "freedom".into(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                    sender_settings_type: None,
                    sender_settings_value: None,
                },
                OutboundSummary {
                    tag: "blocked".into(),
                    protocol: "blackhole".into(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                    sender_settings_type: None,
                    sender_settings_value: None,
                },
            ],
        );
        let route_to = |outbound_tag: &str| {
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some(outbound_tag.into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile UDP route")
        };
        runtime_state.replace_routing(route_to("direct"));

        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local UDP target");
        let target_addr = target.local_addr().expect("read target address");
        let target_location =
            NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());
        let first_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind first logical client");
        let first_client_addr =
            first_client.local_addr().expect("read client address");
        let second_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind second logical client");
        let second_client_addr =
            second_client.local_addr().expect("read client address");
        let relay = Arc::new(UdpRelayState::with_idle_timeout(
            Arc::new(TestUdpReplySink),
            None,
            IDLE_TIMEOUT,
        ));
        let runtime = runtime_state.data_plane();

        let relay_packet = |client_addr, payload: &'static [u8]| {
            relay_dokodemo_udp_datagram(
                Arc::clone(&relay),
                "office-tun".into(),
                0,
                runtime.clone(),
                DokodemoUdpDatagram {
                    client_addr,
                    target_addr,
                    target_location: target_location.clone(),
                    payload: payload.to_vec(),
                },
            )
        };
        let mut received = [0; 32];
        relay_packet(first_client_addr, b"active-before-update")
            .await
            .expect("send first packet through direct route");
        let (length, _) =
            timeout(Duration::from_secs(1), target.recv_from(&mut received))
                .await
                .expect("first packet did not reach target")
                .expect("receive first packet");
        assert_eq!(&received[..length], b"active-before-update");

        runtime_state.replace_routing(route_to("blocked"));

        relay_packet(first_client_addr, b"active-after-update")
            .await
            .expect("existing flow keeps its selected outbound");
        let (length, _) =
            timeout(Duration::from_secs(1), target.recv_from(&mut received))
                .await
                .expect("existing flow stopped after route update")
                .expect("receive packet on existing flow");
        assert_eq!(&received[..length], b"active-after-update");

        relay_packet(second_client_addr, b"new-flow-must-be-blocked")
            .await
            .expect("new flow follows the updated blackhole route");
        assert_eq!(
            target.try_recv_from(&mut received).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "new client tuple must not reach the target"
        );

        let changed_target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind changed UDP target");
        let changed_target_addr = changed_target
            .local_addr()
            .expect("read changed target address");
        relay_dokodemo_udp_datagram(
            Arc::clone(&relay),
            "office-tun".into(),
            0,
            runtime.clone(),
            DokodemoUdpDatagram {
                client_addr: first_client_addr,
                target_addr: changed_target_addr,
                target_location: NetLocation::from_ip_addr(
                    changed_target_addr.ip(),
                    changed_target_addr.port(),
                ),
                payload: b"new-target-must-be-blocked".to_vec(),
            },
        )
        .await
        .expect("same source with a new target follows the updated route");
        assert_eq!(
            changed_target
                .try_recv_from(&mut received)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock,
            "a changed target must not inherit the original route pin"
        );

        advance(IDLE_TIMEOUT).await;
        for _ in 0..32 {
            if !relay.sessions.lock().await.contains_key(&UdpSessionKey {
                client_addr: first_client_addr,
                target_addr,
                outbound_tag: Some("direct".into()),
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let flow_key = UdpFlowKey {
            client_addr: first_client_addr,
            target_addr,
            target_location: target_location.clone(),
        };
        assert!(
            !relay.sessions.lock().await.contains_key(&UdpSessionKey {
                client_addr: first_client_addr,
                target_addr,
                outbound_tag: Some("direct".into()),
            }),
            "idle worker should remove its session"
        );
        assert!(
            !relay.active_routes.lock().await.contains_key(&flow_key),
            "idle worker should remove its pinned route"
        );

        relay_packet(first_client_addr, b"expired-flow-is-blocked")
            .await
            .expect("expired flow reselects the current blackhole route");
        assert_eq!(
            target.try_recv_from(&mut received).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "an expired tuple must not retain its old direct route"
        );
    }
}
