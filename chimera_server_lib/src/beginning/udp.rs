use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    sync::{Mutex, Notify, RwLock, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep},
};
use tracing::{debug, error, info, warn};

#[cfg(target_os = "linux")]
use crate::util::socket::{
    enable_udp_original_destination, new_socket2_udp_socket,
    recv_udp_with_original_destination,
};

use crate::{
    address::{Address, BindLocation, NetLocation},
    async_stream::{
        AsyncMessageStream, AsyncSessionMessageStream, AsyncTargetedMessageStream,
        SessionMessage,
    },
    config::server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
    outbound::{
        DirectOutboundAction, connection_routing_input, select_direct_outbound,
    },
    resolver::{NativeResolver, Resolver, resolve_single_address},
    routing_state::RoutingInput,
    runtime::RuntimeState,
    traffic::{TrafficContext, record_transfer, register_connection},
    xudp_registry::{XUDP_GLOBAL_REATTACH_TTL, XudpGlobalRegistry},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const VMESS_UDP_MESSAGE_BUFFER_SIZE: usize = 8192;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_CHANNEL_CAPACITY: usize = 64;
// Keep UDP routing intentionally limited to direct and drop outbounds for now.

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    outbound_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TargetedUdpSessionKey {
    target_addr: SocketAddr,
    outbound_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GlobalUdpWorkerKey {
    target_is_ipv6: bool,
    outbound_tag: Option<String>,
}

impl From<&TargetedUdpSessionKey> for GlobalUdpWorkerKey {
    fn from(key: &TargetedUdpSessionKey) -> Self {
        Self {
            target_is_ipv6: key.target_addr.is_ipv6(),
            outbound_tag: key.outbound_tag.clone(),
        }
    }
}

struct TargetedUdpResponse {
    source: SocketAddr,
    payload: Vec<u8>,
    traffic_context: Option<TrafficContext>,
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

#[derive(Clone)]
struct GlobalUdpAttachment {
    token: u64,
    session_id: u16,
    generation: u64,
    response_sender: mpsc::Sender<SessionUdpEvent>,
    traffic_context: Option<TrafficContext>,
}

struct LocalUdpPayload {
    target_addr: SocketAddr,
    payload: Vec<u8>,
}

struct GlobalUdpPayload {
    attachment_token: u64,
    target_addr: SocketAddr,
    payload: Vec<u8>,
    completion: oneshot::Sender<std::io::Result<()>>,
}

struct PendingGlobalUdpResponse {
    source: SocketAddr,
    payload: Vec<u8>,
}

#[derive(Clone)]
enum SessionUdpSender {
    Local(mpsc::Sender<LocalUdpPayload>),
    Global {
        sender: mpsc::Sender<GlobalUdpPayload>,
        attachment_token: u64,
    },
}

impl SessionUdpSender {
    fn is_closed(&self) -> bool {
        match self {
            Self::Local(sender) => sender.is_closed(),
            Self::Global { sender, .. } => sender.is_closed(),
        }
    }

    async fn send_to(
        &self,
        payload: Vec<u8>,
        target_addr: SocketAddr,
    ) -> Result<(), Vec<u8>> {
        match self {
            Self::Local(sender) => sender
                .send(LocalUdpPayload {
                    target_addr,
                    payload,
                })
                .await
                .map_err(|error| error.0.payload),
            Self::Global {
                sender,
                attachment_token,
            } => {
                let retry_payload = payload.clone();
                let (completion, completed) = oneshot::channel();
                sender
                    .send(GlobalUdpPayload {
                        attachment_token: *attachment_token,
                        target_addr,
                        payload,
                        completion,
                    })
                    .await
                    .map_err(|error| error.0.payload)?;
                match completed.await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) | Err(_) => Err(retry_payload),
                }
            }
        }
    }
}

struct SessionUdpWorker {
    key: TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
    generation: u64,
    sender: SessionUdpSender,
    task: Option<JoinHandle<()>>,
}

struct GlobalSessionUdpWorker {
    key: GlobalUdpWorkerKey,
    sender: mpsc::Sender<GlobalUdpPayload>,
    attachment: Arc<RwLock<Option<GlobalUdpAttachment>>>,
    attachment_notify: Arc<Notify>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct GlobalXudpWorkers {
    registry: XudpGlobalRegistry,
    workers: HashMap<[u8; 8], GlobalSessionUdpWorker>,
}

static GLOBAL_XUDP_WORKERS: OnceLock<Arc<Mutex<GlobalXudpWorkers>>> =
    OnceLock::new();

fn global_xudp_workers() -> Arc<Mutex<GlobalXudpWorkers>> {
    GLOBAL_XUDP_WORKERS
        .get_or_init(|| Arc::new(Mutex::new(GlobalXudpWorkers::default())))
        .clone()
}

#[derive(Debug)]
struct UdpRelayState {
    server_socket: Arc<UdpSocket>,
    sessions: Mutex<HashMap<UdpSessionKey, mpsc::Sender<Vec<u8>>>>,
}

impl UdpRelayState {
    fn new(server_socket: Arc<UdpSocket>) -> Self {
        Self {
            server_socket,
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

pub(crate) async fn run_bidirectional_udp(
    mut server_stream: Box<dyn AsyncMessageStream>,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    peer_addr: SocketAddr,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    let target_addr = resolve_single_address(&resolver, &remote_location).await?;
    let inbound_tag = traffic_context
        .as_ref()
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default();
    let identity = traffic_context
        .as_ref()
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default();
    let route_input = connection_routing_input(
        inbound_tag,
        identity,
        3,
        peer_addr,
        target_addr,
        &remote_location,
    );
    let action = select_direct_outbound(&runtime, &route_input, "udp")?;
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
    };

    let _ = shutdown_message(&mut *server_stream).await;
    result
}

pub(crate) async fn run_multi_directional_udp(
    mut server_stream: Box<dyn AsyncTargetedMessageStream>,
    resolver: Arc<dyn Resolver>,
    runtime: RuntimeState,
    peer_addr: SocketAddr,
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
    let (response_sender, mut response_receiver) =
        mpsc::channel::<TargetedUdpResponse>(UDP_SESSION_CHANNEL_CAPACITY);
    let mut sessions =
        HashMap::<TargetedUdpSessionKey, mpsc::Sender<Vec<u8>>>::new();
    let mut client_buffer = vec![0u8; UDP_BUFFER_SIZE];

    let result = loop {
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
                let target_addr = match resolve_single_address(&resolver, &target_location).await {
                    Ok(target_addr) => target_addr,
                    Err(error) => {
                        warn!(
                            "targeted udp failed to resolve {}: {}",
                            target_location, error
                        );
                        continue;
                    }
                };
                let route_input = connection_routing_input(
                    &inbound_tag,
                    &identity,
                    3,
                    peer_addr,
                    target_addr,
                    &target_location,
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
                            "targeted udp packet to {} dropped by blackhole outbound {}",
                            target_location, tag
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
                        let sender = match sessions.get(&key) {
                            Some(sender) if !sender.is_closed() => sender.clone(),
                            _ => {
                                let sender = start_targeted_udp_session(
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
    };

    let _ = shutdown_targeted_message(&mut *server_stream).await;
    result
}

pub(crate) async fn run_session_based_udp(
    mut server_stream: Box<dyn AsyncSessionMessageStream>,
    runtime: RuntimeState,
    peer_addr: SocketAddr,
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
                let route_input = connection_routing_input(
                    &inbound_tag,
                    &identity,
                    3,
                    peer_addr,
                    target_addr,
                    &target_location,
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
                        let sender = match sessions.get(&session_id) {
                            Some(worker)
                                if session_udp_worker_matches(
                                    worker,
                                    &key,
                                    global_id,
                                ) =>
                            {
                                worker.sender.clone()
                            }
                            _ => {
                                terminate_session_udp_worker(&mut sessions, session_id).await;
                                let generation = take_session_generation(
                                    &mut next_generation,
                                )?;
                                let worker = start_session_udp_session(
                                    session_id,
                                    generation,
                                    key.clone(),
                                    response_sender.clone(),
                                    packet_context.clone(),
                                    global_id,
                                    UDP_SESSION_IDLE_TIMEOUT,
                                )
                                .await?;
                                let sender = worker.sender.clone();
                                sessions.insert(session_id, worker);
                                sender
                            }
                        };

                        if sender.send_to(payload, target_addr).await.is_err() {
                            terminate_session_udp_worker(&mut sessions, session_id).await;
                            let generation =
                                take_session_generation(&mut next_generation)?;
                            let worker = start_session_udp_session(
                                session_id,
                                generation,
                                key,
                                response_sender.clone(),
                                packet_context,
                                global_id,
                                UDP_SESSION_IDLE_TIMEOUT,
                            )
                            .await?;
                            worker
                                .sender
                                .send_to(
                                    client_buffer[..payload_length].to_vec(),
                                    target_addr,
                                )
                                .await
                                .map_err(|_| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "session udp socket closed before payload was sent",
                                    )
                                })?;
                            sessions.insert(session_id, worker);
                        }
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
                        write_session_message(
                            &mut *server_stream,
                            response.session_id,
                            &response.payload,
                            &response.source,
                        )
                        .await?;
                        flush_session_message(&mut *server_stream).await?;
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
                        write_session_end(
                            &mut *server_stream,
                            session_id,
                            has_error,
                        )
                        .await?;
                        flush_session_message(&mut *server_stream).await?;
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

fn session_udp_worker_matches(
    worker: &SessionUdpWorker,
    key: &TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
) -> bool {
    if worker.global_id != global_id || worker.sender.is_closed() {
        return false;
    }
    GlobalUdpWorkerKey::from(&worker.key) == GlobalUdpWorkerKey::from(key)
}

fn take_session_generation(next_generation: &mut u64) -> std::io::Result<u64> {
    let generation = *next_generation;
    *next_generation = next_generation.checked_add(1).ok_or_else(|| {
        std::io::Error::other("session UDP generation counter exhausted")
    })?;
    Ok(generation)
}

async fn terminate_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
) {
    let Some(worker) = sessions.remove(&session_id) else {
        return;
    };
    if let Some(task) = worker.task {
        task.abort();
    }
    if let (
        Some(global_id),
        SessionUdpSender::Global {
            attachment_token, ..
        },
    ) = (worker.global_id, worker.sender)
    {
        terminate_global_udp_worker(global_id, attachment_token).await;
    }
}

async fn expire_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
) {
    if let Some(worker) = sessions.remove(&session_id) {
        detach_session_udp_worker(worker).await;
    }
}

async fn detach_session_udp_worker(worker: SessionUdpWorker) {
    if let Some(task) = worker.task {
        task.abort();
    }
    if let (
        Some(global_id),
        SessionUdpSender::Global {
            attachment_token, ..
        },
    ) = (worker.global_id, worker.sender)
    {
        detach_global_udp_worker(global_id, attachment_token).await;
    }
}

fn is_current_session_udp_generation(
    sessions: &HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    generation: u64,
) -> bool {
    sessions
        .get(&session_id)
        .is_some_and(|worker| worker.generation == generation)
}

fn is_current_session_udp_response(
    sessions: &HashMap<u16, SessionUdpWorker>,
    response: &SessionUdpResponse,
) -> bool {
    is_current_session_udp_generation(
        sessions,
        response.session_id,
        response.generation,
    )
}

async fn start_session_udp_session(
    session_id: u16,
    generation: u64,
    key: TargetedUdpSessionKey,
    response_sender: mpsc::Sender<SessionUdpEvent>,
    traffic_context: Option<TrafficContext>,
    global_id: Option<[u8; 8]>,
    idle_timeout: Duration,
) -> std::io::Result<SessionUdpWorker> {
    match global_id {
        Some(global_id) => {
            attach_global_session_udp_session(
                global_id,
                session_id,
                generation,
                key,
                response_sender,
                traffic_context,
                idle_timeout,
            )
            .await
        }
        None => {
            start_local_session_udp_session(
                session_id,
                generation,
                key,
                response_sender,
                traffic_context,
                idle_timeout,
            )
            .await
        }
    }
}

async fn start_local_session_udp_session(
    session_id: u16,
    generation: u64,
    key: TargetedUdpSessionKey,
    response_sender: mpsc::Sender<SessionUdpEvent>,
    traffic_context: Option<TrafficContext>,
    idle_timeout: Duration,
) -> std::io::Result<SessionUdpWorker> {
    let bind_addr = if key.target_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let (sender, mut receiver) =
        mpsc::channel::<LocalUdpPayload>(UDP_SESSION_CHANNEL_CAPACITY);

    let worker_key = key.clone();
    let task = tokio::spawn(async move {
        let mut response_buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut idle = Box::pin(sleep(idle_timeout));
        let has_error = loop {
            tokio::select! {
                _ = idle.as_mut() => break false,
                request = receiver.recv() => {
                    let Some(request) = request else {
                        return;
                    };
                    match socket
                        .send_to(&request.payload, request.target_addr)
                        .await
                    {
                        Ok(written) if written == request.payload.len() => {
                            record_transfer(
                                traffic_context.clone(),
                                written as u64,
                                0,
                            );
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                        Ok(written) => {
                            warn!(
                                "session udp write to {} was truncated: {} of {} bytes",
                                request.target_addr,
                                written,
                                request.payload.len()
                            );
                            break true;
                        }
                        Err(error) => {
                            debug!(
                                "session udp write to {} failed: {}",
                                request.target_addr, error
                            );
                            break true;
                        }
                    }
                }
                response = socket.recv_from(&mut response_buffer) => {
                    let (length, source) = match response {
                        Ok(response) => response,
                        Err(error) => {
                            debug!("session udp receive failed: {}", error);
                            break true;
                        }
                    };
                    let response = SessionUdpResponse {
                        session_id,
                        generation,
                        source,
                        payload: response_buffer[..length].to_vec(),
                        traffic_context: traffic_context.clone(),
                    };
                    if response_sender
                        .send(SessionUdpEvent::Data(response))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        };
        let _ = response_sender
            .send(SessionUdpEvent::End {
                session_id,
                generation,
                has_error,
            })
            .await;
    });

    Ok(SessionUdpWorker {
        key: worker_key,
        global_id: None,
        generation,
        sender: SessionUdpSender::Local(sender),
        task: Some(task),
    })
}

async fn attach_global_session_udp_session(
    global_id: [u8; 8],
    session_id: u16,
    generation: u64,
    key: TargetedUdpSessionKey,
    response_sender: mpsc::Sender<SessionUdpEvent>,
    traffic_context: Option<TrafficContext>,
    idle_timeout: Duration,
) -> std::io::Result<SessionUdpWorker> {
    let globals = global_xudp_workers();
    let now = Instant::now();
    let mut guard = globals.lock().await;
    purge_expired_global_udp_workers(&mut guard, now);

    let transition = guard
        .registry
        .attach(global_id, session_id, generation, now)?;
    let attachment = GlobalUdpAttachment {
        token: transition.current.token,
        session_id,
        generation,
        response_sender,
        traffic_context,
    };
    let worker_key = GlobalUdpWorkerKey::from(&key);

    let existing_is_usable = guard.workers.get(&global_id).is_some_and(|worker| {
        worker.key == worker_key
            && !worker.task.is_finished()
            && !worker.sender.is_closed()
    });
    if !existing_is_usable {
        if let Some(worker) = guard.workers.remove(&global_id) {
            worker.task.abort();
        }
        let worker =
            match start_global_session_udp_worker(worker_key.clone(), idle_timeout)
                .await
            {
                Ok(worker) => worker,
                Err(error) => {
                    guard
                        .registry
                        .remove_current(global_id, transition.current.token);
                    return Err(error);
                }
            };
        guard.workers.insert(global_id, worker);
    }

    let worker = guard
        .workers
        .get(&global_id)
        .expect("global XUDP worker inserted before attachment");
    let sender = worker.sender.clone();
    let attachment_state = worker.attachment.clone();
    let attachment_notify = worker.attachment_notify.clone();
    let previous = attachment_state.write().await.replace(attachment.clone());
    attachment_notify.notify_one();
    drop(guard);

    if let Some(previous) = previous
        && previous.token != attachment.token
    {
        let _ = previous
            .response_sender
            .send(SessionUdpEvent::End {
                session_id: previous.session_id,
                generation: previous.generation,
                has_error: false,
            })
            .await;
    }

    debug!(
        "attached XUDP GlobalID {:?} to session {} generation {}{}",
        global_id,
        session_id,
        generation,
        if transition.resumed_detached_session {
            " after reconnect"
        } else {
            ""
        }
    );

    Ok(SessionUdpWorker {
        key,
        global_id: Some(global_id),
        generation,
        sender: SessionUdpSender::Global {
            sender,
            attachment_token: attachment.token,
        },
        task: None,
    })
}

async fn forward_global_udp_response(
    attachment: &Arc<RwLock<Option<GlobalUdpAttachment>>>,
    pending: PendingGlobalUdpResponse,
) -> Result<(), (PendingGlobalUdpResponse, Option<u64>)> {
    let Some(current) = attachment.read().await.clone() else {
        return Err((pending, None));
    };
    let event = SessionUdpEvent::Data(SessionUdpResponse {
        session_id: current.session_id,
        generation: current.generation,
        source: pending.source,
        payload: pending.payload,
        traffic_context: current.traffic_context,
    });
    match current.response_sender.send(event).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let SessionUdpEvent::Data(response) = error.0 else {
                unreachable!("global UDP response sender returned a non-data event")
            };
            Err((
                PendingGlobalUdpResponse {
                    source: response.source,
                    payload: response.payload,
                },
                Some(current.token),
            ))
        }
    }
}

async fn clear_global_attachment_if_current(
    attachment: &Arc<RwLock<Option<GlobalUdpAttachment>>>,
    attachment_token: u64,
) {
    let mut current = attachment.write().await;
    if current.as_ref().map(|attachment| attachment.token) == Some(attachment_token)
    {
        *current = None;
    }
}

async fn start_global_session_udp_worker(
    key: GlobalUdpWorkerKey,
    idle_timeout: Duration,
) -> std::io::Result<GlobalSessionUdpWorker> {
    let bind_addr = if key.target_is_ipv6 {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let (sender, mut receiver) =
        mpsc::channel::<GlobalUdpPayload>(UDP_SESSION_CHANNEL_CAPACITY);
    let attachment = Arc::new(RwLock::new(None::<GlobalUdpAttachment>));
    let attachment_notify = Arc::new(Notify::new());
    let task_attachment = attachment.clone();
    let task_attachment_notify = attachment_notify.clone();
    let worker_key = key.clone();

    let task = tokio::spawn(async move {
        let mut response_buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut pending_responses =
            VecDeque::<PendingGlobalUdpResponse>::with_capacity(
                UDP_SESSION_CHANNEL_CAPACITY,
            );
        let mut idle = Box::pin(sleep(idle_timeout));
        let has_error = loop {
            while let Some(pending) = pending_responses.pop_front() {
                match forward_global_udp_response(&task_attachment, pending).await {
                    Ok(()) => {
                        idle.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    Err((pending, failed_token)) => {
                        pending_responses.push_front(pending);
                        if let Some(failed_token) = failed_token {
                            clear_global_attachment_if_current(
                                &task_attachment,
                                failed_token,
                            )
                            .await;
                        }
                        break;
                    }
                }
            }

            let attachment_present = task_attachment.read().await.is_some();
            let pause_socket = !attachment_present
                && pending_responses.len() >= UDP_SESSION_CHANNEL_CAPACITY;
            tokio::select! {
                _ = idle.as_mut() => break false,
                _ = task_attachment_notify.notified() => continue,
                request = receiver.recv() => {
                    let Some(request) = request else {
                        return;
                    };
                    let current = task_attachment.read().await.clone();
                    let Some(current) = current else {
                        let _ = request.completion.send(Err(
                            std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "XUDP GlobalID attachment is detached",
                            ),
                        ));
                        continue;
                    };
                    if current.token != request.attachment_token {
                        debug!(
                            "dropping stale XUDP GlobalID payload token {}",
                            request.attachment_token
                        );
                        let _ = request.completion.send(Err(
                            std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "XUDP GlobalID attachment token is stale",
                            ),
                        ));
                        continue;
                    }
                    match socket
                        .send_to(&request.payload, request.target_addr)
                        .await
                    {
                        Ok(written) if written == request.payload.len() => {
                            record_transfer(
                                current.traffic_context.clone(),
                                written as u64,
                                0,
                            );
                            let _ = request.completion.send(Ok(()));
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                        Ok(written) => {
                            warn!(
                                "global XUDP write to {} was truncated: {} of {} bytes",
                                request.target_addr,
                                written,
                                request.payload.len()
                            );
                            let _ = request.completion.send(Err(
                                std::io::Error::new(
                                    std::io::ErrorKind::WriteZero,
                                    "global XUDP UDP write was truncated",
                                ),
                            ));
                            break true;
                        }
                        Err(error) => {
                            debug!(
                                "global XUDP write to {} failed: {}",
                                request.target_addr, error
                            );
                            let completion_error = std::io::Error::new(
                                error.kind(),
                                error.to_string(),
                            );
                            let _ = request.completion.send(Err(completion_error));
                            break true;
                        }
                    }
                }
                response = socket.recv_from(&mut response_buffer), if !pause_socket => {
                    let (length, source) = match response {
                        Ok(response) => response,
                        Err(error) => {
                            debug!("global XUDP receive failed: {}", error);
                            break true;
                        }
                    };
                    let pending = PendingGlobalUdpResponse {
                        source,
                        payload: response_buffer[..length].to_vec(),
                    };
                    match forward_global_udp_response(&task_attachment, pending).await {
                        Ok(()) => {
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                        Err((pending, failed_token)) => {
                            if pending_responses.len()
                                < UDP_SESSION_CHANNEL_CAPACITY
                            {
                                pending_responses.push_back(pending);
                            }
                            if let Some(failed_token) = failed_token {
                                clear_global_attachment_if_current(
                                    &task_attachment,
                                    failed_token,
                                )
                                .await;
                            }
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                    }
                }
            }
        };

        if let Some(current) = task_attachment.read().await.clone() {
            let _ = current
                .response_sender
                .send(SessionUdpEvent::End {
                    session_id: current.session_id,
                    generation: current.generation,
                    has_error,
                })
                .await;
        }
    });

    Ok(GlobalSessionUdpWorker {
        key: worker_key,
        sender,
        attachment,
        attachment_notify,
        task,
    })
}

fn purge_expired_global_udp_workers(globals: &mut GlobalXudpWorkers, now: Instant) {
    for global_id in globals.registry.take_expired(now) {
        if let Some(worker) = globals.workers.remove(&global_id) {
            worker.task.abort();
        }
    }
}

async fn detach_global_udp_worker(global_id: [u8; 8], attachment_token: u64) {
    let globals = global_xudp_workers();
    let mut guard = globals.lock().await;
    if !guard
        .registry
        .detach(global_id, attachment_token, Instant::now())
    {
        return;
    }
    if let Some(worker) = guard.workers.get(&global_id) {
        let mut attachment = worker.attachment.write().await;
        if attachment.as_ref().map(|attachment| attachment.token)
            == Some(attachment_token)
        {
            *attachment = None;
            worker.attachment_notify.notify_one();
        }
    }
    drop(guard);

    tokio::spawn(async move {
        sleep(XUDP_GLOBAL_REATTACH_TTL).await;
        let globals = global_xudp_workers();
        let mut guard = globals.lock().await;
        purge_expired_global_udp_workers(&mut guard, Instant::now());
    });
}

async fn terminate_global_udp_worker(global_id: [u8; 8], attachment_token: u64) {
    let globals = global_xudp_workers();
    let mut guard = globals.lock().await;
    if guard.registry.remove_current(global_id, attachment_token)
        && let Some(worker) = guard.workers.remove(&global_id)
    {
        worker.task.abort();
    }
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

async fn start_targeted_udp_session(
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

    tokio::spawn(async move {
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

async fn shutdown_targeted_message(
    stream: &mut dyn AsyncTargetedMessageStream,
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

pub async fn start_udp_server(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        ..
    } = config;

    let dokodemo_config = match protocol {
        ServerProxyConfig::DokodemoDoor { config } => config,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport=udp only supports dokodemo-door in this stage (got {other})"
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
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
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

    let socket = if dokodemo_config.follow_redirect {
        #[cfg(target_os = "linux")]
        {
            let socket = new_socket2_udp_socket(
                bind_addr.is_ipv6(),
                None,
                Some(bind_addr),
                false,
            )?;
            enable_udp_original_destination(&socket, bind_addr.is_ipv6())?;
            let socket: std::net::UdpSocket = socket.into();
            Arc::new(UdpSocket::from_std(socket)?)
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!("non-Linux followRedirect returned before socket setup")
    } else {
        Arc::new(UdpSocket::bind(bind_addr).await?)
    };
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

fn bind_location_to_socket_addr(
    bind_location: &BindLocation,
) -> std::io::Result<SocketAddr> {
    match bind_location {
        BindLocation::Address(location) => location.to_socket_addr(),
    }
}

async fn run_dokodemo_udp_server(
    socket: Arc<UdpSocket>,
    config: DokodemoDoorConfig,
    target_addr: SocketAddr,
    inbound_tag: String,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let relay_state = Arc::new(UdpRelayState::new(socket));
    let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let (len, client_addr) =
            relay_state.server_socket.recv_from(&mut recv_buf).await?;
        let payload = recv_buf[..len].to_vec();
        let target_location = config.target.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();
        let relay_state = relay_state.clone();

        tokio::spawn(async move {
            if let Err(err) = relay_dokodemo_udp_datagram(
                relay_state,
                client_addr,
                target_addr,
                target_location,
                inbound_tag,
                runtime,
                payload,
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
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: NetLocation,
    inbound_tag: String,
    runtime: RuntimeState,
    payload: Vec<u8>,
) -> std::io::Result<()> {
    let outbound_action = select_udp_outbound(
        &runtime,
        &inbound_tag,
        client_addr,
        target_addr,
        &target_location,
    )?;

    let traffic_context = TrafficContext::new("dokodemo-door")
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_addr.ip());

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
                relay_state,
                key,
                target_location,
                tag,
                traffic_context,
            )
            .await?;

            sender.send(payload).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dokodemo-door udp session closed before payload was sent",
                )
            })
        }
    }
}

async fn freedom_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    if let Some(sender) = relay_state.sessions.lock().await.get(&key).cloned() {
        return Ok(sender);
    }

    let bind_addr = if key.target_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let outbound_socket = UdpSocket::bind(bind_addr).await?;
    let (sender, receiver) = mpsc::channel(UDP_SESSION_CHANNEL_CAPACITY);

    let mut sessions = relay_state.sessions.lock().await;
    if let Some(existing) = sessions.get(&key).cloned() {
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    tokio::spawn(run_freedom_udp_session(
        relay_state,
        key,
        target_location,
        outbound_tag,
        traffic_context,
        outbound_socket,
        receiver,
    ));

    Ok(sender)
}

async fn run_freedom_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
    outbound_socket: UdpSocket,
    mut receiver: mpsc::Receiver<Vec<u8>>,
) {
    let outbound_label = outbound_tag.as_deref().unwrap_or("implicit-freedom");
    let mut idle = Box::pin(sleep(UDP_SESSION_IDLE_TIMEOUT));

    loop {
        let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
        tokio::select! {
            _ = idle.as_mut() => {
                debug!(
                    "dokodemo-door udp session {} -> {} via {} expired after {:?}",
                    key.client_addr,
                    target_location,
                    outbound_label,
                    UDP_SESSION_IDLE_TIMEOUT
                );
                break;
            }
            maybe_payload = receiver.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                match outbound_socket.send_to(&payload, key.target_addr).await {
                    Ok(sent) => {
                        record_transfer(Some(traffic_context.clone()), sent as u64, 0);
                        idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
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
                match relay_state.server_socket.send_to(response, key.client_addr).await {
                    Ok(sent) => {
                        record_transfer(Some(traffic_context.clone()), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
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

    relay_state.sessions.lock().await.remove(&key);
}

fn select_udp_outbound(
    runtime: &RuntimeState,
    inbound_tag: &str,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> std::io::Result<UdpOutboundAction> {
    let route_input = RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network: 3,
        source_ips: vec![encode_ip(client_addr.ip())],
        target_ips: vec![encode_ip(target_addr.ip())],
        source_port: client_addr.port() as u32,
        target_port: target_addr.port() as u32,
        target_domain: target_domain(target_location),
        ..RoutingInput::default()
    };

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
        "freedom" => Ok(UdpOutboundAction::Freedom {
            tag: Some(outbound.tag),
        }),
        "blackhole" => Ok(UdpOutboundAction::Blackhole { tag: outbound.tag }),
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
    use std::{
        net::Ipv4Addr,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::{BufMut, BytesMut};
    use tokio::{
        io::{
            AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream,
            ReadBuf, duplex,
        },
        net::UdpSocket,
        time::timeout,
    };

    use crate::{
        address::{Address, NetLocation},
        async_stream::{AsyncPing, AsyncStream},
        config::{
            rule::{BalancerConfig, NetworkListConfig, RoutingConfig, RuleConfig},
            server_config::DokodemoDoorConfig,
        },
        handler::{
            trojan_udp::TrojanUdpStream,
            xudp::{
                frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork},
                message_stream::XudpMessageStream,
            },
        },
        resolver::NativeResolver,
        routing_state::RoutingState,
        runtime::OutboundSummary,
    };

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    fn runtime_with_outbounds(outbounds: Vec<OutboundSummary>) -> RuntimeState {
        RuntimeState::new(Vec::new(), outbounds)
    }

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[test]
    fn session_generation_exhaustion_is_reported_without_wrapping() {
        let mut next_generation = u64::MAX;

        let error = take_session_generation(&mut next_generation)
            .expect_err("exhausted session generation counter must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("generation counter exhausted"));
        assert_eq!(next_generation, u64::MAX);
    }

    #[test]
    fn session_generation_advances_monotonically() {
        let mut next_generation = 41;

        assert_eq!(
            take_session_generation(&mut next_generation)
                .expect("take first session generation"),
            41
        );
        assert_eq!(
            take_session_generation(&mut next_generation)
                .expect("take second session generation"),
            42
        );
        assert_eq!(next_generation, 43);
    }

    #[tokio::test]
    async fn session_udp_blackhole_drops_without_contacting_target() {
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind XUDP blackhole observation socket");
        let target_addr = target
            .local_addr()
            .expect("XUDP blackhole observation address");
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id: 15,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::from_ip_addr(
                target_addr.ip(),
                target_addr.port(),
            )),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        }
        .encode(&mut frame)
        .expect("encode blackholed XUDP request metadata");
        frame.put_u16(4);
        frame.extend_from_slice(b"drop");

        let (mut client, server) = duplex(2048);
        client
            .write_all(&frame)
            .await
            .expect("write blackholed XUDP request");
        let stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(NativeResolver::new()),
        );
        let relay = tokio::spawn(run_session_based_udp(
            Box::new(stream),
            runtime_with_outbounds(vec![outbound("blocked", "blackhole")]),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43115)),
            None,
        ));

        let mut buffer = [0u8; 16];
        assert!(
            timeout(Duration::from_millis(50), target.recv_from(&mut buffer))
                .await
                .is_err(),
            "blackholed XUDP packet must not reach its UDP target"
        );

        relay.abort();
    }

    #[tokio::test]
    async fn session_udp_unsupported_outbound_fails_without_contacting_target() {
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind unsupported-outbound observation socket");
        let target_addr = target
            .local_addr()
            .expect("unsupported-outbound observation address");
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id: 16,
            status: SessionStatus::New,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::from_ip_addr(
                target_addr.ip(),
                target_addr.port(),
            )),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        }
        .encode(&mut frame)
        .expect("encode unsupported-outbound XUDP request metadata");
        frame.put_u16(4);
        frame.extend_from_slice(b"fail");

        let (mut client, server) = duplex(2048);
        client
            .write_all(&frame)
            .await
            .expect("write unsupported-outbound XUDP request");
        let stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(NativeResolver::new()),
        );
        let relay = tokio::spawn(run_session_based_udp(
            Box::new(stream),
            runtime_with_outbounds(vec![outbound("proxy", "vmess")]),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43116)),
            None,
        ));

        let error = timeout(Duration::from_secs(1), relay)
            .await
            .expect("unsupported XUDP outbound must fail promptly")
            .expect("unsupported XUDP relay task must not panic")
            .expect_err("unsupported XUDP outbound must return an error");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("unsupported protocol vmess"));

        let mut buffer = [0u8; 16];
        assert!(
            timeout(Duration::from_millis(20), target.recv_from(&mut buffer))
                .await
                .is_err(),
            "unsupported XUDP outbound must not contact its UDP target"
        );
    }

    #[tokio::test]
    async fn session_udp_response_requires_current_generation() {
        let (sender, _receiver) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        let mut sessions = HashMap::new();
        sessions.insert(
            17,
            SessionUdpWorker {
                key: TargetedUdpSessionKey {
                    target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                    outbound_tag: None,
                },
                global_id: None,
                generation: 2,
                sender: SessionUdpSender::Local(sender),
                task: Some(task),
            },
        );
        let mut response = SessionUdpResponse {
            session_id: 17,
            generation: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            payload: b"response".to_vec(),
            traffic_context: None,
        };

        assert!(!is_current_session_udp_response(&sessions, &response));
        assert!(!is_current_session_udp_generation(&sessions, 17, 1));
        response.generation = 2;
        assert!(is_current_session_udp_response(&sessions, &response));
        assert!(is_current_session_udp_generation(&sessions, 17, 2));

        terminate_session_udp_worker(&mut sessions, 17).await;
    }

    #[tokio::test]
    async fn local_xudp_reuses_socket_across_udp_targets() {
        let target_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind first local XUDP target");
        let target_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind second local XUDP target");
        let target_a_addr = target_a
            .local_addr()
            .expect("first local XUDP target address");
        let target_b_addr = target_b
            .local_addr()
            .expect("second local XUDP target address");

        let target_a_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = target_a
                .recv_from(&mut buffer)
                .await
                .expect("receive first local XUDP request");
            target_a
                .send_to(&buffer[..length], peer)
                .await
                .expect("echo first local XUDP response");
            (buffer[..length].to_vec(), peer)
        });
        let target_b_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = target_b
                .recv_from(&mut buffer)
                .await
                .expect("receive second local XUDP request");
            target_b
                .send_to(&buffer[..length], peer)
                .await
                .expect("echo second local XUDP response");
            (buffer[..length].to_vec(), peer)
        });

        let key_a = TargetedUdpSessionKey {
            target_addr: target_a_addr,
            outbound_tag: None,
        };
        let key_b = TargetedUdpSessionKey {
            target_addr: target_b_addr,
            outbound_tag: None,
        };
        let (response_sender, mut response_receiver) = mpsc::channel(8);
        let worker = start_session_udp_session(
            90,
            1,
            key_a,
            response_sender,
            None,
            None,
            Duration::from_secs(5),
        )
        .await
        .expect("start multi-target local XUDP worker");
        assert!(session_udp_worker_matches(&worker, &key_b, None));

        worker
            .sender
            .send_to(b"local-a".to_vec(), target_a_addr)
            .await
            .expect("send first local XUDP target payload");
        let first_event = timeout(Duration::from_secs(1), response_receiver.recv())
            .await
            .expect("first local XUDP target response timeout")
            .expect("first local XUDP target response event");
        let SessionUdpEvent::Data(first_response) = first_event else {
            panic!("first local XUDP target response was not data");
        };
        assert_eq!(first_response.payload, b"local-a");
        assert_eq!(first_response.source, target_a_addr);

        worker
            .sender
            .send_to(b"local-b".to_vec(), target_b_addr)
            .await
            .expect("send second local XUDP target payload");
        let second_event = timeout(Duration::from_secs(1), response_receiver.recv())
            .await
            .expect("second local XUDP target response timeout")
            .expect("second local XUDP target response event");
        let SessionUdpEvent::Data(second_response) = second_event else {
            panic!("second local XUDP target response was not data");
        };
        assert_eq!(second_response.payload, b"local-b");
        assert_eq!(second_response.source, target_b_addr);

        let (payload_a, peer_a) =
            target_a_task.await.expect("first local XUDP target task");
        let (payload_b, peer_b) =
            target_b_task.await.expect("second local XUDP target task");
        assert_eq!(payload_a, b"local-a");
        assert_eq!(payload_b, b"local-b");
        assert_eq!(peer_a, peer_b);

        let mut sessions = HashMap::from([(90, worker)]);
        terminate_session_udp_worker(&mut sessions, 90).await;
    }

    #[tokio::test]
    async fn global_xudp_reuses_socket_across_udp_targets() {
        let target_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind first GlobalID UDP target");
        let target_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind second GlobalID UDP target");
        let target_a_addr = target_a
            .local_addr()
            .expect("first GlobalID target address");
        let target_b_addr = target_b
            .local_addr()
            .expect("second GlobalID target address");

        let target_a_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = target_a
                .recv_from(&mut buffer)
                .await
                .expect("receive first GlobalID target request");
            target_a
                .send_to(&buffer[..length], peer)
                .await
                .expect("echo first GlobalID target response");
            (buffer[..length].to_vec(), peer)
        });
        let target_b_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = target_b
                .recv_from(&mut buffer)
                .await
                .expect("receive second GlobalID target request");
            target_b
                .send_to(&buffer[..length], peer)
                .await
                .expect("echo second GlobalID target response");
            (buffer[..length].to_vec(), peer)
        });

        let global_id = [81, 82, 83, 84, 85, 86, 87, 88];
        let key_a = TargetedUdpSessionKey {
            target_addr: target_a_addr,
            outbound_tag: None,
        };
        let key_b = TargetedUdpSessionKey {
            target_addr: target_b_addr,
            outbound_tag: None,
        };
        let (response_sender, mut response_receiver) = mpsc::channel(8);
        let worker = start_session_udp_session(
            91,
            1,
            key_a,
            response_sender,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start multi-target GlobalID UDP worker");
        assert!(session_udp_worker_matches(&worker, &key_b, Some(global_id)));

        worker
            .sender
            .send_to(b"target-a".to_vec(), target_a_addr)
            .await
            .expect("send first GlobalID target payload");
        let first_event = timeout(Duration::from_secs(1), response_receiver.recv())
            .await
            .expect("first GlobalID target response timeout")
            .expect("first GlobalID target response event");
        let SessionUdpEvent::Data(first_response) = first_event else {
            panic!("first GlobalID target response was not data");
        };
        assert_eq!(first_response.payload, b"target-a");
        assert_eq!(first_response.source, target_a_addr);

        worker
            .sender
            .send_to(b"target-b".to_vec(), target_b_addr)
            .await
            .expect("send second GlobalID target payload");
        let second_event = timeout(Duration::from_secs(1), response_receiver.recv())
            .await
            .expect("second GlobalID target response timeout")
            .expect("second GlobalID target response event");
        let SessionUdpEvent::Data(second_response) = second_event else {
            panic!("second GlobalID target response was not data");
        };
        assert_eq!(second_response.payload, b"target-b");
        assert_eq!(second_response.source, target_b_addr);

        let (payload_a, peer_a) =
            target_a_task.await.expect("first GlobalID target task");
        let (payload_b, peer_b) =
            target_b_task.await.expect("second GlobalID target task");
        assert_eq!(payload_a, b"target-a");
        assert_eq!(payload_b, b"target-b");
        assert_eq!(peer_a, peer_b);

        let mut sessions = HashMap::from([(91, worker)]);
        terminate_session_udp_worker(&mut sessions, 91).await;
    }

    #[tokio::test]
    async fn global_xudp_takeover_reuses_socket_and_rejects_stale_sender() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind GlobalID UDP echo socket");
        let echo_addr = echo_socket.local_addr().expect("GlobalID UDP echo address");
        let (observation_sender, mut observation_receiver) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            for _ in 0..2 {
                let (length, peer) = echo_socket
                    .recv_from(&mut buffer)
                    .await
                    .expect("receive GlobalID UDP request");
                observation_sender
                    .send((buffer[..length].to_vec(), peer))
                    .await
                    .expect("record GlobalID UDP request");
                echo_socket
                    .send_to(&buffer[..length], peer)
                    .await
                    .expect("send GlobalID UDP response");
            }
        });

        let global_id = [91, 92, 93, 94, 95, 96, 97, 98];
        let key = TargetedUdpSessionKey {
            target_addr: echo_addr,
            outbound_tag: None,
        };
        let (response_sender_a, mut response_receiver_a) = mpsc::channel(8);
        let worker_a = start_session_udp_session(
            101,
            1,
            key.clone(),
            response_sender_a,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start first GlobalID UDP attachment");
        let stale_sender = worker_a.sender.clone();
        stale_sender
            .send_to(b"first".to_vec(), echo_addr)
            .await
            .expect("send first GlobalID UDP payload");

        let first_response =
            timeout(Duration::from_secs(1), response_receiver_a.recv())
                .await
                .expect("first GlobalID response timeout")
                .expect("first GlobalID response event");
        let SessionUdpEvent::Data(first_response) = first_response else {
            panic!("first GlobalID response was not data");
        };
        assert_eq!(first_response.session_id, 101);
        assert_eq!(first_response.generation, 1);
        assert_eq!(first_response.payload, b"first");

        let (response_sender_b, mut response_receiver_b) = mpsc::channel(8);
        let worker_b = start_session_udp_session(
            202,
            2,
            key,
            response_sender_b,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("take over GlobalID UDP attachment");

        let replaced_event =
            timeout(Duration::from_secs(1), response_receiver_a.recv())
                .await
                .expect("replaced GlobalID End timeout")
                .expect("replaced GlobalID End event");
        assert!(matches!(
            replaced_event,
            SessionUdpEvent::End {
                session_id: 101,
                generation: 1,
                has_error: false,
            }
        ));

        let stale_payload = stale_sender
            .send_to(b"stale".to_vec(), echo_addr)
            .await
            .expect_err("stale GlobalID sender must reject its payload");
        assert_eq!(stale_payload, b"stale");
        worker_b
            .sender
            .send_to(b"second".to_vec(), echo_addr)
            .await
            .expect("send second GlobalID UDP payload");

        let second_response =
            timeout(Duration::from_secs(1), response_receiver_b.recv())
                .await
                .expect("second GlobalID response timeout")
                .expect("second GlobalID response event");
        let SessionUdpEvent::Data(second_response) = second_response else {
            panic!("second GlobalID response was not data");
        };
        assert_eq!(second_response.session_id, 202);
        assert_eq!(second_response.generation, 2);
        assert_eq!(second_response.payload, b"second");

        let (first_payload, first_peer) = observation_receiver
            .recv()
            .await
            .expect("first GlobalID UDP observation");
        let (second_payload, second_peer) = observation_receiver
            .recv()
            .await
            .expect("second GlobalID UDP observation");
        assert_eq!(first_payload, b"first");
        assert_eq!(second_payload, b"second");
        assert_eq!(first_peer, second_peer);

        let mut sessions = HashMap::from([(101, worker_a), (202, worker_b)]);
        terminate_session_udp_worker(&mut sessions, 101).await;
        assert!(sessions.contains_key(&202));
        terminate_session_udp_worker(&mut sessions, 202).await;
        assert!(sessions.is_empty());
        echo_task.await.expect("GlobalID UDP echo task");
    }

    #[tokio::test]
    async fn detached_global_xudp_sender_returns_original_payload_promptly() {
        let global_id = [141, 142, 143, 144, 145, 146, 147, 148];
        let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let key = TargetedUdpSessionKey {
            target_addr,
            outbound_tag: None,
        };
        let (response_sender, _response_receiver) = mpsc::channel(1);
        let worker = start_session_udp_session(
            601,
            1,
            key,
            response_sender,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start detachable GlobalID sender test worker");
        let detached_sender = worker.sender.clone();
        let attachment_token = match &detached_sender {
            SessionUdpSender::Global {
                attachment_token, ..
            } => *attachment_token,
            SessionUdpSender::Local(_) => {
                panic!("GlobalID worker returned a local sender")
            }
        };
        detach_session_udp_worker(worker).await;

        let payload = timeout(
            Duration::from_secs(1),
            detached_sender.send_to(b"detached".to_vec(), target_addr),
        )
        .await
        .expect("detached GlobalID sender must not hang")
        .expect_err("detached GlobalID sender must reject its payload");
        assert_eq!(payload, b"detached");

        terminate_global_udp_worker(global_id, attachment_token).await;
    }

    #[tokio::test]
    async fn terminated_global_xudp_sender_returns_original_payload_promptly() {
        let global_id = [149, 150, 151, 152, 153, 154, 155, 156];
        let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let key = TargetedUdpSessionKey {
            target_addr,
            outbound_tag: None,
        };
        let (response_sender, _response_receiver) = mpsc::channel(1);
        let worker = start_session_udp_session(
            602,
            1,
            key,
            response_sender,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start terminable GlobalID sender test worker");
        let terminated_sender = worker.sender.clone();
        let attachment_token = match &terminated_sender {
            SessionUdpSender::Global {
                attachment_token, ..
            } => *attachment_token,
            SessionUdpSender::Local(_) => {
                panic!("GlobalID worker returned a local sender")
            }
        };

        terminate_global_udp_worker(global_id, attachment_token).await;

        let payload = timeout(
            Duration::from_secs(1),
            terminated_sender.send_to(b"terminated".to_vec(), target_addr),
        )
        .await
        .expect("terminated GlobalID sender must not hang")
        .expect_err("terminated GlobalID sender must reject its payload");
        assert_eq!(payload, b"terminated");
    }

    #[tokio::test]
    async fn ended_global_xudp_attachment_resumes_same_socket() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind detached GlobalID UDP echo socket");
        let echo_addr = echo_socket
            .local_addr()
            .expect("detached GlobalID UDP echo address");
        let (peer_sender, mut peer_receiver) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            for _ in 0..2 {
                let (length, peer) = echo_socket
                    .recv_from(&mut buffer)
                    .await
                    .expect("receive detached GlobalID UDP request");
                peer_sender
                    .send(peer)
                    .await
                    .expect("record detached GlobalID UDP peer");
                echo_socket
                    .send_to(&buffer[..length], peer)
                    .await
                    .expect("send detached GlobalID UDP response");
            }
        });

        let global_id = [99, 100, 101, 102, 103, 104, 105, 106];
        let key = TargetedUdpSessionKey {
            target_addr: echo_addr,
            outbound_tag: None,
        };
        let (response_sender_a, mut response_receiver_a) = mpsc::channel(8);
        let worker_a = start_session_udp_session(
            301,
            1,
            key.clone(),
            response_sender_a,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start detachable GlobalID UDP attachment");
        worker_a
            .sender
            .send_to(b"before-detach".to_vec(), echo_addr)
            .await
            .expect("send pre-detach GlobalID payload");
        let first_response =
            timeout(Duration::from_secs(1), response_receiver_a.recv())
                .await
                .expect("pre-detach GlobalID response timeout")
                .expect("pre-detach GlobalID response event");
        assert!(matches!(
            first_response,
            SessionUdpEvent::Data(SessionUdpResponse {
                session_id: 301,
                generation: 1,
                ..
            })
        ));
        let mut ended_sessions = HashMap::from([(301, worker_a)]);
        expire_session_udp_worker(&mut ended_sessions, 301).await;
        assert!(ended_sessions.is_empty());

        let (response_sender_b, mut response_receiver_b) = mpsc::channel(8);
        let worker_b = start_session_udp_session(
            302,
            2,
            key,
            response_sender_b,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("resume detached GlobalID UDP attachment");
        worker_b
            .sender
            .send_to(b"after-detach".to_vec(), echo_addr)
            .await
            .expect("send resumed GlobalID payload");
        let second_response =
            timeout(Duration::from_secs(1), response_receiver_b.recv())
                .await
                .expect("resumed GlobalID response timeout")
                .expect("resumed GlobalID response event");
        assert!(matches!(
            second_response,
            SessionUdpEvent::Data(SessionUdpResponse {
                session_id: 302,
                generation: 2,
                ..
            })
        ));

        let first_peer = peer_receiver
            .recv()
            .await
            .expect("pre-detach GlobalID UDP peer");
        let second_peer = peer_receiver
            .recv()
            .await
            .expect("resumed GlobalID UDP peer");
        assert_eq!(first_peer, second_peer);

        let mut sessions = HashMap::from([(302, worker_b)]);
        terminate_session_udp_worker(&mut sessions, 302).await;
        echo_task.await.expect("ended GlobalID UDP echo task");
    }

    #[tokio::test]
    async fn stale_global_xudp_cleanup_does_not_remove_reattachment() {
        let now = Instant::now();
        let global_id = [121, 122, 123, 124, 125, 126, 127, 128];
        let mut globals = GlobalXudpWorkers::default();
        let first = globals
            .registry
            .attach(global_id, 501, 1, now)
            .expect("attach GlobalID before cleanup test");
        assert!(globals.registry.detach(global_id, first.current.token, now));

        let (payload_sender, _payload_receiver) = mpsc::channel(1);
        let (response_sender, _response_receiver) = mpsc::channel(1);
        let attachment = Arc::new(RwLock::new(None));
        let task = tokio::spawn(std::future::pending::<()>());
        globals.workers.insert(
            global_id,
            GlobalSessionUdpWorker {
                key: GlobalUdpWorkerKey {
                    target_is_ipv6: false,
                    outbound_tag: None,
                },
                sender: payload_sender,
                attachment: attachment.clone(),
                attachment_notify: Arc::new(Notify::new()),
                task,
            },
        );

        let reattached = globals
            .registry
            .attach(
                global_id,
                502,
                2,
                now + XUDP_GLOBAL_REATTACH_TTL - Duration::from_millis(1),
            )
            .expect("reattach GlobalID before stale cleanup");
        *attachment.write().await = Some(GlobalUdpAttachment {
            token: reattached.current.token,
            session_id: 502,
            generation: 2,
            response_sender,
            traffic_context: None,
        });

        purge_expired_global_udp_workers(
            &mut globals,
            now + XUDP_GLOBAL_REATTACH_TTL + Duration::from_secs(1),
        );

        assert_eq!(
            globals.registry.current(
                global_id,
                now + XUDP_GLOBAL_REATTACH_TTL + Duration::from_secs(1),
            ),
            Some(reattached.current)
        );
        assert!(globals.workers.contains_key(&global_id));
        globals
            .workers
            .remove(&global_id)
            .expect("GlobalID worker survives stale cleanup")
            .task
            .abort();
    }

    #[tokio::test]
    async fn detached_global_xudp_buffers_downlink_until_reattach() {
        let remote_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind buffered GlobalID UDP socket");
        let remote_addr = remote_socket
            .local_addr()
            .expect("buffered GlobalID UDP address");
        let (request_sender, mut request_receiver) = mpsc::channel(1);
        let (release_sender, mut release_receiver) = mpsc::channel(1);
        let remote_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = remote_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive buffered GlobalID request");
            request_sender
                .send((buffer[..length].to_vec(), peer))
                .await
                .expect("report buffered GlobalID request");
            release_receiver
                .recv()
                .await
                .expect("release buffered GlobalID response");
            remote_socket
                .send_to(b"delayed-response", peer)
                .await
                .expect("send buffered GlobalID response");
        });

        let global_id = [107, 108, 109, 110, 111, 112, 113, 114];
        let key = TargetedUdpSessionKey {
            target_addr: remote_addr,
            outbound_tag: None,
        };
        let (response_sender_a, mut response_receiver_a) = mpsc::channel(8);
        let worker_a = start_session_udp_session(
            401,
            1,
            key.clone(),
            response_sender_a,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start buffered GlobalID attachment");
        worker_a
            .sender
            .send_to(b"request-before-detach".to_vec(), remote_addr)
            .await
            .expect("send buffered GlobalID request");
        let (request, _) = timeout(Duration::from_secs(1), request_receiver.recv())
            .await
            .expect("buffered GlobalID request timeout")
            .expect("buffered GlobalID request observation");
        assert_eq!(request, b"request-before-detach");

        detach_session_udp_worker(worker_a).await;
        release_sender
            .send(())
            .await
            .expect("release detached GlobalID response");
        remote_task.await.expect("buffered GlobalID remote task");
        sleep(Duration::from_millis(20)).await;
        match timeout(Duration::from_millis(20), response_receiver_a.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(_)) => panic!(
                "detached GlobalID response must not be sent to the old attachment"
            ),
        }

        let (response_sender_b, mut response_receiver_b) = mpsc::channel(8);
        let worker_b = start_session_udp_session(
            402,
            2,
            key,
            response_sender_b,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("reattach buffered GlobalID session");
        let buffered_event =
            timeout(Duration::from_secs(1), response_receiver_b.recv())
                .await
                .expect("buffered GlobalID downlink timeout")
                .expect("buffered GlobalID downlink event");
        let SessionUdpEvent::Data(buffered_response) = buffered_event else {
            panic!("buffered GlobalID downlink was not data");
        };
        assert_eq!(buffered_response.session_id, 402);
        assert_eq!(buffered_response.generation, 2);
        assert_eq!(buffered_response.payload, b"delayed-response");

        let mut sessions = HashMap::from([(402, worker_b)]);
        terminate_session_udp_worker(&mut sessions, 402).await;
    }

    #[tokio::test]
    async fn session_udp_worker_emits_end_on_idle_timeout() {
        let (event_sender, mut event_receiver) = mpsc::channel(4);
        let worker = start_session_udp_session(
            19,
            7,
            TargetedUdpSessionKey {
                target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                outbound_tag: None,
            },
            event_sender,
            None,
            None,
            Duration::from_millis(10),
        )
        .await
        .expect("start short-lived session UDP worker");

        let event = timeout(Duration::from_secs(1), event_receiver.recv())
            .await
            .expect("session UDP idle End timeout")
            .expect("session UDP idle End event");
        assert!(matches!(
            event,
            SessionUdpEvent::End {
                session_id: 19,
                generation: 7,
                has_error: false,
            }
        ));

        worker
            .task
            .expect("local session UDP worker task")
            .await
            .expect("idle session UDP worker should finish cleanly");
    }

    #[tokio::test]
    async fn global_session_udp_worker_emits_end_on_idle_timeout() {
        let global_id = [151, 152, 153, 154, 155, 156, 157, 158];
        let (event_sender, mut event_receiver) = mpsc::channel(4);
        let worker = start_session_udp_session(
            20,
            8,
            TargetedUdpSessionKey {
                target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                outbound_tag: None,
            },
            event_sender,
            None,
            Some(global_id),
            Duration::from_millis(10),
        )
        .await
        .expect("start short-lived GlobalID session UDP worker");
        let mut sessions = HashMap::from([(20, worker)]);

        let event = timeout(Duration::from_secs(1), event_receiver.recv())
            .await
            .expect("GlobalID session UDP idle End timeout")
            .expect("GlobalID session UDP idle End event");
        assert!(matches!(
            event,
            SessionUdpEvent::End {
                session_id: 20,
                generation: 8,
                has_error: false,
            }
        ));

        terminate_session_udp_worker(&mut sessions, 20).await;
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn global_session_udp_worker_emits_error_end_on_write_failure() {
        let global_id = [161, 162, 163, 164, 165, 166, 167, 168];
        let (event_sender, mut event_receiver) = mpsc::channel(4);
        let worker = start_session_udp_session(
            21,
            9,
            TargetedUdpSessionKey {
                target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
                outbound_tag: None,
            },
            event_sender,
            None,
            Some(global_id),
            Duration::from_secs(5),
        )
        .await
        .expect("start GlobalID write-failure UDP worker");
        let sender = worker.sender.clone();
        let mut sessions = HashMap::from([(21, worker)]);
        let invalid_target = SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 9));

        let payload = timeout(
            Duration::from_secs(1),
            sender.send_to(b"write-failure".to_vec(), invalid_target),
        )
        .await
        .expect("GlobalID write failure must not hang")
        .expect_err("IPv4 GlobalID worker must reject an IPv6 target");
        assert_eq!(payload, b"write-failure");

        let event = timeout(Duration::from_secs(1), event_receiver.recv())
            .await
            .expect("GlobalID write-failure End timeout")
            .expect("GlobalID write-failure End event");
        assert!(matches!(
            event,
            SessionUdpEvent::End {
                session_id: 21,
                generation: 9,
                has_error: true,
            }
        ));

        terminate_session_udp_worker(&mut sessions, 21).await;
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn removing_session_udp_worker_aborts_task() {
        let (sender, _receiver) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        let abort_handle = task.abort_handle();
        let mut sessions = HashMap::new();
        sessions.insert(
            23,
            SessionUdpWorker {
                key: TargetedUdpSessionKey {
                    target_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                    outbound_tag: None,
                },
                global_id: None,
                generation: 1,
                sender: SessionUdpSender::Local(sender),
                task: Some(task),
            },
        );

        terminate_session_udp_worker(&mut sessions, 23).await;
        tokio::task::yield_now().await;

        assert!(abort_handle.is_finished());
        assert!(!sessions.contains_key(&23));
    }

    #[tokio::test]
    async fn multi_directional_udp_relays_trojan_packets() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Trojan UDP echo socket");
        let echo_addr = echo_socket.local_addr().expect("Trojan UDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 128];
            let (length, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive Trojan UDP echo request");
            echo_socket
                .send_to(&buffer[..length], peer)
                .await
                .expect("send Trojan UDP echo response");
        });

        let (mut client, server) = duplex(4096);
        let relay_task = tokio::spawn(run_multi_directional_udp(
            Box::new(TrojanUdpStream::new(Box::new(TestStream(server)))),
            Arc::new(NativeResolver::new()),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 32000)),
            Some(
                TrafficContext::new("trojan")
                    .with_identity("udp-user")
                    .with_inbound_tag("trojan-udp"),
            ),
        ));

        let mut request = vec![1];
        let IpAddr::V4(echo_ip) = echo_addr.ip() else {
            unreachable!("test echo address must be IPv4");
        };
        request.extend_from_slice(&echo_ip.octets());
        request.extend_from_slice(&echo_addr.port().to_be_bytes());
        request.extend_from_slice(&4u16.to_be_bytes());
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(b"ping");
        client
            .write_all(&request)
            .await
            .expect("write Trojan UDP packet");

        let mut header = [0u8; 9];
        timeout(Duration::from_secs(5), client.read_exact(&mut header))
            .await
            .expect("Trojan UDP response header timeout")
            .expect("read Trojan UDP response header");
        assert_eq!(header[0], 1);
        assert_eq!(&header[1..5], &echo_ip.octets());
        assert_eq!(u16::from_be_bytes([header[5], header[6]]), echo_addr.port());
        assert_eq!(u16::from_be_bytes([header[7], header[8]]), 4);

        let mut suffix_and_payload = [0u8; 6];
        client
            .read_exact(&mut suffix_and_payload)
            .await
            .expect("read Trojan UDP response payload");
        assert_eq!(&suffix_and_payload[..2], b"\r\n");
        assert_eq!(&suffix_and_payload[2..], b"ping");

        echo_task.await.expect("Trojan UDP echo task finished");
        relay_task.abort();
    }

    #[tokio::test]
    async fn bidirectional_udp_relay_preserves_message_boundaries() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP echo socket");
        let echo_addr = echo_socket.local_addr().expect("UDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 128];
            let (len, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive UDP echo request");
            echo_socket
                .send_to(&buffer[..len], peer)
                .await
                .expect("send UDP echo response");
        });

        let relay_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind message relay socket");
        let relay_addr = relay_socket.local_addr().expect("message relay address");
        let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind message client socket");
        let client_addr =
            client_socket.local_addr().expect("message client address");
        relay_socket
            .connect(client_addr)
            .await
            .expect("connect relay message socket");
        client_socket
            .connect(relay_addr)
            .await
            .expect("connect client message socket");

        let relay_task = tokio::spawn(run_bidirectional_udp(
            Box::new(relay_socket),
            NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port()),
            Arc::new(NativeResolver::new()),
            runtime_with_outbounds(Vec::new()),
            client_addr,
            Some(
                TrafficContext::new("vmess")
                    .with_identity("udp-user")
                    .with_inbound_tag("vmess-udp"),
            ),
        ));

        client_socket
            .send(b"vmess-udp-message")
            .await
            .expect("send message to relay");
        let mut response = [0u8; 128];
        let len = timeout(Duration::from_secs(5), client_socket.recv(&mut response))
            .await
            .expect("bidirectional UDP response timeout")
            .expect("receive bidirectional UDP response");

        assert_eq!(&response[..len], b"vmess-udp-message");
        echo_task.await.expect("UDP echo task finished");
        relay_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_udp_relay_forwards_datagrams() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo socket");
        let echo_addr = echo_socket.local_addr().expect("echo addr");
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, peer) =
                echo_socket.recv_from(&mut buf).await.expect("echo recv");
            echo_socket
                .send_to(&buf[..len], peer)
                .await
                .expect("echo send");
        });

        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dokodemo socket"),
        );
        let server_addr = server_socket.local_addr().expect("dokodemo addr");
        let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
        let server_task = tokio::spawn(run_dokodemo_udp_server(
            server_socket,
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
            },
            echo_addr,
            "dokodemo-udp-test".into(),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
        ));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        client
            .send_to(b"ping", server_addr)
            .await
            .expect("client send");

        let mut response = [0u8; 32];
        let (len, _peer) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("relay response timeout")
                .expect("client receive");
        assert_eq!(&response[..len], b"ping");

        echo_task.await.expect("echo task finished");
        server_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_udp_reuses_session_for_same_flow() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo socket");
        let echo_addr = echo_socket.local_addr().expect("echo addr");
        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            for _ in 0..2 {
                let (len, peer) =
                    echo_socket.recv_from(&mut buf).await.expect("echo recv");
                peer_tx.send(peer).await.expect("record peer");
                echo_socket
                    .send_to(&buf[..len], peer)
                    .await
                    .expect("echo send");
            }
        });

        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dokodemo socket"),
        );
        let server_addr = server_socket.local_addr().expect("dokodemo addr");
        let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
        let server_task = tokio::spawn(run_dokodemo_udp_server(
            server_socket,
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
            },
            echo_addr,
            "dokodemo-udp-test".into(),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
        ));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        let mut response = [0u8; 32];

        client
            .send_to(b"one", server_addr)
            .await
            .expect("client send one");
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("relay response one timeout")
                .expect("client receive one");
        assert_eq!(&response[..len], b"one");

        client
            .send_to(b"two", server_addr)
            .await
            .expect("client send two");
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("relay response two timeout")
                .expect("client receive two");
        assert_eq!(&response[..len], b"two");

        let first_peer = peer_rx.recv().await.expect("first outbound peer");
        let second_peer = peer_rx.recv().await.expect("second outbound peer");
        assert_eq!(first_peer, second_peer);

        echo_task.await.expect("echo task finished");
        server_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_udp_session_forwards_multiple_responses() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo socket");
        let echo_addr = echo_socket.local_addr().expect("echo addr");
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (_len, peer) =
                echo_socket.recv_from(&mut buf).await.expect("echo recv");
            echo_socket
                .send_to(b"first", peer)
                .await
                .expect("send first");
            echo_socket
                .send_to(b"second", peer)
                .await
                .expect("send second");
        });

        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dokodemo socket"),
        );
        let server_addr = server_socket.local_addr().expect("dokodemo addr");
        let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
        let server_task = tokio::spawn(run_dokodemo_udp_server(
            server_socket,
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
            },
            echo_addr,
            "dokodemo-udp-test".into(),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
        ));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        client
            .send_to(b"request", server_addr)
            .await
            .expect("client send");

        let mut response = [0u8; 32];
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("first relay response timeout")
                .expect("client receive first");
        assert_eq!(&response[..len], b"first");
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("second relay response timeout")
                .expect("client receive second");
        assert_eq!(&response[..len], b"second");

        echo_task.await.expect("echo task finished");
        server_task.abort();
    }

    #[test]
    fn udp_routing_selects_blackhole_outbound() {
        let runtime = runtime_with_outbounds(vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["dokodemo-udp".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("routing should build"),
        );

        let action = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect("outbound selection should succeed");

        assert_eq!(
            action,
            UdpOutboundAction::Blackhole {
                tag: "blocked".into()
            }
        );
    }

    #[test]
    fn udp_routing_defaults_to_first_outbound() {
        let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);

        let action = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect("outbound selection should succeed");

        assert_eq!(
            action,
            UdpOutboundAction::Freedom {
                tag: Some("direct".into())
            }
        );
    }

    #[test]
    fn udp_routing_rejects_missing_routed_outbound() {
        let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["dokodemo-udp".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("missing".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("missing UDP outbound routing rule should compile"),
        );

        let error = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect_err("missing routed UDP outbound must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("missing outbound missing"));
    }

    #[test]
    fn udp_routing_rejects_empty_balancer_without_falling_back() {
        let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["dokodemo-udp".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    balancer_tag: Some("empty".into()),
                    ..RuleConfig::default()
                }],
                balancers: vec![BalancerConfig {
                    tag: "empty".into(),
                    outbound_selector: vec!["missing-prefix".into()],
                    fallback_tag: None,
                }],
                ..RoutingConfig::default()
            }))
            .expect("empty UDP balancer routing rule should compile"),
        );

        let error = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect_err("empty routed UDP balancer must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("balancer empty has no available outbound")
        );
    }

    #[test]
    fn udp_routing_rejects_unsupported_outbound_protocol() {
        let runtime = runtime_with_outbounds(vec![outbound("proxy", "vmess")]);

        let err = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect_err("unsupported udp outbound protocol should fail");

        assert!(
            err.to_string()
                .contains("udp outbound proxy uses unsupported protocol vmess")
        );
    }

    #[test]
    fn udp_bind_location_converts_ip_address() {
        let bind_location = BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1080,
        ));

        let socket_addr = bind_location_to_socket_addr(&bind_location)
            .expect("ip bind should convert to socket address");
        assert_eq!(socket_addr.port(), 1080);
    }
}
