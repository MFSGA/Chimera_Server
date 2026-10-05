#[cfg(feature = "vless-reverse")]
use bytes::Bytes;
use tokio::task::JoinHandle;

use crate::{
    address::NetLocation,
    outbound::connect_vless_udp_via_outbound,
    resolver::{Resolver, resolve_single_address},
    runtime::OutboundSummary,
};

use super::*;

#[derive(Clone)]
pub(crate) enum SessionUdpSender {
    Local(mpsc::Sender<LocalUdpPayload>),
    Vless(mpsc::Sender<Vec<u8>>),
    #[cfg(feature = "vless-reverse")]
    Reverse(mpsc::Sender<Vec<u8>>),
    #[cfg(feature = "trojan")]
    Trojan(mpsc::Sender<LocalUdpPayload>),
    Global {
        sender: mpsc::Sender<GlobalUdpPayload>,
        attachment_token: u64,
    },
}

impl SessionUdpSender {
    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Self::Local(sender) => sender.is_closed(),
            Self::Vless(sender) => sender.is_closed(),
            #[cfg(feature = "vless-reverse")]
            Self::Reverse(sender) => sender.is_closed(),
            #[cfg(feature = "trojan")]
            Self::Trojan(sender) => sender.is_closed(),
            Self::Global { sender, .. } => sender.is_closed(),
        }
    }

    pub(crate) async fn send_to(
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
            Self::Vless(sender) => {
                sender.send(payload).await.map_err(|error| error.0)
            }
            #[cfg(feature = "vless-reverse")]
            Self::Reverse(sender) => {
                sender.send(payload).await.map_err(|error| error.0)
            }
            #[cfg(feature = "trojan")]
            Self::Trojan(sender) => sender
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

pub(crate) struct LocalSessionUdpTask {
    pub(crate) cancellation: CancellationToken,
    pub(crate) join: Option<JoinHandle<()>>,
}

impl LocalSessionUdpTask {
    async fn stop(mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for LocalSessionUdpTask {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.as_ref() {
            join.abort();
        }
    }
}

pub(crate) struct SessionUdpWorker {
    pub(crate) key: TargetedUdpSessionKey,
    pub(crate) route_target: NetLocation,
    pub(crate) global_id: Option<[u8; 8]>,
    pub(crate) global_backend_key: Option<GlobalUdpWorkerKey>,
    pub(crate) generation: u64,
    pub(crate) sender: SessionUdpSender,
    pub(crate) task: Option<LocalSessionUdpTask>,
}

pub(crate) enum SessionUdpWorkerPlan {
    Reuse(SessionUdpSender),
    Replace,
}

pub(crate) struct SessionUdpWorkerStart {
    pub(crate) key: TargetedUdpSessionKey,
    pub(crate) route_target: NetLocation,
    pub(crate) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(crate) traffic_context: Option<TrafficContext>,
    pub(crate) global_id: Option<[u8; 8]>,
    pub(crate) idle_timeout: Duration,
}

#[cfg(feature = "trojan")]
pub(crate) struct TrojanSessionUdpWorkerStart {
    pub(crate) key: TargetedUdpSessionKey,
    pub(crate) route_target: NetLocation,
    pub(crate) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(crate) traffic_context: Option<TrafficContext>,
    pub(crate) resolver: Arc<dyn Resolver>,
    pub(crate) runtime: DataPlaneRuntime,
    pub(crate) outbound: crate::runtime::OutboundSummary,
    pub(crate) global_id: Option<[u8; 8]>,
    pub(crate) idle_timeout: Duration,
}

pub(crate) struct VlessSessionUdpWorkerStart {
    pub(crate) key: TargetedUdpSessionKey,
    pub(crate) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(crate) traffic_context: Option<TrafficContext>,
    pub(crate) resolver: Arc<dyn Resolver>,
    pub(crate) runtime: DataPlaneRuntime,
    pub(crate) outbound: OutboundSummary,
    pub(crate) target: NetLocation,
    pub(crate) idle_timeout: Duration,
}

#[cfg(feature = "vless-reverse")]
pub(crate) struct ReverseSessionUdpWorkerStart {
    pub(crate) key: TargetedUdpSessionKey,
    pub(crate) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(crate) traffic_context: Option<TrafficContext>,
    pub(crate) resolver: Arc<dyn Resolver>,
    pub(crate) runtime: DataPlaneRuntime,
    pub(crate) tag: String,
    pub(crate) target: NetLocation,
    pub(crate) source: SocketAddr,
    pub(crate) local: Option<SocketAddr>,
    pub(crate) global_id: Option<[u8; 8]>,
    pub(crate) idle_timeout: Duration,
}

pub(crate) fn session_udp_worker_matches(
    worker: &SessionUdpWorker,
    key: &TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
) -> bool {
    let expected_backend_key = global_id.map(|_| GlobalUdpWorkerKey::from(key));
    session_udp_worker_matches_backend(
        worker,
        key,
        global_id,
        expected_backend_key.as_ref(),
    )
}

pub(crate) fn session_udp_worker_matches_backend(
    worker: &SessionUdpWorker,
    key: &TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
    global_backend_key: Option<&GlobalUdpWorkerKey>,
) -> bool {
    if worker.global_id != global_id || worker.sender.is_closed() {
        return false;
    }
    match global_id {
        Some(_) => worker.global_backend_key.as_ref() == global_backend_key,
        None => {
            worker.global_backend_key.is_none()
                && GlobalUdpWorkerKey::from(&worker.key)
                    == GlobalUdpWorkerKey::from(key)
        }
    }
}

pub(crate) fn plan_session_udp_worker(
    worker: Option<&SessionUdpWorker>,
    key: &TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
) -> SessionUdpWorkerPlan {
    worker
        .filter(|worker| session_udp_worker_matches(worker, key, global_id))
        .map(|worker| SessionUdpWorkerPlan::Reuse(worker.sender.clone()))
        .unwrap_or(SessionUdpWorkerPlan::Replace)
}

pub(crate) fn plan_session_generation(
    next_generation: u64,
) -> std::io::Result<(u64, u64)> {
    let following_generation = next_generation.checked_add(1).ok_or_else(|| {
        std::io::Error::other("session UDP generation counter exhausted")
    })?;
    Ok((next_generation, following_generation))
}

pub(crate) async fn replace_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    next_generation: &mut u64,
    start: SessionUdpWorkerStart,
) -> std::io::Result<SessionUdpSender> {
    terminate_session_udp_worker(sessions, session_id).await;
    let (generation, following_generation) =
        plan_session_generation(*next_generation)?;
    *next_generation = following_generation;
    let worker =
        start_session_udp_session_with_route_target(session_id, generation, start)
            .await?;
    let sender = worker.sender.clone();
    sessions.insert(session_id, worker);
    Ok(sender)
}

#[cfg(feature = "trojan")]
pub(crate) async fn replace_trojan_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    next_generation: &mut u64,
    start: TrojanSessionUdpWorkerStart,
) -> std::io::Result<SessionUdpSender> {
    terminate_session_udp_worker(sessions, session_id).await;
    let (generation, following_generation) =
        plan_session_generation(*next_generation)?;
    *next_generation = following_generation;
    let worker =
        start_trojan_session_udp_session(session_id, generation, start).await?;
    let sender = worker.sender.clone();
    sessions.insert(session_id, worker);
    Ok(sender)
}

pub(crate) async fn replace_vless_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    next_generation: &mut u64,
    start: VlessSessionUdpWorkerStart,
) -> std::io::Result<SessionUdpSender> {
    terminate_session_udp_worker(sessions, session_id).await;
    let (generation, following_generation) =
        plan_session_generation(*next_generation)?;
    *next_generation = following_generation;
    let worker =
        start_vless_session_udp_session(session_id, generation, start).await?;
    let sender = worker.sender.clone();
    sessions.insert(session_id, worker);
    Ok(sender)
}

#[cfg(feature = "vless-reverse")]
pub(crate) async fn replace_reverse_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    next_generation: &mut u64,
    start: ReverseSessionUdpWorkerStart,
) -> std::io::Result<SessionUdpSender> {
    terminate_session_udp_worker(sessions, session_id).await;
    let (generation, following_generation) =
        plan_session_generation(*next_generation)?;
    *next_generation = following_generation;
    let worker = if let Some(global_id) = start.global_id {
        let route_target = start.target.clone();
        attach_global_session_udp_session(GlobalSessionUdpAttachStart {
            global_id,
            session_id,
            generation,
            key: start.key,
            route_target,
            response_sender: start.response_sender,
            traffic_context: start.traffic_context,
            idle_timeout: start.idle_timeout,
            backend_start: GlobalUdpBackendStart::Reverse {
                runtime: start.runtime,
                tag: start.tag,
                source: start.source,
                local: start.local,
            },
        })
        .await?
    } else {
        start_reverse_session_udp_session(session_id, generation, start)?
    };
    let sender = worker.sender.clone();
    sessions.insert(session_id, worker);
    Ok(sender)
}

pub(crate) async fn resolve_session_udp_location(
    resolver: &Arc<dyn Resolver>,
    runtime: &DataPlaneRuntime,
    target: &NetLocation,
) -> std::io::Result<SocketAddr> {
    match target.to_socket_addr_nonblocking() {
        Some(address) => Ok(address),
        None => match resolve_single_address(resolver, target).await {
            Ok(address) => Ok(address),
            Err(error) => {
                runtime.record_user_domain_dns_failure();
                Err(error)
            }
        },
    }
}

async fn stop_local_session_udp_task(task: LocalSessionUdpTask) {
    task.stop().await;
}

pub(crate) async fn terminate_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
) {
    let Some(worker) = sessions.remove(&session_id) else {
        return;
    };
    if let Some(task) = worker.task {
        stop_local_session_udp_task(task).await;
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

pub(crate) async fn expire_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
) {
    if let Some(worker) = sessions.remove(&session_id) {
        detach_session_udp_worker(worker).await;
    }
}

pub(crate) async fn detach_session_udp_worker(worker: SessionUdpWorker) {
    if let Some(task) = worker.task {
        stop_local_session_udp_task(task).await;
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

pub(crate) fn is_current_session_udp_generation(
    sessions: &HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    generation: u64,
) -> bool {
    sessions
        .get(&session_id)
        .is_some_and(|worker| worker.generation == generation)
}

pub(crate) fn is_current_session_udp_response(
    sessions: &HashMap<u16, SessionUdpWorker>,
    response: &SessionUdpResponse,
) -> bool {
    is_current_session_udp_generation(
        sessions,
        response.session_id,
        response.generation,
    )
}

#[cfg(test)]
pub(crate) async fn start_session_udp_session(
    session_id: u16,
    generation: u64,
    key: TargetedUdpSessionKey,
    response_sender: mpsc::Sender<SessionUdpEvent>,
    traffic_context: Option<TrafficContext>,
    global_id: Option<[u8; 8]>,
    idle_timeout: Duration,
) -> std::io::Result<SessionUdpWorker> {
    let route_target =
        NetLocation::from_ip_addr(key.target_addr.ip(), key.target_addr.port());
    start_session_udp_session_with_route_target(
        session_id,
        generation,
        SessionUdpWorkerStart {
            key,
            route_target,
            response_sender,
            traffic_context,
            global_id,
            idle_timeout,
        },
    )
    .await
}

async fn start_session_udp_session_with_route_target(
    session_id: u16,
    generation: u64,
    start: SessionUdpWorkerStart,
) -> std::io::Result<SessionUdpWorker> {
    match start.global_id {
        Some(global_id) => {
            attach_global_session_udp_session(GlobalSessionUdpAttachStart {
                global_id,
                session_id,
                generation,
                key: start.key,
                route_target: start.route_target,
                response_sender: start.response_sender,
                traffic_context: start.traffic_context,
                idle_timeout: start.idle_timeout,
                backend_start: GlobalUdpBackendStart::Direct,
            })
            .await
        }
        None => {
            start_local_session_udp_session(
                session_id,
                generation,
                start.key,
                start.route_target,
                start.response_sender,
                start.traffic_context,
                start.idle_timeout,
            )
            .await
        }
    }
}

async fn start_vless_session_udp_session(
    session_id: u16,
    generation: u64,
    start: VlessSessionUdpWorkerStart,
) -> std::io::Result<SessionUdpWorker> {
    let mut proxy = connect_vless_udp_via_outbound(
        &start.resolver,
        &start.target,
        &start.runtime,
        &start.outbound,
    )
    .await?;
    let (sender, mut receiver) =
        mpsc::channel::<Vec<u8>>(UDP_SESSION_CHANNEL_CAPACITY);
    let worker_key = start.key.clone();
    let route_target = start.target.clone();
    let target = start.target;
    let target_addr = start.key.target_addr;
    let response_sender = start.response_sender;
    let traffic_context = start.traffic_context;
    let idle_timeout = start.idle_timeout;
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();

    let join = tokio::spawn(async move {
        let mut response_buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut idle = Box::pin(sleep(idle_timeout));
        let has_error = task_cancellation
            .run_until_cancelled(async {
                loop {
                    tokio::select! {
                        _ = idle.as_mut() => break false,
                        maybe_payload = receiver.recv() => {
                            let Some(payload) = maybe_payload else {
                                break false;
                            };
                            if let Err(error) = proxy.send_to(&target, &payload).await {
                                debug!("VLESS session UDP write to {} failed: {}", target, error);
                                break true;
                            }
                            record_transfer(traffic_context.clone(), payload.len() as u64, 0);
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                        response = proxy.recv_from(&mut response_buffer) => {
                            let (_source, length) = match response {
                                Ok(response) => response,
                                Err(error) => {
                                    debug!("VLESS session UDP receive failed: {}", error);
                                    break true;
                                }
                            };
                            let response = SessionUdpResponse {
                                session_id,
                                generation,
                                source: target_addr,
                                payload: response_buffer[..length].to_vec(),
                                traffic_context: traffic_context.clone(),
                            };
                            if response_sender.send(SessionUdpEvent::Data(response)).await.is_err() {
                                break false;
                            }
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                    }
                }
            })
            .await;
        let has_error = has_error.unwrap_or(false);
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
        route_target,
        global_id: None,
        global_backend_key: None,
        generation,
        sender: SessionUdpSender::Vless(sender),
        task: Some(LocalSessionUdpTask {
            cancellation,
            join: Some(join),
        }),
    })
}

#[cfg(feature = "vless-reverse")]
fn start_reverse_session_udp_session(
    session_id: u16,
    generation: u64,
    start: ReverseSessionUdpWorkerStart,
) -> std::io::Result<SessionUdpWorker> {
    let route_target = start.target.clone();
    let mut session = start.runtime.open_reverse_udp(
        &start.tag,
        start.target.clone(),
        start.source,
        start.local,
    )?;
    let (sender, mut receiver) =
        mpsc::channel::<Vec<u8>>(UDP_SESSION_CHANNEL_CAPACITY);
    let worker_key = start.key.clone();
    let fallback_source = start.key.target_addr;
    let resolver = start.resolver;
    let runtime = start.runtime;
    let response_sender = start.response_sender;
    let traffic_context = start.traffic_context;
    let idle_timeout = start.idle_timeout;
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();

    let join = tokio::spawn(async move {
        let mut idle = Box::pin(sleep(idle_timeout));
        let has_error = task_cancellation
            .run_until_cancelled(async {
                loop {
                    tokio::select! {
                        _ = idle.as_mut() => break false,
                        maybe_payload = receiver.recv() => {
                            let Some(payload) = maybe_payload else {
                                break false;
                            };
                            let payload_length = payload.len();
                            if let Err(error) = session.send(Bytes::from(payload), None).await {
                                debug!("VLESS Reverse session UDP write failed: {}", error);
                                break true;
                            }
                            record_transfer(traffic_context.clone(), payload_length as u64, 0);
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                        response = session.recv() => {
                            let (payload, target_override) = match response {
                                Ok(Some(response)) => response,
                                Ok(None) => break false,
                                Err(error) => {
                                    debug!("VLESS Reverse session UDP receive failed: {}", error);
                                    break true;
                                }
                            };
                            let source = match target_override {
                                Some(source) => match resolve_session_udp_location(&resolver, &runtime, &source.location).await {
                                    Ok(source) => source,
                                    Err(error) => {
                                        debug!("VLESS Reverse UDP response source resolution failed: {}", error);
                                        break true;
                                    }
                                },
                                None => fallback_source,
                            };
                            let response = SessionUdpResponse {
                                session_id,
                                generation,
                                source,
                                payload: payload.to_vec(),
                                traffic_context: traffic_context.clone(),
                            };
                            if response_sender.send(SessionUdpEvent::Data(response)).await.is_err() {
                                break false;
                            }
                            idle.as_mut().reset(Instant::now() + idle_timeout);
                        }
                    }
                }
            })
            .await;
        let mut has_error = has_error.unwrap_or(false);
        if let Err(error) = session.close().await {
            debug!("VLESS Reverse session UDP close failed: {}", error);
            has_error = true;
        }
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
        route_target,
        global_id: None,
        global_backend_key: None,
        generation,
        sender: SessionUdpSender::Reverse(sender),
        task: Some(LocalSessionUdpTask {
            cancellation,
            join: Some(join),
        }),
    })
}

async fn start_local_session_udp_session(
    session_id: u16,
    generation: u64,
    key: TargetedUdpSessionKey,
    route_target: NetLocation,
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
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let join = tokio::spawn(async move {
        let mut response_buffer = vec![0u8; UDP_BUFFER_SIZE];
        let mut idle = Box::pin(sleep(idle_timeout));
        let has_error = task_cancellation
            .run_until_cancelled(async {
                loop {
                    tokio::select! {
                _ = idle.as_mut() => break false,
                request = receiver.recv() => {
                    let Some(request) = request else {
                        break false;
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
                        break false;
                    }
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
                    }
                }
            })
            .await;
        let Some(has_error) = has_error else {
            return;
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
        route_target,
        global_id: None,
        global_backend_key: None,
        generation,
        sender: SessionUdpSender::Local(sender),
        task: Some(LocalSessionUdpTask {
            cancellation,
            join: Some(join),
        }),
    })
}

#[cfg(feature = "trojan")]
async fn start_trojan_session_udp_session(
    session_id: u16,
    generation: u64,
    start: TrojanSessionUdpWorkerStart,
) -> std::io::Result<SessionUdpWorker> {
    if let Some(global_id) = start.global_id {
        return attach_global_session_udp_session(GlobalSessionUdpAttachStart {
            global_id,
            session_id,
            generation,
            key: start.key,
            route_target: start.route_target,
            response_sender: start.response_sender,
            traffic_context: start.traffic_context,
            idle_timeout: start.idle_timeout,
            backend_start: GlobalUdpBackendStart::Trojan {
                outbound: Box::new(start.outbound),
            },
        })
        .await;
    }

    let initial_target = NetLocation::from_ip_addr(
        start.key.target_addr.ip(),
        start.key.target_addr.port(),
    );
    let mut proxy = connect_trojan_udp_via_outbound(
        &start.resolver,
        &initial_target,
        &start.runtime,
        &start.outbound,
    )
    .await?;
    let (sender, mut receiver) =
        mpsc::channel::<LocalUdpPayload>(UDP_SESSION_CHANNEL_CAPACITY);
    let worker_key = start.key.clone();
    let route_target = start.route_target;
    let response_sender = start.response_sender;
    let traffic_context = start.traffic_context;
    let resolver = start.resolver;
    let idle_timeout = start.idle_timeout;
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();

    let join = tokio::spawn(async move {
        let mut response_buffer = vec![0u8; VMESS_UDP_MESSAGE_BUFFER_SIZE];
        let mut idle = Box::pin(sleep(idle_timeout));
        let has_error = task_cancellation
            .run_until_cancelled(async {
                loop {
                    tokio::select! {
                _ = idle.as_mut() => break false,
                request = receiver.recv() => {
                    let Some(request) = request else {
                        break false;
                    };
                    let target = NetLocation::from_ip_addr(
                        request.target_addr.ip(),
                        request.target_addr.port(),
                    );
                    if let Err(error) = proxy.send_to(&target, &request.payload).await {
                        debug!(
                            "Trojan session UDP write to {} failed: {}",
                            target, error
                        );
                        break true;
                    }
                    record_transfer(
                        traffic_context.clone(),
                        request.payload.len() as u64,
                        0,
                    );
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
                response = proxy.recv_from(&mut response_buffer) => {
                    let (source_location, length) = match response {
                        Ok(response) => response,
                        Err(error) => {
                            debug!("Trojan session UDP receive failed: {}", error);
                            break true;
                        }
                    };
                    let source = match source_location.to_socket_addr_nonblocking() {
                        Some(source) => source,
                        None => match resolve_single_address(&resolver, &source_location).await {
                            Ok(source) => source,
                            Err(error) => {
                                debug!(
                                    "Trojan session UDP response source {} did not resolve: {}",
                                    source_location, error
                                );
                                break true;
                            }
                        },
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
                        break false;
                    }
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                }
                    }
                }
            })
            .await;
        let _ = shutdown_targeted_message(&mut proxy).await;
        let Some(has_error) = has_error else {
            return;
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
        route_target,
        global_id: None,
        global_backend_key: None,
        generation,
        sender: SessionUdpSender::Trojan(sender),
        task: Some(LocalSessionUdpTask {
            cancellation,
            join: Some(join),
        }),
    })
}
