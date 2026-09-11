use tokio::task::JoinHandle;

#[cfg(feature = "trojan")]
use crate::resolver::resolve_single_address;

use super::*;

#[derive(Clone)]
pub(super) enum SessionUdpSender {
    Local(mpsc::Sender<LocalUdpPayload>),
    #[cfg(feature = "trojan")]
    Trojan(mpsc::Sender<LocalUdpPayload>),
    Global {
        sender: mpsc::Sender<GlobalUdpPayload>,
        attachment_token: u64,
    },
}

impl SessionUdpSender {
    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Local(sender) => sender.is_closed(),
            #[cfg(feature = "trojan")]
            Self::Trojan(sender) => sender.is_closed(),
            Self::Global { sender, .. } => sender.is_closed(),
        }
    }

    pub(super) async fn send_to(
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

pub(super) struct LocalSessionUdpTask {
    pub(super) cancellation: CancellationToken,
    pub(super) join: Option<JoinHandle<()>>,
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

pub(super) struct SessionUdpWorker {
    pub(super) key: TargetedUdpSessionKey,
    pub(super) global_id: Option<[u8; 8]>,
    pub(super) generation: u64,
    pub(super) sender: SessionUdpSender,
    pub(super) task: Option<LocalSessionUdpTask>,
}

pub(super) enum SessionUdpWorkerPlan {
    Reuse(SessionUdpSender),
    Replace,
}

pub(super) struct SessionUdpWorkerStart {
    pub(super) key: TargetedUdpSessionKey,
    pub(super) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(super) traffic_context: Option<TrafficContext>,
    pub(super) global_id: Option<[u8; 8]>,
    pub(super) idle_timeout: Duration,
}

#[cfg(feature = "trojan")]
pub(super) struct TrojanSessionUdpWorkerStart {
    pub(super) key: TargetedUdpSessionKey,
    pub(super) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(super) traffic_context: Option<TrafficContext>,
    pub(super) resolver: Arc<dyn Resolver>,
    pub(super) runtime: DataPlaneRuntime,
    pub(super) outbound: crate::runtime::OutboundSummary,
    pub(super) global_id: Option<[u8; 8]>,
    pub(super) idle_timeout: Duration,
}

pub(super) fn session_udp_worker_matches(
    worker: &SessionUdpWorker,
    key: &TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
) -> bool {
    worker.global_id == global_id
        && !worker.sender.is_closed()
        && GlobalUdpWorkerKey::from(&worker.key) == GlobalUdpWorkerKey::from(key)
}

pub(super) fn plan_session_udp_worker(
    worker: Option<&SessionUdpWorker>,
    key: &TargetedUdpSessionKey,
    global_id: Option<[u8; 8]>,
) -> SessionUdpWorkerPlan {
    worker
        .filter(|worker| session_udp_worker_matches(worker, key, global_id))
        .map(|worker| SessionUdpWorkerPlan::Reuse(worker.sender.clone()))
        .unwrap_or(SessionUdpWorkerPlan::Replace)
}

pub(super) fn plan_session_generation(
    next_generation: u64,
) -> std::io::Result<(u64, u64)> {
    let following_generation = next_generation.checked_add(1).ok_or_else(|| {
        std::io::Error::other("session UDP generation counter exhausted")
    })?;
    Ok((next_generation, following_generation))
}

pub(super) async fn replace_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    next_generation: &mut u64,
    start: SessionUdpWorkerStart,
) -> std::io::Result<SessionUdpSender> {
    terminate_session_udp_worker(sessions, session_id).await;
    let (generation, following_generation) =
        plan_session_generation(*next_generation)?;
    *next_generation = following_generation;
    let worker = start_session_udp_session(
        session_id,
        generation,
        start.key,
        start.response_sender,
        start.traffic_context,
        start.global_id,
        start.idle_timeout,
    )
    .await?;
    let sender = worker.sender.clone();
    sessions.insert(session_id, worker);
    Ok(sender)
}

#[cfg(feature = "trojan")]
pub(super) async fn replace_trojan_session_udp_worker(
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

async fn stop_local_session_udp_task(task: LocalSessionUdpTask) {
    task.stop().await;
}

pub(super) async fn terminate_session_udp_worker(
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

pub(super) async fn expire_session_udp_worker(
    sessions: &mut HashMap<u16, SessionUdpWorker>,
    session_id: u16,
) {
    if let Some(worker) = sessions.remove(&session_id) {
        detach_session_udp_worker(worker).await;
    }
}

pub(super) async fn detach_session_udp_worker(worker: SessionUdpWorker) {
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

pub(super) fn is_current_session_udp_generation(
    sessions: &HashMap<u16, SessionUdpWorker>,
    session_id: u16,
    generation: u64,
) -> bool {
    sessions
        .get(&session_id)
        .is_some_and(|worker| worker.generation == generation)
}

pub(super) fn is_current_session_udp_response(
    sessions: &HashMap<u16, SessionUdpWorker>,
    response: &SessionUdpResponse,
) -> bool {
    is_current_session_udp_generation(
        sessions,
        response.session_id,
        response.generation,
    )
}

pub(super) async fn start_session_udp_session(
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
            attach_global_session_udp_session(GlobalSessionUdpAttachStart {
                global_id,
                session_id,
                generation,
                key,
                response_sender,
                traffic_context,
                idle_timeout,
                backend_start: GlobalUdpBackendStart::Direct,
            })
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
        global_id: None,
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
        global_id: None,
        generation,
        sender: SessionUdpSender::Trojan(sender),
        task: Some(LocalSessionUdpTask {
            cancellation,
            join: Some(join),
        }),
    })
}
