use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, OnceLock, Weak},
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{Mutex, Notify, RwLock, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, warn};

#[cfg(feature = "trojan")]
use crate::runtime::OutboundSummary;
use crate::{
    traffic::{TrafficContext, record_transfer},
    xudp_registry::{XUDP_GLOBAL_REATTACH_TTL, XudpGlobalRegistry},
};

use super::{
    SessionUdpEvent, SessionUdpResponse, SessionUdpSender, SessionUdpWorker,
    TargetedUdpSessionKey, UDP_BUFFER_SIZE, UDP_SESSION_CHANNEL_CAPACITY,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GlobalUdpWorkerKey {
    Direct {
        target_is_ipv6: bool,
        outbound_tag: Option<String>,
    },
    #[cfg(feature = "trojan")]
    Trojan { outbound: OutboundSummary },
}

impl From<&TargetedUdpSessionKey> for GlobalUdpWorkerKey {
    fn from(key: &TargetedUdpSessionKey) -> Self {
        Self::Direct {
            target_is_ipv6: key.target_addr.is_ipv6(),
            outbound_tag: key.outbound_tag.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) enum GlobalUdpBackendStart {
    Direct,
    #[cfg(feature = "trojan")]
    Trojan {
        outbound: Box<OutboundSummary>,
    },
}

impl GlobalUdpBackendStart {
    fn worker_key(&self, key: &TargetedUdpSessionKey) -> GlobalUdpWorkerKey {
        match self {
            Self::Direct => GlobalUdpWorkerKey::from(key),
            #[cfg(feature = "trojan")]
            Self::Trojan { outbound } => GlobalUdpWorkerKey::Trojan {
                outbound: outbound.as_ref().clone(),
            },
        }
    }
}

pub(super) struct GlobalSessionUdpAttachStart {
    pub(super) global_id: [u8; 8],
    pub(super) session_id: u16,
    pub(super) generation: u64,
    pub(super) key: TargetedUdpSessionKey,
    pub(super) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(super) traffic_context: Option<TrafficContext>,
    pub(super) idle_timeout: Duration,
    pub(super) backend_start: GlobalUdpBackendStart,
}

#[derive(Clone)]
pub(super) struct GlobalUdpAttachment {
    pub(super) token: u64,
    pub(super) session_id: u16,
    pub(super) generation: u64,
    pub(super) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(super) traffic_context: Option<TrafficContext>,
}

pub(super) struct GlobalUdpPayload {
    pub(super) attachment_token: u64,
    pub(super) target_addr: SocketAddr,
    pub(super) payload: Vec<u8>,
    pub(super) completion: oneshot::Sender<std::io::Result<()>>,
}

pub(super) struct PendingGlobalUdpResponse {
    pub(super) source: SocketAddr,
    pub(super) payload: Vec<u8>,
}

pub(super) struct GlobalUdpResponseDelivery {
    pub(super) attachment_token: u64,
    pub(super) response_sender: mpsc::Sender<SessionUdpEvent>,
    pub(super) response: SessionUdpResponse,
}

pub(super) enum GlobalUdpPayloadPlan {
    Send(GlobalUdpAttachment),
    RejectDetached,
    RejectStale { current_token: u64 },
}

pub(super) fn plan_global_udp_payload(
    attachment: Option<GlobalUdpAttachment>,
    request_token: u64,
) -> GlobalUdpPayloadPlan {
    match attachment {
        None => GlobalUdpPayloadPlan::RejectDetached,
        Some(attachment) if attachment.token != request_token => {
            GlobalUdpPayloadPlan::RejectStale {
                current_token: attachment.token,
            }
        }
        Some(attachment) => GlobalUdpPayloadPlan::Send(attachment),
    }
}

pub(super) fn should_pause_global_udp_receive(
    attachment_present: bool,
    pending_responses: usize,
    capacity: usize,
) -> bool {
    !attachment_present && pending_responses >= capacity
}

pub(super) fn plan_global_udp_response_delivery(
    attachment: Option<GlobalUdpAttachment>,
    pending: PendingGlobalUdpResponse,
) -> Result<GlobalUdpResponseDelivery, PendingGlobalUdpResponse> {
    let Some(attachment) = attachment else {
        return Err(pending);
    };
    Ok(GlobalUdpResponseDelivery {
        attachment_token: attachment.token,
        response_sender: attachment.response_sender,
        response: SessionUdpResponse {
            session_id: attachment.session_id,
            generation: attachment.generation,
            source: pending.source,
            payload: pending.payload,
            traffic_context: attachment.traffic_context,
        },
    })
}

pub(super) struct GlobalSessionUdpWorker {
    pub(super) key: GlobalUdpWorkerKey,
    pub(super) sender: mpsc::Sender<GlobalUdpPayload>,
    pub(super) attachment: Arc<RwLock<Option<GlobalUdpAttachment>>>,
    pub(super) attachment_notify: Arc<Notify>,
    pub(super) task: JoinHandle<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GlobalUdpWorkerSnapshot {
    pub(super) key_matches: bool,
    pub(super) task_finished: bool,
    pub(super) sender_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GlobalUdpWorkerPlan {
    Reuse,
    Replace,
}

pub(super) fn plan_global_udp_worker(
    snapshot: Option<GlobalUdpWorkerSnapshot>,
) -> GlobalUdpWorkerPlan {
    match snapshot {
        Some(GlobalUdpWorkerSnapshot {
            key_matches: true,
            task_finished: false,
            sender_closed: false,
        }) => GlobalUdpWorkerPlan::Reuse,
        _ => GlobalUdpWorkerPlan::Replace,
    }
}

pub(super) fn snapshot_global_udp_worker(
    worker: Option<&GlobalSessionUdpWorker>,
    desired_key: &GlobalUdpWorkerKey,
) -> Option<GlobalUdpWorkerSnapshot> {
    worker.map(|worker| GlobalUdpWorkerSnapshot {
        key_matches: worker.key == *desired_key,
        task_finished: worker.task.is_finished(),
        sender_closed: worker.sender.is_closed(),
    })
}

#[derive(Default)]
pub(super) struct GlobalXudpWorkers {
    pub(super) registry: XudpGlobalRegistry,
    pub(super) workers: HashMap<[u8; 8], GlobalSessionUdpWorker>,
    pub(super) gates: HashMap<[u8; 8], Weak<Mutex<()>>>,
    pub(super) maintenance_tasks: TaskTracker,
    pub(super) maintenance_cancellation: CancellationToken,
}

static GLOBAL_XUDP_WORKERS: OnceLock<Arc<Mutex<GlobalXudpWorkers>>> =
    OnceLock::new();

pub(super) fn global_xudp_workers() -> Arc<Mutex<GlobalXudpWorkers>> {
    GLOBAL_XUDP_WORKERS
        .get_or_init(|| Arc::new(Mutex::new(GlobalXudpWorkers::default())))
        .clone()
}

pub(super) async fn global_xudp_gate(global_id: [u8; 8]) -> Arc<Mutex<()>> {
    let globals = global_xudp_workers();
    let mut guard = globals.lock().await;
    guard.gates.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = guard.gates.get(&global_id).and_then(Weak::upgrade) {
        return gate;
    }

    let gate = Arc::new(Mutex::new(()));
    guard.gates.insert(global_id, Arc::downgrade(&gate));
    gate
}

pub(super) async fn attach_global_session_udp_session(
    start: GlobalSessionUdpAttachStart,
) -> std::io::Result<SessionUdpWorker> {
    let GlobalSessionUdpAttachStart {
        global_id,
        session_id,
        generation,
        key,
        response_sender,
        traffic_context,
        idle_timeout,
        backend_start,
    } = start;
    let gate = global_xudp_gate(global_id).await;
    let _gate_guard = gate.lock().await;
    let globals = global_xudp_workers();
    let now = Instant::now();
    let worker_key = backend_start.worker_key(&key);

    let (expired_worker, transition, attachment, worker_plan, replaced_worker) = {
        let mut guard = globals.lock().await;
        let expired_worker =
            take_expired_global_udp_worker(&mut guard, global_id, now);
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
        let worker_plan = plan_global_udp_worker(snapshot_global_udp_worker(
            guard.workers.get(&global_id),
            &worker_key,
        ));
        let replaced_worker = if worker_plan == GlobalUdpWorkerPlan::Replace {
            guard.workers.remove(&global_id)
        } else {
            None
        };
        (
            expired_worker,
            transition,
            attachment,
            worker_plan,
            replaced_worker,
        )
    };

    if let Some(worker) = expired_worker {
        stop_global_udp_worker(worker).await;
    }
    if let Some(worker) = replaced_worker {
        stop_global_udp_worker(worker).await;
    }

    if worker_plan == GlobalUdpWorkerPlan::Replace {
        let worker = match start_global_session_udp_worker(
            worker_key.clone(),
            key.target_addr,
            idle_timeout,
            backend_start,
        )
        .await
        {
            Ok(worker) => worker,
            Err(error) => {
                let mut guard = globals.lock().await;
                guard
                    .registry
                    .remove_current(global_id, transition.current.token);
                return Err(error);
            }
        };

        let install_result = {
            let mut guard = globals.lock().await;
            if guard.registry.current(global_id, Instant::now())
                != Some(transition.current)
            {
                Err(worker)
            } else {
                Ok(guard.workers.insert(global_id, worker))
            }
        };
        match install_result {
            Ok(Some(previous_worker)) => {
                stop_global_udp_worker(previous_worker).await;
            }
            Ok(None) => {}
            Err(worker) => {
                stop_global_udp_worker(worker).await;
                return Err(std::io::Error::other(
                    "global XUDP attachment changed during worker startup",
                ));
            }
        }
    }

    let (sender, attachment_state, attachment_notify) = {
        let mut guard = globals.lock().await;
        let Some(worker) = guard.workers.get(&global_id) else {
            guard
                .registry
                .remove_current(global_id, transition.current.token);
            return Err(std::io::Error::other(
                "global XUDP worker missing after attachment planning",
            ));
        };
        (
            worker.sender.clone(),
            worker.attachment.clone(),
            worker.attachment_notify.clone(),
        )
    };

    let previous = attachment_state.write().await.replace(attachment.clone());
    attachment_notify.notify_one();

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

pub(super) async fn forward_global_udp_response(
    attachment: &Arc<RwLock<Option<GlobalUdpAttachment>>>,
    pending: PendingGlobalUdpResponse,
) -> Result<(), (PendingGlobalUdpResponse, Option<u64>)> {
    let delivery = match plan_global_udp_response_delivery(
        attachment.read().await.clone(),
        pending,
    ) {
        Ok(delivery) => delivery,
        Err(pending) => return Err((pending, None)),
    };
    let attachment_token = delivery.attachment_token;
    match delivery
        .response_sender
        .send(SessionUdpEvent::Data(delivery.response))
        .await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            let SessionUdpEvent::Data(response) = error.0 else {
                unreachable!("global UDP response delivery only sends data events")
            };
            Err((
                PendingGlobalUdpResponse {
                    source: response.source,
                    payload: response.payload,
                },
                Some(attachment_token),
            ))
        }
    }
}

pub(super) async fn clear_global_attachment_if_current(
    attachment: &Arc<RwLock<Option<GlobalUdpAttachment>>>,
    attachment_token: u64,
) {
    let mut current = attachment.write().await;
    if current.as_ref().map(|attachment| attachment.token) == Some(attachment_token)
    {
        *current = None;
    }
}

pub(super) async fn start_global_session_udp_worker(
    key: GlobalUdpWorkerKey,
    target_addr: SocketAddr,
    idle_timeout: Duration,
    backend_start: GlobalUdpBackendStart,
) -> std::io::Result<GlobalSessionUdpWorker> {
    let bind_addr = match backend_start {
        GlobalUdpBackendStart::Direct => {
            if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            }
        }
        #[cfg(feature = "trojan")]
        GlobalUdpBackendStart::Trojan { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Trojan outbound for GlobalID XUDP is not implemented yet",
            ));
        }
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
            let pause_socket = should_pause_global_udp_receive(
                attachment_present,
                pending_responses.len(),
                UDP_SESSION_CHANNEL_CAPACITY,
            );
            tokio::select! {
                _ = idle.as_mut() => break false,
                _ = task_attachment_notify.notified() => continue,
                request = receiver.recv() => {
                    let Some(request) = request else {
                        return;
                    };
                    let current = match plan_global_udp_payload(
                        task_attachment.read().await.clone(),
                        request.attachment_token,
                    ) {
                        GlobalUdpPayloadPlan::Send(current) => current,
                        GlobalUdpPayloadPlan::RejectDetached => {
                            let _ = request.completion.send(Err(
                                std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "XUDP GlobalID attachment is detached",
                                ),
                            ));
                            continue;
                        }
                        GlobalUdpPayloadPlan::RejectStale { current_token } => {
                            debug!(
                                "dropping stale XUDP GlobalID payload token {} (current {})",
                                request.attachment_token, current_token,
                            );
                            let _ = request.completion.send(Err(
                                std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "XUDP GlobalID attachment token is stale",
                                ),
                            ));
                            continue;
                        }
                    };
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

pub(super) fn take_expired_global_udp_worker(
    globals: &mut GlobalXudpWorkers,
    global_id: [u8; 8],
    now: Instant,
) -> Option<GlobalSessionUdpWorker> {
    if globals.registry.remove_expired_id(global_id, now) {
        globals.workers.remove(&global_id)
    } else {
        None
    }
}

pub(super) async fn expire_global_udp_worker(global_id: [u8; 8], now: Instant) {
    let gate = global_xudp_gate(global_id).await;
    let _gate_guard = gate.lock().await;
    let globals = global_xudp_workers();
    let worker = {
        let mut guard = globals.lock().await;
        take_expired_global_udp_worker(&mut guard, global_id, now)
    };
    if let Some(worker) = worker {
        stop_global_udp_worker(worker).await;
    }
}

pub(super) fn schedule_global_udp_worker_expiry(
    maintenance_tasks: TaskTracker,
    maintenance_cancellation: CancellationToken,
    global_id: [u8; 8],
    delay: Duration,
) {
    drop(maintenance_tasks.spawn(async move {
        tokio::select! {
            _ = maintenance_cancellation.cancelled() => {}
            _ = sleep(delay) => expire_global_udp_worker(global_id, Instant::now()).await,
        }
    }));
}

pub(super) async fn detach_global_udp_worker(
    global_id: [u8; 8],
    attachment_token: u64,
) {
    let gate = global_xudp_gate(global_id).await;
    let _gate_guard = gate.lock().await;
    let globals = global_xudp_workers();
    let (worker_state, maintenance_tasks, maintenance_cancellation) = {
        let mut guard = globals.lock().await;
        if !guard
            .registry
            .detach(global_id, attachment_token, Instant::now())
        {
            return;
        }
        (
            guard.workers.get(&global_id).map(|worker| {
                (worker.attachment.clone(), worker.attachment_notify.clone())
            }),
            guard.maintenance_tasks.clone(),
            guard.maintenance_cancellation.clone(),
        )
    };

    if let Some((attachment_state, attachment_notify)) = worker_state {
        let mut attachment = attachment_state.write().await;
        if attachment.as_ref().map(|attachment| attachment.token)
            == Some(attachment_token)
        {
            *attachment = None;
            attachment_notify.notify_one();
        }
    }

    schedule_global_udp_worker_expiry(
        maintenance_tasks,
        maintenance_cancellation,
        global_id,
        XUDP_GLOBAL_REATTACH_TTL,
    );
}

pub(super) async fn shutdown_workers() -> usize {
    let globals = global_xudp_workers();
    let (workers, maintenance_tasks) = {
        let mut guard = globals.lock().await;
        guard.maintenance_cancellation.cancel();
        let maintenance_tasks = std::mem::take(&mut guard.maintenance_tasks);
        maintenance_tasks.close();
        guard.maintenance_cancellation = CancellationToken::new();
        guard.registry = XudpGlobalRegistry::default();
        guard.gates.clear();
        (
            std::mem::take(&mut guard.workers)
                .into_values()
                .collect::<Vec<_>>(),
            maintenance_tasks,
        )
    };

    let stopped = workers.len();
    for worker in &workers {
        worker.task.abort();
    }
    for worker in workers {
        let _ = worker.task.await;
    }
    maintenance_tasks.wait().await;
    stopped
}

pub(super) async fn stop_global_udp_worker(worker: GlobalSessionUdpWorker) {
    worker.task.abort();
    let _ = worker.task.await;
}

pub(super) async fn terminate_global_udp_worker(
    global_id: [u8; 8],
    attachment_token: u64,
) {
    let gate = global_xudp_gate(global_id).await;
    let _gate_guard = gate.lock().await;
    let globals = global_xudp_workers();
    let worker = {
        let mut guard = globals.lock().await;
        if guard.registry.remove_current(global_id, attachment_token) {
            guard.workers.remove(&global_id)
        } else {
            None
        }
    };
    if let Some(worker) = worker {
        stop_global_udp_worker(worker).await;
    }
}
