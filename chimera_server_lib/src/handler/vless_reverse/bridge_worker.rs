use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    sync::mpsc,
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    address::NetLocation, async_stream::AsyncStream,
    config::server_config::InboundSniffingConfig,
};

use super::{
    bridge_control::BridgeControlState,
    mux_frame::{
        Destination, FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
    },
    mux_io::{MuxFrame, encode_frame, read_frame_with_source_and_local},
    session_core::track_task,
};

const OUTBOUND_FRAME_CAPACITY: usize = 16;
const INBOUND_FRAME_CAPACITY: usize = 16;
const STREAM_CHUNK_SIZE: usize = 8 * 1024;
// Xray common/mux.ServerWorker checks for an idle server-side Mux once per minute.
const XRAY_SERVER_IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
enum InboundEvent {
    Data {
        payload: Bytes,
        target: Option<NetLocation>,
    },
    HalfClose,
    End,
}

pub(crate) struct BridgeUdpRequest {
    pub(crate) payload: Bytes,
    pub(crate) target: NetLocation,
}

pub(crate) struct BridgeUdpResponse {
    pub(crate) payload: Bytes,
    pub(crate) source: SocketAddr,
}

pub(crate) struct BridgeUdpSession {
    pub(crate) requests: mpsc::Sender<BridgeUdpRequest>,
    pub(crate) responses: mpsc::Receiver<BridgeUdpResponse>,
}

#[derive(Clone, Default)]
pub(crate) struct BridgeDispatchContext {
    pub(crate) sniffing: Option<InboundSniffingConfig>,
    pub(crate) routing_user: String,
    pub(crate) policy_identity: String,
    pub(crate) user_level: u32,
    pub(crate) site_to_site: Option<super::site_policy::SiteToSitePolicy>,
}

type SessionRoutes = Arc<Mutex<HashMap<u16, mpsc::Sender<InboundEvent>>>>;

#[async_trait]
pub(crate) trait BridgeTcpDispatcher: Send + Sync {
    async fn open_tcp(
        &self,
        reverse_tag: &str,
        target: NetLocation,
        source: Option<SocketAddr>,
        local: Option<SocketAddr>,
        context: BridgeDispatchContext,
    ) -> std::io::Result<Box<dyn AsyncStream>>;

    async fn open_udp(
        &self,
        reverse_tag: &str,
        source: Option<SocketAddr>,
        local: Option<SocketAddr>,
        context: BridgeDispatchContext,
    ) -> std::io::Result<BridgeUdpSession>;
}

pub(crate) struct MuxServerWorker {
    control: Arc<BridgeControlState>,
    sessions: SessionRoutes,
    cancellation: CancellationToken,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl MuxServerWorker {
    #[cfg(test)]
    pub(crate) fn new(
        physical: Box<dyn AsyncStream>,
        reverse_tag: String,
        dispatcher: Arc<dyn BridgeTcpDispatcher>,
    ) -> Self {
        Self::new_with_context(
            physical,
            reverse_tag,
            dispatcher,
            BridgeDispatchContext::default(),
        )
    }

    pub(crate) fn new_with_context(
        physical: Box<dyn AsyncStream>,
        reverse_tag: String,
        dispatcher: Arc<dyn BridgeTcpDispatcher>,
        context: BridgeDispatchContext,
    ) -> Self {
        let control = Arc::new(BridgeControlState::new());
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = CancellationToken::new();
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let session_count = Arc::new(AtomicU64::new(0));
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_FRAME_CAPACITY);
        let (reader, writer) = split(physical);

        let reader_task = tokio::spawn(run_physical_reader(
            reader,
            reverse_tag,
            dispatcher,
            sessions.clone(),
            outbound.clone(),
            control.clone(),
            cancellation.clone(),
            tasks.clone(),
            session_count.clone(),
            context,
        ));
        let writer_task = tokio::spawn(run_physical_writer(
            writer,
            outbound_rx,
            control.clone(),
            cancellation.clone(),
        ));
        let monitor_task = tokio::spawn(run_idle_monitor(
            sessions.clone(),
            session_count,
            cancellation.clone(),
        ));
        tasks
            .lock()
            .expect("Reverse Bridge task lock poisoned")
            .extend([reader_task, writer_task, monitor_task]);

        Self {
            control,
            sessions,
            cancellation,
            tasks,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.control.is_active() && !self.closed()
    }

    pub(crate) fn active_connections(&self) -> usize {
        self.sessions
            .lock()
            .expect("Reverse Bridge routes lock poisoned")
            .len()
    }

    pub(crate) fn closed(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub(crate) fn close(&self) {
        self.control.close();
        self.cancellation.cancel();
    }

    #[cfg(test)]
    pub(crate) async fn wait_closed(&self) {
        self.cancellation.cancelled().await;
    }
}

impl Drop for MuxServerWorker {
    fn drop(&mut self) {
        self.close();
        for task in self
            .tasks
            .lock()
            .expect("Reverse Bridge task lock poisoned")
            .drain(..)
        {
            task.abort();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_physical_reader<R>(
    mut reader: R,
    reverse_tag: String,
    dispatcher: Arc<dyn BridgeTcpDispatcher>,
    sessions: SessionRoutes,
    outbound: mpsc::Sender<Bytes>,
    control: Arc<BridgeControlState>,
    cancellation: CancellationToken,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    session_count: Arc<AtomicU64>,
    context: BridgeDispatchContext,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            frame = read_frame_with_source_and_local(&mut reader, true) => frame,
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                debug!(
                    reverse_tag = %reverse_tag,
                    error = %error,
                    "VLESS Reverse Bridge failed to read Mux frame"
                );
                break;
            }
        };
        match control.handle_frame(&frame) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => {
                debug!(
                    reverse_tag = %reverse_tag,
                    session_id = frame.metadata.session_id,
                    error = %error,
                    "VLESS Reverse Bridge rejected control frame"
                );
                break;
            }
        }

        let session_id = frame.metadata.session_id;
        let frame_status = frame.metadata.status;
        let has_data = frame.metadata.option.has_data();
        let half_close = frame.metadata.option.has_half_close();
        let result = match frame.metadata.status {
            SessionStatus::New => {
                handle_new_tcp(
                    frame,
                    &reverse_tag,
                    dispatcher.clone(),
                    sessions.clone(),
                    outbound.clone(),
                    cancellation.clone(),
                    tasks.clone(),
                    session_count.clone(),
                    context.clone(),
                )
                .await
            }
            SessionStatus::Keep => forward_keep(frame, &sessions, &outbound).await,
            SessionStatus::End => {
                if frame.metadata.option.has_half_close() {
                    half_close_session(
                        frame.metadata.session_id,
                        &sessions,
                        &outbound,
                    )
                    .await
                } else {
                    end_session(frame.metadata.session_id, &sessions).await;
                    Ok(())
                }
            }
            SessionStatus::KeepAlive => Ok(()),
        };
        if let Err(error) = result {
            debug!(
                reverse_tag = %reverse_tag,
                session_id,
                status = ?frame_status,
                has_data,
                half_close,
                error = %error,
                "VLESS Reverse Bridge failed to handle Mux session frame"
            );
            break;
        }
    }
    control.close();
    cancellation.cancel();
}

#[allow(clippy::too_many_arguments)]
async fn handle_new_tcp(
    frame: MuxFrame,
    reverse_tag: &str,
    dispatcher: Arc<dyn BridgeTcpDispatcher>,
    sessions: SessionRoutes,
    outbound: mpsc::Sender<Bytes>,
    cancellation: CancellationToken,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    session_count: Arc<AtomicU64>,
    context: BridgeDispatchContext,
) -> std::io::Result<()> {
    let target = frame.metadata.target.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse Mux NEW frame is missing its target",
        )
    })?;
    if target.network == TargetNetwork::Udp {
        if frame.metadata.global_id.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "VLESS Reverse Bridge XUDP reattachment is not implemented yet",
            ));
        }
        return handle_new_udp(
            frame,
            reverse_tag,
            dispatcher,
            sessions,
            outbound,
            cancellation,
            tasks,
            session_count,
            context,
        )
        .await;
    }
    if sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .contains_key(&frame.metadata.session_id)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "duplicate Reverse Mux session id: {}",
                frame.metadata.session_id
            ),
        ));
    }

    let source = frame
        .metadata
        .source
        .as_ref()
        .and_then(destination_socket_addr);
    let local = frame
        .metadata
        .local
        .as_ref()
        .and_then(destination_socket_addr);
    let target = if let Some(policy) = context.site_to_site.as_ref() {
        match policy.map_tcp_target(&target.location) {
            Ok(target) => target,
            Err(_) => {
                send_end_frame(frame.metadata.session_id, true, &outbound).await?;
                return Ok(());
            }
        }
    } else {
        target.location.clone()
    };
    debug!(
        reverse_tag = %reverse_tag,
        session_id = frame.metadata.session_id,
        target = %target,
        initial_payload_bytes = frame.payload.len(),
        "dispatching VLESS Reverse TCP session"
    );
    let stream = dispatcher
        .open_tcp(reverse_tag, target, source, local, context)
        .await?;

    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_FRAME_CAPACITY);
    sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .insert(frame.metadata.session_id, inbound_tx);
    session_count.fetch_add(1, Ordering::Relaxed);
    let task = tokio::spawn(run_tcp_session(
        frame.metadata.session_id,
        stream,
        frame.payload,
        inbound_rx,
        outbound,
        sessions,
        cancellation,
    ));
    track_task(&tasks, task);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_new_udp(
    frame: MuxFrame,
    reverse_tag: &str,
    dispatcher: Arc<dyn BridgeTcpDispatcher>,
    sessions: SessionRoutes,
    outbound: mpsc::Sender<Bytes>,
    cancellation: CancellationToken,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    session_count: Arc<AtomicU64>,
    context: BridgeDispatchContext,
) -> std::io::Result<()> {
    let target = frame.metadata.target.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse Mux UDP NEW frame is missing its target",
        )
    })?;
    let site_to_site = context.site_to_site.clone();
    if let Some(policy) = site_to_site.as_ref()
        && policy.map_udp_target(&target.location).is_err()
    {
        send_end_frame(frame.metadata.session_id, true, &outbound).await?;
        return Ok(());
    }
    if sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .contains_key(&frame.metadata.session_id)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "duplicate Reverse Mux session id: {}",
                frame.metadata.session_id
            ),
        ));
    }

    let source = frame
        .metadata
        .source
        .as_ref()
        .and_then(destination_socket_addr);
    let local = frame
        .metadata
        .local
        .as_ref()
        .and_then(destination_socket_addr);
    let session = dispatcher
        .open_udp(reverse_tag, source, local, context)
        .await?;
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_FRAME_CAPACITY);
    sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .insert(frame.metadata.session_id, inbound_tx);
    session_count.fetch_add(1, Ordering::Relaxed);
    let task = tokio::spawn(run_udp_session(
        frame.metadata.session_id,
        target.location.clone(),
        frame.payload,
        session,
        inbound_rx,
        outbound,
        sessions,
        cancellation,
        site_to_site,
    ));
    track_task(&tasks, task);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    session_id: u16,
    mut target: NetLocation,
    initial_payload: Bytes,
    mut session: BridgeUdpSession,
    mut inbound: mpsc::Receiver<InboundEvent>,
    outbound: mpsc::Sender<Bytes>,
    sessions: SessionRoutes,
    cancellation: CancellationToken,
    site_to_site: Option<super::site_policy::SiteToSitePolicy>,
) {
    if !initial_payload.is_empty() {
        let request_target = match site_to_site.as_ref() {
            Some(policy) => match policy.map_udp_target(&target) {
                Ok(target) => target,
                Err(_) => {
                    let _ = send_end_frame(session_id, true, &outbound).await;
                    sessions
                        .lock()
                        .expect("Reverse Bridge routes lock poisoned")
                        .remove(&session_id);
                    return;
                }
            },
            None => target.clone(),
        };
        if session
            .requests
            .send(BridgeUdpRequest {
                payload: initial_payload,
                target: request_target,
            })
            .await
            .is_err()
        {
            let _ = send_end_frame(session_id, true, &outbound).await;
            sessions
                .lock()
                .expect("Reverse Bridge routes lock poisoned")
                .remove(&session_id);
            return;
        }
    }

    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            event = inbound.recv() => {
                match event {
                    Some(InboundEvent::Data { payload, target: override_target }) => {
                        if let Some(override_target) = override_target {
                            target = override_target;
                        }
                        let request_target = match site_to_site.as_ref() {
                            Some(policy) => match policy.map_udp_target(&target) {
                                Ok(target) => target,
                                Err(_) => {
                                    let _ = send_end_frame(session_id, true, &outbound).await;
                                    break;
                                }
                            },
                            None => target.clone(),
                        };
                        if session
                            .requests
                            .send(BridgeUdpRequest {
                                payload,
                                target: request_target,
                            })
                            .await
                            .is_err()
                        {
                            let _ = send_end_frame(session_id, true, &outbound).await;
                            break;
                        }
                    }
                    Some(InboundEvent::HalfClose | InboundEvent::End) | None => break,
                }
            }
            response = session.responses.recv() => {
                let Some(response) = response else {
                    let _ = send_end_frame(session_id, false, &outbound).await;
                    break;
                };
                let source = match site_to_site.as_ref() {
                    Some(policy) => match policy.map_response_source(response.source) {
                        Ok(source) => source,
                        Err(_) => {
                            let _ = send_end_frame(session_id, true, &outbound).await;
                            break;
                        }
                    },
                    None => response.source,
                };
                let response_target = Destination {
                    network: TargetNetwork::Udp,
                    location: NetLocation::from_ip_addr(
                        source.ip(),
                        source.port(),
                    ),
                };
                if send_frame(
                    session_id,
                    SessionStatus::Keep,
                    FrameOption::default().with_data(),
                    Some(response_target),
                    response.payload,
                    &outbound,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
        }
    }
    sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .remove(&session_id);
}

async fn run_idle_monitor(
    sessions: SessionRoutes,
    session_count: Arc<AtomicU64>,
    cancellation: CancellationToken,
) {
    loop {
        let check_size = sessions
            .lock()
            .expect("Reverse Bridge routes lock poisoned")
            .len();
        let check_count = session_count.load(Ordering::Relaxed);
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = sleep(XRAY_SERVER_IDLE_CHECK_INTERVAL) => {}
        }
        let current_size = sessions
            .lock()
            .expect("Reverse Bridge routes lock poisoned")
            .len();
        let current_count = session_count.load(Ordering::Relaxed);
        if idle_snapshot_is_unchanged(
            check_size,
            check_count,
            current_size,
            current_count,
        ) {
            cancellation.cancel();
            return;
        }
    }
}

fn idle_snapshot_is_unchanged(
    check_size: usize,
    check_count: u64,
    current_size: usize,
    current_count: u64,
) -> bool {
    current_size == 0 && check_size == 0 && current_count == check_count
}

async fn forward_keep(
    frame: MuxFrame,
    sessions: &SessionRoutes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let session_id = frame.metadata.session_id;
    let route = sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .get(&session_id)
        .cloned();
    match route {
        Some(route) => {
            if frame.metadata.option.has_data()
                && route
                    .send(InboundEvent::Data {
                        payload: frame.payload,
                        target: frame.metadata.target.map(|target| target.location),
                    })
                    .await
                    .is_err()
            {
                // The per-session task can remove its route after this reader
                // clones the sender. Close that logical session like Xray does
                // for a missing KEEP route; keep unrelated Mux sessions alive.
                return send_end_frame(session_id, false, outbound).await;
            }
            Ok(())
        }
        None => send_end_frame(session_id, false, outbound).await,
    }
}

async fn end_session(session_id: u16, sessions: &SessionRoutes) {
    let route = sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .remove(&session_id);
    if let Some(route) = route {
        let _ = route.send(InboundEvent::End).await;
    }
}

async fn half_close_session(
    session_id: u16,
    sessions: &SessionRoutes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let route = sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .get(&session_id)
        .cloned();
    if let Some(route) = route
        && route.send(InboundEvent::HalfClose).await.is_err()
    {
        // The task ended between route lookup and delivery. Treat the late
        // directional close as a per-session close, never a physical-link
        // failure.
        return send_end_frame(session_id, false, outbound).await;
    }
    Ok(())
}

async fn run_tcp_session(
    session_id: u16,
    stream: Box<dyn AsyncStream>,
    initial_payload: Bytes,
    mut inbound: mpsc::Receiver<InboundEvent>,
    outbound: mpsc::Sender<Bytes>,
    sessions: SessionRoutes,
    cancellation: CancellationToken,
) {
    let initial_payload_bytes = initial_payload.len();
    let (mut remote_read, mut remote_write) = split(stream);
    if !initial_payload.is_empty()
        && remote_write.write_all(&initial_payload).await.is_err()
    {
        let _ = send_end_frame(session_id, false, &outbound).await;
        sessions
            .lock()
            .expect("Reverse Bridge routes lock poisoned")
            .remove(&session_id);
        return;
    }

    debug!(
        session_id,
        initial_payload_bytes, "started VLESS Reverse TCP relay"
    );

    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    let mut inbound_open = true;
    let mut remote_read_open = true;
    let mut first_keep_logged = false;
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            event = inbound.recv(), if inbound_open => {
                match event {
                    Some(InboundEvent::Data { payload, .. }) => {
                        if !first_keep_logged {
                            debug!(
                                session_id,
                                payload_bytes = payload.len(),
                                "received first VLESS Reverse TCP data frame"
                            );
                            first_keep_logged = true;
                        }
                        if remote_write.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Some(InboundEvent::HalfClose) => {
                        let _ = remote_write.shutdown().await;
                        inbound_open = false;
                        if !remote_read_open {
                            break;
                        }
                    }
                    Some(InboundEvent::End) | None => {
                        let _ = remote_write.shutdown().await;
                        break;
                    }
                }
            }
            read = remote_read.read(&mut buffer), if remote_read_open => {
                match read {
                    Ok(0) => {
                        if send_half_close_frame(session_id, &outbound).await.is_err() {
                            break;
                        }
                        remote_read_open = false;
                        if !inbound_open {
                            break;
                        }
                    }
                    Ok(size) => {
                        if send_keep_frame(
                            session_id,
                            Bytes::copy_from_slice(&buffer[..size]),
                            &outbound,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = send_end_frame(session_id, true, &outbound).await;
                        break;
                    }
                }
            }
        }
    }
    sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .remove(&session_id);
}

fn destination_socket_addr(destination: &Destination) -> Option<SocketAddr> {
    destination.location.to_socket_addr_nonblocking()
}

async fn run_physical_writer<W>(
    mut writer: W,
    mut outbound: mpsc::Receiver<Bytes>,
    control: Arc<BridgeControlState>,
    cancellation: CancellationToken,
) where
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            frame = outbound.recv() => {
                let Some(frame) = frame else {
                    break;
                };
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
    control.close();
    cancellation.cancel();
}

async fn send_keep_frame(
    session_id: u16,
    payload: Bytes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    send_frame(
        session_id,
        SessionStatus::Keep,
        FrameOption::default().with_data(),
        None,
        payload,
        outbound,
    )
    .await
}

async fn send_end_frame(
    session_id: u16,
    has_error: bool,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let option = if has_error {
        FrameOption::default().with_error()
    } else {
        FrameOption::default()
    };
    send_frame(
        session_id,
        SessionStatus::End,
        option,
        None,
        Bytes::new(),
        outbound,
    )
    .await
}

async fn send_half_close_frame(
    session_id: u16,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    send_frame(
        session_id,
        SessionStatus::End,
        FrameOption::default().with_half_close(),
        None,
        Bytes::new(),
        outbound,
    )
    .await
}

async fn send_frame(
    session_id: u16,
    status: SessionStatus,
    option: FrameOption,
    target: Option<Destination>,
    payload: Bytes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let encoded = encode_frame(&MuxFrame {
        metadata: FrameMetadata {
            session_id,
            status,
            option,
            target,
            source: None,
            local: None,
            global_id: None,
        },
        payload,
    })?;
    outbound.send(encoded).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Reverse Bridge physical writer is closed",
        )
    })
}

#[cfg(test)]
#[path = "bridge_worker_tests.rs"]
mod tests;
