// Batch D provides the standalone Mux TCP worker. Batch E will attach these
// workers to the Reverse registry/routing owner.
#![allow(dead_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex,
        split,
    },
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::async_stream::AsyncStream;

use super::{
    control::ControlState,
    mux_frame::{Destination, FrameMetadata, FrameOption, SessionStatus},
    mux_io::{MuxFrame, encode_frame, read_frame},
    session_core::{SessionLimits, WorkerCore, WorkerPhase},
    session_stream::ReverseSessionStream,
};

const SESSION_DUPLEX_CAPACITY: usize = 16 * 1024;
const OUTBOUND_FRAME_CAPACITY: usize = 16;
const INBOUND_FRAME_CAPACITY: usize = 16;
const STREAM_CHUNK_SIZE: usize = 8 * 1024;

#[derive(Debug)]
enum InboundEvent {
    Data {
        payload: Bytes,
        target: Option<Destination>,
    },
    End,
}

#[derive(Debug)]
pub(crate) struct ReversePacketSession {
    session_id: u16,
    target: Destination,
    source: Option<Destination>,
    local: Option<Destination>,
    first: bool,
    inbound: mpsc::Receiver<InboundEvent>,
    outbound: mpsc::Sender<Bytes>,
    sessions: SessionRoutes,
    core: Arc<WorkerCore>,
}

impl ReversePacketSession {
    pub(crate) async fn send(
        &mut self,
        payload: Bytes,
        target: Option<Destination>,
    ) -> std::io::Result<()> {
        let status = if self.first {
            SessionStatus::New
        } else {
            SessionStatus::Keep
        };
        let frame_target = if self.first {
            Some(self.target.clone())
        } else {
            target
        };
        let source = self.first.then(|| self.source.clone()).flatten();
        let local = self.first.then(|| self.local.clone()).flatten();
        send_stream_frame(
            self.session_id,
            status,
            FrameOption::default().with_data(),
            frame_target,
            source,
            local,
            payload,
            &self.outbound,
        )
        .await?;
        self.first = false;
        Ok(())
    }

    pub(crate) async fn close(&mut self) -> std::io::Result<()> {
        if self.first {
            return Ok(());
        }
        send_end_frame(self.session_id, &self.outbound).await
    }

    pub(crate) async fn recv(
        &mut self,
    ) -> std::io::Result<Option<(Bytes, Option<Destination>)>> {
        match self.inbound.recv().await {
            Some(InboundEvent::Data { payload, target }) => {
                Ok(Some((payload, target)))
            }
            Some(InboundEvent::End) | None => Ok(None),
        }
    }
}

impl Drop for ReversePacketSession {
    fn drop(&mut self) {
        self.sessions
            .lock()
            .expect("Reverse routes lock poisoned")
            .remove(&self.session_id);
        self.core.release_session(self.session_id);
    }
}

type SessionRoutes = Arc<Mutex<HashMap<u16, mpsc::Sender<InboundEvent>>>>;

pub(crate) struct MuxClientWorker {
    core: Arc<WorkerCore>,
    outbound: mpsc::Sender<Bytes>,
    sessions: SessionRoutes,
    cancellation: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for MuxClientWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MuxClientWorker")
            .field("id", &self.core.id())
            .field("phase", &self.core.phase())
            .field("active_connections", &self.core.active_connections())
            .field("total_connections", &self.core.total_connections())
            .finish()
    }
}

impl MuxClientWorker {
    pub(crate) fn new(
        id: u64,
        physical: Box<dyn AsyncStream>,
        limits: SessionLimits,
    ) -> Self {
        let core = Arc::new(WorkerCore::new(id, limits));
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = CancellationToken::new();
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_FRAME_CAPACITY);
        let (reader, writer) = split(physical);

        let reader_task = tokio::spawn(run_physical_reader(
            reader,
            sessions.clone(),
            outbound.clone(),
            core.clone(),
            cancellation.clone(),
        ));
        let writer_task = tokio::spawn(run_physical_writer(
            writer,
            outbound_rx,
            core.clone(),
            cancellation.clone(),
        ));

        Self {
            core,
            outbound,
            sessions,
            cancellation,
            tasks: Mutex::new(vec![reader_task, writer_task]),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.core.id()
    }

    pub(crate) fn phase(&self) -> WorkerPhase {
        self.core.phase()
    }

    pub(crate) fn control_session_became_active(&self) -> std::io::Result<()> {
        self.core.apply_control_state(ControlState::Active)
    }

    pub(crate) fn begin_drain(&self) -> std::io::Result<()> {
        self.core.apply_control_state(ControlState::Drain)
    }

    pub(crate) fn is_selectable(&self) -> bool {
        self.core.is_selectable() && !self.cancellation.is_cancelled()
    }

    pub(crate) fn active_connections(&self) -> usize {
        self.core.active_connections()
    }

    pub(crate) fn total_connections(&self) -> u32 {
        self.core.total_connections()
    }

    pub(crate) fn should_begin_drain(&self) -> bool {
        self.core.should_begin_drain()
    }

    pub(crate) fn allocate_internal_session(&self) -> std::io::Result<u16> {
        self.core.allocate_internal_session()
    }

    pub(crate) fn release_internal_session(&self, session_id: u16) -> bool {
        self.core.release_session(session_id)
    }

    pub(crate) async fn send_internal_packet(
        &self,
        session_id: u16,
        status: SessionStatus,
        target: Option<Destination>,
        payload: Bytes,
    ) -> std::io::Result<()> {
        let option = if payload.is_empty() {
            FrameOption::default()
        } else {
            FrameOption::default().with_data()
        };
        send_stream_frame(
            session_id,
            status,
            option,
            target,
            None,
            None,
            payload,
            &self.outbound,
        )
        .await
    }

    pub(crate) async fn end_internal_session(
        &self,
        session_id: u16,
    ) -> std::io::Result<()> {
        send_end_frame(session_id, &self.outbound).await
    }

    pub(crate) fn open_packet_session(
        &self,
        target: Destination,
        source: Option<Destination>,
        local: Option<Destination>,
    ) -> std::io::Result<ReversePacketSession> {
        if target.network != super::mux_frame::TargetNetwork::Udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Reverse packet session requires a UDP target",
            ));
        }
        let session_id = self.core.allocate_session()?;
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_FRAME_CAPACITY);
        {
            let mut sessions =
                self.sessions.lock().expect("Reverse routes lock poisoned");
            if sessions.insert(session_id, inbound_tx).is_some() {
                self.core.release_session(session_id);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("duplicate Reverse Mux session id: {session_id}"),
                ));
            }
        }
        Ok(ReversePacketSession {
            session_id,
            target,
            source,
            local,
            first: true,
            inbound,
            outbound: self.outbound.clone(),
            sessions: self.sessions.clone(),
            core: self.core.clone(),
        })
    }

    pub(crate) fn open_tcp_session(
        &self,
        target: Destination,
        source: Option<Destination>,
        local: Option<Destination>,
    ) -> std::io::Result<ReverseSessionStream> {
        let session_id = self.core.allocate_session()?;
        let (application, worker_side) = duplex(SESSION_DUPLEX_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_FRAME_CAPACITY);

        {
            let mut sessions =
                self.sessions.lock().expect("Reverse routes lock poisoned");
            if sessions.insert(session_id, inbound_tx).is_some() {
                self.core.release_session(session_id);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("duplicate Reverse Mux session id: {session_id}"),
                ));
            }
        }

        let task = tokio::spawn(run_tcp_session(
            session_id,
            worker_side,
            target,
            source,
            local,
            inbound_rx,
            self.outbound.clone(),
            self.sessions.clone(),
            self.core.clone(),
            self.cancellation.clone(),
        ));
        self.tasks
            .lock()
            .expect("Reverse task lock poisoned")
            .push(task);

        Ok(ReverseSessionStream::new(application))
    }

    pub(crate) fn close(&self) {
        shutdown_worker(&self.core, &self.cancellation);
    }

    pub(crate) async fn wait_closed(&self) {
        self.cancellation.cancelled().await;
    }
}

impl Drop for MuxClientWorker {
    fn drop(&mut self) {
        shutdown_worker(&self.core, &self.cancellation);
        for task in self
            .tasks
            .lock()
            .expect("Reverse task lock poisoned")
            .drain(..)
        {
            task.abort();
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct MuxClientPicker {
    workers: Mutex<Vec<Arc<MuxClientWorker>>>,
}

impl MuxClientPicker {
    pub(crate) fn add(&self, worker: Arc<MuxClientWorker>) {
        self.workers
            .lock()
            .expect("Reverse client picker lock poisoned")
            .push(worker);
    }

    pub(crate) fn pick_available(&self) -> std::io::Result<Arc<MuxClientWorker>> {
        let mut workers = self
            .workers
            .lock()
            .expect("Reverse client picker lock poisoned");
        workers.retain(|worker| worker.phase() != WorkerPhase::Closed);

        workers
            .iter()
            .filter(|worker| worker.is_selectable())
            .min_by_key(|worker| worker.active_connections())
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "no ACTIVE Reverse Mux client worker available",
                )
            })
    }
}

async fn run_physical_writer<W>(
    mut writer: W,
    mut outbound: mpsc::Receiver<Bytes>,
    core: Arc<WorkerCore>,
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
    shutdown_worker(&core, &cancellation);
}

async fn run_physical_reader<R>(
    mut reader: R,
    sessions: SessionRoutes,
    outbound: mpsc::Sender<Bytes>,
    core: Arc<WorkerCore>,
    cancellation: CancellationToken,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            frame = read_frame(&mut reader) => frame,
        };
        let Ok(frame) = frame else {
            break;
        };

        match frame.metadata.status {
            SessionStatus::Keep => {
                let route = sessions
                    .lock()
                    .expect("Reverse routes lock poisoned")
                    .get(&frame.metadata.session_id)
                    .cloned();
                if let Some(route) = route {
                    if frame.metadata.option.has_data()
                        && route
                            .send(InboundEvent::Data {
                                payload: frame.payload,
                                target: frame.metadata.target,
                            })
                            .await
                            .is_err()
                    {
                        break;
                    }
                } else if send_end_frame(frame.metadata.session_id, &outbound)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            SessionStatus::End => {
                let route = sessions
                    .lock()
                    .expect("Reverse routes lock poisoned")
                    .remove(&frame.metadata.session_id);
                if let Some(route) = route {
                    let _ = route.send(InboundEvent::End).await;
                }
            }
            SessionStatus::New | SessionStatus::KeepAlive => {
                // Xray's mux.ClientWorker does not create a local session for
                // response-side NEW/KEEPALIVE frames; optional data is consumed.
            }
        }
    }

    shutdown_worker(&core, &cancellation);
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp_session(
    session_id: u16,
    stream: DuplexStream,
    target: Destination,
    source: Option<Destination>,
    local: Option<Destination>,
    mut inbound: mpsc::Receiver<InboundEvent>,
    outbound: mpsc::Sender<Bytes>,
    sessions: SessionRoutes,
    core: Arc<WorkerCore>,
    cancellation: CancellationToken,
) {
    let (mut uplink, mut downlink) = split(stream);
    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    let mut first = true;

    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            event = inbound.recv() => {
                match event {
                    Some(InboundEvent::Data { payload, .. }) => {
                        if downlink.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Some(InboundEvent::End) | None => {
                        let _ = downlink.shutdown().await;
                        break;
                    }
                }
            }
            read = uplink.read(&mut buffer) => {
                match read {
                    Ok(0) => {
                        if first
                            && send_stream_frame(
                                session_id,
                                SessionStatus::New,
                                FrameOption::default(),
                                Some(target.clone()),
                                source.clone(),
                                local.clone(),
                                Bytes::new(),
                                &outbound,
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if send_end_frame(session_id, &outbound).await.is_err() {
                            break;
                        }
                        break;
                    }
                    Ok(size) => {
                        let status = if first {
                            SessionStatus::New
                        } else {
                            SessionStatus::Keep
                        };
                        let frame_target = first.then(|| target.clone());
                        let frame_source = first.then(|| source.clone()).flatten();
                        let frame_local = first.then(|| local.clone()).flatten();
                        if send_stream_frame(
                            session_id,
                            status,
                            FrameOption::default().with_data(),
                            frame_target,
                            frame_source,
                            frame_local,
                            Bytes::copy_from_slice(&buffer[..size]),
                            &outbound,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                        first = false;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    sessions
        .lock()
        .expect("Reverse routes lock poisoned")
        .remove(&session_id);
    core.release_session(session_id);
}

#[allow(clippy::too_many_arguments)]
async fn send_stream_frame(
    session_id: u16,
    status: SessionStatus,
    option: FrameOption,
    target: Option<Destination>,
    source: Option<Destination>,
    local: Option<Destination>,
    payload: Bytes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let encoded = encode_frame(&MuxFrame {
        metadata: FrameMetadata {
            session_id,
            status,
            option,
            target,
            source,
            local,
            global_id: None,
        },
        payload,
    })?;
    outbound.send(encoded).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Reverse Mux physical writer is closed",
        )
    })
}

async fn send_end_frame(
    session_id: u16,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    send_stream_frame(
        session_id,
        SessionStatus::End,
        FrameOption::default(),
        None,
        None,
        None,
        Bytes::new(),
        outbound,
    )
    .await
}

fn shutdown_worker(core: &WorkerCore, cancellation: &CancellationToken) {
    core.close();
    cancellation.cancel();
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
