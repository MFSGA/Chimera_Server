use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{address::NetLocation, async_stream::AsyncStream};

use super::{
    bridge_control::BridgeControlState,
    mux_frame::{
        Destination, FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
    },
    mux_io::{MuxFrame, encode_frame, read_frame_with_source_and_local},
};

const OUTBOUND_FRAME_CAPACITY: usize = 16;
const INBOUND_FRAME_CAPACITY: usize = 16;
const STREAM_CHUNK_SIZE: usize = 8 * 1024;

#[derive(Debug)]
enum InboundEvent {
    Data(Bytes),
    End,
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
    ) -> std::io::Result<Box<dyn AsyncStream>>;
}

pub(crate) struct MuxServerWorker {
    control: Arc<BridgeControlState>,
    sessions: SessionRoutes,
    cancellation: CancellationToken,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl MuxServerWorker {
    pub(crate) fn new(
        physical: Box<dyn AsyncStream>,
        reverse_tag: String,
        dispatcher: Arc<dyn BridgeTcpDispatcher>,
    ) -> Self {
        let control = Arc::new(BridgeControlState::new());
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = CancellationToken::new();
        let tasks = Arc::new(Mutex::new(Vec::new()));
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
        ));
        let writer_task = tokio::spawn(run_physical_writer(
            writer,
            outbound_rx,
            control.clone(),
            cancellation.clone(),
        ));
        tasks
            .lock()
            .expect("Reverse Bridge task lock poisoned")
            .extend([reader_task, writer_task]);

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
) where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            frame = read_frame_with_source_and_local(&mut reader, true) => frame,
        };
        let Ok(frame) = frame else {
            break;
        };
        match control.handle_frame(&frame) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => break,
        }

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
                )
                .await
            }
            SessionStatus::Keep => forward_keep(frame, &sessions, &outbound).await,
            SessionStatus::End => {
                end_session(frame.metadata.session_id, &sessions).await;
                Ok(())
            }
            SessionStatus::KeepAlive => Ok(()),
        };
        if result.is_err() {
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
) -> std::io::Result<()> {
    let target = frame.metadata.target.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse Mux NEW frame is missing its target",
        )
    })?;
    if target.network != TargetNetwork::Tcp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "VLESS Reverse Bridge UDP/XUDP is not implemented yet",
        ));
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
    let stream = dispatcher
        .open_tcp(reverse_tag, target.location.clone(), source, local)
        .await?;

    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_FRAME_CAPACITY);
    sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .insert(frame.metadata.session_id, inbound_tx);
    let task = tokio::spawn(run_tcp_session(
        frame.metadata.session_id,
        stream,
        frame.payload,
        inbound_rx,
        outbound,
        sessions,
        cancellation,
    ));
    tasks
        .lock()
        .expect("Reverse Bridge task lock poisoned")
        .push(task);
    Ok(())
}

async fn forward_keep(
    frame: MuxFrame,
    sessions: &SessionRoutes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let route = sessions
        .lock()
        .expect("Reverse Bridge routes lock poisoned")
        .get(&frame.metadata.session_id)
        .cloned();
    if let Some(route) = route {
        if frame.metadata.option.has_data() {
            route
                .send(InboundEvent::Data(frame.payload))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Reverse Bridge logical session is closed",
                    )
                })?;
        }
        return Ok(());
    }
    send_end_frame(frame.metadata.session_id, false, outbound).await
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

async fn run_tcp_session(
    session_id: u16,
    stream: Box<dyn AsyncStream>,
    initial_payload: Bytes,
    mut inbound: mpsc::Receiver<InboundEvent>,
    outbound: mpsc::Sender<Bytes>,
    sessions: SessionRoutes,
    cancellation: CancellationToken,
) {
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

    let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            event = inbound.recv() => {
                match event {
                    Some(InboundEvent::Data(payload)) => {
                        if remote_write.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Some(InboundEvent::End) | None => {
                        let _ = remote_write.shutdown().await;
                        break;
                    }
                }
            }
            read = remote_read.read(&mut buffer) => {
                match read {
                    Ok(0) => {
                        let _ = send_end_frame(session_id, false, &outbound).await;
                        break;
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
        Bytes::new(),
        outbound,
    )
    .await
}

async fn send_frame(
    session_id: u16,
    status: SessionStatus,
    option: FrameOption,
    payload: Bytes,
    outbound: &mpsc::Sender<Bytes>,
) -> std::io::Result<()> {
    let encoded = encode_frame(&MuxFrame {
        metadata: FrameMetadata {
            session_id,
            status,
            option,
            target: None,
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
