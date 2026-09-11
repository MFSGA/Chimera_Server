use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::Body;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex},
    sync::mpsc,
    time::{Duration, sleep},
};
use tokio_util::sync::CancellationToken;

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    runtime::DataPlaneRuntime,
};

use super::XHTTP_PIPE_CAPACITY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionTtlSnapshot {
    pub(super) is_current: bool,
    pub(super) fully_connected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionTtlPlan {
    Keep,
    RemoveAndClose,
}

fn same_xhttp_session(
    current: Option<&Arc<XhttpSession>>,
    candidate: &Arc<XhttpSession>,
) -> bool {
    current.is_some_and(|current| Arc::ptr_eq(current, candidate))
}

pub(super) fn plan_session_ttl(snapshot: SessionTtlSnapshot) -> SessionTtlPlan {
    if snapshot.is_current && !snapshot.fully_connected {
        SessionTtlPlan::RemoveAndClose
    } else {
        SessionTtlPlan::Keep
    }
}

#[derive(Clone)]
pub(super) struct SessionStore {
    pub(super) inner: Arc<RwLock<HashMap<String, Arc<XhttpSession>>>>,
    ttl: Duration,
    pub(super) max_buffered_posts: usize,
    shutdown: CancellationToken,
    runtime: DataPlaneRuntime,
}

impl SessionStore {
    pub(super) fn new(
        ttl: Duration,
        max_buffered_posts: usize,
        shutdown: CancellationToken,
        runtime: DataPlaneRuntime,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            max_buffered_posts,
            shutdown,
            runtime,
        }
    }

    pub(super) fn get_or_create(&self, session_id: &str) -> Arc<XhttpSession> {
        if let Some(existing) = self.inner.read().unwrap().get(session_id) {
            return existing.clone();
        }

        let session = Arc::new(XhttpSession::new(self.max_buffered_posts));
        let mut sessions = self.inner.write().unwrap();
        if let Some(existing) = sessions.get(session_id) {
            return existing.clone();
        }
        sessions.insert(session_id.to_string(), session.clone());
        drop(sessions);
        if !self.spawn_ttl_cleanup(session_id.to_string(), session.clone()) {
            self.remove_if_current(session_id, &session);
            session.close_upload_queue();
        }
        session
    }

    pub(super) fn remove(&self, session_id: &str) {
        self.inner.write().unwrap().remove(session_id);
    }

    fn remove_if_current(&self, session_id: &str, session: &Arc<XhttpSession>) {
        let mut sessions = self.inner.write().unwrap();
        if same_xhttp_session(sessions.get(session_id), session) {
            sessions.remove(session_id);
        }
    }

    fn spawn_ttl_cleanup(
        &self,
        session_id: String,
        session: Arc<XhttpSession>,
    ) -> bool {
        let ttl = self.ttl;
        let sessions = self.inner.clone();
        let shutdown = self.shutdown.clone();
        self.runtime.spawn_inbound_connection(async move {
            tokio::select! {
                _ = sleep(ttl) => {}
                _ = shutdown.cancelled() => {
                    let mut current = sessions.write().unwrap();
                    if same_xhttp_session(current.get(&session_id), &session) {
                        current.remove(&session_id);
                    }
                    drop(current);
                    session.close_upload_queue();
                    return;
                }
            }

            let snapshot = {
                let current = sessions.read().unwrap();
                SessionTtlSnapshot {
                    is_current: same_xhttp_session(
                        current.get(&session_id),
                        &session,
                    ),
                    fully_connected: session.fully_connected.load(Ordering::Acquire),
                }
            };
            if plan_session_ttl(snapshot) == SessionTtlPlan::RemoveAndClose {
                let mut current = sessions.write().unwrap();
                if same_xhttp_session(current.get(&session_id), &session) {
                    current.remove(&session_id);
                }
                drop(current);
                session.close_upload_queue();
            }
        })
    }
}

pub(super) struct SessionCleanupGuard {
    pub(super) sessions: SessionStore,
    pub(super) session_id: String,
    pub(super) session: Arc<XhttpSession>,
}

impl Drop for SessionCleanupGuard {
    fn drop(&mut self) {
        self.sessions
            .remove_if_current(&self.session_id, &self.session);
        self.session.close_upload_queue();
    }
}

pub(super) struct IncomingBodyReader<B> {
    body: B,
    current: Bytes,
}

impl<B> IncomingBodyReader<B> {
    pub(super) fn new(body: B) -> Self {
        Self {
            body,
            current: Bytes::new(),
        }
    }
}

impl<B> AsyncRead for IncomingBodyReader<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.current.is_empty() {
                let len = self.current.len().min(buf.remaining());
                buf.put_slice(&self.current.split_to(len));
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        self.current = data;
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

type BoxedUploadReader = Pin<Box<dyn AsyncRead + Send>>;

enum UploadPacket {
    ReaderClaim,
    Payload { seq: u64, data: Bytes },
}

pub(super) struct UploadQueueSender {
    sender: mpsc::Sender<UploadPacket>,
    pub(super) reader_claimed: AtomicBool,
    reader: Arc<StdMutex<Option<BoxedUploadReader>>>,
    pub(super) closed: Arc<AtomicBool>,
}

impl UploadQueueSender {
    pub(super) async fn push_reader(
        &self,
        reader: BoxedUploadReader,
    ) -> std::io::Result<()> {
        if self
            .reader_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(std::io::Error::other("h.reader already exists"));
        }
        *self
            .reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reader);
        self.sender
            .send(UploadPacket::ReaderClaim)
            .await
            .map_err(|_| std::io::Error::other("packet queue closed"))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(std::io::Error::other("packet queue closed"));
        }
        Ok(())
    }

    pub(super) async fn push_payload(
        &self,
        seq: u64,
        data: Bytes,
    ) -> std::io::Result<()> {
        if self.reader_claimed.load(Ordering::Acquire) {
            return Err(std::io::Error::other("h.reader already exists"));
        }
        self.sender
            .send(UploadPacket::Payload { seq, data })
            .await
            .map_err(|_| std::io::Error::other("packet queue closed"))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(std::io::Error::other("packet queue closed"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UploadReassemblySnapshot {
    pub(super) has_current_payload: bool,
    pub(super) has_next_buffered_payload: bool,
    pub(super) buffered_packets: usize,
    pub(super) max_buffered_posts: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UploadReassemblyPlan {
    ConsumeCurrent,
    PromoteBuffered,
    RejectTooLarge,
    PollReceiver,
}

pub(super) fn plan_upload_reassembly(
    snapshot: UploadReassemblySnapshot,
) -> UploadReassemblyPlan {
    if snapshot.has_current_payload {
        UploadReassemblyPlan::ConsumeCurrent
    } else if snapshot.has_next_buffered_payload {
        UploadReassemblyPlan::PromoteBuffered
    } else if snapshot.buffered_packets > snapshot.max_buffered_posts + 1 {
        UploadReassemblyPlan::RejectTooLarge
    } else {
        UploadReassemblyPlan::PollReceiver
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UploadPayloadPlan {
    Buffer,
    DropStale,
}

pub(super) fn plan_upload_payload(
    next_seq: u64,
    incoming_seq: u64,
) -> UploadPayloadPlan {
    if incoming_seq >= next_seq {
        UploadPayloadPlan::Buffer
    } else {
        UploadPayloadPlan::DropStale
    }
}

pub(super) struct XhttpUploadReader {
    receiver: mpsc::Receiver<UploadPacket>,
    reader: Arc<StdMutex<Option<BoxedUploadReader>>>,
    pub(super) closed: Arc<AtomicBool>,
    current_payload: Option<Bytes>,
    buffered: BTreeMap<u64, VecDeque<Bytes>>,
    pub(super) buffered_packets: usize,
    next_seq: u64,
    pub(super) max_buffered_posts: usize,
}

impl XhttpUploadReader {
    pub(super) fn new(max_buffered_posts: usize) -> (UploadQueueSender, Self) {
        let (sender, receiver) = mpsc::channel(max_buffered_posts);
        let reader = Arc::new(StdMutex::new(None));
        let closed = Arc::new(AtomicBool::new(false));
        (
            UploadQueueSender {
                sender,
                reader_claimed: AtomicBool::new(false),
                reader: reader.clone(),
                closed: closed.clone(),
            },
            Self {
                receiver,
                reader,
                closed,
                current_payload: None,
                buffered: BTreeMap::new(),
                buffered_packets: 0,
                next_seq: 0,
                max_buffered_posts,
            },
        )
    }
}

impl AsyncRead for XhttpUploadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            {
                let mut reader = self
                    .reader
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(reader) = reader.as_mut() {
                    return reader.as_mut().poll_read(cx, buf);
                }
            }

            // Xray's uploadQueue checks its closed signal before consulting
            // any buffered packet heap. Once session reaping closes the queue,
            // queued packet data must not leak into the logical stream.
            if self.closed.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }

            let plan = plan_upload_reassembly(UploadReassemblySnapshot {
                has_current_payload: self.current_payload.is_some(),
                has_next_buffered_payload: self
                    .buffered
                    .contains_key(&self.next_seq),
                buffered_packets: self.buffered_packets,
                max_buffered_posts: self.max_buffered_posts,
            });

            match plan {
                UploadReassemblyPlan::ConsumeCurrent => {
                    let Some(mut payload) = self.current_payload.take() else {
                        continue;
                    };
                    if payload.is_empty() {
                        // Xray advances past an empty packet with (0, nil). Tokio
                        // interprets a successful zero-byte AsyncRead as EOF, so
                        // consume the empty sequence internally instead of exposing
                        // a false end-of-stream to the logical connection.
                        self.next_seq += 1;
                        continue;
                    }

                    let len = payload.len().min(buf.remaining());
                    buf.put_slice(&payload.split_to(len));
                    if payload.is_empty() {
                        self.next_seq += 1;
                    } else {
                        self.current_payload = Some(payload);
                    }
                    return Poll::Ready(Ok(()));
                }
                UploadReassemblyPlan::PromoteBuffered => {
                    let next_seq = self.next_seq;
                    let mut remove_entry = false;
                    let Some(payload) =
                        self.buffered.get_mut(&next_seq).and_then(|payloads| {
                            let payload = payloads.pop_front();
                            remove_entry = payloads.is_empty();
                            payload
                        })
                    else {
                        continue;
                    };
                    self.buffered_packets -= 1;
                    if remove_entry {
                        self.buffered.remove(&next_seq);
                    }
                    self.current_payload = Some(payload);
                }
                UploadReassemblyPlan::RejectTooLarge => {
                    return Poll::Ready(Err(std::io::Error::other(
                        "packet queue is too large",
                    )));
                }
                UploadReassemblyPlan::PollReceiver => {
                    match Pin::new(&mut self.receiver).poll_recv(cx) {
                        Poll::Ready(Some(UploadPacket::ReaderClaim)) => continue,
                        Poll::Ready(Some(UploadPacket::Payload { seq, data })) => {
                            if plan_upload_payload(self.next_seq, seq)
                                == UploadPayloadPlan::Buffer
                            {
                                self.buffered
                                    .entry(seq)
                                    .or_default()
                                    .push_back(data);
                                self.buffered_packets += 1;
                            }
                        }
                        Poll::Ready(None) => return Poll::Ready(Ok(())),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

pub(super) struct SharedUploadReader {
    pub(super) inner: Arc<StdMutex<XhttpUploadReader>>,
}

impl AsyncRead for SharedUploadReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut reader = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Pin::new(&mut *reader).poll_read(cx, buf)
    }
}

pub(super) struct XhttpSession {
    pub(super) upload_queue: UploadQueueSender,
    pub(super) upload_reader: Arc<StdMutex<XhttpUploadReader>>,
    pub(super) fully_connected: AtomicBool,
    pub(super) closed: CancellationToken,
}

impl XhttpSession {
    pub(super) fn new(max_buffered_posts: usize) -> Self {
        let (upload_queue, upload_reader) =
            XhttpUploadReader::new(max_buffered_posts);

        Self {
            upload_queue,
            upload_reader: Arc::new(StdMutex::new(upload_reader)),
            fully_connected: AtomicBool::new(false),
            closed: CancellationToken::new(),
        }
    }

    pub(super) fn new_downlink_connection(
        &self,
    ) -> (XhttpLogicalStream, DuplexStream) {
        // Xray v26.2.6 creates a fresh logical inbound connection for every
        // stream-down GET while all of them compete on the same uploadQueue.
        let (server_write, client_download) = duplex(XHTTP_PIPE_CAPACITY);
        let reader = SharedUploadReader {
            inner: self.upload_reader.clone(),
        };
        (
            XhttpLogicalStream::new(reader, server_write),
            client_download,
        )
    }

    pub(super) fn close_upload_queue(&self) {
        self.closed.cancel();
        let mut reader = self
            .upload_reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reader.closed.store(true, Ordering::Release);
        reader.receiver.close();
        reader
            .reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

pub(super) struct XhttpLogicalStream {
    reader: BoxedUploadReader,
    writer: DuplexStream,
}

impl XhttpLogicalStream {
    pub(super) fn new<R>(reader: R, writer: DuplexStream) -> Self
    where
        R: AsyncRead + Send + 'static,
    {
        Self {
            reader: Box::pin(reader),
            writer,
        }
    }
}

impl AsyncRead for XhttpLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl AsyncPing for XhttpLogicalStream {
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

impl AsyncStream for XhttpLogicalStream {}
