use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, ReadBuf, WriteHalf, split},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{
    address::NetLocation,
    async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadSessionMessage,
        AsyncSessionMessageStream, AsyncShutdownMessage, AsyncStream,
        AsyncWriteSessionMessage, SessionMessage,
    },
    resolver::Resolver,
};

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};

const READ_CHUNK_SIZE: usize = 8192;
const MAX_FRAME_SIZE: usize = 2 + 512 + 2 + u16::MAX as usize;
const CHANNEL_CAPACITY: usize = 16;
const MAX_CONSECUTIVE_CONTROL_FRAMES: usize = 1024;

type IncomingResult = std::io::Result<IncomingMessage>;

enum IncomingMessage {
    Data {
        session_id: u16,
        payload: BytesMut,
        target: SocketAddr,
        global_id: Option<[u8; 8]>,
        is_new: bool,
    },
    End {
        session_id: u16,
        reply: bool,
    },
}

pub(crate) struct XudpMessageStream {
    receiver: mpsc::Receiver<IncomingResult>,
    writer: WriteHalf<Box<dyn AsyncStream>>,
    pending_write: BytesMut,
    pending_write_offset: usize,
    write_prefix: Option<Vec<u8>>,
    pending_end_reply: Option<(u16, bool)>,
    reader_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for XudpMessageStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XudpMessageStream")
            .field("pending_write_len", &self.pending_write.len())
            .field("pending_write_offset", &self.pending_write_offset)
            .field(
                "write_prefix_len",
                &self.write_prefix.as_ref().map_or(0, Vec::len),
            )
            .finish_non_exhaustive()
    }
}

impl XudpMessageStream {
    pub(crate) fn new(
        stream: Box<dyn AsyncStream>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::with_write_prefix(stream, resolver, Vec::new())
    }

    pub(crate) fn with_write_prefix(
        stream: Box<dyn AsyncStream>,
        resolver: Arc<dyn Resolver>,
        write_prefix: Vec<u8>,
    ) -> Self {
        let (reader, writer) = split(stream);
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let reader_task = tokio::spawn(run_reader(reader, resolver, sender));
        Self {
            receiver,
            writer,
            pending_write: BytesMut::new(),
            pending_write_offset: 0,
            write_prefix: (!write_prefix.is_empty()).then_some(write_prefix),
            pending_end_reply: None,
            reader_task: Some(reader_task),
        }
    }

    fn poll_reader_task_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let finished = match self.reader_task.as_mut() {
            Some(task) => {
                task.abort();
                std::future::Future::poll(Pin::new(task), cx).is_ready()
            }
            None => true,
        };
        if finished {
            self.reader_task = None;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn poll_pending_write(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.pending_write_offset < self.pending_write.len() {
            match Pin::new(&mut self.writer)
                .poll_write(cx, &self.pending_write[self.pending_write_offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "XUDP stream closed while writing a frame",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.pending_write_offset += written;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.pending_write.clear();
        self.pending_write_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_pending_end_reply(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<Option<SessionMessage>>> {
        let Some((session_id, queued)) = self.pending_end_reply else {
            return Poll::Ready(Ok(None));
        };

        if !queued {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if let Some(prefix) = self.write_prefix.take() {
                self.pending_write.extend_from_slice(&prefix);
            }
            FrameMetadata {
                session_id,
                status: SessionStatus::End,
                option: FrameOption::default(),
                target: None,
                network: None,
                global_id: None,
            }
            .encode(&mut self.pending_write)?;
            self.pending_write_offset = 0;
            self.pending_end_reply = Some((session_id, true));
        }

        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_end_reply = None;
                Poll::Ready(Ok(Some(SessionMessage::End { session_id })))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for XudpMessageStream {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.as_ref() {
            task.abort();
        }
    }
}

impl AsyncReadSessionMessage for XudpMessageStream {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>> {
        let this = self.get_mut();
        match this.poll_pending_end_reply(cx) {
            Poll::Ready(Ok(Some(message))) => return Poll::Ready(Ok(message)),
            Poll::Ready(Ok(None)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut this.receiver).poll_recv(cx) {
            Poll::Ready(Some(Ok(IncomingMessage::Data {
                session_id,
                payload,
                target,
                global_id,
                is_new,
            }))) => {
                if payload.len() > buffer.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "XUDP payload exceeds receive buffer: {} > {}",
                            payload.len(),
                            buffer.remaining()
                        ),
                    )));
                }
                buffer.put_slice(&payload);
                Poll::Ready(Ok(SessionMessage::Data {
                    session_id,
                    target,
                    global_id,
                    is_new,
                }))
            }
            Poll::Ready(Some(Ok(IncomingMessage::End { session_id, reply }))) => {
                if reply {
                    this.pending_end_reply = Some((session_id, false));
                    match this.poll_pending_end_reply(cx) {
                        Poll::Ready(Ok(Some(message))) => Poll::Ready(Ok(message)),
                        Poll::Ready(Ok(None)) => unreachable!(
                            "pending XUDP End reply disappeared before completion"
                        ),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Ready(Ok(SessionMessage::End { session_id }))
                }
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "XUDP reader stopped",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteSessionMessage for XudpMessageStream {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        payload: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_write.is_empty() {
            if payload.len() > u16::MAX as usize {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "XUDP payload exceeds 65535 bytes",
                )));
            }
            if let Some(prefix) = this.write_prefix.take() {
                this.pending_write.extend_from_slice(&prefix);
            }
            let metadata = FrameMetadata {
                session_id,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: Some(NetLocation::from_ip_addr(source.ip(), source.port())),
                network: Some(TargetNetwork::Udp),
                global_id: None,
            };
            metadata.encode(&mut this.pending_write)?;
            this.pending_write.put_u16(payload.len() as u16);
            this.pending_write.extend_from_slice(payload);
            this.pending_write_offset = 0;
        }
        this.poll_pending_write(cx)
    }

    fn poll_write_session_end(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_write.is_empty() {
            if let Some(prefix) = this.write_prefix.take() {
                this.pending_write.extend_from_slice(&prefix);
            }
            let option = if has_error {
                FrameOption::default().with_error()
            } else {
                FrameOption::default()
            };
            FrameMetadata {
                session_id,
                status: SessionStatus::End,
                option,
                target: None,
                network: None,
                global_id: None,
            }
            .encode(&mut this.pending_write)?;
            this.pending_write_offset = 0;
        }
        this.poll_pending_write(cx)
    }
}

impl AsyncFlushMessage for XudpMessageStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.writer).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncShutdownMessage for XudpMessageStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.poll_reader_task_shutdown(cx).is_pending() {
            return Poll::Pending;
        }
        match this.poll_pending_write(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.writer).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncPing for XudpMessageStream {
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

impl AsyncSessionMessageStream for XudpMessageStream {}

async fn run_reader<R>(
    mut reader: R,
    resolver: Arc<dyn Resolver>,
    sender: mpsc::Sender<IncomingResult>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = BytesMut::with_capacity(READ_CHUNK_SIZE);
    let mut sessions = HashMap::<u16, XudpSessionState>::new();
    let mut consecutive_control_frames = 0usize;

    loop {
        match decode_frame_with_control_count(
            &mut buffer,
            &mut sessions,
            &mut consecutive_control_frames,
        ) {
            Ok(Some(DecodedFrame::Data {
                session_id,
                payload,
                target,
                global_id,
                is_new,
            })) => {
                let resolved =
                    resolver
                        .resolve_location(&target)
                        .await
                        .and_then(|addresses| {
                            addresses.into_iter().next().ok_or_else(|| {
                                std::io::Error::other(format!(
                                    "could not resolve XUDP target: {target}"
                                ))
                            })
                        });
                let result = resolved.map(|target| IncomingMessage::Data {
                    session_id,
                    payload,
                    target,
                    global_id,
                    is_new,
                });
                if sender.send(result).await.is_err() {
                    break;
                }
                continue;
            }
            Ok(Some(DecodedFrame::End { session_id, reply })) => {
                if sender
                    .send(Ok(IncomingMessage::End { session_id, reply }))
                    .await
                    .is_err()
                {
                    break;
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                let _ = sender.send(Err(error)).await;
                break;
            }
        }

        if buffer.len() >= MAX_FRAME_SIZE {
            let _ = sender
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "XUDP frame exceeds maximum size",
                )))
                .await;
            break;
        }
        match reader.read_buf(&mut buffer).await {
            Ok(0) => {
                let _ = sender
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "XUDP stream closed",
                    )))
                    .await;
                break;
            }
            Ok(_) => {}
            Err(error) => {
                let _ = sender.send(Err(error)).await;
                break;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XudpSessionState {
    target: NetLocation,
    global_id: Option<[u8; 8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecodedFrame {
    Data {
        session_id: u16,
        payload: BytesMut,
        target: NetLocation,
        global_id: Option<[u8; 8]>,
        is_new: bool,
    },
    End {
        session_id: u16,
        reply: bool,
    },
}

#[cfg(test)]
fn decode_frame(
    input: &mut BytesMut,
    sessions: &mut HashMap<u16, XudpSessionState>,
) -> std::io::Result<Option<DecodedFrame>> {
    let mut consecutive_control_frames = 0usize;
    decode_frame_with_control_count(input, sessions, &mut consecutive_control_frames)
}

fn decode_frame_with_control_count(
    input: &mut BytesMut,
    sessions: &mut HashMap<u16, XudpSessionState>,
    consecutive_control_frames: &mut usize,
) -> std::io::Result<Option<DecodedFrame>> {
    loop {
        if input.len() < 2 {
            return Ok(None);
        }
        let metadata_length = u16::from_be_bytes([input[0], input[1]]) as usize;
        if metadata_length > 512 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("XUDP metadata exceeds 512 bytes: {metadata_length}"),
            ));
        }
        if metadata_length < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("XUDP metadata is too short: {metadata_length}"),
            ));
        }
        let metadata_end = 2 + metadata_length;
        if input.len() < metadata_end {
            return Ok(None);
        }
        let option = FrameOption::from(input[5]);
        let frame_end = if option.has_data() {
            if input.len() < metadata_end + 2 {
                return Ok(None);
            }
            let payload_length =
                u16::from_be_bytes([input[metadata_end], input[metadata_end + 1]])
                    as usize;
            let frame_end = metadata_end + 2 + payload_length;
            if input.len() < frame_end {
                return Ok(None);
            }
            frame_end
        } else {
            metadata_end
        };

        let mut complete = input.split_to(frame_end);
        let metadata = FrameMetadata::decode(&mut complete)?.ok_or_else(|| {
            std::io::Error::other("complete XUDP metadata missing")
        })?;
        if metadata.option.has_error() {
            sessions.remove(&metadata.session_id);
            *consecutive_control_frames = 0;
            return Ok(Some(DecodedFrame::End {
                session_id: metadata.session_id,
                reply: false,
            }));
        }
        if metadata.network == Some(TargetNetwork::Tcp) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TCP destinations over XUDP are not supported",
            ));
        }

        let global_id = normalize_global_id(metadata.global_id);
        let existing_global_id = sessions
            .get(&metadata.session_id)
            .map(|session| session.global_id);
        let session_known = existing_global_id.is_some();
        match metadata.status {
            SessionStatus::New => {
                if let Some(existing_global_id) = existing_global_id
                    && (global_id.is_none() || existing_global_id != global_id)
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "duplicate XUDP session ID: {}",
                            metadata.session_id
                        ),
                    ));
                }
                if let Some(target) = metadata.target.clone() {
                    sessions.insert(
                        metadata.session_id,
                        XudpSessionState { target, global_id },
                    );
                }
            }
            SessionStatus::Keep if session_known => {
                if let Some(target) = metadata.target.as_ref()
                    && let Some(session) = sessions.get_mut(&metadata.session_id)
                    && session.target != *target
                {
                    session.target = target.clone();
                }
            }
            SessionStatus::Keep | SessionStatus::End | SessionStatus::KeepAlive => {}
        }

        if metadata.status == SessionStatus::End {
            sessions.remove(&metadata.session_id);
            *consecutive_control_frames = 0;
            return Ok(Some(DecodedFrame::End {
                session_id: metadata.session_id,
                reply: false,
            }));
        }
        if metadata.status == SessionStatus::KeepAlive || !metadata.option.has_data()
        {
            *consecutive_control_frames += 1;
        } else {
            let payload_length = complete.get_u16() as usize;
            let payload = complete.split_to(payload_length);
            if payload.is_empty() {
                *consecutive_control_frames += 1;
            } else if metadata.status == SessionStatus::Keep && !session_known {
                *consecutive_control_frames = 0;
                return Ok(Some(DecodedFrame::End {
                    session_id: metadata.session_id,
                    reply: true,
                }));
            } else {
                let session = sessions.get(&metadata.session_id);
                let target = metadata
                    .target
                    .or_else(|| session.map(|session| session.target.clone()))
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("unknown XUDP session: {}", metadata.session_id),
                        )
                    })?;
                let global_id = session.and_then(|session| session.global_id);
                *consecutive_control_frames = 0;
                return Ok(Some(DecodedFrame::Data {
                    session_id: metadata.session_id,
                    payload,
                    target,
                    global_id,
                    is_new: metadata.status == SessionStatus::New,
                }));
            }
        }

        if *consecutive_control_frames > MAX_CONSECUTIVE_CONTROL_FRAMES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "XUDP contains more than {MAX_CONSECUTIVE_CONTROL_FRAMES} consecutive control frames"
                ),
            ));
        }
    }
}

fn normalize_global_id(global_id: Option<[u8; 8]>) -> Option<[u8; 8]> {
    global_id.filter(|global_id| *global_id != [0; 8])
}

#[cfg(test)]
mod tests;
