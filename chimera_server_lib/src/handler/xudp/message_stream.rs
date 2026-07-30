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
        payload: Vec<u8>,
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
    reader_task: JoinHandle<()>,
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
            reader_task,
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
        self.reader_task.abort();
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
        payload: Vec<u8>,
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
        let existing_session = sessions.get(&metadata.session_id).cloned();
        let session_known = existing_session.is_some();
        match metadata.status {
            SessionStatus::New => {
                if let Some(existing) = &existing_session
                    && (global_id.is_none() || existing.global_id != global_id)
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
                if let Some(target) = metadata.target.clone()
                    && let Some(session) = sessions.get_mut(&metadata.session_id)
                {
                    session.target = target;
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
            let payload = complete.split_to(payload_length).to_vec();
            if payload.is_empty() {
                *consecutive_control_frames += 1;
            } else if metadata.status == SessionStatus::Keep && !session_known {
                *consecutive_control_frames = 0;
                return Ok(Some(DecodedFrame::End {
                    session_id: metadata.session_id,
                    reply: true,
                }));
            } else {
                let session = sessions.get(&metadata.session_id).cloned();
                let target = metadata
                    .target
                    .or_else(|| {
                        session.as_ref().map(|session| session.target.clone())
                    })
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("unknown XUDP session: {}", metadata.session_id),
                        )
                    })?;
                *consecutive_control_frames = 0;
                return Ok(Some(DecodedFrame::Data {
                    session_id: metadata.session_id,
                    payload,
                    target,
                    global_id: session.and_then(|session| session.global_id),
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
mod tests {
    use std::{
        future::{Future, poll_fn},
        net::Ipv4Addr,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        net::UdpSocket,
        time::{Duration, timeout},
    };

    use crate::{
        address::Address,
        async_stream::{AsyncReadSessionMessage, AsyncWriteSessionMessage},
        beginning::udp::run_session_based_udp,
        runtime::RuntimeState,
    };

    use super::*;

    struct StaticResolver;

    impl Resolver for StaticResolver {
        fn resolve_location(
            &self,
            location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        {
            let port = location.port();
            Box::pin(async move {
                Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
            })
        }
    }

    fn encode_data_frame(
        status: SessionStatus,
        session_id: u16,
        target: Option<NetLocation>,
        payload: &[u8],
    ) -> BytesMut {
        encode_data_frame_with_global_id(status, session_id, target, payload, None)
    }

    fn encode_data_frame_with_global_id(
        status: SessionStatus,
        session_id: u16,
        target: Option<NetLocation>,
        payload: &[u8],
        global_id: Option<[u8; 8]>,
    ) -> BytesMut {
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status,
            option: FrameOption::default().with_data(),
            network: target.as_ref().map(|_| TargetNetwork::Udp),
            target,
            global_id,
        }
        .encode(&mut frame)
        .expect("encode XUDP metadata");
        frame.put_u16(payload.len() as u16);
        frame.extend_from_slice(payload);
        frame
    }

    async fn read_response_frame(
        client: &mut tokio::io::DuplexStream,
    ) -> (FrameMetadata, Vec<u8>) {
        let mut length_bytes = [0u8; 2];
        timeout(Duration::from_secs(5), client.read_exact(&mut length_bytes))
            .await
            .expect("XUDP response metadata timeout")
            .expect("read XUDP response metadata length");
        let metadata_length = u16::from_be_bytes(length_bytes) as usize;
        let mut metadata_bytes = BytesMut::from(&length_bytes[..]);
        metadata_bytes.resize(2 + metadata_length, 0);
        client
            .read_exact(&mut metadata_bytes[2..])
            .await
            .expect("read XUDP response metadata");
        let metadata = FrameMetadata::decode(&mut metadata_bytes)
            .expect("decode XUDP response metadata")
            .expect("complete XUDP response metadata");
        assert!(metadata_bytes.is_empty());

        let payload = if metadata.option.has_data() {
            let mut payload_length = [0u8; 2];
            client
                .read_exact(&mut payload_length)
                .await
                .expect("read XUDP response payload length");
            let mut payload = vec![0u8; u16::from_be_bytes(payload_length) as usize];
            client
                .read_exact(&mut payload)
                .await
                .expect("read XUDP response payload");
            payload
        } else {
            Vec::new()
        };
        (metadata, payload)
    }

    fn encode_control_frame(status: SessionStatus, session_id: u16) -> BytesMut {
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status,
            option: FrameOption::default(),
            network: None,
            target: None,
            global_id: None,
        }
        .encode(&mut frame)
        .expect("encode XUDP control metadata");
        frame
    }

    fn encode_error_frame(session_id: u16, payload: &[u8]) -> BytesMut {
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id,
            status: SessionStatus::End,
            option: FrameOption::from(FrameOption::ERROR).with_data(),
            network: None,
            target: None,
            global_id: None,
        }
        .encode(&mut frame)
        .expect("encode XUDP error metadata");
        frame.put_u16(payload.len() as u16);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn metadata_only_new_initializes_target_for_following_keep() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut input = BytesMut::new();
        FrameMetadata {
            session_id: 39,
            status: SessionStatus::New,
            option: FrameOption::default(),
            network: Some(TargetNetwork::Udp),
            target: Some(target.clone()),
            global_id: None,
        }
        .encode(&mut input)
        .expect("encode metadata-only XUDP New frame");
        input.extend_from_slice(&encode_data_frame(
            SessionStatus::Keep,
            39,
            None,
            b"payload",
        ));
        let mut sessions = HashMap::new();

        let DecodedFrame::Data {
            session_id,
            payload,
            target: decoded_target,
            global_id,
            is_new,
        } = decode_frame(&mut input, &mut sessions)
            .expect("decode metadata-only New and following Keep")
            .expect("following Keep must produce data")
        else {
            panic!("following Keep decoded as End");
        };

        assert_eq!(session_id, 39);
        assert_eq!(payload, b"payload");
        assert_eq!(decoded_target, target);
        assert_eq!(global_id, None);
        assert!(!is_new);
        assert_eq!(sessions.get(&39).unwrap().target, target);
        assert!(input.is_empty());
    }

    #[test]
    fn zero_global_id_is_normalized_to_none() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut input = encode_data_frame_with_global_id(
            SessionStatus::New,
            40,
            Some(target),
            b"payload",
            Some([0; 8]),
        );
        let mut sessions = HashMap::new();

        let DecodedFrame::Data { global_id, .. } =
            decode_frame(&mut input, &mut sessions)
                .expect("decode zero GlobalID XUDP frame")
                .expect("zero GlobalID XUDP data frame")
        else {
            panic!("zero GlobalID XUDP frame decoded as End");
        };
        assert_eq!(global_id, None);
        assert_eq!(sessions.get(&40).unwrap().global_id, None);
    }

    #[test]
    fn duplicate_new_without_global_id_is_rejected() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut first = encode_data_frame(
            SessionStatus::New,
            41,
            Some(target.clone()),
            b"first",
        );
        let mut sessions = HashMap::new();
        let decoded = decode_frame(&mut first, &mut sessions)
            .expect("decode initial XUDP New")
            .expect("initial XUDP New data");
        assert!(matches!(decoded, DecodedFrame::Data { is_new: true, .. }));

        let mut duplicate =
            encode_data_frame(SessionStatus::New, 41, Some(target), b"duplicate");
        let error = decode_frame(&mut duplicate, &mut sessions)
            .expect_err("duplicate XUDP New without GlobalID must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate XUDP session ID: 41"));
        assert!(sessions.contains_key(&41));
    }

    #[test]
    fn duplicate_new_with_different_global_id_is_rejected() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let first_global_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let second_global_id = [8, 7, 6, 5, 4, 3, 2, 1];
        let mut first = encode_data_frame_with_global_id(
            SessionStatus::New,
            42,
            Some(target.clone()),
            b"first",
            Some(first_global_id),
        );
        let mut sessions = HashMap::new();
        decode_frame(&mut first, &mut sessions)
            .expect("decode initial GlobalID XUDP New")
            .expect("initial GlobalID XUDP New data");

        let mut duplicate = encode_data_frame_with_global_id(
            SessionStatus::New,
            42,
            Some(target),
            b"duplicate",
            Some(second_global_id),
        );
        let error = decode_frame(&mut duplicate, &mut sessions)
            .expect_err("duplicate XUDP New with a different GlobalID must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate XUDP session ID: 42"));
        assert_eq!(sessions.get(&42).unwrap().global_id, Some(first_global_id));
    }

    #[test]
    fn duplicate_new_with_same_global_id_is_a_new_attachment() {
        let first_target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let second_target =
            NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 5353);
        let global_id = [9, 10, 11, 12, 13, 14, 15, 16];
        let mut sessions = HashMap::new();
        let mut first = encode_data_frame_with_global_id(
            SessionStatus::New,
            43,
            Some(first_target),
            b"first",
            Some(global_id),
        );
        decode_frame(&mut first, &mut sessions)
            .expect("decode first GlobalID XUDP New")
            .expect("first GlobalID XUDP New data");

        let mut duplicate = encode_data_frame_with_global_id(
            SessionStatus::New,
            43,
            Some(second_target.clone()),
            b"reattach",
            Some(global_id),
        );
        let DecodedFrame::Data {
            session_id,
            payload,
            target,
            global_id: decoded_global_id,
            is_new,
        } = decode_frame(&mut duplicate, &mut sessions)
            .expect("decode repeated GlobalID XUDP New")
            .expect("repeated GlobalID XUDP New data")
        else {
            panic!("repeated GlobalID XUDP New decoded as End");
        };

        assert_eq!(session_id, 43);
        assert_eq!(payload, b"reattach");
        assert_eq!(target, second_target);
        assert_eq!(decoded_global_id, Some(global_id));
        assert!(is_new);
        assert_eq!(sessions.get(&43).unwrap().target, second_target);
        assert_eq!(sessions.get(&43).unwrap().global_id, Some(global_id));
    }

    #[test]
    fn peer_error_ends_only_its_session_and_consumes_payload() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut input = encode_error_frame(41, b"ignored error details");
        input.extend_from_slice(&encode_data_frame(
            SessionStatus::New,
            42,
            Some(target.clone()),
            b"next",
        ));
        let mut sessions = HashMap::from([(
            41,
            XudpSessionState {
                target,
                global_id: None,
            },
        )]);

        assert_eq!(
            decode_frame(&mut input, &mut sessions).expect("decode XUDP peer error"),
            Some(DecodedFrame::End {
                session_id: 41,
                reply: false,
            })
        );
        assert!(!sessions.contains_key(&41));

        let DecodedFrame::Data {
            session_id,
            payload,
            target,
            ..
        } = decode_frame(&mut input, &mut sessions)
            .expect("decode frame after XUDP peer error")
            .expect("frame after XUDP peer error should remain readable")
        else {
            panic!("frame after XUDP peer error decoded as End");
        };
        assert_eq!(session_id, 42);
        assert_eq!(payload, b"next");
        assert_eq!(target.port(), 53);
        assert!(input.is_empty());
    }

    #[test]
    fn unknown_keep_requests_end_without_creating_session() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut input = encode_data_frame(
            SessionStatus::Keep,
            51,
            Some(target.clone()),
            b"orphan",
        );
        input.extend_from_slice(&encode_data_frame(
            SessionStatus::New,
            52,
            Some(target),
            b"next",
        ));
        let mut sessions = HashMap::new();

        assert_eq!(
            decode_frame(&mut input, &mut sessions)
                .expect("decode unknown XUDP Keep"),
            Some(DecodedFrame::End {
                session_id: 51,
                reply: true,
            })
        );
        assert!(!sessions.contains_key(&51));

        let DecodedFrame::Data {
            session_id,
            payload,
            ..
        } = decode_frame(&mut input, &mut sessions)
            .expect("decode frame after unknown XUDP Keep")
            .expect("frame after unknown XUDP Keep should remain readable")
        else {
            panic!("frame after unknown XUDP Keep decoded as End");
        };
        assert_eq!(session_id, 52);
        assert_eq!(payload, b"next");
        assert!(input.is_empty());
    }

    #[test]
    fn keepalive_payload_is_discarded_before_next_data_frame() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut input = encode_data_frame(
            SessionStatus::KeepAlive,
            61,
            None,
            b"ignored heartbeat payload",
        );
        input.extend_from_slice(&encode_data_frame(
            SessionStatus::New,
            62,
            Some(target),
            b"next",
        ));
        let mut sessions = HashMap::new();

        let DecodedFrame::Data {
            session_id,
            payload,
            ..
        } = decode_frame(&mut input, &mut sessions)
            .expect("decode XUDP KeepAlive followed by data")
            .expect("data after XUDP KeepAlive should remain readable")
        else {
            panic!("data after XUDP KeepAlive decoded as End");
        };
        assert_eq!(session_id, 62);
        assert_eq!(payload, b"next");
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn unknown_keep_writes_end_reply_and_keeps_stream_open() {
        let (mut client, server) = duplex(2048);
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut frames = encode_data_frame(SessionStatus::Keep, 71, None, b"orphan");
        frames.extend_from_slice(&encode_data_frame(
            SessionStatus::New,
            72,
            Some(target),
            b"next",
        ));
        client
            .write_all(&frames)
            .await
            .expect("write unknown Keep and following New frame");

        let mut stream = XudpMessageStream::with_write_prefix(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
            vec![0, 0],
        );
        let mut buffer = [0u8; 32];
        let end = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut buffer);
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buffer)
        })
        .await
        .expect("read local End event for unknown Keep");
        assert_eq!(end, SessionMessage::End { session_id: 71 });

        let mut response_prefix = [0u8; 2];
        client
            .read_exact(&mut response_prefix)
            .await
            .expect("read VLESS response prefix before XUDP End reply");
        assert_eq!(response_prefix, [0, 0]);

        let mut length_bytes = [0u8; 2];
        client
            .read_exact(&mut length_bytes)
            .await
            .expect("read XUDP End reply metadata length");
        let metadata_length = u16::from_be_bytes(length_bytes) as usize;
        let mut raw = BytesMut::from(&length_bytes[..]);
        raw.resize(2 + metadata_length, 0);
        client
            .read_exact(&mut raw[2..])
            .await
            .expect("read XUDP End reply metadata");
        let metadata = FrameMetadata::decode(&mut raw)
            .expect("decode XUDP End reply")
            .expect("complete XUDP End reply");
        assert_eq!(metadata.session_id, 71);
        assert_eq!(metadata.status, SessionStatus::End);
        assert!(!metadata.option.has_data());
        assert!(!metadata.option.has_error());
        assert!(raw.is_empty());

        let next = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut buffer);
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buffer)
        })
        .await
        .expect("read data after unknown Keep");
        assert!(matches!(next, SessionMessage::Data { session_id: 72, .. }));
        assert_eq!(&buffer[..4], b"next");
    }

    #[test]
    fn iterative_decoder_skips_control_frames_before_data() {
        let mut input = BytesMut::new();
        for session_id in 0..64 {
            input.extend_from_slice(&encode_control_frame(
                SessionStatus::KeepAlive,
                session_id,
            ));
        }
        input.extend_from_slice(&encode_data_frame(
            SessionStatus::New,
            91,
            Some(NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53)),
            b"payload",
        ));
        let mut sessions = HashMap::new();

        let DecodedFrame::Data {
            session_id,
            payload,
            target,
            ..
        } = decode_frame(&mut input, &mut sessions)
            .expect("decode XUDP controls and data")
            .expect("XUDP data frame should exist")
        else {
            panic!("XUDP data frame decoded as a control event");
        };

        assert_eq!(session_id, 91);
        assert_eq!(payload, b"payload");
        assert_eq!(target.port(), 53);
        assert!(input.is_empty());
    }

    #[test]
    fn truncated_data_frame_prefixes_do_not_consume_or_mutate_state() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let frame = encode_data_frame(
            SessionStatus::New,
            90,
            Some(target),
            b"complete-payload",
        );

        for prefix_length in 0..frame.len() {
            let mut input = BytesMut::from(&frame[..prefix_length]);
            let original = input.clone();
            let mut sessions = HashMap::new();

            let decoded = decode_frame(&mut input, &mut sessions)
                .expect("truncated XUDP prefix must remain a partial frame");

            assert_eq!(decoded, None, "prefix length {prefix_length}");
            assert_eq!(input, original, "prefix length {prefix_length}");
            assert!(sessions.is_empty(), "prefix length {prefix_length}");
        }
    }

    #[tokio::test]
    async fn payload_larger_than_read_buffer_is_rejected_without_truncation() {
        let (mut client, server) = duplex(2048);
        let frame = encode_data_frame(
            SessionStatus::New,
            89,
            Some(NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53)),
            b"payload-too-large",
        );
        client
            .write_all(&frame)
            .await
            .expect("write oversized-for-caller XUDP frame");
        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let mut buffer = [0u8; 4];

        let error = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut buffer);
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buffer)
        })
        .await
        .expect_err("XUDP payload larger than the caller buffer must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds receive buffer"));
        assert_eq!(buffer, [0; 4]);
    }

    #[test]
    fn maximum_udp_payload_decodes_without_truncation() {
        let payload = vec![0x5a; u16::MAX as usize];
        let mut input = encode_data_frame(
            SessionStatus::New,
            88,
            Some(NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53)),
            &payload,
        );
        let mut sessions = HashMap::new();

        let DecodedFrame::Data {
            session_id,
            payload: decoded_payload,
            ..
        } = decode_frame(&mut input, &mut sessions)
            .expect("decode maximum-size XUDP payload")
            .expect("maximum-size XUDP payload must produce data")
        else {
            panic!("maximum-size XUDP payload decoded as End");
        };

        assert_eq!(session_id, 88);
        assert_eq!(decoded_payload.len(), u16::MAX as usize);
        assert_eq!(decoded_payload, payload);
        assert!(input.is_empty());
    }

    #[test]
    fn rejects_excessive_consecutive_control_frames() {
        let mut input = BytesMut::new();
        for session_id in 0..=MAX_CONSECUTIVE_CONTROL_FRAMES {
            input.extend_from_slice(&encode_control_frame(
                SessionStatus::KeepAlive,
                session_id as u16,
            ));
        }
        let mut sessions = HashMap::new();

        let error = decode_frame(&mut input, &mut sessions)
            .expect_err("excessive XUDP control frames must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("consecutive control frames"));
    }

    #[test]
    fn rejects_excessive_control_frames_split_across_decode_calls() {
        let mut sessions = HashMap::new();
        let mut consecutive_control_frames = 0usize;

        for session_id in 0..MAX_CONSECUTIVE_CONTROL_FRAMES {
            let mut input =
                encode_control_frame(SessionStatus::KeepAlive, session_id as u16);
            assert_eq!(
                decode_frame_with_control_count(
                    &mut input,
                    &mut sessions,
                    &mut consecutive_control_frames,
                )
                .expect("control frame below the limit must decode"),
                None
            );
            assert!(input.is_empty());
        }
        assert_eq!(consecutive_control_frames, MAX_CONSECUTIVE_CONTROL_FRAMES);

        let mut input = encode_control_frame(
            SessionStatus::KeepAlive,
            MAX_CONSECUTIVE_CONTROL_FRAMES as u16,
        );
        let error = decode_frame_with_control_count(
            &mut input,
            &mut sessions,
            &mut consecutive_control_frames,
        )
        .expect_err("split control frames above the limit must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("consecutive control frames"));
    }

    #[test]
    fn data_resets_split_control_frame_limit() {
        let mut sessions = HashMap::new();
        let mut consecutive_control_frames = 0usize;
        for session_id in 0..MAX_CONSECUTIVE_CONTROL_FRAMES {
            let mut input =
                encode_control_frame(SessionStatus::KeepAlive, session_id as u16);
            decode_frame_with_control_count(
                &mut input,
                &mut sessions,
                &mut consecutive_control_frames,
            )
            .expect("control frame below the limit must decode");
        }

        let mut data = encode_data_frame(
            SessionStatus::New,
            77,
            Some(NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53)),
            b"reset",
        );
        assert!(matches!(
            decode_frame_with_control_count(
                &mut data,
                &mut sessions,
                &mut consecutive_control_frames,
            )
            .expect("data after controls must decode"),
            Some(DecodedFrame::Data { session_id: 77, .. })
        ));
        assert_eq!(consecutive_control_frames, 0);

        let mut next_control = encode_control_frame(SessionStatus::KeepAlive, 78);
        assert_eq!(
            decode_frame_with_control_count(
                &mut next_control,
                &mut sessions,
                &mut consecutive_control_frames,
            )
            .expect("control frame after data must start a new sequence"),
            None
        );
        assert_eq!(consecutive_control_frames, 1);
    }

    #[tokio::test]
    async fn fragmented_frame_is_reassembled_across_single_byte_reads() {
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let frame =
            encode_data_frame(SessionStatus::New, 94, Some(target), b"fragmented");
        let (mut client, server) = duplex(2048);
        let writer = tokio::spawn(async move {
            for byte in frame {
                client
                    .write_all(&[byte])
                    .await
                    .expect("write fragmented XUDP byte");
                tokio::task::yield_now().await;
            }
        });
        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let mut payload = [0u8; 32];

        let (message, length) = timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                let mut read_buffer = ReadBuf::new(&mut payload);
                match Pin::new(&mut stream)
                    .poll_read_session_message(cx, &mut read_buffer)
                {
                    Poll::Ready(result) => Poll::Ready(
                        result.map(|message| (message, read_buffer.filled().len())),
                    ),
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await
        .expect("fragmented XUDP frame timeout")
        .expect("read fragmented XUDP frame");

        assert!(matches!(
            message,
            SessionMessage::Data {
                session_id: 94,
                is_new: true,
                ..
            }
        ));
        assert_eq!(&payload[..length], b"fragmented");
        writer.await.expect("fragmented XUDP writer task");
    }

    #[tokio::test]
    async fn coalesced_frames_preserve_order_across_channel_backpressure() {
        const FRAME_COUNT: u16 = CHANNEL_CAPACITY as u16 + 5;
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut frames =
            encode_data_frame(SessionStatus::New, 95, Some(target), &[0]);
        for sequence in 1..FRAME_COUNT {
            frames.extend_from_slice(&encode_data_frame(
                SessionStatus::Keep,
                95,
                None,
                &[sequence as u8],
            ));
        }

        let (mut client, server) = duplex(4096);
        client
            .write_all(&frames)
            .await
            .expect("write coalesced XUDP frames");
        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );

        for expected in 0..FRAME_COUNT {
            let mut payload = [0u8; 1];
            let message = timeout(
                Duration::from_secs(1),
                poll_fn(|cx| {
                    let mut read_buffer = ReadBuf::new(&mut payload);
                    Pin::new(&mut stream)
                        .poll_read_session_message(cx, &mut read_buffer)
                }),
            )
            .await
            .expect("coalesced XUDP frame timeout")
            .expect("read coalesced XUDP frame");
            assert!(matches!(
                message,
                SessionMessage::Data {
                    session_id: 95,
                    is_new,
                    ..
                } if is_new == (expected == 0)
            ));
            assert_eq!(payload[0], expected as u8);
        }
    }

    #[tokio::test]
    async fn partial_frame_eof_is_reported_without_hanging() {
        let frame = encode_data_frame(
            SessionStatus::New,
            96,
            Some(NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53)),
            b"incomplete",
        );
        let (mut client, server) = duplex(2048);
        client
            .write_all(&frame[..frame.len() - 1])
            .await
            .expect("write partial XUDP frame");
        client
            .shutdown()
            .await
            .expect("shutdown partial XUDP writer");
        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let mut payload = [0u8; 32];

        let error = timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                let mut read_buffer = ReadBuf::new(&mut payload);
                Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buffer)
            }),
        )
        .await
        .expect("partial XUDP EOF must not hang")
        .expect_err("partial XUDP frame at EOF must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn reads_new_and_keep_frames_for_same_session() {
        let (mut client, server) = duplex(2048);
        let target = NetLocation::new(Address::from("example.test").unwrap(), 53);
        let global_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut frames = encode_data_frame_with_global_id(
            SessionStatus::New,
            17,
            Some(target),
            b"first",
            Some(global_id),
        );
        frames.extend_from_slice(&encode_data_frame(
            SessionStatus::Keep,
            17,
            None,
            b"second",
        ));
        client.write_all(&frames).await.expect("write XUDP frames");

        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let mut buffer = [0u8; 32];
        for (expected, expected_is_new) in
            [(b"first".as_slice(), true), (b"second".as_slice(), false)]
        {
            let (length, session_id, target, actual_global_id, is_new) =
                poll_fn(|cx| {
                    let mut read_buffer = ReadBuf::new(&mut buffer);
                    match Pin::new(&mut stream)
                        .poll_read_session_message(cx, &mut read_buffer)
                    {
                        Poll::Ready(Ok(SessionMessage::Data {
                            session_id,
                            target,
                            global_id,
                            is_new,
                        })) => Poll::Ready(Ok((
                            read_buffer.filled().len(),
                            session_id,
                            target,
                            global_id,
                            is_new,
                        ))),
                        Poll::Ready(Ok(SessionMessage::End { .. })) => {
                            Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "unexpected XUDP End while reading data",
                            )))
                        }
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await
                .expect("read XUDP message");
            assert_eq!(&buffer[..length], expected);
            assert_eq!(session_id, 17);
            assert_eq!(target, SocketAddr::from((Ipv4Addr::LOCALHOST, 53)));
            assert_eq!(actual_global_id, Some(global_id));
            assert_eq!(is_new, expected_is_new);
        }
    }

    #[tokio::test]
    async fn repeated_global_new_preserves_queued_payload_and_udp_socket() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind repeated GlobalID echo socket");
        let echo_address = echo_socket
            .local_addr()
            .expect("repeated GlobalID echo address");
        let (peer_sender, mut peer_receiver) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            for expected in [b"first".as_slice(), b"second".as_slice()] {
                let (length, peer) = timeout(
                    Duration::from_secs(5),
                    echo_socket.recv_from(&mut buffer),
                )
                .await
                .expect("repeated GlobalID UDP request timeout")
                .expect("receive repeated GlobalID UDP request");
                assert_eq!(&buffer[..length], expected);
                peer_sender
                    .send(peer)
                    .await
                    .expect("record repeated GlobalID UDP peer");
                echo_socket
                    .send_to(&buffer[..length], peer)
                    .await
                    .expect("echo repeated GlobalID UDP response");
            }
        });

        let target =
            NetLocation::from_ip_addr(echo_address.ip(), echo_address.port());
        let global_id = [21, 22, 23, 24, 25, 26, 27, 28];
        let mut frames = encode_data_frame_with_global_id(
            SessionStatus::New,
            24,
            Some(target.clone()),
            b"first",
            Some(global_id),
        );
        frames.extend_from_slice(&encode_data_frame_with_global_id(
            SessionStatus::New,
            24,
            Some(target),
            b"second",
            Some(global_id),
        ));

        let (mut client, server) = duplex(4096);
        client
            .write_all(&frames)
            .await
            .expect("write repeated GlobalID New frames");
        let stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let relay_task = tokio::spawn(run_session_based_udp(
            Box::new(stream),
            RuntimeState::new(Vec::new(), Vec::new()),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43024)),
            None,
        ));

        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let (metadata, payload) = read_response_frame(&mut client).await;
            assert_eq!(metadata.session_id, 24);
            assert_eq!(metadata.status, SessionStatus::Keep);
            assert_eq!(metadata.network, Some(TargetNetwork::Udp));
            assert_eq!(payload, expected);
        }

        let first_peer = peer_receiver
            .recv()
            .await
            .expect("first repeated GlobalID UDP peer");
        let second_peer = peer_receiver
            .recv()
            .await
            .expect("second repeated GlobalID UDP peer");
        assert_eq!(first_peer, second_peer);

        echo_task.await.expect("repeated GlobalID echo task");
        relay_task.abort();
    }

    #[tokio::test]
    async fn global_id_takeover_across_session_ids_rebinds_responses() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind cross-session GlobalID echo socket");
        let echo_address = echo_socket
            .local_addr()
            .expect("cross-session GlobalID echo address");
        let (peer_sender, mut peer_receiver) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            for expected in [b"first".as_slice(), b"second".as_slice()] {
                let (length, peer) = timeout(
                    Duration::from_secs(5),
                    echo_socket.recv_from(&mut buffer),
                )
                .await
                .expect("cross-session GlobalID UDP request timeout")
                .expect("receive cross-session GlobalID UDP request");
                assert_eq!(&buffer[..length], expected);
                peer_sender
                    .send(peer)
                    .await
                    .expect("record cross-session GlobalID UDP peer");
                echo_socket
                    .send_to(&buffer[..length], peer)
                    .await
                    .expect("echo cross-session GlobalID UDP response");
            }
        });

        let target =
            NetLocation::from_ip_addr(echo_address.ip(), echo_address.port());
        let global_id = [31, 32, 33, 34, 35, 36, 37, 38];
        let mut frames = encode_data_frame_with_global_id(
            SessionStatus::New,
            24,
            Some(target.clone()),
            b"first",
            Some(global_id),
        );
        frames.extend_from_slice(&encode_data_frame_with_global_id(
            SessionStatus::New,
            25,
            Some(target),
            b"second",
            Some(global_id),
        ));

        let (mut client, server) = duplex(4096);
        client
            .write_all(&frames)
            .await
            .expect("write cross-session GlobalID New frames");
        let stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let relay_task = tokio::spawn(run_session_based_udp(
            Box::new(stream),
            RuntimeState::new(Vec::new(), Vec::new()),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43025)),
            None,
        ));

        let mut end_count = 0;
        let mut payloads = Vec::new();
        for _ in 0..3 {
            let (metadata, payload) = read_response_frame(&mut client).await;
            match metadata.status {
                SessionStatus::End => {
                    assert_eq!(metadata.session_id, 24);
                    assert!(!metadata.option.has_data());
                    assert!(payload.is_empty());
                    end_count += 1;
                }
                SessionStatus::Keep => {
                    assert_eq!(metadata.session_id, 25);
                    assert!(metadata.option.has_data());
                    assert_eq!(metadata.network, Some(TargetNetwork::Udp));
                    payloads.push(payload);
                }
                status => {
                    panic!("unexpected cross-session response status: {status:?}")
                }
            }
        }
        assert_eq!(end_count, 1);
        assert_eq!(payloads, [b"first".to_vec(), b"second".to_vec()]);

        let first_peer = peer_receiver
            .recv()
            .await
            .expect("first cross-session GlobalID UDP peer");
        let second_peer = peer_receiver
            .recv()
            .await
            .expect("second cross-session GlobalID UDP peer");
        assert_eq!(first_peer, second_peer);

        echo_task.await.expect("cross-session GlobalID echo task");
        relay_task.abort();
    }

    #[tokio::test]
    async fn end_frame_is_forwarded_and_clears_codec_session() {
        let (mut client, server) = duplex(2048);
        let target = NetLocation::from_ip_addr(Ipv4Addr::LOCALHOST.into(), 53);
        let mut frames =
            encode_data_frame(SessionStatus::New, 31, Some(target), b"first");
        frames.extend_from_slice(&encode_control_frame(SessionStatus::End, 31));
        client
            .write_all(&frames)
            .await
            .expect("write XUDP session frames");

        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let mut buffer = [0u8; 32];
        let first = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut buffer);
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buffer)
        })
        .await
        .expect("read XUDP data event");
        assert!(matches!(first, SessionMessage::Data { session_id: 31, .. }));

        let end = poll_fn(|cx| {
            let mut read_buffer = ReadBuf::new(&mut buffer);
            Pin::new(&mut stream).poll_read_session_message(cx, &mut read_buffer)
        })
        .await
        .expect("read XUDP End event");
        assert_eq!(end, SessionMessage::End { session_id: 31 });
    }

    #[tokio::test]
    async fn session_runtime_roundtrips_udp_payload() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind XUDP echo socket");
        let echo_address = echo_socket.local_addr().expect("XUDP echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = echo_socket
                .recv_from(&mut buffer)
                .await
                .expect("receive XUDP echo request");
            echo_socket
                .send_to(&buffer[..length], peer)
                .await
                .expect("send XUDP echo response");
        });

        let (mut client, server) = duplex(2048);
        let frame = encode_data_frame(
            SessionStatus::New,
            23,
            Some(NetLocation::from_ip_addr(
                echo_address.ip(),
                echo_address.port(),
            )),
            b"ping",
        );
        client.write_all(&frame).await.expect("write XUDP request");
        let stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let relay_task = tokio::spawn(run_session_based_udp(
            Box::new(stream),
            RuntimeState::new(Vec::new(), Vec::new()),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 43023)),
            None,
        ));

        let mut length_bytes = [0u8; 2];
        timeout(Duration::from_secs(5), client.read_exact(&mut length_bytes))
            .await
            .expect("XUDP response metadata timeout")
            .expect("read XUDP response metadata length");
        let metadata_length = u16::from_be_bytes(length_bytes) as usize;
        let mut response = BytesMut::from(&length_bytes[..]);
        response.resize(2 + metadata_length + 2 + 4, 0);
        client
            .read_exact(&mut response[2..])
            .await
            .expect("read XUDP response frame");

        let metadata = FrameMetadata::decode(&mut response)
            .expect("decode XUDP runtime response")
            .expect("complete XUDP runtime response");
        assert_eq!(metadata.session_id, 23);
        assert_eq!(metadata.status, SessionStatus::Keep);
        assert_eq!(metadata.network, Some(TargetNetwork::Udp));
        assert_eq!(
            metadata.target,
            Some(NetLocation::from_ip_addr(
                echo_address.ip(),
                echo_address.port(),
            ))
        );
        assert_eq!(response.get_u16(), 4);
        assert_eq!(&response[..], b"ping");

        echo_task.await.expect("XUDP echo task should finish");
        relay_task.abort();
    }

    #[tokio::test]
    async fn partial_writes_preserve_prefix_data_and_end_frames() {
        let source = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
        let mut expected = BytesMut::from(&[0, 0][..]);
        FrameMetadata {
            session_id: 9,
            status: SessionStatus::Keep,
            option: FrameOption::default().with_data(),
            target: Some(NetLocation::from_ip_addr(source.ip(), source.port())),
            network: Some(TargetNetwork::Udp),
            global_id: None,
        }
        .encode(&mut expected)
        .expect("encode expected XUDP data metadata");
        expected.put_u16(4);
        expected.extend_from_slice(b"pong");
        for (session_id, has_error) in [(9, false), (10, true)] {
            FrameMetadata {
                session_id,
                status: SessionStatus::End,
                option: if has_error {
                    FrameOption::default().with_error()
                } else {
                    FrameOption::default()
                },
                target: None,
                network: None,
                global_id: None,
            }
            .encode(&mut expected)
            .expect("encode expected XUDP End metadata");
        }

        let (mut client, server) = duplex(1);
        let writer_task = tokio::spawn(async move {
            let mut stream = XudpMessageStream::with_write_prefix(
                Box::new(TestStream(server)),
                Arc::new(StaticResolver),
                vec![0, 0],
            );
            poll_fn(|cx| {
                Pin::new(&mut stream)
                    .poll_write_session_message(cx, 9, b"pong", &source)
            })
            .await
            .expect("write XUDP data through one-byte transport");
            for (session_id, has_error) in [(9, false), (10, true)] {
                poll_fn(|cx| {
                    Pin::new(&mut stream)
                        .poll_write_session_end(cx, session_id, has_error)
                })
                .await
                .expect("write XUDP End through one-byte transport");
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .expect("shutdown XUDP one-byte transport");
        });

        let mut actual = Vec::new();
        client
            .read_to_end(&mut actual)
            .await
            .expect("read XUDP one-byte transport frames");
        writer_task.await.expect("XUDP partial writer task");

        assert_eq!(actual, expected.to_vec());
    }

    #[tokio::test]
    async fn oversized_write_does_not_consume_or_emit_prefix() {
        let (mut client, server) = duplex(128);
        let mut stream = XudpMessageStream::with_write_prefix(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
            vec![0, 0],
        );
        let payload = vec![0u8; u16::MAX as usize + 1];
        let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));

        let error = poll_fn(|cx| {
            Pin::new(&mut stream)
                .poll_write_session_message(cx, 11, &payload, &source)
        })
        .await
        .expect_err("oversized XUDP payload must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            timeout(Duration::from_millis(20), client.read_u8())
                .await
                .is_err(),
            "oversized XUDP payload must not emit its write prefix"
        );

        poll_fn(|cx| Pin::new(&mut stream).poll_write_session_end(cx, 11, false))
            .await
            .expect("write XUDP End after oversized payload");
        let mut prefix = [0u8; 2];
        client
            .read_exact(&mut prefix)
            .await
            .expect("read preserved XUDP write prefix");
        assert_eq!(prefix, [0, 0]);
        let mut metadata_length = [0u8; 2];
        client
            .read_exact(&mut metadata_length)
            .await
            .expect("read XUDP End metadata length");
        let mut raw = BytesMut::from(&metadata_length[..]);
        raw.resize(2 + u16::from_be_bytes(metadata_length) as usize, 0);
        client
            .read_exact(&mut raw[2..])
            .await
            .expect("read XUDP End metadata");
        let metadata = FrameMetadata::decode(&mut raw)
            .expect("decode XUDP End after oversized payload")
            .expect("complete XUDP End after oversized payload");
        assert_eq!(metadata.session_id, 11);
        assert_eq!(metadata.status, SessionStatus::End);
    }

    #[tokio::test]
    async fn writes_session_end_with_optional_error_flag() {
        for (session_id, has_error) in [(81, false), (82, true)] {
            let (mut client, server) = duplex(2048);
            let mut stream = XudpMessageStream::new(
                Box::new(TestStream(server)),
                Arc::new(StaticResolver),
            );

            poll_fn(|cx| {
                Pin::new(&mut stream)
                    .poll_write_session_end(cx, session_id, has_error)
            })
            .await
            .expect("write XUDP session End");

            let mut length_bytes = [0u8; 2];
            client
                .read_exact(&mut length_bytes)
                .await
                .expect("read XUDP End metadata length");
            let metadata_length = u16::from_be_bytes(length_bytes) as usize;
            let mut raw = BytesMut::from(&length_bytes[..]);
            raw.resize(2 + metadata_length, 0);
            client
                .read_exact(&mut raw[2..])
                .await
                .expect("read XUDP End metadata");
            let metadata = FrameMetadata::decode(&mut raw)
                .expect("decode XUDP End metadata")
                .expect("complete XUDP End metadata");
            assert_eq!(metadata.session_id, session_id);
            assert_eq!(metadata.status, SessionStatus::End);
            assert_eq!(metadata.option.has_error(), has_error);
            assert!(!metadata.option.has_data());
            assert!(raw.is_empty());
        }
    }

    #[tokio::test]
    async fn writes_keep_udp_response_frame() {
        let (mut client, server) = duplex(2048);
        let mut stream = XudpMessageStream::new(
            Box::new(TestStream(server)),
            Arc::new(StaticResolver),
        );
        let source = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));

        poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_session_message(cx, 9, b"pong", &source)
        })
        .await
        .expect("write XUDP response");

        let mut raw = BytesMut::new();
        let mut temporary = [0u8; 64];
        let length = client
            .read(&mut temporary)
            .await
            .expect("read XUDP response");
        raw.extend_from_slice(&temporary[..length]);
        let metadata = FrameMetadata::decode(&mut raw)
            .expect("decode XUDP response metadata")
            .expect("complete XUDP response metadata");
        assert_eq!(metadata.session_id, 9);
        assert_eq!(metadata.status, SessionStatus::Keep);
        assert_eq!(metadata.network, Some(TargetNetwork::Udp));
        assert_eq!(metadata.target.unwrap().port(), 53);
        assert_eq!(raw.get_u16(), 4);
        assert_eq!(&raw[..], b"pong");
    }

    struct TestStream(tokio::io::DuplexStream);

    impl tokio::io::AsyncRead for TestStream {
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
}
