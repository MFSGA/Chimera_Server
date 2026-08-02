use std::{
    io::{self, Read, Write},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::{Reader, ServerConnection, Writer};

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    handler::tls_deframer::{TLS_MAX_RECORD_SIZE, TlsDeframer},
    reality::{RealityIoState, RealitySession},
};

const READ_SCRATCH_SIZE: usize = TLS_MAX_RECORD_SIZE * 2;

#[derive(Debug)]
struct VisionRecordState {
    deframer: TlsDeframer,
    current_record: Bytes,
    yield_after_record: bool,
    vision_mode: bool,
    direct_mode: bool,
}

impl Default for VisionRecordState {
    fn default() -> Self {
        Self {
            deframer: TlsDeframer::new(),
            current_record: Bytes::new(),
            yield_after_record: false,
            vision_mode: false,
            direct_mode: false,
        }
    }
}

impl VisionRecordState {
    fn enter_direct(&mut self) -> Vec<u8> {
        self.direct_mode = true;
        self.yield_after_record = false;

        let mut remaining = Vec::with_capacity(
            self.current_record.len() + self.deframer.pending_bytes(),
        );
        remaining.extend_from_slice(&self.current_record);
        self.current_record = Bytes::new();
        remaining.extend_from_slice(
            &std::mem::take(&mut self.deframer).into_remaining_data(),
        );
        remaining
    }
}

/// Limits rustls to one complete outer TLS record per async read turn.
///
/// Vision may switch from outer TLS to raw TCP after a `Direct` command. A
/// normal buffered TLS reader can consume bytes following that command before
/// the Vision layer sees it. This wrapper keeps later records (or raw bytes)
/// outside rustls until the previously delivered record has been processed.
pub(crate) struct VisionRecordIo<IO> {
    inner: IO,
    state: Arc<Mutex<VisionRecordState>>,
    scratch: Box<[u8]>,
}

impl<IO> VisionRecordIo<IO> {
    pub(crate) fn new(inner: IO) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(VisionRecordState::default())),
            scratch: vec![0u8; READ_SCRATCH_SIZE].into_boxed_slice(),
        }
    }

    pub(crate) fn session(
        &self,
        connection: ServerConnection,
    ) -> RustlsVisionSession {
        RustlsVisionSession {
            connection,
            record_state: self.state.clone(),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, VisionRecordState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<IO> std::fmt::Debug for VisionRecordIo<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock_state();
        f.debug_struct("VisionRecordIo")
            .field("buffered", &state.deframer.pending_bytes())
            .field("current_record", &state.current_record.len())
            .field("vision_mode", &state.vision_mode)
            .field("direct_mode", &state.direct_mode)
            .finish_non_exhaustive()
    }
}

impl<IO> AsyncRead for VisionRecordIo<IO>
where
    IO: AsyncStream,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            {
                let mut state = this.lock_state();
                if state.direct_mode {
                    drop(state);
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }

                if state.yield_after_record {
                    state.yield_after_record = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                if !state.current_record.is_empty() {
                    let len = buf.remaining().min(state.current_record.len());
                    buf.put_slice(&state.current_record[..len]);
                    state.current_record.advance(len);
                    if state.current_record.is_empty() {
                        state.yield_after_record = true;
                    }
                    return Poll::Ready(Ok(()));
                }

                match state.deframer.next_record() {
                    Ok(Some(record)) => {
                        state.current_record = record;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) if state.vision_mode => {
                        // The bytes after a Vision Direct record are raw inner
                        // TLS bytes, not another outer TLS record. Keep them for
                        // `take_remaining_ciphertext` instead of feeding rustls.
                        let _ = error;
                        return Poll::Pending;
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }

            let filled_len = {
                let mut read_buf = ReadBuf::new(&mut this.scratch);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => read_buf.filled().len(),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            };

            if filled_len == 0 {
                let state = this.lock_state();
                if state.deframer.pending_bytes() == 0 {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "outer TLS stream ended inside a record",
                )));
            }

            this.lock_state()
                .deframer
                .feed(&this.scratch[..filled_len]);
        }
    }
}

impl<IO> AsyncWrite for VisionRecordIo<IO>
where
    IO: AsyncStream,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<IO> AsyncPing for VisionRecordIo<IO>
where
    IO: AsyncStream,
{
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().inner).poll_write_ping(cx)
    }
}

impl<IO> AsyncStream for VisionRecordIo<IO> where IO: AsyncStream {}

pub(crate) struct RustlsVisionSession {
    connection: ServerConnection,
    record_state: Arc<Mutex<VisionRecordState>>,
}

impl std::fmt::Debug for RustlsVisionSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsVisionSession").finish_non_exhaustive()
    }
}

impl RealitySession for RustlsVisionSession {
    type Reader<'a> = Reader<'a>;
    type Writer<'a> = Writer<'a>;

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        self.connection.read_tls(rd)
    }

    fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        let state = self
            .connection
            .process_new_packets()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(RealityIoState::new(state.plaintext_bytes_to_read()))
    }

    fn reader(&mut self) -> Self::Reader<'_> {
        self.connection.reader()
    }

    fn writer(&mut self) -> Self::Writer<'_> {
        self.connection.writer()
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        self.connection.write_tls(wr)
    }

    fn wants_write(&self) -> bool {
        self.connection.wants_write()
    }

    fn wants_read(&self) -> bool {
        self.connection.wants_read()
    }

    fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    fn take_remaining_ciphertext(&mut self) -> Vec<u8> {
        self.record_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .enter_direct()
    }

    fn enable_vision_direct_transition(&mut self) {
        self.record_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .vision_mode = true;
    }

    fn send_close_notify(&mut self) {
        self.connection.send_close_notify();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    };

    use crate::async_stream::{AsyncPing, AsyncStream};

    use super::VisionRecordIo;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut output = vec![0x17, 0x03, 0x03];
        output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        output.extend_from_slice(payload);
        output
    }

    #[tokio::test]
    async fn direct_transition_preserves_coalesced_raw_bytes() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut io = VisionRecordIo::new(TestStream(server));
        let outer_record = record(b"vision-direct");
        let raw = b"raw-inner-tls";
        let mut wire = outer_record.clone();
        wire.extend_from_slice(raw);
        client.write_all(&wire).await.unwrap();

        let mut received = vec![0u8; outer_record.len()];
        io.read_exact(&mut received).await.unwrap();
        assert_eq!(received, outer_record);

        let mut session_state = io.lock_state();
        session_state.vision_mode = true;
        let remaining = session_state.enter_direct();
        drop(session_state);

        assert_eq!(remaining, raw);
    }
}
