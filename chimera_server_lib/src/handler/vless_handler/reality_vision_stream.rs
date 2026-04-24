use std::{
    io::{self, BufRead, Write},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    reality::{RealityIoState, RealitySession, SyncReadAdapter, SyncWriteAdapter},
};

use super::{
    append_plaintext_to_read_buf, bounded_write_chunk,
    contains_tls_application_data, drain_pending_read, queue_padded_packet,
    take_vless_response_header, unpad_into_pending_read,
    vision_unpad::{UnpadCommand, VisionUnpadder},
};

const COMMAND_CONTINUE: u8 = 0x00;
const COMMAND_DIRECT: u8 = 0x02;
const MAX_WRITE_CONTENT_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadMode {
    Padding,
    Plain,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    Padding,
    Direct,
}

pub struct RealityVisionServerStream<IO, S> {
    tcp: IO,
    session: S,
    user_uuid: [u8; 16],
    unpadder: VisionUnpadder,
    read_mode: ReadMode,
    write_mode: WriteMode,
    first_write: bool,
    vless_response_to_send: bool,
    pending_read: BytesMut,
    pending_write: BytesMut,
    is_read_eof: bool,
}

impl<IO, S> std::fmt::Debug for RealityVisionServerStream<IO, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityVisionServerStream")
            .field("read_mode", &self.read_mode)
            .field("write_mode", &self.write_mode)
            .field("first_write", &self.first_write)
            .field("pending_read_len", &self.pending_read.len())
            .field("pending_write_len", &self.pending_write.len())
            .finish()
    }
}

impl<IO, S> RealityVisionServerStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
    pub fn new(
        tcp: IO,
        session: S,
        user_uuid: [u8; 16],
        initial_plaintext: &[u8],
    ) -> io::Result<Self> {
        let mut stream = Self {
            tcp,
            session,
            user_uuid,
            unpadder: VisionUnpadder::new(user_uuid),
            read_mode: ReadMode::Padding,
            write_mode: WriteMode::Padding,
            first_write: true,
            vless_response_to_send: true,
            pending_read: BytesMut::new(),
            pending_write: BytesMut::new(),
            is_read_eof: false,
        };

        if !initial_plaintext.is_empty() {
            stream.handle_padded_read(initial_plaintext)?;
        }

        Ok(stream)
    }

    pub fn drain_plaintext_from_session(session: &mut S) -> io::Result<Vec<u8>> {
        Self::drain_plaintext_from_session_with_capacity(session, 0)
    }

    fn process_new_packets(
        &mut self,
        io_state: RealityIoState,
    ) -> io::Result<Vec<u8>> {
        Self::drain_plaintext_from_session_with_capacity(
            &mut self.session,
            io_state.plaintext_bytes_to_read(),
        )
    }

    fn drain_plaintext_from_session_with_capacity(
        session: &mut S,
        capacity: usize,
    ) -> io::Result<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(capacity);
        let mut reader = session.reader();
        loop {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                break;
            }
            let len = chunk.len();
            plaintext.extend_from_slice(chunk);
            reader.consume(len);
        }
        Ok(plaintext)
    }

    fn flush_tls_ciphertext(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            let mut writer = SyncWriteAdapter {
                io: &mut self.tcp,
                cx,
            };
            match self.session.write_tls(&mut writer) {
                Ok(0) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(_) => {}
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        Poll::Ready(Ok(()))
    }

    fn flush_pending_write_padding(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending_write.is_empty() {
            self.session.writer().write_all(&self.pending_write)?;
            self.pending_write.clear();
        }
        self.flush_tls_ciphertext(cx)
    }

    fn poll_complete_padded_write(
        &mut self,
        cx: &mut Context<'_>,
        written_len: usize,
        enter_direct: bool,
    ) -> Poll<io::Result<usize>> {
        match self.flush_pending_write_padding(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => {
                if enter_direct {
                    self.write_mode = WriteMode::Direct;
                }
                Poll::Ready(Ok(written_len))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush_padding_mode(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.flush_pending_write_padding(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.tcp).poll_flush(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn handle_padded_read(&mut self, padded: &[u8]) -> io::Result<()> {
        match unpad_into_pending_read(
            &mut self.unpadder,
            &mut self.pending_read,
            padded,
        )? {
            Some(UnpadCommand::Continue) | None => Ok(()),
            Some(UnpadCommand::End) => {
                self.read_mode = ReadMode::Plain;
                Ok(())
            }
            Some(UnpadCommand::Direct) => {
                let leftover =
                    Self::drain_plaintext_from_session(&mut self.session)?;
                if !leftover.is_empty() {
                    self.pending_read.extend_from_slice(&leftover);
                }
                let raw_leftover = self.session.take_remaining_ciphertext();
                if !raw_leftover.is_empty() {
                    self.pending_read.extend_from_slice(&raw_leftover);
                }
                self.read_mode = ReadMode::Direct;
                Ok(())
            }
        }
    }

    fn queue_vless_response_if_needed(&mut self) -> io::Result<()> {
        if let Some(response_header) =
            take_vless_response_header(&mut self.vless_response_to_send)
        {
            self.session.writer().write_all(response_header)?;
        }
        Ok(())
    }

    fn queue_padded_write(&mut self, content: &[u8], command: u8) {
        queue_padded_packet(
            &mut self.pending_write,
            &mut self.first_write,
            &self.user_uuid,
            content,
            command,
        );
    }

    fn read_from_session_or_tcp(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Vec<u8>>> {
        let existing = Self::drain_plaintext_from_session(&mut self.session)?;
        if !existing.is_empty() {
            return Poll::Ready(Ok(existing));
        }

        if self.is_read_eof {
            return Poll::Ready(Ok(Vec::new()));
        }

        let mut adapter = SyncReadAdapter {
            io: &mut self.tcp,
            cx,
        };
        match self.session.read_tls(&mut adapter) {
            Ok(0) => {
                self.is_read_eof = true;
                Poll::Ready(Ok(Vec::new()))
            }
            Ok(_) => {
                let io_state = self.session.process_new_packets()?;
                let plaintext = self.process_new_packets(io_state)?;
                Poll::Ready(Ok(plaintext))
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<IO, S> AsyncRead for RealityVisionServerStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if drain_pending_read(&mut this.pending_read, buf) {
            return Poll::Ready(Ok(()));
        }

        match this.read_mode {
            ReadMode::Direct => return Pin::new(&mut this.tcp).poll_read(cx, buf),
            ReadMode::Plain => {
                let plaintext = match this.read_from_session_or_tcp(cx) {
                    Poll::Ready(Ok(v)) => v,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                };
                if plaintext.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                append_plaintext_to_read_buf(
                    &mut this.pending_read,
                    buf,
                    &plaintext,
                );
                return Poll::Ready(Ok(()));
            }
            ReadMode::Padding => {}
        }

        let plaintext = match this.read_from_session_or_tcp(cx) {
            Poll::Ready(Ok(v)) => v,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        if plaintext.is_empty() {
            return Poll::Ready(Ok(()));
        }

        this.handle_padded_read(&plaintext)?;
        let _ = drain_pending_read(&mut this.pending_read, buf);

        Poll::Ready(Ok(()))
    }
}

impl<IO, S> AsyncWrite for RealityVisionServerStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.write_mode {
            WriteMode::Direct => return Pin::new(&mut this.tcp).poll_write(cx, buf),
            WriteMode::Padding => {}
        }

        if let Err(err) = this.queue_vless_response_if_needed() {
            return Poll::Ready(Err(err));
        }
        match this.flush_pending_write_padding(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let chunk = bounded_write_chunk(buf, MAX_WRITE_CONTENT_LEN);
        if chunk.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if contains_tls_application_data(chunk) {
            this.queue_padded_write(chunk, COMMAND_DIRECT);
            this.poll_complete_padded_write(cx, chunk.len(), true)
        } else {
            this.queue_padded_write(chunk, COMMAND_CONTINUE);
            this.poll_complete_padded_write(cx, chunk.len(), false)
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.write_mode {
            WriteMode::Direct => Pin::new(&mut this.tcp).poll_flush(cx),
            WriteMode::Padding => this.poll_flush_padding_mode(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}

impl<IO, S> AsyncPing for RealityVisionServerStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
    fn supports_ping(&self) -> bool {
        self.tcp.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().tcp).poll_write_ping(cx)
    }
}

impl<IO, S> AsyncStream for RealityVisionServerStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
}
