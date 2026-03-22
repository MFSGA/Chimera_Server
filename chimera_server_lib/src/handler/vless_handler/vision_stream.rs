use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::{
    bounded_write_chunk, drain_pending_read, queue_padded_packet,
    take_vless_response_header, unpad_into_pending_read,
    vision_unpad::{UnpadCommand, VisionUnpadder},
};

const COMMAND_CONTINUE: u8 = 0x00;
const READ_BUFFER_SIZE: usize = 16 * 1024;
const MAX_WRITE_CONTENT_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisionReadMode {
    Padding,
    Plain,
}

pub struct VisionServerStream {
    stream: Box<dyn AsyncStream>,
    user_uuid: [u8; 16],
    unpadder: VisionUnpadder,
    read_mode: VisionReadMode,
    first_write: bool,
    vless_response_to_send: bool,
    pending_read: BytesMut,
    pending_write: BytesMut,
    read_buffer: Box<[u8]>,
    is_read_eof: bool,
}

impl std::fmt::Debug for VisionServerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisionServerStream")
            .field("read_mode", &self.read_mode)
            .field("first_write", &self.first_write)
            .field("pending_read_len", &self.pending_read.len())
            .field("pending_write_len", &self.pending_write.len())
            .finish()
    }
}

impl VisionServerStream {
    pub fn new(stream: Box<dyn AsyncStream>, user_uuid: [u8; 16]) -> Self {
        Self {
            stream,
            user_uuid,
            unpadder: VisionUnpadder::new(user_uuid),
            read_mode: VisionReadMode::Padding,
            first_write: true,
            vless_response_to_send: true,
            pending_read: BytesMut::new(),
            pending_write: BytesMut::new(),
            read_buffer: vec![0u8; READ_BUFFER_SIZE].into_boxed_slice(),
            is_read_eof: false,
        }
    }

    fn flush_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_write.is_empty() {
            match Pin::new(&mut self.stream).poll_write(cx, &self.pending_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    self.pending_write.advance(written);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn poll_complete_buffered_write(
        &mut self,
        cx: &mut Context<'_>,
        written_len: usize,
    ) -> Poll<io::Result<usize>> {
        match self.flush_pending_write(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(written_len)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush_or_shutdown(
        &mut self,
        cx: &mut Context<'_>,
        shutdown: bool,
    ) -> Poll<io::Result<()>> {
        match self.flush_pending_write(cx) {
            Poll::Ready(Ok(())) => {
                if shutdown {
                    Pin::new(&mut self.stream).poll_shutdown(cx)
                } else {
                    Pin::new(&mut self.stream).poll_flush(cx)
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn handle_padded_read_parts(
        unpadder: &mut VisionUnpadder,
        pending_read: &mut BytesMut,
        read_mode: &mut VisionReadMode,
        decrypted: &[u8],
    ) -> io::Result<()> {
        match unpad_into_pending_read(unpadder, pending_read, decrypted)? {
            Some(UnpadCommand::Continue) | None => Ok(()),
            Some(UnpadCommand::End) => {
                *read_mode = VisionReadMode::Plain;
                Ok(())
            }
            Some(UnpadCommand::Direct) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "xtls-rprx-vision direct mode is not implemented yet",
            )),
        }
    }

    fn queue_padded_write(&mut self, content: &[u8]) {
        queue_padded_packet(
            &mut self.pending_write,
            &mut self.first_write,
            &self.user_uuid,
            content,
            COMMAND_CONTINUE,
        );
    }
}

impl AsyncRead for VisionServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if drain_pending_read(&mut this.pending_read, buf) {
            return Poll::Ready(Ok(()));
        }

        if this.read_mode == VisionReadMode::Plain {
            return Pin::new(&mut this.stream).poll_read(cx, buf);
        }

        if this.is_read_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            let filled_len = {
                let mut read_buf = ReadBuf::new(&mut this.read_buffer);
                match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
                read_buf.filled().len()
            };
            if filled_len == 0 {
                this.is_read_eof = true;
                return Poll::Ready(Ok(()));
            }

            Self::handle_padded_read_parts(
                &mut this.unpadder,
                &mut this.pending_read,
                &mut this.read_mode,
                &this.read_buffer[..filled_len],
            )?;

            if drain_pending_read(&mut this.pending_read, buf) {
                return Poll::Ready(Ok(()));
            }

            if this.read_mode == VisionReadMode::Plain {
                return Pin::new(&mut this.stream).poll_read(cx, buf);
            }
        }
    }
}

impl AsyncWrite for VisionServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.flush_pending_write(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        if let Some(response_header) =
            take_vless_response_header(&mut this.vless_response_to_send)
        {
            this.pending_write.extend_from_slice(response_header);
            match this.flush_pending_write(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let chunk = bounded_write_chunk(buf, MAX_WRITE_CONTENT_LEN);
        if chunk.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.queue_padded_write(chunk);

        this.poll_complete_buffered_write(cx, chunk.len())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_or_shutdown(cx, false)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_or_shutdown(cx, true)
    }
}

impl AsyncPing for VisionServerStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncStream for VisionServerStream {}

#[cfg(test)]
mod tests {
    use crate::handler::vless_handler::{
        looks_like_tls_record,
        vision_pad::pad_with_uuid_and_command,
        vision_unpad::{UnpadCommand, VisionUnpadder},
    };

    #[test]
    fn vision_pad_roundtrip_with_continue_command() {
        let uuid = [7u8; 16];
        let payload = b"hello over vision";
        let padded = pad_with_uuid_and_command(payload, &uuid, 0, false);

        let mut unpadder = VisionUnpadder::new(uuid);
        let result = unpadder
            .unpad(&padded)
            .expect("vision unpad should succeed");
        assert_eq!(result.content, payload);
        assert_eq!(result.command, Some(UnpadCommand::Continue));
    }

    #[test]
    fn looks_like_tls_record_detects_tls_handshake() {
        assert!(looks_like_tls_record(&[0x16, 0x03, 0x03, 0x00, 0x31]));
        assert!(!looks_like_tls_record(b"GET / HTTP/1.1\r\n"));
    }
}
