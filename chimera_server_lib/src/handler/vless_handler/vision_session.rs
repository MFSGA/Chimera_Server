use std::{
    io::{self, BufRead, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy)]
pub(super) struct VisionIoState {
    plaintext_bytes_to_read: usize,
}

impl VisionIoState {
    pub(super) fn new(plaintext_bytes_to_read: usize) -> Self {
        Self {
            plaintext_bytes_to_read,
        }
    }

    pub(super) fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}

pub(super) trait VisionSession {
    type Reader<'a>: BufRead
    where
        Self: 'a;
    type Writer<'a>: Write
    where
        Self: 'a;

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize>;
    fn process_new_packets(&mut self) -> io::Result<VisionIoState>;
    fn reader(&mut self) -> Self::Reader<'_>;
    fn writer(&mut self) -> Self::Writer<'_>;
    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize>;
    fn wants_write(&self) -> bool;
    fn wants_read(&self) -> bool;
    fn is_handshaking(&self) -> bool;
    fn take_remaining_ciphertext(&mut self) -> Vec<u8> {
        Vec::new()
    }
    fn enable_vision_direct_transition(&mut self) {}
    fn send_close_notify(&mut self);
}

pub(super) struct SyncReadAdapter<'a, 'b, T> {
    pub(super) io: &'a mut T,
    pub(super) cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncReadAdapter<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

pub(super) struct SyncWriteAdapter<'a, 'b, T> {
    pub(super) io: &'a mut T,
    pub(super) cx: &'a mut Context<'b>,
}

impl<T: AsyncWrite + Unpin> Write for SyncWriteAdapter<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

#[cfg(feature = "reality")]
impl VisionSession for crate::reality::RealityServerConnection {
    type Reader<'a> = crate::reality::RealityReader<'a>;
    type Writer<'a> = crate::reality::RealityWriter<'a>;

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        crate::reality::RealityServerConnection::read_tls(self, rd)
    }

    fn process_new_packets(&mut self) -> io::Result<VisionIoState> {
        crate::reality::RealityServerConnection::process_new_packets(self)
            .map(|state| VisionIoState::new(state.plaintext_bytes_to_read()))
    }

    fn reader(&mut self) -> Self::Reader<'_> {
        crate::reality::RealityServerConnection::reader(self)
    }

    fn writer(&mut self) -> Self::Writer<'_> {
        crate::reality::RealityServerConnection::writer(self)
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        crate::reality::RealityServerConnection::write_tls(self, wr)
    }

    fn wants_write(&self) -> bool {
        crate::reality::RealityServerConnection::wants_write(self)
    }

    fn wants_read(&self) -> bool {
        crate::reality::RealityServerConnection::wants_read(self)
    }

    fn is_handshaking(&self) -> bool {
        crate::reality::RealityServerConnection::is_handshaking(self)
    }

    fn take_remaining_ciphertext(&mut self) -> Vec<u8> {
        crate::reality::RealityServerConnection::take_remaining_ciphertext(self)
    }

    fn enable_vision_direct_transition(&mut self) {
        crate::reality::RealityServerConnection::enable_vision_direct_transition(
            self,
        )
    }

    fn send_close_notify(&mut self) {
        crate::reality::RealityServerConnection::send_close_notify(self)
    }
}
