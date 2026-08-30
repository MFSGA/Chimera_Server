use std::io::{self, BufRead, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::client::RealityClientConnection;
use super::reality_io_state::RealityIoState;
use super::reality_server_connection::RealityServerConnection;
use super::sync_adapter::{SyncReadAdapter, SyncWriteAdapter};
use super::{RealityReader, RealityWriter};
use crate::async_stream::{AsyncPing, AsyncStream};

/// Minimal trait that both REALITY server and client connections satisfy.
pub trait RealitySession {
    type Reader<'a>: BufRead
    where
        Self: 'a;
    type Writer<'a>: Write
    where
        Self: 'a;

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize>;
    fn process_new_packets(&mut self) -> io::Result<RealityIoState>;
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

impl RealitySession for RealityServerConnection {
    type Reader<'a> = RealityReader<'a>;
    type Writer<'a> = RealityWriter<'a>;

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        RealityServerConnection::read_tls(self, rd)
    }

    fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        RealityServerConnection::process_new_packets(self)
    }

    fn reader(&mut self) -> RealityReader<'_> {
        RealityServerConnection::reader(self)
    }

    fn writer(&mut self) -> RealityWriter<'_> {
        RealityServerConnection::writer(self)
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        RealityServerConnection::write_tls(self, wr)
    }

    fn wants_write(&self) -> bool {
        RealityServerConnection::wants_write(self)
    }

    fn wants_read(&self) -> bool {
        RealityServerConnection::wants_read(self)
    }

    fn is_handshaking(&self) -> bool {
        RealityServerConnection::is_handshaking(self)
    }

    fn take_remaining_ciphertext(&mut self) -> Vec<u8> {
        RealityServerConnection::take_remaining_ciphertext(self)
    }

    fn enable_vision_direct_transition(&mut self) {
        RealityServerConnection::enable_vision_direct_transition(self)
    }

    fn send_close_notify(&mut self) {
        RealityServerConnection::send_close_notify(self)
    }
}

impl RealitySession for RealityClientConnection {
    type Reader<'a> = RealityReader<'a>;
    type Writer<'a> = RealityWriter<'a>;

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        RealityClientConnection::read_tls(self, rd)
    }

    fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        RealityClientConnection::process_new_packets(self)
    }

    fn reader(&mut self) -> RealityReader<'_> {
        RealityClientConnection::reader(self)
    }

    fn writer(&mut self) -> RealityWriter<'_> {
        RealityClientConnection::writer(self)
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        RealityClientConnection::write_tls(self, wr)
    }

    fn wants_write(&self) -> bool {
        RealityClientConnection::wants_write(self)
    }

    fn wants_read(&self) -> bool {
        RealityClientConnection::wants_read(self)
    }

    fn is_handshaking(&self) -> bool {
        RealityClientConnection::is_handshaking(self)
    }

    fn send_close_notify(&mut self) {
        RealityClientConnection::send_close_notify(self)
    }
}

/// Async wrapper around a REALITY session, exposing AsyncRead/AsyncWrite.
pub struct RealityTlsStream<IO, S> {
    io: IO,
    session: S,
    is_read_eof: bool,
}

impl<IO, S> RealityTlsStream<IO, S> {
    pub fn new(io: IO, session: S) -> Self {
        Self {
            io,
            session,
            is_read_eof: false,
        }
    }

    pub fn into_inner(self) -> (IO, S) {
        (self.io, self.session)
    }
}

impl<IO, S> RealityTlsStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
    fn write_tls_direct(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut adapter = SyncWriteAdapter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut adapter) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn drain_all_writes(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            match self.write_tls_direct(cx) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn complete_handshake_if_needed(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.session.is_handshaking() {
            match self.drain_all_writes(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            let mut adapter = SyncReadAdapter {
                io: &mut self.io,
                cx,
            };
            match self.session.read_tls(&mut adapter) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF during handshake",
                    )));
                }
                Ok(_) => {
                    self.session.process_new_packets()?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<IO, S> AsyncRead for RealityTlsStream<IO, S>
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

        // Serve already decrypted data first
        {
            let mut reader = this.session.reader();
            if let Ok(available) = reader.fill_buf()
                && !available.is_empty()
            {
                let len = buf.remaining().min(available.len());
                buf.put_slice(&available[..len]);
                reader.consume(len);
                return Poll::Ready(Ok(()));
            }
        }

        if this.is_read_eof {
            return Poll::Ready(Ok(()));
        }

        // Ensure handshake is finished
        if this.session.is_handshaking() {
            match this.complete_handshake_if_needed(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        loop {
            let bytes_read = {
                let mut adapter = SyncReadAdapter {
                    io: &mut this.io,
                    cx,
                };
                match this.session.read_tls(&mut adapter) {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Poll::Pending;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            };

            if bytes_read == 0 {
                this.is_read_eof = true;
                return Poll::Ready(Ok(()));
            }

            let io_state = match this.session.process_new_packets() {
                Ok(state) => state,
                Err(e) => {
                    // Best-effort pending alerts without spinning if the transport
                    // reports a zero-byte write. Preserve the packet-processing error.
                    let _ = this.drain_all_writes(cx);
                    return Poll::Ready(Err(e));
                }
            };

            if io_state.plaintext_bytes_to_read() == 0 {
                continue;
            }

            let mut reader = this.session.reader();
            match reader.fill_buf() {
                Ok(available) => {
                    if available.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Read zero bytes when plaintext is available",
                        )));
                    }
                    let len = buf.remaining().min(available.len());
                    buf.put_slice(&available[..len]);
                    reader.consume(len);
                    return Poll::Ready(Ok(()));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl<IO, S> AsyncWrite for RealityTlsStream<IO, S>
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

        if this.session.is_handshaking() {
            match this.complete_handshake_if_needed(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let n = {
            let mut writer = this.session.writer();
            writer.write(buf)?
        };

        match this.drain_all_writes(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.drain_all_writes(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.session.send_close_notify();

        match this.drain_all_writes(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

impl<IO, S> AsyncPing for RealityTlsStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
    fn supports_ping(&self) -> bool {
        self.io.supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        Pin::new(&mut this.io).poll_write_ping(cx)
    }
}

impl<IO, S> crate::async_stream::AsyncStream for RealityTlsStream<IO, S>
where
    IO: AsyncStream,
    S: RealitySession + Unpin + Send,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ZeroWriteIo;

    impl AsyncRead for ZeroWriteIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() > 0 {
                buf.put_slice(&[1]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ZeroWriteIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ZeroWriteIo {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for ZeroWriteIo {}

    struct PendingTlsSession;

    impl RealitySession for PendingTlsSession {
        type Reader<'a> = io::Cursor<&'a [u8]>;
        type Writer<'a> = io::Sink;

        fn read_tls(&mut self, _rd: &mut dyn Read) -> io::Result<usize> {
            unreachable!()
        }

        fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
            unreachable!()
        }

        fn reader(&mut self) -> Self::Reader<'_> {
            io::Cursor::new(&[])
        }

        fn writer(&mut self) -> Self::Writer<'_> {
            io::sink()
        }

        fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
            wr.write(&[1])
        }

        fn wants_write(&self) -> bool {
            true
        }

        fn wants_read(&self) -> bool {
            false
        }

        fn is_handshaking(&self) -> bool {
            false
        }

        fn send_close_notify(&mut self) {}
    }

    #[test]
    fn tls_drain_returns_write_zero_like_current_shoes() {
        let mut stream = RealityTlsStream::new(ZeroWriteIo, PendingTlsSession);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        let result = stream.drain_all_writes(&mut cx);
        assert!(matches!(
            result,
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
        ));
    }

    struct ErrorAlertSession;

    impl RealitySession for ErrorAlertSession {
        type Reader<'a> = io::Cursor<&'a [u8]>;
        type Writer<'a> = io::Sink;

        fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
            let mut byte = [0u8; 1];
            rd.read(&mut byte)
        }

        fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic TLS processing error",
            ))
        }

        fn reader(&mut self) -> Self::Reader<'_> {
            io::Cursor::new(&[])
        }

        fn writer(&mut self) -> Self::Writer<'_> {
            io::sink()
        }

        fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
            wr.write(&[1])
        }

        fn wants_write(&self) -> bool {
            true
        }

        fn wants_read(&self) -> bool {
            true
        }

        fn is_handshaking(&self) -> bool {
            false
        }

        fn send_close_notify(&mut self) {}
    }

    #[test]
    fn packet_error_alert_zero_write_does_not_spin() {
        let mut stream = RealityTlsStream::new(ZeroWriteIo, ErrorAlertSession);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut storage = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut storage);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(
            result,
            Poll::Ready(Err(error))
                if error.kind() == io::ErrorKind::InvalidData
                    && error.to_string() == "synthetic TLS processing error"
        ));
    }
}
