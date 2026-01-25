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
    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize>;
    fn process_new_packets(&mut self) -> io::Result<RealityIoState>;
    fn reader(&mut self) -> RealityReader<'_>;
    fn writer(&mut self) -> RealityWriter<'_>;
    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize>;
    fn wants_write(&self) -> bool;
    fn is_handshaking(&self) -> bool;
    fn send_close_notify(&mut self);
}

impl RealitySession for RealityServerConnection {
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

    fn is_handshaking(&self) -> bool {
        RealityServerConnection::is_handshaking(self)
    }

    fn send_close_notify(&mut self) {
        RealityServerConnection::send_close_notify(self)
    }
}

impl RealitySession for RealityClientConnection {
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
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn complete_handshake_if_needed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
                    )))
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
            if let Ok(available) = reader.fill_buf() {
                if !available.is_empty() {
                    let len = buf.remaining().min(available.len());
                    buf.put_slice(&available[..len]);
                    reader.consume(len);
                    return Poll::Ready(Ok(()));
                }
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
                    // Attempt to flush pending alerts before returning the error
                    while this.session.wants_write() {
                        let mut adapter = SyncWriteAdapter {
                            io: &mut this.io,
                            cx,
                        };
                        match this.session.write_tls(&mut adapter) {
                            Ok(_) => {}
                            Err(ref write_err) if write_err.kind() == io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(_) => break,
                        }
                    }
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

        let mut writer = this.session.writer();
        let n = writer.write(buf)?;

        match this.drain_all_writes(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.drain_all_writes(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
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
