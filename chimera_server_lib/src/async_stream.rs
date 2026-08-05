use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

use crate::address::NetLocation;

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UdpSocket},
};
#[cfg(feature = "tls")]
use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream,
};

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncReadMessage {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncWriteMessage {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncFlushMessage {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncShutdownMessage {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawTcpRelayState {
    Unavailable,
    Pending,
    Ready,
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        RawTcpRelayState::Unavailable
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<RawFd> {
        None
    }
}

pub trait AsyncMessageStream:
    AsyncReadMessage
    + AsyncWriteMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

pub trait AsyncReadTargetedMessage {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>>;
}

pub trait AsyncWriteSourcedMessage {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMessage {
    Data {
        session_id: u16,
        target: NetLocation,
        global_id: Option<[u8; 8]>,
        is_new: bool,
    },
    End {
        session_id: u16,
    },
}

pub trait AsyncReadSessionMessage {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SessionMessage>>;
}

pub trait AsyncWriteSessionMessage {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;

    fn poll_write_session_end(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        has_error: bool,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncTargetedMessageStream:
    AsyncReadTargetedMessage
    + AsyncWriteSourcedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

pub trait AsyncSessionMessageStream:
    AsyncReadSessionMessage
    + AsyncWriteSessionMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

impl AsyncPing for TcpStream {
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

impl AsyncStream for TcpStream {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        RawTcpRelayState::Ready
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

impl AsyncPing for UdpSocket {
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

impl AsyncReadMessage for UdpSocket {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_recv(cx, buf)
    }
}

impl AsyncWriteMessage for UdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        self.poll_send(cx, buf).map(|result| {
            result.and_then(|written| {
                if written == buf.len() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!(
                            "udp message write was truncated: wrote {written} of {} bytes",
                            buf.len()
                        ),
                    ))
                }
            })
        })
    }
}

impl AsyncFlushMessage for UdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncMessageStream for UdpSocket {}

impl<T: ?Sized + AsyncStream> AsyncPing for Box<T> {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        unsafe { self.map_unchecked_mut(|boxed| &mut **boxed) }.poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncStream> AsyncStream for Box<T> {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        (**self).raw_tcp_relay_state()
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<RawFd> {
        (**self).raw_tcp_fd()
    }
}

#[cfg(feature = "tls")]
impl<S> AsyncPing for ServerTlsStream<S>
where
    S: AsyncPing + AsyncRead + AsyncWrite + Unpin + Send,
{
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

#[cfg(feature = "tls")]
impl<S> AsyncStream for ServerTlsStream<S> where S: AsyncStream {}

#[cfg(feature = "tls")]
impl<S> AsyncPing for ClientTlsStream<S>
where
    S: AsyncPing + AsyncRead + AsyncWrite + Unpin + Send,
{
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

#[cfg(feature = "tls")]
impl<S> AsyncStream for ClientTlsStream<S> where S: AsyncStream {}

#[cfg(test)]
impl AsyncPing for tokio::io::DuplexStream {
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

#[cfg(test)]
impl AsyncStream for tokio::io::DuplexStream {}
