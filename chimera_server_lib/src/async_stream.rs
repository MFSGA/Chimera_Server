use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send {}

impl AsyncPing for TcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for TcpStream {}

impl<T: ?Sized + AsyncStream> AsyncPing for Box<T> {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unsafe { self.map_unchecked_mut(|boxed| &mut **boxed) }.poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncStream> AsyncStream for Box<T> {}

impl<S> AsyncPing for TlsStream<S>
where
    S: AsyncPing + AsyncRead + AsyncWrite + Unpin + Send,
{
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S> AsyncStream for TlsStream<S> where S: AsyncStream {}
