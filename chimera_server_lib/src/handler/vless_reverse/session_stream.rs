// Batch D uses an in-memory bounded duplex as the TCP-like logical stream
// surfaced by a Reverse Mux worker. The bounded buffer participates in
// backpressure; Batch E will hand this stream to the normal data plane.
#![allow(dead_code)]

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

#[derive(Debug)]
pub(crate) struct ReverseSessionStream {
    inner: DuplexStream,
}

impl ReverseSessionStream {
    pub(crate) fn new(inner: DuplexStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for ReverseSessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReverseSessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for ReverseSessionStream {
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

impl AsyncStream for ReverseSessionStream {}
