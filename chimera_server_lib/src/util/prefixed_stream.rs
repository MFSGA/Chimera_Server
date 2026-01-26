use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

pub struct PrefixedStream {
    prefix: Box<[u8]>,
    prefix_offset: usize,
    inner: Box<dyn AsyncStream>,
}

impl PrefixedStream {
    pub fn new(prefix: Vec<u8>, inner: Box<dyn AsyncStream>) -> Self {
        Self {
            prefix: prefix.into_boxed_slice(),
            prefix_offset: 0,
            inner,
        }
    }

    fn remaining_prefix(&self) -> &[u8] {
        &self.prefix[self.prefix_offset..]
    }
}

impl AsyncPing for PrefixedStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write_ping(cx)
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let remaining = this.remaining_prefix();
        if !remaining.is_empty() {
            let to_copy = remaining.len().min(buf.remaining());
            if to_copy > 0 {
                buf.put_slice(&remaining[..to_copy]);
                this.prefix_offset += to_copy;
                return Poll::Ready(Ok(()));
            }
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncStream for PrefixedStream {}
