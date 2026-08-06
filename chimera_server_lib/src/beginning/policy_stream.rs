use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::timeout,
};

use crate::async_stream::{AsyncPing, AsyncStream};

use super::tcp_relay::{self, TcpRelayResult};

struct ActivityStream<'a, S: ?Sized> {
    inner: &'a mut S,
    activity: watch::Sender<()>,
}

impl<'a, S: ?Sized> ActivityStream<'a, S> {
    fn new(inner: &'a mut S, activity: watch::Sender<()>) -> Self {
        Self { inner, activity }
    }

    fn notify_activity(&self) {
        self.activity.send_replace(());
    }
}

impl<S> AsyncRead for ActivityStream<'_, S>
where
    S: AsyncRead + Unpin + ?Sized,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.notify_activity();
        }
        result
    }
}

impl<S> AsyncWrite for ActivityStream<'_, S>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.notify_activity();
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl<S> AsyncPing for ActivityStream<'_, S>
where
    S: AsyncPing + Unpin + ?Sized,
{
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let result = Pin::new(&mut *self.inner).poll_write_ping(cx);
        if matches!(result, Poll::Ready(Ok(true))) {
            self.notify_activity();
        }
        result
    }
}

// Policy activity accounting must observe every byte. Deliberately use the
// default raw-relay state so configured connIdle sessions stay in userspace.
impl<S> AsyncStream for ActivityStream<'_, S> where S: AsyncStream + ?Sized {}

pub(super) async fn copy_bidirectional_with_idle_timeout<A, B>(
    left: &mut A,
    right: &mut B,
    idle_timeout: Duration,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let (activity_sender, mut activity_receiver) = watch::channel(());
    let mut left = ActivityStream::new(left, activity_sender.clone());
    let mut right = ActivityStream::new(right, activity_sender);
    let relay = tcp_relay::copy_bidirectional(&mut left, &mut right);
    tokio::pin!(relay);

    loop {
        tokio::select! {
            result = &mut relay => return result,
            changed = timeout(idle_timeout, activity_receiver.changed()) => {
                match changed {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => return relay.await,
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "TCP relay was idle for {} seconds",
                                idle_timeout.as_secs()
                            ),
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        time::{sleep, timeout},
    };

    use super::copy_bidirectional_with_idle_timeout;

    #[tokio::test]
    async fn relay_times_out_after_configured_inactivity() {
        let (mut left, _left_peer) = duplex(64);
        let (mut right, _right_peer) = duplex(64);

        let error = copy_bidirectional_with_idle_timeout(
            &mut left,
            &mut right,
            Duration::from_millis(20),
        )
        .await
        .expect_err("idle relay must time out");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn relay_activity_resets_the_idle_deadline() {
        let (mut left, mut left_peer) = duplex(64);
        let (mut right, mut right_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(
                &mut left,
                &mut right,
                Duration::from_millis(100),
            )
            .await
        });

        for payload in [b"one".as_slice(), b"two".as_slice()] {
            left_peer.write_all(payload).await.expect("write activity");
            let mut received = vec![0_u8; payload.len()];
            right_peer
                .read_exact(&mut received)
                .await
                .expect("read relayed activity");
            assert_eq!(received, payload);
            sleep(Duration::from_millis(45)).await;
            assert!(!relay.is_finished());
        }

        drop(left_peer);
        drop(right_peer);
        timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay should finish after both peers close")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
    }
}
