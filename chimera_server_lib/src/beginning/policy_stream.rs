use std::{
    future::pending,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{
        AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf, copy_buf, split,
    },
    sync::watch,
    time::{Instant, Sleep, sleep},
};

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    runtime::PolicyRelayTimeouts,
};

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
        if matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
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
        if matches!(&result, Poll::Ready(Ok(written)) if *written > 0) {
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
        if matches!(&result, Poll::Ready(Ok(true))) {
            self.notify_activity();
        }
        result
    }
}

// Policy activity accounting must observe every byte. Deliberately use the
// default raw-relay state so policy-controlled sessions stay in userspace.
impl<S> AsyncStream for ActivityStream<'_, S> where S: AsyncStream + ?Sized {}

async fn copy_and_shutdown<R, W>(
    reader: R,
    mut writer: W,
    buffer_size: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::with_capacity(buffer_size, reader);
    let transferred = copy_buf(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(transferred)
}

async fn wait_optional_sleep(timer: &mut Option<Pin<Box<Sleep>>>) {
    match timer {
        Some(timer) => timer.as_mut().await,
        None => pending().await,
    }
}

async fn wait_for_activity(
    receiver: &mut watch::Receiver<()>,
    enabled: bool,
) -> Result<(), watch::error::RecvError> {
    if enabled {
        receiver.changed().await
    } else {
        pending().await
    }
}

pub(super) async fn copy_bidirectional_with_timeouts<A, B>(
    left: &mut A,
    right: &mut B,
    timeouts: PolicyRelayTimeouts,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    if timeouts.is_empty() {
        return tcp_relay::copy_bidirectional(left, right).await;
    }
    if timeouts.connection_idle.is_none()
        && timeouts.uplink_only.is_none()
        && timeouts.downlink_only.is_none()
    {
        return tcp_relay::copy_bidirectional_with_buffer_size(
            left,
            right,
            timeouts.buffer_size.unwrap_or(1),
        )
        .await;
    }

    let (activity_sender, mut activity_receiver) = watch::channel(());
    let left = ActivityStream::new(left, activity_sender.clone());
    let right = ActivityStream::new(right, activity_sender);
    let (left_reader, left_writer) = split(left);
    let (right_reader, right_writer) = split(right);
    let buffer_size = timeouts
        .buffer_size
        .unwrap_or_else(tcp_relay::configured_copy_buffer_size);
    let uplink = copy_and_shutdown(left_reader, right_writer, buffer_size);
    let downlink = copy_and_shutdown(right_reader, left_writer, buffer_size);
    tokio::pin!(uplink);
    tokio::pin!(downlink);

    let mut uplink_done = None;
    let mut downlink_done = None;
    let mut idle_timer = timeouts
        .connection_idle
        .map(|duration| Box::pin(sleep(duration)));
    let mut uplink_grace = None;
    let mut downlink_grace = None;

    loop {
        tokio::select! {
            result = &mut uplink, if uplink_done.is_none() => {
                uplink_done = Some(result?);
                if downlink_done.is_some() {
                    break;
                }
                uplink_grace = timeouts.downlink_only.map(|duration| Box::pin(sleep(duration)));
            }
            result = &mut downlink, if downlink_done.is_none() => {
                downlink_done = Some(result?);
                if uplink_done.is_some() {
                    break;
                }
                downlink_grace = timeouts.uplink_only.map(|duration| Box::pin(sleep(duration)));
            }
            activity = wait_for_activity(
                &mut activity_receiver,
                timeouts.connection_idle.is_some(),
            ) => {
                if activity.is_err() {
                    break;
                }
                if let (Some(duration), Some(timer)) = (
                    timeouts.connection_idle,
                    idle_timer.as_mut(),
                ) {
                    timer.as_mut().reset(Instant::now() + duration);
                }
            }
            _ = wait_optional_sleep(&mut idle_timer) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "TCP relay was idle for {} seconds",
                        timeouts.connection_idle.unwrap_or_default().as_secs()
                    ),
                ));
            }
            _ = wait_optional_sleep(&mut uplink_grace) => break,
            _ = wait_optional_sleep(&mut downlink_grace) => break,
        }
    }

    Ok(TcpRelayResult::policy_userspace(
        uplink_done.unwrap_or_default(),
        downlink_done.unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        time::{sleep, timeout},
    };

    use crate::runtime::PolicyRelayTimeouts;

    use super::copy_bidirectional_with_timeouts;

    #[tokio::test]
    async fn relay_times_out_after_configured_inactivity() {
        let (mut left, _left_peer) = duplex(64);
        let (mut right, _right_peer) = duplex(64);

        let error = copy_bidirectional_with_timeouts(
            &mut left,
            &mut right,
            PolicyRelayTimeouts {
                connection_idle: Some(Duration::from_millis(20)),
                ..PolicyRelayTimeouts::default()
            },
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
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    connection_idle: Some(Duration::from_millis(100)),
                    ..PolicyRelayTimeouts::default()
                },
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

    #[tokio::test]
    async fn uplink_eof_starts_the_downlink_only_grace_period() {
        let (mut left, mut left_peer) = duplex(64);
        let (mut right, mut right_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    downlink_only: Some(Duration::from_millis(30)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        left_peer.write_all(b"hello").await.expect("write uplink");
        left_peer.shutdown().await.expect("close uplink");
        let mut received = [0_u8; 5];
        right_peer
            .read_exact(&mut received)
            .await
            .expect("read uplink");
        assert_eq!(&received, b"hello");

        let result = timeout(Duration::from_millis(200), relay)
            .await
            .expect("downlink-only grace should expire")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
        assert_eq!(result.left_to_right, 5);
    }

    #[tokio::test]
    async fn downlink_eof_starts_the_uplink_only_grace_period() {
        let (mut left, mut left_peer) = duplex(64);
        let (mut right, mut right_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    uplink_only: Some(Duration::from_millis(30)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        right_peer
            .write_all(b"hello")
            .await
            .expect("write downlink");
        right_peer.shutdown().await.expect("close downlink");
        let mut received = [0_u8; 5];
        left_peer
            .read_exact(&mut received)
            .await
            .expect("read downlink");
        assert_eq!(&received, b"hello");

        let result = timeout(Duration::from_millis(200), relay)
            .await
            .expect("uplink-only grace should expire")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
        assert_eq!(result.right_to_left, 5);
    }
}
