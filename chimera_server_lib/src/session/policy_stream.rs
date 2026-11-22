use std::{
    future::pending,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::{Instant, Sleep, sleep},
};

use crate::{
    async_stream::{AsyncPing, AsyncStream, RawTcpRelayState},
    runtime::PolicyRelayTimeouts,
};

use super::tcp_relay::{
    self, RelayDirection, RelayProgress, RelayProgressReporter,
    RelayTrafficAccounting, TcpRelayResult,
};

struct ActivityStream<'a, S: ?Sized> {
    inner: &'a mut S,
    progress: RelayProgressReporter,
    read_direction: RelayDirection,
    shutdown_reported: bool,
}

impl<'a, S: ?Sized> ActivityStream<'a, S> {
    fn new(
        inner: &'a mut S,
        progress: RelayProgressReporter,
        read_direction: RelayDirection,
    ) -> Self {
        Self {
            inner,
            progress,
            read_direction,
            shutdown_reported: false,
        }
    }

    fn notify_activity(&self) {
        self.progress.activity();
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
            self.progress
                .bytes(self.read_direction, buffer.filled().len() - before);
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
            self.progress.activity_if_unobserved();
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
        let result = Pin::new(&mut *self.inner).poll_shutdown(cx);
        if matches!(&result, Poll::Ready(Ok(()))) && !self.shutdown_reported {
            self.shutdown_reported = true;
            self.progress.direction_done(match self.read_direction {
                RelayDirection::LeftToRight => RelayDirection::RightToLeft,
                RelayDirection::RightToLeft => RelayDirection::LeftToRight,
            });
        }
        result
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

// Keep the accounting wrapper transparent so eligible TCP streams still reach
// the raw relay path while policy timers observe userspace and splice progress.
impl<S> AsyncStream for ActivityStream<'_, S>
where
    S: AsyncStream + ?Sized,
{
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        self.inner.raw_tcp_relay_state()
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<std::os::fd::RawFd> {
        self.inner.raw_tcp_fd()
    }
}

async fn wait_optional_sleep(timer: &mut Option<Pin<Box<Sleep>>>) {
    match timer {
        Some(timer) => timer.as_mut().await,
        None => pending().await,
    }
}

async fn wait_for_activity(
    receiver: &mut watch::Receiver<RelayProgress>,
) -> Result<(), watch::error::RecvError> {
    receiver.changed().await
}

fn take_grace_tick_activity(
    receiver: &mut watch::Receiver<RelayProgress>,
    progress_reporter: &RelayProgressReporter,
    direction: RelayDirection,
    last_bytes: &mut u64,
    activity_seen: &mut bool,
) -> (RelayProgress, bool) {
    progress_reporter.acknowledge_activity();
    let progress = *receiver.borrow_and_update();
    let current_bytes = match direction {
        RelayDirection::LeftToRight => progress.left_to_right_bytes,
        RelayDirection::RightToLeft => progress.right_to_left_bytes,
    };
    if current_bytes > *last_bytes {
        *last_bytes = current_bytes;
        *activity_seen = true;
    }
    let activity = *activity_seen;
    *activity_seen = false;
    (progress, activity)
}

#[cfg(test)]
pub(crate) async fn copy_bidirectional_with_timeouts<A, B>(
    left: &mut A,
    right: &mut B,
    timeouts: PolicyRelayTimeouts,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    copy_bidirectional_with_timeouts_and_accounting(
        left,
        right,
        timeouts,
        RelayTrafficAccounting::new(None),
    )
    .await
}

pub(crate) async fn copy_bidirectional_with_timeouts_and_accounting<A, B>(
    left: &mut A,
    right: &mut B,
    timeouts: PolicyRelayTimeouts,
    accounting: Arc<RelayTrafficAccounting>,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    copy_bidirectional_with_timeouts_inner(left, right, timeouts, accounting, false)
        .await
}

async fn copy_bidirectional_with_timeouts_inner<A, B>(
    left: &mut A,
    right: &mut B,
    timeouts: PolicyRelayTimeouts,
    accounting: Arc<RelayTrafficAccounting>,
    force_splice_downlink: bool,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    if timeouts.is_empty() {
        return tcp_relay::copy_bidirectional_with_accounting(
            left, right, accounting,
        )
        .await;
    }
    if timeouts.connection_idle.is_none()
        && timeouts.uplink_only.is_none()
        && timeouts.downlink_only.is_none()
    {
        let size = timeouts.buffer_size.unwrap_or(1);
        let (left_to_right, right_to_left) =
            tokio::io::copy_bidirectional_with_sizes(left, right, size, size)
                .await?;
        return Ok(TcpRelayResult::policy_userspace(
            left_to_right,
            right_to_left,
        ));
    }

    let (progress_sender, mut activity_receiver) =
        watch::channel(RelayProgress::default());
    let progress = RelayProgressReporter::new(progress_sender, accounting);
    let activity_reporter = progress.clone();
    let mut left =
        ActivityStream::new(left, progress.clone(), RelayDirection::LeftToRight);
    let mut right =
        ActivityStream::new(right, progress.clone(), RelayDirection::RightToLeft);
    #[cfg(test)]
    let relay = async {
        #[cfg(target_os = "linux")]
        {
            if force_splice_downlink {
                tcp_relay::copy_bidirectional_with_downlink_splice_and_progress(
                    &mut left,
                    &mut right,
                    progress,
                    timeouts.buffer_size,
                )
                .await
            } else {
                tcp_relay::copy_bidirectional_with_progress(
                    &mut left,
                    &mut right,
                    progress,
                    timeouts.buffer_size,
                )
                .await
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = force_splice_downlink;
            tcp_relay::copy_bidirectional_with_progress(
                &mut left,
                &mut right,
                progress,
                timeouts.buffer_size,
            )
            .await
        }
    };
    #[cfg(not(test))]
    let relay = {
        let _ = force_splice_downlink;
        tcp_relay::copy_bidirectional_with_progress(
            &mut left,
            &mut right,
            progress,
            timeouts.buffer_size,
        )
    };
    tokio::pin!(relay);

    // Xray's ActivityTimer checks at fixed intervals and extends the timeout
    // when activity was observed during that interval. Keep that cadence
    // instead of restarting the timer on every byte.
    let mut last_activity_generation = 0;
    let mut last_left_to_right_bytes = 0;
    let mut last_right_to_left_bytes = 0;
    let mut uplink_done = false;
    let mut downlink_done = false;
    let mut uplink_grace_activity = false;
    let mut downlink_grace_activity = false;
    let mut idle_timer = timeouts
        .connection_idle
        .map(|duration| Box::pin(sleep(duration)));
    let mut uplink_grace = None;
    let mut downlink_grace = None;

    loop {
        tokio::select! {
            result = &mut relay => {
                return result.map_err(|error| {
                    tcp_relay::error_with_partial_result(
                        error,
                        *activity_receiver.borrow(),
                    )
                });
            }
            activity = wait_for_activity(&mut activity_receiver) => {
                if activity.is_err() {
                    return relay.await.map_err(|error| {
                        tcp_relay::error_with_partial_result(
                            error,
                            *activity_receiver.borrow(),
                        )
                    });
                }
                activity_reporter.acknowledge_activity();
                let progress = *activity_receiver.borrow_and_update();
                let uplink_activity =
                    progress.left_to_right_bytes > last_left_to_right_bytes;
                let downlink_activity =
                    progress.right_to_left_bytes > last_right_to_left_bytes;
                last_left_to_right_bytes = progress.left_to_right_bytes;
                last_right_to_left_bytes = progress.right_to_left_bytes;
                if uplink_done && !downlink_done && downlink_activity {
                    downlink_grace_activity = true;
                }
                if downlink_done && !uplink_done && uplink_activity {
                    uplink_grace_activity = true;
                }
                if progress.activity_generation != last_activity_generation {
                    last_activity_generation = progress.activity_generation;
                    if !uplink_done
                        && !downlink_done
                        && let (Some(duration), Some(timer)) = (
                            timeouts.connection_idle,
                            idle_timer.as_mut(),
                        )
                    {
                        timer.as_mut().reset(Instant::now() + duration);
                    }
                }
                if !uplink_done && progress.left_to_right_done {
                    uplink_done = true;
                    idle_timer = None;
                    downlink_grace_activity = false;
                    downlink_grace = timeouts
                        .downlink_only
                        .map(|duration| Box::pin(sleep(duration)));
                }
                if !downlink_done && progress.right_to_left_done {
                    downlink_done = true;
                    idle_timer = None;
                    uplink_grace_activity = false;
                    uplink_grace = timeouts
                        .uplink_only
                        .map(|duration| Box::pin(sleep(duration)));
                }
                if uplink_done && downlink_done {
                    return relay.await.map_err(|error| {
                        tcp_relay::error_with_partial_result(
                            error,
                            *activity_receiver.borrow(),
                        )
                    });
                }
            }
            _ = wait_optional_sleep(&mut idle_timer) => {
                let error = io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "TCP relay was idle for {} seconds",
                        timeouts.connection_idle.unwrap_or_default().as_secs()
                    ),
                );
                return Err(tcp_relay::error_with_partial_result(
                    error,
                    *activity_receiver.borrow(),
                ));
            }
            _ = wait_optional_sleep(&mut uplink_grace) => {
                let duration = timeouts.uplink_only.unwrap_or_default();
                let (progress, activity) = take_grace_tick_activity(
                    &mut activity_receiver,
                    &activity_reporter,
                    RelayDirection::LeftToRight,
                    &mut last_left_to_right_bytes,
                    &mut uplink_grace_activity,
                );
                if progress.left_to_right_done && progress.right_to_left_done {
                    return relay.await.map_err(|error| {
                        tcp_relay::error_with_partial_result(
                            error,
                            progress,
                        )
                    });
                }
                if activity && !duration.is_zero() {
                    uplink_grace = Some(Box::pin(sleep(duration)));
                } else {
                    return Ok(TcpRelayResult::partial(progress));
                }
            }
            _ = wait_optional_sleep(&mut downlink_grace) => {
                let duration = timeouts.downlink_only.unwrap_or_default();
                let (progress, activity) = take_grace_tick_activity(
                    &mut activity_receiver,
                    &activity_reporter,
                    RelayDirection::RightToLeft,
                    &mut last_right_to_left_bytes,
                    &mut downlink_grace_activity,
                );
                if progress.left_to_right_done && progress.right_to_left_done {
                    return relay.await.map_err(|error| {
                        tcp_relay::error_with_partial_result(
                            error,
                            progress,
                        )
                    });
                }
                if activity && !duration.is_zero() {
                    downlink_grace = Some(Box::pin(sleep(duration)));
                } else {
                    return Ok(TcpRelayResult::partial(progress));
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
async fn copy_bidirectional_with_downlink_splice_and_timeouts<A, B>(
    left: &mut A,
    right: &mut B,
    timeouts: PolicyRelayTimeouts,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    copy_bidirectional_with_timeouts_inner(
        left,
        right,
        timeouts,
        RelayTrafficAccounting::new(None),
        true,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        io::ErrorKind,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex},
        sync::{Notify, watch},
        time::{advance, sleep, timeout},
    };

    #[cfg(target_os = "linux")]
    use tokio::{net::TcpListener, net::TcpStream};

    use crate::runtime::PolicyRelayTimeouts;

    #[cfg(target_os = "linux")]
    use super::copy_bidirectional_with_downlink_splice_and_timeouts;
    use super::{
        RelayDirection, RelayProgressReporter, RelayTrafficAccounting,
        copy_bidirectional_with_timeouts, take_grace_tick_activity,
    };
    use crate::session::tcp_relay::RelayProgress;

    struct WriteObservedStream {
        inner: tokio::io::DuplexStream,
        writes: Arc<AtomicUsize>,
        writes_changed: Arc<Notify>,
    }

    impl AsyncRead for WriteObservedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for WriteObservedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let result = Pin::new(&mut self.inner).poll_write(cx, buffer);
            if let Poll::Ready(Ok(written)) = &result
                && *written > 0
            {
                self.writes.fetch_add(*written, Ordering::Release);
                self.writes_changed.notify_one();
            }
            result
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

    impl crate::async_stream::AsyncPing for WriteObservedStream {
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

    impl crate::async_stream::AsyncStream for WriteObservedStream {}

    async fn wait_for_writes(
        writes: &AtomicUsize,
        writes_changed: &Notify,
        expected: usize,
    ) {
        loop {
            let notified = writes_changed.notified();
            tokio::pin!(notified);
            if writes.load(Ordering::Acquire) >= expected {
                return;
            }
            notified.await;
        }
    }

    impl crate::async_stream::AsyncPing for tokio::io::DuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<bool>> {
            std::task::Poll::Ready(Ok(false))
        }
    }

    impl crate::async_stream::AsyncStream for tokio::io::DuplexStream {}

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

    #[tokio::test(start_paused = true)]
    async fn successful_writes_reset_idle_deadline_without_new_reads() {
        let (mut left, mut left_peer) = duplex(64);
        let (right, mut right_peer) = duplex(1);
        let writes = Arc::new(AtomicUsize::new(0));
        let writes_changed = Arc::new(Notify::new());
        let mut right = WriteObservedStream {
            inner: right,
            writes: Arc::clone(&writes),
            writes_changed: Arc::clone(&writes_changed),
        };
        left_peer
            .write_all(b"abc")
            .await
            .expect("queue source bytes");

        let relay = tokio::spawn(async move {
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    connection_idle: Some(Duration::from_secs(1)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        wait_for_writes(&writes, &writes_changed, 1).await;
        let mut first = [0_u8; 1];
        right_peer
            .read_exact(&mut first)
            .await
            .expect("read first byte");
        assert_eq!(first, *b"a");
        wait_for_writes(&writes, &writes_changed, 2).await;

        advance(Duration::from_millis(900)).await;
        let mut second = [0_u8; 1];
        right_peer
            .read_exact(&mut second)
            .await
            .expect("read second byte");
        assert_eq!(second, *b"b");
        wait_for_writes(&writes, &writes_changed, 3).await;

        advance(Duration::from_millis(900)).await;
        assert!(
            !relay.is_finished(),
            "successful writes must reset idle time"
        );
        let mut third = [0_u8; 1];
        right_peer
            .read_exact(&mut third)
            .await
            .expect("read third byte");
        assert_eq!(third, *b"c");

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

    #[tokio::test(start_paused = true)]
    async fn downlink_activity_ready_at_grace_deadline_is_observed() {
        let (sender, mut receiver) = watch::channel(RelayProgress::default());
        let progress_reporter =
            RelayProgressReporter::new(sender, RelayTrafficAccounting::new(None));
        let mut timer = Box::pin(sleep(Duration::from_secs(1)));
        assert!(futures::poll!(timer.as_mut()).is_pending());
        advance(Duration::from_secs(1)).await;
        progress_reporter.bytes(RelayDirection::RightToLeft, 1);

        assert!(timer.is_elapsed(), "grace timer must be ready");
        assert!(receiver.has_changed().expect("watch remains open"));

        let mut last_bytes = 0;
        let mut activity_seen = false;
        let (progress, should_extend) = take_grace_tick_activity(
            &mut receiver,
            &progress_reporter,
            RelayDirection::RightToLeft,
            &mut last_bytes,
            &mut activity_seen,
        );

        assert!(should_extend, "deadline must observe queued downlink data");
        assert_eq!(last_bytes, 1);
        assert_eq!(progress.right_to_left_bytes, 1);
        assert!(!receiver.has_changed().expect("watch remains open"));
    }

    #[test]
    fn write_activity_coalesces_without_losing_activity_during_observation() {
        let (sender, mut receiver) = watch::channel(RelayProgress::default());
        let progress =
            RelayProgressReporter::new(sender, RelayTrafficAccounting::new(None));

        progress.bytes(RelayDirection::LeftToRight, 7);
        progress.activity_if_unobserved();
        progress.acknowledge_activity();
        progress.activity_if_unobserved();
        let observed = *receiver.borrow_and_update();
        assert_eq!(observed.activity_generation, 2);
        assert_eq!(observed.left_to_right_bytes, 7);

        progress.acknowledge_activity();
        progress.activity_if_unobserved();
        let observed = *receiver.borrow_and_update();
        assert_eq!(observed.activity_generation, 3);
        assert_eq!(observed.left_to_right_bytes, 7);
    }

    #[tokio::test]
    async fn downlink_activity_resets_grace_and_replaces_connection_idle() {
        let (mut left, mut left_peer) = duplex(64);
        let (mut right, mut right_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    connection_idle: Some(Duration::from_millis(10)),
                    downlink_only: Some(Duration::from_millis(100)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        left_peer.write_all(b"up").await.expect("write uplink");
        left_peer.shutdown().await.expect("close uplink");
        let mut uplink = [0_u8; 2];
        right_peer
            .read_exact(&mut uplink)
            .await
            .expect("read uplink");
        assert_eq!(&uplink, b"up");

        sleep(Duration::from_millis(20)).await;
        right_peer
            .write_all(b"a")
            .await
            .expect("write first downlink byte");
        let mut first = [0_u8; 1];
        left_peer
            .read_exact(&mut first)
            .await
            .expect("read first downlink byte");
        assert_eq!(&first, b"a");

        // The fixed Xray timeout check at 100 ms observes the first byte and
        // starts another interval. A second byte at 150 ms must still pass.
        sleep(Duration::from_millis(130)).await;
        right_peer
            .write_all(b"b")
            .await
            .expect("write second downlink byte");
        let mut second = [0_u8; 1];
        left_peer
            .read_exact(&mut second)
            .await
            .expect("read second downlink byte");
        assert_eq!(&second, b"b");
        assert!(
            !relay.is_finished(),
            "downlink-only grace must track activity at its fixed check intervals"
        );

        let result = timeout(Duration::from_secs(1), relay)
            .await
            .expect("downlink-only grace should expire after activity stops")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
        assert_eq!(result.left_to_right, 2);
        assert_eq!(result.right_to_left, 2);
    }

    #[tokio::test]
    async fn uplink_activity_resets_grace_at_fixed_timeout_checks() {
        let (mut left, mut left_peer) = duplex(64);
        let (mut right, mut right_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    connection_idle: Some(Duration::from_millis(10)),
                    uplink_only: Some(Duration::from_millis(100)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        right_peer
            .write_all(b"response")
            .await
            .expect("write downlink");
        right_peer.shutdown().await.expect("close downlink");
        let mut response = [0_u8; 8];
        left_peer
            .read_exact(&mut response)
            .await
            .expect("read downlink");
        assert_eq!(&response, b"response");
        let mut eof = [0_u8; 1];
        assert_eq!(
            left_peer.read(&mut eof).await.expect("read downlink EOF"),
            0
        );

        sleep(Duration::from_millis(20)).await;
        left_peer
            .write_all(b"a")
            .await
            .expect("write first uplink byte");
        let mut first = [0_u8; 1];
        right_peer
            .read_exact(&mut first)
            .await
            .expect("read first uplink byte");
        assert_eq!(&first, b"a");

        sleep(Duration::from_millis(130)).await;
        left_peer
            .write_all(b"b")
            .await
            .expect("write second uplink byte");
        let mut second = [0_u8; 1];
        right_peer
            .read_exact(&mut second)
            .await
            .expect("read second uplink byte");
        assert_eq!(&second, b"b");
        assert!(
            !relay.is_finished(),
            "uplink-only grace must track activity at its fixed check intervals"
        );

        let result = timeout(Duration::from_secs(1), relay)
            .await
            .expect("uplink-only grace should expire after activity stops")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
        assert_eq!(result.left_to_right, 2);
        assert_eq!(result.right_to_left, 8);
    }

    #[tokio::test]
    async fn zero_downlink_only_timeout_expires_immediately_after_uplink_eof() {
        let (mut left, mut left_peer) = duplex(64);
        let (mut right, mut _right_peer) = duplex(64);
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    downlink_only: Some(Duration::ZERO),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        left_peer.shutdown().await.expect("close uplink");
        let result = timeout(Duration::from_millis(100), relay)
            .await
            .expect("zero downlink-only timeout did not expire")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
        assert_eq!(result.left_to_right, 0);
        assert_eq!(result.right_to_left, 0);
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

    #[cfg(target_os = "linux")]
    async fn tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address);
        let ((server, _), client) = tokio::try_join!(listener.accept(), client)?;
        Ok((server, client))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn raw_ready_policy_relay_keeps_half_close_with_splice() {
        let (mut left_peer, left_relay) = tcp_pair().await.expect("left TCP pair");
        let (mut right_peer, right_relay) =
            tcp_pair().await.expect("right TCP pair");
        let relay = tokio::spawn(async move {
            let mut left = left_relay;
            let mut right = right_relay;
            copy_bidirectional_with_downlink_splice_and_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    connection_idle: Some(Duration::from_secs(2)),
                    uplink_only: Some(Duration::from_millis(250)),
                    downlink_only: Some(Duration::from_millis(250)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        left_peer
            .write_all(b"request")
            .await
            .expect("write request");
        left_peer.shutdown().await.expect("half-close request");
        let mut request = [0_u8; 7];
        right_peer
            .read_exact(&mut request)
            .await
            .expect("read request");
        assert_eq!(&request, b"request");
        right_peer
            .write_all(b"response")
            .await
            .expect("write response");
        right_peer.shutdown().await.expect("half-close response");
        let mut response = [0_u8; 8];
        left_peer
            .read_exact(&mut response)
            .await
            .expect("read response");
        assert_eq!(&response, b"response");
        let mut eof = [0_u8; 1];
        assert_eq!(left_peer.read(&mut eof).await.expect("read EOF"), 0);

        let result = timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay should finish after both half-closes")
            .expect("relay task should not panic")
            .expect("relay should close cleanly");
        assert_eq!(result.effective_path(), "splice-downlink");
        assert_eq!(result.bypassed_right_to_left, 8);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn idle_timeout_preserves_partial_splice_accounting() {
        let (mut left_peer, left_relay) = tcp_pair().await.expect("left TCP pair");
        let (mut right_peer, right_relay) =
            tcp_pair().await.expect("right TCP pair");
        let relay = tokio::spawn(async move {
            let mut left = left_relay;
            let mut right = right_relay;
            copy_bidirectional_with_downlink_splice_and_timeouts(
                &mut left,
                &mut right,
                PolicyRelayTimeouts {
                    connection_idle: Some(Duration::from_millis(150)),
                    ..PolicyRelayTimeouts::default()
                },
            )
            .await
        });

        right_peer
            .write_all(b"downlink")
            .await
            .expect("write payload");
        let mut payload = [0_u8; 8];
        left_peer
            .read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"downlink");

        let error = timeout(Duration::from_secs(1), relay)
            .await
            .expect("idle connection should time out")
            .expect("relay task should not panic")
            .expect_err("idle relay must return a timeout");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        let partial = crate::session::tcp_relay::partial_result_from_error(&error)
            .expect("timeout should include partial relay accounting");
        assert_eq!(partial.effective_path(), "splice-downlink");
        assert_eq!(partial.bypassed_right_to_left, 8);
    }
}
