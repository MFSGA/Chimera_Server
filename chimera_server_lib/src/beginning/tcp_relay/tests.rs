use std::{
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
};
#[cfg(target_os = "linux")]
use tokio::net::{TcpListener, TcpStream};

use crate::async_stream::{AsyncPing, AsyncStream, RawTcpRelayState};

use super::*;

struct HandoffTestStream {
    inner: DuplexStream,
    ready: Arc<AtomicBool>,
}

impl AsyncRead for HandoffTestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HandoffTestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for HandoffTestStream {
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

impl AsyncStream for HandoffTestStream {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        if self.ready.load(Ordering::Acquire) {
            RawTcpRelayState::Ready
        } else {
            RawTcpRelayState::Pending
        }
    }
}

struct ReadyPanicStream;

impl AsyncRead for ReadyPanicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        panic!("ready raw stream must not be polled during handoff prelude")
    }
}

impl AsyncWrite for ReadyPanicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        panic!("ready raw stream must not be polled during handoff prelude")
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        panic!("ready raw stream must not be flushed during handoff prelude")
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        panic!("ready raw stream must not be shut down during handoff prelude")
    }
}

impl AsyncPing for ReadyPanicStream {
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

impl AsyncStream for ReadyPanicStream {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        RawTcpRelayState::Ready
    }
}

#[derive(Default)]
struct FlushGateWriter {
    pending: Vec<u8>,
    visible: Arc<Mutex<Vec<u8>>>,
    flushes: Arc<std::sync::atomic::AtomicUsize>,
}

impl AsyncWrite for FlushGateWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.pending.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let pending = std::mem::take(&mut self.pending);
        self.visible.lock().unwrap().extend_from_slice(&pending);
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[derive(Default)]
struct FinishCountingWriter {
    pending: Vec<u8>,
    visible: Vec<u8>,
    flushes: usize,
    shutdowns: usize,
}

impl AsyncWrite for FinishCountingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.pending.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let pending = std::mem::take(&mut self.pending);
        self.visible.extend_from_slice(&pending);
        self.flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending.is_empty() {
            return Poll::Ready(Err(io::Error::other(
                "shutdown observed bytes that copy_buf did not flush",
            )));
        }
        self.shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

#[test]
fn default_uses_measured_thirty_two_kibibyte_buffer() {
    assert_eq!(parse_copy_buffer_size(None).unwrap(), 32 * 1024);
}

#[cfg(target_os = "linux")]
#[test]
fn auto_uplink_uses_measured_sixty_four_kibibyte_default() {
    assert_eq!(
        auto_uplink_copy_buffer_size(CopyBufferConfig {
            size: DEFAULT_COPY_BUFFER_SIZE,
            explicit: false,
        }),
        DEFAULT_AUTO_UPLINK_COPY_BUFFER_SIZE,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn auto_uplink_preserves_explicit_copy_buffer_size() {
    for size in [32 * 1024, 64 * 1024, 128 * 1024] {
        assert_eq!(
            auto_uplink_copy_buffer_size(CopyBufferConfig {
                size,
                explicit: true,
            }),
            size,
        );
    }
}

#[test]
fn accepts_buffer_matrix_boundaries() {
    for size in [
        4 * 1024,
        8 * 1024,
        16 * 1024,
        32 * 1024,
        64 * 1024,
        128 * 1024,
        256 * 1024,
        1024 * 1024,
    ] {
        assert_eq!(
            parse_copy_buffer_size(Some(&size.to_string())).unwrap(),
            size,
        );
    }
}

#[test]
fn rejects_invalid_or_unbounded_buffers() {
    assert!(parse_copy_buffer_size(Some("invalid")).is_err());
    assert!(parse_copy_buffer_size(Some("0")).is_err());
    assert!(parse_copy_buffer_size(Some("2097152")).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn parses_adaptive_splice_limit_boundaries() {
    assert_eq!(
        parse_auto_max_connections(None).unwrap(),
        DEFAULT_AUTO_MAX_CONNECTIONS,
    );
    assert_eq!(parse_auto_max_connections(Some("0")).unwrap(), 0);
    assert_eq!(parse_auto_max_connections(Some("8")).unwrap(), 8);
    assert_eq!(
        parse_auto_max_connections(Some("4096")).unwrap(),
        AUTO_MAX_CONNECTIONS_LIMIT,
    );
    assert!(parse_auto_max_connections(Some("invalid")).is_err());
    assert!(parse_auto_max_connections(Some("4097")).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn adaptive_relay_guard_reserves_only_available_slots() {
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 0);
    assert!(AutoRelayGuard::try_acquire(0).is_none());
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 0);

    let first = AutoRelayGuard::try_acquire(2).expect("first slot available");
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 1);
    let second = AutoRelayGuard::try_acquire(2).expect("second slot available");
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 2);
    assert!(AutoRelayGuard::try_acquire(2).is_none());
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 2);

    drop(first);
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 1);
    drop(second);
    assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn parses_splice_pipe_size_boundaries() {
    assert_eq!(
        parse_splice_pipe_size(None).unwrap(),
        DEFAULT_SPLICE_PIPE_SIZE,
    );
    for size in [
        MIN_SPLICE_PIPE_SIZE,
        64 * 1024,
        DEFAULT_SPLICE_PIPE_SIZE,
        MAX_SPLICE_PIPE_SIZE,
    ] {
        assert_eq!(
            parse_splice_pipe_size(Some(&size.to_string())).unwrap(),
            size,
        );
    }
    assert!(parse_splice_pipe_size(Some("invalid")).is_err());
    assert!(parse_splice_pipe_size(Some("0")).is_err());
    assert!(parse_splice_pipe_size(Some("2097152")).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn nonblocking_pipe_reports_actual_capacity() {
    let (_read, write, actual) = nonblocking_pipe(DEFAULT_SPLICE_PIPE_SIZE).unwrap();
    assert_eq!(pipe_capacity(write.as_raw_fd()).unwrap(), actual);
    assert!(actual >= MIN_SPLICE_PIPE_SIZE);
}

#[test]
fn parses_relay_backend() {
    assert_eq!(parse_relay_backend(None).unwrap(), RelayBackend::Handoff);
    assert_eq!(
        parse_relay_backend(Some("handoff")).unwrap(),
        RelayBackend::Handoff,
    );
    #[cfg(target_os = "linux")]
    {
        assert_eq!(
            parse_relay_backend(Some("splice")).unwrap(),
            RelayBackend::Splice,
        );
        assert_eq!(
            parse_relay_backend(Some("splice-downlink")).unwrap(),
            RelayBackend::SpliceDownlink,
        );
        assert_eq!(
            parse_relay_backend(Some("auto")).unwrap(),
            RelayBackend::Auto,
        );
    }
    assert!(parse_relay_backend(Some("unknown")).is_err());
}

#[test]
fn relay_result_reports_configured_and_effective_paths() {
    let handoff = TcpRelayResult::userspace(RelayBackend::Handoff, 11, 22);
    assert_eq!(handoff.configured_backend(), "handoff");
    assert_eq!(handoff.effective_path(), "userspace-copy");
    assert_eq!(handoff.fallback_reason(), None);

    let incomplete = TcpRelayResult::userspace_fallback(
        RelayBackend::Handoff,
        RelayFallbackReason::DirectNotReached,
        33,
        44,
    );
    assert_eq!(incomplete.configured_backend(), "handoff");
    assert_eq!(incomplete.effective_path(), "userspace-copy");
    assert_eq!(incomplete.fallback_reason(), Some("direct-not-reached"));
}

#[cfg(target_os = "linux")]
#[test]
fn relay_result_reports_auto_splice_and_limit_fallback() {
    let spliced = TcpRelayResult::with_bypassed(
        RelayBackend::Auto,
        RelayEffectivePath::SpliceDownlink,
        10,
        20,
        0,
        30,
    );
    assert_eq!(spliced.configured_backend(), "auto");
    assert_eq!(spliced.effective_path(), "splice-downlink");
    assert_eq!(spliced.fallback_reason(), None);
    assert_eq!(spliced.left_to_right, 10);
    assert_eq!(spliced.right_to_left, 50);

    let limited = TcpRelayResult::userspace_fallback(
        RelayBackend::Auto,
        RelayFallbackReason::AutoConnectionLimit,
        40,
        50,
    );
    assert_eq!(limited.configured_backend(), "auto");
    assert_eq!(limited.effective_path(), "userspace-copy");
    assert_eq!(limited.fallback_reason(), Some("auto-connection-limit"),);
}

#[tokio::test]
async fn prelude_short_circuits_when_both_raw_streams_are_ready() {
    let mut left = ReadyPanicStream;
    let mut right = ReadyPanicStream;

    let outcome = copy_until_raw_ready(&mut left, &mut right, 32 * 1024)
        .await
        .unwrap();

    assert_eq!(
        outcome,
        PreludeOutcome::RawReady {
            left_to_right: 0,
            right_to_left: 0,
        }
    );
}

#[tokio::test]
async fn prelude_flushes_accepted_writes_before_becoming_idle() {
    let (mut peer, mut reader) = tokio::io::duplex(64);
    peer.write_all(b"server-hello").await.unwrap();

    let visible = Arc::new(Mutex::new(Vec::new()));
    let flushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut writer = FlushGateWriter {
        pending: Vec::new(),
        visible: visible.clone(),
        flushes: flushes.clone(),
    };
    let mut state = CopyDirection::new(64);

    std::future::poll_fn(|cx| {
        let step = poll_copy_direction(cx, &mut reader, &mut writer, &mut state)?;
        if state.is_idle() && visible.lock().unwrap().as_slice() == b"server-hello" {
            Poll::Ready(Ok::<(), io::Error>(()))
        } else if step.made_progress {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Pending
        }
    })
    .await
    .unwrap();

    assert_eq!(visible.lock().unwrap().as_slice(), b"server-hello");
    assert_eq!(flushes.load(Ordering::Relaxed), 1);
    assert!(!state.flush_pending);
}

#[tokio::test]
async fn one_direction_copy_flushes_once_before_shutdown() {
    let payload = b"copy-buf-flush-contract";
    let mut reader = &payload[..];
    let mut writer = FinishCountingWriter::default();

    let copied = copy_one_direction(&mut reader, &mut writer, 5)
        .await
        .unwrap();

    assert_eq!(copied, payload.len() as u64);
    assert_eq!(writer.visible, payload);
    assert_eq!(writer.flushes, 1);
    assert_eq!(writer.shutdowns, 1);
    assert!(writer.pending.is_empty());
}

#[tokio::test]
async fn handoff_barrier_preserves_bidirectional_data() {
    let ready = Arc::new(AtomicBool::new(false));
    let (left_peer, left_inner) = tokio::io::duplex(64);
    let (right_peer, right_inner) = tokio::io::duplex(64);
    let mut left = HandoffTestStream {
        inner: left_inner,
        ready: ready.clone(),
    };
    let mut right = HandoffTestStream {
        inner: right_inner,
        ready: ready.clone(),
    };

    let relay = tokio::spawn(async move {
        let prelude = copy_until_raw_ready(&mut left, &mut right, 8).await?;
        assert!(matches!(prelude, PreludeOutcome::RawReady { .. }));
        tokio::io::copy_bidirectional(&mut left, &mut right).await
    });

    let left_task = tokio::spawn(async move {
        let mut peer = left_peer;
        peer.write_all(b"left-before").await?;
        let mut response = [0_u8; 12];
        peer.read_exact(&mut response).await?;
        ready.store(true, Ordering::Release);
        peer.write_all(b"left-after").await?;
        peer.shutdown().await?;
        let mut tail = Vec::new();
        peer.read_to_end(&mut tail).await?;
        Ok::<_, io::Error>((response, tail))
    });

    let right_task = tokio::spawn(async move {
        let mut peer = right_peer;
        peer.write_all(b"right-before").await?;
        let mut request = [0_u8; 11];
        peer.read_exact(&mut request).await?;
        peer.write_all(b"right-after").await?;
        peer.shutdown().await?;
        let mut tail = Vec::new();
        peer.read_to_end(&mut tail).await?;
        Ok::<_, io::Error>((request, tail))
    });

    let (left_result, right_result, relay_result) =
        tokio::try_join!(left_task, right_task, relay).unwrap();
    let (left_response, left_tail) = left_result.unwrap();
    let (right_request, right_tail) = right_result.unwrap();
    relay_result.unwrap();

    assert_eq!(&left_response, b"right-before");
    assert_eq!(&right_request, b"left-before");
    assert_eq!(left_tail, b"right-after");
    assert_eq!(right_tail, b"left-after");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn full_splice_shares_endpoint_readiness_registrations() {
    let (_left_peer, left_relay) = tcp_pair().await.unwrap();
    let (_right_peer, right_relay) = tcp_pair().await.unwrap();
    let splice = SpliceRelay::new(
        left_relay.as_raw_fd(),
        right_relay.as_raw_fd(),
        DEFAULT_SPLICE_PIPE_SIZE,
    )
    .unwrap();

    assert!(Arc::ptr_eq(
        &splice.left_to_right.source,
        &splice.right_to_left.destination,
    ));
    assert!(Arc::ptr_eq(
        &splice.left_to_right.destination,
        &splice.right_to_left.source,
    ));
    assert_ne!(
        splice.left_to_right.pipe_read.as_raw_fd(),
        splice.right_to_left.pipe_read.as_raw_fd(),
    );
    assert_ne!(
        splice.left_to_right.pipe_write.as_raw_fd(),
        splice.right_to_left.pipe_write.as_raw_fd(),
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn splice_preserves_bidirectional_data_and_half_close() {
    let (mut left_peer, left_relay) = tcp_pair().await.unwrap();
    let (mut right_peer, right_relay) = tcp_pair().await.unwrap();
    let splice = SpliceRelay::new(
        left_relay.as_raw_fd(),
        right_relay.as_raw_fd(),
        DEFAULT_SPLICE_PIPE_SIZE,
    )
    .unwrap();

    let relay = tokio::spawn(async move {
        let _keep_alive = (left_relay, right_relay);
        splice.run().await
    });

    let left_payload = vec![0x5a; 1024 * 1024 + 17];
    let right_payload = vec![0xa5; 768 * 1024 + 31];
    let expected_left = right_payload.clone();
    let expected_right = left_payload.clone();

    let left = tokio::spawn(async move {
        left_peer.write_all(&left_payload).await?;
        left_peer.shutdown().await?;
        let mut received = Vec::new();
        left_peer.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    });
    let right = tokio::spawn(async move {
        right_peer.write_all(&right_payload).await?;
        right_peer.shutdown().await?;
        let mut received = Vec::new();
        right_peer.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    });

    let (left_result, right_result, relay_result) =
        tokio::try_join!(left, right, relay).unwrap();
    assert_eq!(left_result.unwrap(), expected_left);
    assert_eq!(right_result.unwrap(), expected_right);
    assert_eq!(
        relay_result.unwrap(),
        (expected_right.len() as u64, expected_left.len() as u64),
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn downlink_splice_preserves_bidirectional_data_and_half_close() {
    let (mut left_peer, mut left_relay) = tcp_pair().await.unwrap();
    let (mut right_peer, mut right_relay) = tcp_pair().await.unwrap();
    let downlink = SpliceDirection::new(
        right_relay.as_raw_fd(),
        left_relay.as_raw_fd(),
        DEFAULT_SPLICE_PIPE_SIZE,
    )
    .unwrap();

    let relay = tokio::spawn(async move {
        tokio::try_join!(
            copy_one_direction(&mut left_relay, &mut right_relay, 64 * 1024),
            downlink.run(),
        )
    });

    let upload = vec![0x31; 1024 * 1024 + 37];
    let download = vec![0x73; 768 * 1024 + 53];
    let expected_upload = upload.clone();
    let expected_download = download.clone();

    let left = tokio::spawn(async move {
        left_peer.write_all(&upload).await?;
        left_peer.shutdown().await?;
        let mut received = Vec::new();
        left_peer.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    });
    let right = tokio::spawn(async move {
        right_peer.write_all(&download).await?;
        right_peer.shutdown().await?;
        let mut received = Vec::new();
        right_peer.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    });

    let (left_result, right_result, relay_result) =
        tokio::try_join!(left, right, relay).unwrap();
    assert_eq!(left_result.unwrap(), expected_download);
    assert_eq!(right_result.unwrap(), expected_upload);
    assert_eq!(
        relay_result.unwrap(),
        (expected_upload.len() as u64, expected_download.len() as u64),
    );
}

#[cfg(target_os = "linux")]
async fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let connect = tokio::spawn(TcpStream::connect(address));
    let (accepted, _) = listener.accept().await?;
    let connected = connect.await.map_err(io::Error::other)??;
    Ok((connected, accepted))
}
