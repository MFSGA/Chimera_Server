use std::{
    io,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{info, warn};

use crate::async_stream::{AsyncStream, RawTcpRelayState};

const ENV_COPY_BUFFER_SIZE: &str = "CHIMERA_TCP_COPY_BUFFER_SIZE";
const ENV_RELAY_BACKEND: &str = "CHIMERA_TCP_RELAY_BACKEND";
const DEFAULT_COPY_BUFFER_SIZE: usize = 8 * 1024;
const MIN_COPY_BUFFER_SIZE: usize = 4 * 1024;
const MAX_COPY_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_STEPS_PER_POLL: usize = 16;

static COPY_BUFFER_SIZE: OnceLock<usize> = OnceLock::new();
static RELAY_BACKEND: OnceLock<RelayBackend> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayBackend {
    Copy,
    Handoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreludeOutcome {
    Complete {
        left_to_right: u64,
        right_to_left: u64,
    },
    RawReady {
        left_to_right: u64,
        right_to_left: u64,
    },
}

pub(crate) async fn copy_bidirectional<A, B>(
    left: &mut A,
    right: &mut B,
) -> io::Result<(u64, u64)>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let size = configured_copy_buffer_size();
    match configured_relay_backend() {
        RelayBackend::Copy => {
            tokio::io::copy_bidirectional_with_sizes(left, right, size, size).await
        }
        RelayBackend::Handoff => {
            match copy_until_raw_ready(left, right, size).await? {
                PreludeOutcome::Complete {
                    left_to_right,
                    right_to_left,
                } => Ok((left_to_right, right_to_left)),
                PreludeOutcome::RawReady {
                    left_to_right,
                    right_to_left,
                } => {
                    let (raw_left_to_right, raw_right_to_left) =
                        tokio::io::copy_bidirectional_with_sizes(
                            left, right, size, size,
                        )
                        .await?;
                    Ok((
                        left_to_right.saturating_add(raw_left_to_right),
                        right_to_left.saturating_add(raw_right_to_left),
                    ))
                }
            }
        }
    }
}

pub(crate) fn configured_copy_buffer_size() -> usize {
    *COPY_BUFFER_SIZE.get_or_init(|| {
        let configured = std::env::var(ENV_COPY_BUFFER_SIZE).ok();
        match parse_copy_buffer_size(configured.as_deref()) {
            Ok(size) => {
                info!(
                    copy_buffer_size = size,
                    source = if configured.is_some() {
                        ENV_COPY_BUFFER_SIZE
                    } else {
                        "default"
                    },
                    "configured TCP userspace relay buffer"
                );
                size
            }
            Err(error) => {
                warn!(
                    value = configured.as_deref().unwrap_or_default(),
                    default = DEFAULT_COPY_BUFFER_SIZE,
                    %error,
                    "invalid TCP userspace relay buffer; using default"
                );
                DEFAULT_COPY_BUFFER_SIZE
            }
        }
    })
}

fn configured_relay_backend() -> RelayBackend {
    *RELAY_BACKEND.get_or_init(|| {
        let configured = std::env::var(ENV_RELAY_BACKEND).ok();
        match parse_relay_backend(configured.as_deref()) {
            Ok(backend) => {
                info!(
                    ?backend,
                    source = if configured.is_some() {
                        ENV_RELAY_BACKEND
                    } else {
                        "default"
                    },
                    "configured TCP relay backend"
                );
                backend
            }
            Err(error) => {
                warn!(
                    value = configured.as_deref().unwrap_or_default(),
                    %error,
                    "invalid TCP relay backend; using copy"
                );
                RelayBackend::Copy
            }
        }
    })
}

fn parse_copy_buffer_size(value: Option<&str>) -> io::Result<usize> {
    let Some(value) = value else {
        return Ok(DEFAULT_COPY_BUFFER_SIZE);
    };
    let size = value.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {ENV_COPY_BUFFER_SIZE}: {error}"),
        )
    })?;
    if !(MIN_COPY_BUFFER_SIZE..=MAX_COPY_BUFFER_SIZE).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{ENV_COPY_BUFFER_SIZE} must be between {MIN_COPY_BUFFER_SIZE} and {MAX_COPY_BUFFER_SIZE} bytes"
            ),
        ));
    }
    Ok(size)
}

fn parse_relay_backend(value: Option<&str>) -> io::Result<RelayBackend> {
    match value.unwrap_or("copy") {
        "copy" => Ok(RelayBackend::Copy),
        "handoff" => Ok(RelayBackend::Handoff),
        value => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {ENV_RELAY_BACKEND} value {value:?}"),
        )),
    }
}

async fn copy_until_raw_ready<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
) -> io::Result<PreludeOutcome>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let mut left_to_right = CopyDirection::new(buffer_size);
    let mut right_to_left = CopyDirection::new(buffer_size);

    std::future::poll_fn(|cx| {
        for _ in 0..MAX_STEPS_PER_POLL {
            if left_to_right.is_idle()
                && right_to_left.is_idle()
                && raw_relay_ready(left, right)
            {
                return Poll::Ready(Ok(PreludeOutcome::RawReady {
                    left_to_right: left_to_right.transferred,
                    right_to_left: right_to_left.transferred,
                }));
            }

            let left_step =
                poll_copy_direction(cx, left, right, &mut left_to_right)?;
            let right_step =
                poll_copy_direction(cx, right, left, &mut right_to_left)?;

            if left_to_right.is_complete() && right_to_left.is_complete() {
                return Poll::Ready(Ok(PreludeOutcome::Complete {
                    left_to_right: left_to_right.transferred,
                    right_to_left: right_to_left.transferred,
                }));
            }

            if left_to_right.is_idle()
                && right_to_left.is_idle()
                && raw_relay_ready(left, right)
            {
                return Poll::Ready(Ok(PreludeOutcome::RawReady {
                    left_to_right: left_to_right.transferred,
                    right_to_left: right_to_left.transferred,
                }));
            }

            if !left_step.made_progress && !right_step.made_progress {
                return Poll::Pending;
            }
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

fn raw_relay_ready<A, B>(left: &A, right: &B) -> bool
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    left.raw_tcp_relay_state() == RawTcpRelayState::Ready
        && right.raw_tcp_relay_state() == RawTcpRelayState::Ready
}

#[derive(Debug)]
struct CopyDirection {
    buffer: Box<[u8]>,
    position: usize,
    filled: usize,
    read_eof: bool,
    shutdown_done: bool,
    transferred: u64,
}

impl CopyDirection {
    fn new(buffer_size: usize) -> Self {
        Self {
            buffer: vec![0_u8; buffer_size].into_boxed_slice(),
            position: 0,
            filled: 0,
            read_eof: false,
            shutdown_done: false,
            transferred: 0,
        }
    }

    fn is_idle(&self) -> bool {
        self.position == self.filled
    }

    fn is_complete(&self) -> bool {
        self.read_eof && self.shutdown_done && self.is_idle()
    }
}

#[derive(Debug, Clone, Copy)]
struct StepResult {
    made_progress: bool,
}

fn poll_copy_direction<R, W>(
    cx: &mut Context<'_>,
    reader: &mut R,
    writer: &mut W,
    state: &mut CopyDirection,
) -> io::Result<StepResult>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut made_progress = false;

    while state.position < state.filled {
        match Pin::new(&mut *writer)
            .poll_write(cx, &state.buffer[state.position..state.filled])
        {
            Poll::Ready(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
            Poll::Ready(Ok(written)) => {
                state.position += written;
                state.transferred = state.transferred.saturating_add(written as u64);
                made_progress = true;
            }
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Ok(StepResult { made_progress }),
        }
    }

    if state.position == state.filled {
        state.position = 0;
        state.filled = 0;
    }

    if state.read_eof {
        if !state.shutdown_done {
            match Pin::new(writer).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    state.shutdown_done = true;
                    made_progress = true;
                }
                Poll::Ready(Err(error)) => return Err(error),
                Poll::Pending => return Ok(StepResult { made_progress }),
            }
        }
        return Ok(StepResult { made_progress });
    }

    let mut read_buf = ReadBuf::new(&mut state.buffer);
    match Pin::new(reader).poll_read(cx, &mut read_buf) {
        Poll::Ready(Ok(())) => {
            state.filled = read_buf.filled().len();
            if state.filled == 0 {
                state.read_eof = true;
            }
            Ok(StepResult {
                made_progress: true,
            })
        }
        Poll::Ready(Err(error)) => Err(error),
        Poll::Pending => Ok(StepResult { made_progress }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    };

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

    #[test]
    fn default_matches_tokio_copy_bidirectional_default() {
        assert_eq!(parse_copy_buffer_size(None).unwrap(), 8 * 1024);
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

    #[test]
    fn parses_relay_backend() {
        assert_eq!(parse_relay_backend(None).unwrap(), RelayBackend::Copy);
        assert_eq!(
            parse_relay_backend(Some("handoff")).unwrap(),
            RelayBackend::Handoff,
        );
        assert!(parse_relay_backend(Some("splice")).is_err());
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
}
