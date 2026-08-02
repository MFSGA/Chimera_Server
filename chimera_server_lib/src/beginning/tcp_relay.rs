use std::{
    io,
    pin::Pin,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{info, warn};

use crate::async_stream::{AsyncStream, RawTcpRelayState};

const ENV_COPY_BUFFER_SIZE: &str = "CHIMERA_TCP_COPY_BUFFER_SIZE";
const ENV_RELAY_BACKEND: &str = "CHIMERA_TCP_RELAY_BACKEND";
#[cfg(target_os = "linux")]
const ENV_SPLICE_PIPE_SIZE: &str = "CHIMERA_TCP_SPLICE_PIPE_SIZE";
#[cfg(target_os = "linux")]
const ENV_AUTO_MAX_CONNECTIONS: &str = "CHIMERA_TCP_AUTO_MAX_CONNECTIONS";
const DEFAULT_COPY_BUFFER_SIZE: usize = 32 * 1024;
const MIN_COPY_BUFFER_SIZE: usize = 4 * 1024;
const MAX_COPY_BUFFER_SIZE: usize = 1024 * 1024;
const MAX_STEPS_PER_POLL: usize = 16;
#[cfg(target_os = "linux")]
const DEFAULT_SPLICE_PIPE_SIZE: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const MIN_SPLICE_PIPE_SIZE: usize = 4 * 1024;
#[cfg(target_os = "linux")]
const MAX_SPLICE_PIPE_SIZE: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const DEFAULT_AUTO_MAX_CONNECTIONS: usize = 8;
#[cfg(target_os = "linux")]
const AUTO_MAX_CONNECTIONS_LIMIT: usize = 4096;

static COPY_BUFFER_SIZE: OnceLock<usize> = OnceLock::new();
static RELAY_BACKEND: OnceLock<RelayBackend> = OnceLock::new();
#[cfg(target_os = "linux")]
static SPLICE_PIPE_SIZE: OnceLock<usize> = OnceLock::new();
#[cfg(target_os = "linux")]
static AUTO_MAX_CONNECTIONS: OnceLock<usize> = OnceLock::new();
#[cfg(target_os = "linux")]
static ACTIVE_AUTO_RELAYS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayBackend {
    Copy,
    Handoff,
    #[cfg(target_os = "linux")]
    Splice,
    #[cfg(target_os = "linux")]
    SpliceDownlink,
    #[cfg(target_os = "linux")]
    Auto,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpRelayResult {
    pub(crate) left_to_right: u64,
    pub(crate) right_to_left: u64,
    pub(crate) bypassed_left_to_right: u64,
    pub(crate) bypassed_right_to_left: u64,
}

impl TcpRelayResult {
    fn userspace(left_to_right: u64, right_to_left: u64) -> Self {
        Self {
            left_to_right,
            right_to_left,
            bypassed_left_to_right: 0,
            bypassed_right_to_left: 0,
        }
    }

    fn with_bypassed(
        prelude_left_to_right: u64,
        prelude_right_to_left: u64,
        bypassed_left_to_right: u64,
        bypassed_right_to_left: u64,
    ) -> Self {
        Self {
            left_to_right: prelude_left_to_right
                .saturating_add(bypassed_left_to_right),
            right_to_left: prelude_right_to_left
                .saturating_add(bypassed_right_to_left),
            bypassed_left_to_right,
            bypassed_right_to_left,
        }
    }
}

pub(crate) async fn copy_bidirectional<A, B>(
    left: &mut A,
    right: &mut B,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let size = configured_copy_buffer_size();
    let backend = configured_relay_backend();
    #[cfg(target_os = "linux")]
    let _auto_guard =
        matches!(backend, RelayBackend::Auto).then(AutoRelayGuard::acquire);
    match backend {
        RelayBackend::Copy => {
            let (left_to_right, right_to_left) =
                tokio::io::copy_bidirectional_with_sizes(left, right, size, size)
                    .await?;
            Ok(TcpRelayResult::userspace(left_to_right, right_to_left))
        }
        RelayBackend::Handoff => {
            relay_after_handoff_with_userspace_copy(left, right, size).await
        }
        #[cfg(target_os = "linux")]
        RelayBackend::Splice => {
            relay_after_handoff_with_splice(left, right, size).await
        }
        #[cfg(target_os = "linux")]
        RelayBackend::SpliceDownlink => {
            relay_after_handoff_with_downlink_splice(left, right, size, None).await
        }
        #[cfg(target_os = "linux")]
        RelayBackend::Auto => {
            relay_after_handoff_with_downlink_splice(
                left,
                right,
                size,
                Some(configured_auto_max_connections()),
            )
            .await
        }
    }
}

async fn relay_after_handoff_with_userspace_copy<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    match copy_until_raw_ready(left, right, buffer_size).await? {
        PreludeOutcome::Complete {
            left_to_right,
            right_to_left,
        } => Ok(TcpRelayResult::userspace(left_to_right, right_to_left)),
        PreludeOutcome::RawReady {
            left_to_right,
            right_to_left,
        } => {
            let (remaining_left_to_right, remaining_right_to_left) =
                tokio::io::copy_bidirectional_with_sizes(
                    left,
                    right,
                    buffer_size,
                    buffer_size,
                )
                .await?;
            Ok(TcpRelayResult::userspace(
                left_to_right.saturating_add(remaining_left_to_right),
                right_to_left.saturating_add(remaining_right_to_left),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
async fn relay_after_handoff_with_splice<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    match copy_until_raw_ready(left, right, buffer_size).await? {
        PreludeOutcome::Complete {
            left_to_right,
            right_to_left,
        } => Ok(TcpRelayResult::userspace(left_to_right, right_to_left)),
        PreludeOutcome::RawReady {
            left_to_right,
            right_to_left,
        } => {
            let Some(left_fd) = left.raw_tcp_fd() else {
                warn!(
                    "raw relay became ready without a left TCP fd; falling back to copy"
                );
                return continue_userspace_copy(
                    left,
                    right,
                    buffer_size,
                    left_to_right,
                    right_to_left,
                )
                .await;
            };
            let Some(right_fd) = right.raw_tcp_fd() else {
                warn!(
                    "raw relay became ready without a right TCP fd; falling back to copy"
                );
                return continue_userspace_copy(
                    left,
                    right,
                    buffer_size,
                    left_to_right,
                    right_to_left,
                )
                .await;
            };

            let splice = match SpliceRelay::new(
                left_fd,
                right_fd,
                configured_splice_pipe_size(),
            ) {
                Ok(splice) => splice,
                Err(error) => {
                    warn!(%error, "failed to initialize splice relay; falling back to copy");
                    return continue_userspace_copy(
                        left,
                        right,
                        buffer_size,
                        left_to_right,
                        right_to_left,
                    )
                    .await;
                }
            };

            let (bypassed_left_to_right, bypassed_right_to_left) =
                splice.run().await?;
            Ok(TcpRelayResult::with_bypassed(
                left_to_right,
                right_to_left,
                bypassed_left_to_right,
                bypassed_right_to_left,
            ))
        }
    }
}

#[cfg(target_os = "linux")]
async fn relay_after_handoff_with_downlink_splice<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
    auto_connection_limit: Option<usize>,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    match copy_until_raw_ready(left, right, buffer_size).await? {
        PreludeOutcome::Complete {
            left_to_right,
            right_to_left,
        } => Ok(TcpRelayResult::userspace(left_to_right, right_to_left)),
        PreludeOutcome::RawReady {
            left_to_right,
            right_to_left,
        } => {
            if auto_connection_limit.is_some_and(|limit| {
                limit == 0 || ACTIVE_AUTO_RELAYS.load(Ordering::Acquire) > limit
            }) {
                return continue_userspace_copy(
                    left,
                    right,
                    buffer_size,
                    left_to_right,
                    right_to_left,
                )
                .await;
            }

            let (Some(left_fd), Some(right_fd)) =
                (left.raw_tcp_fd(), right.raw_tcp_fd())
            else {
                warn!(
                    "raw relay became ready without both TCP fds; falling back to copy"
                );
                return continue_userspace_copy(
                    left,
                    right,
                    buffer_size,
                    left_to_right,
                    right_to_left,
                )
                .await;
            };

            let downlink = match SpliceDirection::new(
                right_fd,
                left_fd,
                configured_splice_pipe_size(),
            ) {
                Ok(direction) => direction,
                Err(error) => {
                    warn!(%error, "failed to initialize downlink splice; falling back to copy");
                    return continue_userspace_copy(
                        left,
                        right,
                        buffer_size,
                        left_to_right,
                        right_to_left,
                    )
                    .await;
                }
            };

            let (remaining_left_to_right, bypassed_right_to_left) = tokio::try_join!(
                copy_one_direction(left, right, buffer_size),
                downlink.run(),
            )?;
            Ok(TcpRelayResult::with_bypassed(
                left_to_right.saturating_add(remaining_left_to_right),
                right_to_left,
                0,
                bypassed_right_to_left,
            ))
        }
    }
}

async fn copy_one_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer_size: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buffered_reader =
        tokio::io::BufReader::with_capacity(buffer_size, reader);
    let copied = tokio::io::copy_buf(&mut buffered_reader, &mut *writer).await?;
    writer.flush().await?;
    writer.shutdown().await?;
    Ok(copied)
}

async fn continue_userspace_copy<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
    prelude_left_to_right: u64,
    prelude_right_to_left: u64,
) -> io::Result<TcpRelayResult>
where
    A: AsyncStream + ?Sized,
    B: AsyncStream + ?Sized,
{
    let (left_to_right, right_to_left) = tokio::io::copy_bidirectional_with_sizes(
        left,
        right,
        buffer_size,
        buffer_size,
    )
    .await?;
    Ok(TcpRelayResult::userspace(
        prelude_left_to_right.saturating_add(left_to_right),
        prelude_right_to_left.saturating_add(right_to_left),
    ))
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
                    "invalid TCP relay backend; using handoff"
                );
                RelayBackend::Handoff
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

#[cfg(target_os = "linux")]
struct AutoRelayGuard;

#[cfg(target_os = "linux")]
impl AutoRelayGuard {
    fn acquire() -> Self {
        ACTIVE_AUTO_RELAYS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

#[cfg(target_os = "linux")]
impl Drop for AutoRelayGuard {
    fn drop(&mut self) {
        ACTIVE_AUTO_RELAYS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(target_os = "linux")]
fn configured_auto_max_connections() -> usize {
    *AUTO_MAX_CONNECTIONS.get_or_init(|| {
        let configured = std::env::var(ENV_AUTO_MAX_CONNECTIONS).ok();
        match parse_auto_max_connections(configured.as_deref()) {
            Ok(limit) => {
                info!(
                    auto_max_connections = limit,
                    source = if configured.is_some() {
                        ENV_AUTO_MAX_CONNECTIONS
                    } else {
                        "default"
                    },
                    "configured adaptive splice connection threshold"
                );
                limit
            }
            Err(error) => {
                warn!(
                    value = configured.as_deref().unwrap_or_default(),
                    default = DEFAULT_AUTO_MAX_CONNECTIONS,
                    %error,
                    "invalid adaptive splice connection threshold; using default"
                );
                DEFAULT_AUTO_MAX_CONNECTIONS
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn parse_auto_max_connections(value: Option<&str>) -> io::Result<usize> {
    let Some(value) = value else {
        return Ok(DEFAULT_AUTO_MAX_CONNECTIONS);
    };
    let limit = value.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {ENV_AUTO_MAX_CONNECTIONS}: {error}"),
        )
    })?;
    if limit > AUTO_MAX_CONNECTIONS_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{ENV_AUTO_MAX_CONNECTIONS} must not exceed {AUTO_MAX_CONNECTIONS_LIMIT}"
            ),
        ));
    }
    Ok(limit)
}

#[cfg(target_os = "linux")]
fn configured_splice_pipe_size() -> usize {
    *SPLICE_PIPE_SIZE.get_or_init(|| {
        let configured = std::env::var(ENV_SPLICE_PIPE_SIZE).ok();
        match parse_splice_pipe_size(configured.as_deref()) {
            Ok(size) => {
                info!(
                    splice_pipe_size = size,
                    source = if configured.is_some() {
                        ENV_SPLICE_PIPE_SIZE
                    } else {
                        "default"
                    },
                    "configured TCP splice pipe capacity"
                );
                size
            }
            Err(error) => {
                warn!(
                    value = configured.as_deref().unwrap_or_default(),
                    default = DEFAULT_SPLICE_PIPE_SIZE,
                    %error,
                    "invalid TCP splice pipe capacity; using default"
                );
                DEFAULT_SPLICE_PIPE_SIZE
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn parse_splice_pipe_size(value: Option<&str>) -> io::Result<usize> {
    let Some(value) = value else {
        return Ok(DEFAULT_SPLICE_PIPE_SIZE);
    };
    let size = value.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {ENV_SPLICE_PIPE_SIZE}: {error}"),
        )
    })?;
    if !(MIN_SPLICE_PIPE_SIZE..=MAX_SPLICE_PIPE_SIZE).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{ENV_SPLICE_PIPE_SIZE} must be between {MIN_SPLICE_PIPE_SIZE} and {MAX_SPLICE_PIPE_SIZE} bytes"
            ),
        ));
    }
    Ok(size)
}

fn parse_relay_backend(value: Option<&str>) -> io::Result<RelayBackend> {
    match value.unwrap_or("handoff") {
        "copy" => Ok(RelayBackend::Copy),
        "handoff" => Ok(RelayBackend::Handoff),
        #[cfg(target_os = "linux")]
        "splice" => Ok(RelayBackend::Splice),
        #[cfg(target_os = "linux")]
        "splice-downlink" => Ok(RelayBackend::SpliceDownlink),
        #[cfg(target_os = "linux")]
        "auto" => Ok(RelayBackend::Auto),
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
    flush_pending: bool,
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
            flush_pending: false,
            shutdown_done: false,
            transferred: 0,
        }
    }

    fn is_idle(&self) -> bool {
        self.position == self.filled && !self.flush_pending
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
                state.flush_pending = true;
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

    if state.flush_pending {
        match Pin::new(&mut *writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                state.flush_pending = false;
                made_progress = true;
            }
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Ok(StepResult { made_progress }),
        }
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

#[cfg(target_os = "linux")]
struct SpliceRelay {
    left_to_right: SpliceDirection,
    right_to_left: SpliceDirection,
}

#[cfg(target_os = "linux")]
impl SpliceRelay {
    fn new(
        left_fd: RawFd,
        right_fd: RawFd,
        requested_pipe_size: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            left_to_right: SpliceDirection::new(
                left_fd,
                right_fd,
                requested_pipe_size,
            )?,
            right_to_left: SpliceDirection::new(
                right_fd,
                left_fd,
                requested_pipe_size,
            )?,
        })
    }

    async fn run(self) -> io::Result<(u64, u64)> {
        let Self {
            left_to_right,
            right_to_left,
        } = self;
        tokio::try_join!(left_to_right.run(), right_to_left.run())
    }
}

#[cfg(target_os = "linux")]
struct SpliceDirection {
    source: AsyncFd<OwnedFd>,
    destination: AsyncFd<OwnedFd>,
    pipe_read: OwnedFd,
    pipe_write: OwnedFd,
    pipe_capacity: usize,
}

#[cfg(target_os = "linux")]
impl SpliceDirection {
    fn new(
        source_fd: RawFd,
        destination_fd: RawFd,
        requested_pipe_size: usize,
    ) -> io::Result<Self> {
        let source = AsyncFd::new(duplicate_fd(source_fd)?)?;
        let destination = AsyncFd::new(duplicate_fd(destination_fd)?)?;
        let (pipe_read, pipe_write, pipe_capacity) =
            nonblocking_pipe(requested_pipe_size)?;
        Ok(Self {
            source,
            destination,
            pipe_read,
            pipe_write,
            pipe_capacity,
        })
    }

    async fn run(self) -> io::Result<u64> {
        let mut pending = 0_usize;
        let mut transferred = 0_u64;

        loop {
            if pending > 0 {
                let pipe_read_fd = self.pipe_read.as_raw_fd();
                let mut writable = self.destination.writable().await?;
                match writable.try_io(|destination| {
                    splice_once(
                        pipe_read_fd,
                        destination.get_ref().as_raw_fd(),
                        pending,
                    )
                }) {
                    Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(Ok(written)) => {
                        pending -= written;
                        transferred = transferred.saturating_add(written as u64);
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_would_block) => continue,
                }
                continue;
            }

            let pipe_write_fd = self.pipe_write.as_raw_fd();
            let mut readable = self.source.readable().await?;
            match readable.try_io(|source| {
                splice_once(
                    source.get_ref().as_raw_fd(),
                    pipe_write_fd,
                    self.pipe_capacity,
                )
            }) {
                Ok(Ok(0)) => {
                    shutdown_write(self.destination.get_ref().as_raw_fd())?;
                    return Ok(transferred);
                }
                Ok(Ok(read)) => pending = read,
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(target_os = "linux")]
fn nonblocking_pipe(
    requested_capacity: usize,
) -> io::Result<(OwnedFd, OwnedFd, usize)> {
    let mut fds = [-1; 2];
    let result =
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let pipe_read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let pipe_write = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    let current_capacity = pipe_capacity(pipe_write.as_raw_fd())?;
    if requested_capacity > current_capacity {
        let _ = unsafe {
            libc::fcntl(
                pipe_write.as_raw_fd(),
                libc::F_SETPIPE_SZ,
                requested_capacity as libc::c_int,
            )
        };
    }
    let actual_capacity = pipe_capacity(pipe_write.as_raw_fd())?;
    Ok((pipe_read, pipe_write, actual_capacity))
}

#[cfg(target_os = "linux")]
fn pipe_capacity(fd: RawFd) -> io::Result<usize> {
    let capacity = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
    if capacity < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(capacity as usize)
}

#[cfg(target_os = "linux")]
fn splice_once(source: RawFd, destination: RawFd, len: usize) -> io::Result<usize> {
    loop {
        let result = unsafe {
            libc::splice(
                source,
                std::ptr::null_mut(),
                destination,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

#[cfg(target_os = "linux")]
fn shutdown_write(fd: RawFd) -> io::Result<()> {
    let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENOTCONN | libc::EPIPE)) {
        return Ok(());
    }
    Err(error)
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn default_uses_measured_thirty_two_kibibyte_buffer() {
        assert_eq!(parse_copy_buffer_size(None).unwrap(), 32 * 1024);
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
    fn adaptive_relay_guard_tracks_and_releases_active_connections() {
        assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 0);
        let first = AutoRelayGuard::acquire();
        assert_eq!(ACTIVE_AUTO_RELAYS.load(Ordering::Acquire), 1);
        let second = AutoRelayGuard::acquire();
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
        let (_read, write, actual) =
            nonblocking_pipe(DEFAULT_SPLICE_PIPE_SIZE).unwrap();
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
            let step =
                poll_copy_direction(cx, &mut reader, &mut writer, &mut state)?;
            if state.is_idle()
                && visible.lock().unwrap().as_slice() == b"server-hello"
            {
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
}
