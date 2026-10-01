use std::{
    io,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};

use crate::async_stream::AsyncStream;

#[cfg(target_os = "linux")]
mod linux_splice;
mod prelude;

#[cfg(target_os = "linux")]
use linux_splice::{SpliceDirection, SpliceRelay};
#[cfg(all(test, target_os = "linux"))]
use linux_splice::{nonblocking_pipe, pipe_capacity};
use prelude::copy_until_raw_ready;
#[cfg(test)]
use prelude::{CopyDirection, poll_copy_direction};

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
// The auto backend is limited to a small number of splice relays. For its one
// remaining userspace direction, 64 KiB cuts send syscalls roughly in half vs
// the 32 KiB general-purpose default without paying that footprint on fallback
// or high-concurrency all-userspace relays.
const DEFAULT_AUTO_UPLINK_COPY_BUFFER_SIZE: usize = 64 * 1024;
#[cfg(target_os = "linux")]
// 128 KiB halves the steady-state splice syscall rate for bulk loopback
// transfers compared with Linux's common 64 KiB pipe capacity, while keeping
// the worst-case two-direction pipe footprint bounded to 256 KiB per relay.
// Higher-throughput deployments can still override this with
// CHIMERA_TCP_SPLICE_PIPE_SIZE.
const DEFAULT_SPLICE_PIPE_SIZE: usize = 128 * 1024;
#[cfg(target_os = "linux")]
const MIN_SPLICE_PIPE_SIZE: usize = 4 * 1024;
#[cfg(target_os = "linux")]
const MAX_SPLICE_PIPE_SIZE: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
// Controlled raw-ready contention shows that 32 concurrent downlink-splice
// relays materially reduce CPU for 192-256 KiB flows versus eight, while
// 64-128 KiB flows remain effectively neutral. Keep the cap configurable for
// hosts where pipe memory or scheduler pressure makes a lower value preferable.
const DEFAULT_AUTO_MAX_CONNECTIONS: usize = 32;
#[cfg(target_os = "linux")]
const AUTO_MAX_CONNECTIONS_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct CopyBufferConfig {
    size: usize,
    explicit: bool,
}

static COPY_BUFFER_CONFIG: OnceLock<CopyBufferConfig> = OnceLock::new();
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

impl RelayBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Handoff => "handoff",
            #[cfg(target_os = "linux")]
            Self::Splice => "splice",
            #[cfg(target_os = "linux")]
            Self::SpliceDownlink => "splice-downlink",
            #[cfg(target_os = "linux")]
            Self::Auto => "auto",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayEffectivePath {
    UserspaceCopy,
    #[cfg(target_os = "linux")]
    Splice,
    #[cfg(target_os = "linux")]
    SpliceDownlink,
}

impl RelayEffectivePath {
    fn as_str(self) -> &'static str {
        match self {
            Self::UserspaceCopy => "userspace-copy",
            #[cfg(target_os = "linux")]
            Self::Splice => "splice",
            #[cfg(target_os = "linux")]
            Self::SpliceDownlink => "splice-downlink",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayFallbackReason {
    DirectNotReached,
    #[cfg(target_os = "linux")]
    AutoConnectionLimit,
    #[cfg(target_os = "linux")]
    MissingLeftTcpFd,
    #[cfg(target_os = "linux")]
    MissingRightTcpFd,
    #[cfg(target_os = "linux")]
    MissingTcpFds,
    #[cfg(target_os = "linux")]
    SpliceInitialization,
}

impl RelayFallbackReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::DirectNotReached => "direct-not-reached",
            #[cfg(target_os = "linux")]
            Self::AutoConnectionLimit => "auto-connection-limit",
            #[cfg(target_os = "linux")]
            Self::MissingLeftTcpFd => "missing-left-tcp-fd",
            #[cfg(target_os = "linux")]
            Self::MissingRightTcpFd => "missing-right-tcp-fd",
            #[cfg(target_os = "linux")]
            Self::MissingTcpFds => "missing-tcp-fds",
            #[cfg(target_os = "linux")]
            Self::SpliceInitialization => "splice-initialization",
        }
    }
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
    configured_backend: RelayBackend,
    effective_path: RelayEffectivePath,
    fallback_reason: Option<RelayFallbackReason>,
}

impl TcpRelayResult {
    fn userspace(
        configured_backend: RelayBackend,
        left_to_right: u64,
        right_to_left: u64,
    ) -> Self {
        Self {
            left_to_right,
            right_to_left,
            bypassed_left_to_right: 0,
            bypassed_right_to_left: 0,
            configured_backend,
            effective_path: RelayEffectivePath::UserspaceCopy,
            fallback_reason: None,
        }
    }

    pub(super) fn policy_userspace(left_to_right: u64, right_to_left: u64) -> Self {
        Self::userspace(configured_relay_backend(), left_to_right, right_to_left)
    }

    fn userspace_fallback(
        configured_backend: RelayBackend,
        fallback_reason: RelayFallbackReason,
        left_to_right: u64,
        right_to_left: u64,
    ) -> Self {
        let mut result =
            Self::userspace(configured_backend, left_to_right, right_to_left);
        result.fallback_reason = Some(fallback_reason);
        result
    }

    fn with_bypassed(
        configured_backend: RelayBackend,
        effective_path: RelayEffectivePath,
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
            configured_backend,
            effective_path,
            fallback_reason: None,
        }
    }

    pub(crate) fn configured_backend(&self) -> &'static str {
        self.configured_backend.as_str()
    }

    pub(crate) fn effective_path(&self) -> &'static str {
        self.effective_path.as_str()
    }

    pub(crate) fn fallback_reason(&self) -> Option<&'static str> {
        self.fallback_reason.map(RelayFallbackReason::as_str)
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
    let copy_buffer = configured_copy_buffer();
    let size = copy_buffer.size;
    let backend = configured_relay_backend();
    match backend {
        RelayBackend::Copy => {
            let (left_to_right, right_to_left) =
                tokio::io::copy_bidirectional_with_sizes(left, right, size, size)
                    .await?;
            Ok(TcpRelayResult::userspace(
                RelayBackend::Copy,
                left_to_right,
                right_to_left,
            ))
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
            relay_after_handoff_with_downlink_splice(
                left,
                right,
                size,
                size,
                RelayBackend::SpliceDownlink,
                None,
            )
            .await
        }
        #[cfg(target_os = "linux")]
        RelayBackend::Auto => {
            relay_after_handoff_with_downlink_splice(
                left,
                right,
                size,
                auto_uplink_copy_buffer_size(copy_buffer),
                RelayBackend::Auto,
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
        } => Ok(TcpRelayResult::userspace_fallback(
            RelayBackend::Handoff,
            RelayFallbackReason::DirectNotReached,
            left_to_right,
            right_to_left,
        )),
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
                RelayBackend::Handoff,
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
        } => Ok(TcpRelayResult::userspace_fallback(
            RelayBackend::Splice,
            RelayFallbackReason::DirectNotReached,
            left_to_right,
            right_to_left,
        )),
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
                    RelayBackend::Splice,
                    RelayFallbackReason::MissingLeftTcpFd,
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
                    RelayBackend::Splice,
                    RelayFallbackReason::MissingRightTcpFd,
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
                        RelayBackend::Splice,
                        RelayFallbackReason::SpliceInitialization,
                        left_to_right,
                        right_to_left,
                    )
                    .await;
                }
            };

            let (bypassed_left_to_right, bypassed_right_to_left) =
                splice.run().await?;
            Ok(TcpRelayResult::with_bypassed(
                RelayBackend::Splice,
                RelayEffectivePath::Splice,
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
    uplink_buffer_size: usize,
    configured_backend: RelayBackend,
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
        } => Ok(TcpRelayResult::userspace_fallback(
            configured_backend,
            RelayFallbackReason::DirectNotReached,
            left_to_right,
            right_to_left,
        )),
        PreludeOutcome::RawReady {
            left_to_right,
            right_to_left,
        } => {
            let auto_guard = if let Some(limit) = auto_connection_limit {
                let Some(guard) = AutoRelayGuard::try_acquire(limit) else {
                    return continue_userspace_copy(
                        left,
                        right,
                        buffer_size,
                        configured_backend,
                        RelayFallbackReason::AutoConnectionLimit,
                        left_to_right,
                        right_to_left,
                    )
                    .await;
                };
                Some(guard)
            } else {
                None
            };

            let (Some(left_fd), Some(right_fd)) =
                (left.raw_tcp_fd(), right.raw_tcp_fd())
            else {
                drop(auto_guard);
                warn!(
                    "raw relay became ready without both TCP fds; falling back to copy"
                );
                return continue_userspace_copy(
                    left,
                    right,
                    buffer_size,
                    configured_backend,
                    RelayFallbackReason::MissingTcpFds,
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
                    drop(auto_guard);
                    warn!(%error, "failed to initialize downlink splice; falling back to copy");
                    return continue_userspace_copy(
                        left,
                        right,
                        buffer_size,
                        configured_backend,
                        RelayFallbackReason::SpliceInitialization,
                        left_to_right,
                        right_to_left,
                    )
                    .await;
                }
            };

            let (remaining_left_to_right, bypassed_right_to_left) = tokio::try_join!(
                copy_one_direction(left, right, uplink_buffer_size),
                downlink.run(),
            )?;
            Ok(TcpRelayResult::with_bypassed(
                configured_backend,
                RelayEffectivePath::SpliceDownlink,
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
    // `copy_buf` flushes the writer after observing EOF. Avoid polling the
    // entire wrapper chain a second time before the required half-close.
    writer.shutdown().await?;
    Ok(copied)
}

async fn continue_userspace_copy<A, B>(
    left: &mut A,
    right: &mut B,
    buffer_size: usize,
    configured_backend: RelayBackend,
    fallback_reason: RelayFallbackReason,
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
    Ok(TcpRelayResult::userspace_fallback(
        configured_backend,
        fallback_reason,
        prelude_left_to_right.saturating_add(left_to_right),
        prelude_right_to_left.saturating_add(right_to_left),
    ))
}

pub(super) fn configured_copy_buffer_size() -> usize {
    configured_copy_buffer().size
}

fn configured_copy_buffer() -> CopyBufferConfig {
    *COPY_BUFFER_CONFIG.get_or_init(|| {
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
                CopyBufferConfig {
                    size,
                    explicit: configured.is_some(),
                }
            }
            Err(error) => {
                warn!(
                    value = configured.as_deref().unwrap_or_default(),
                    default = DEFAULT_COPY_BUFFER_SIZE,
                    %error,
                    "invalid TCP userspace relay buffer; using default"
                );
                CopyBufferConfig {
                    size: DEFAULT_COPY_BUFFER_SIZE,
                    explicit: false,
                }
            }
        }
    })
}

#[cfg(target_os = "linux")]
fn auto_uplink_copy_buffer_size(config: CopyBufferConfig) -> usize {
    if config.explicit {
        config.size
    } else {
        DEFAULT_AUTO_UPLINK_COPY_BUFFER_SIZE
    }
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
    fn try_acquire(limit: usize) -> Option<Self> {
        if limit == 0 {
            return None;
        }

        let previous = ACTIVE_AUTO_RELAYS.fetch_add(1, Ordering::AcqRel);
        if previous >= limit {
            ACTIVE_AUTO_RELAYS.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(Self)
        }
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

#[cfg(test)]
mod tests;
