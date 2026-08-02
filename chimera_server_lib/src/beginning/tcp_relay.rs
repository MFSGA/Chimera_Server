use std::{io, sync::OnceLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

const ENV_COPY_BUFFER_SIZE: &str = "CHIMERA_TCP_COPY_BUFFER_SIZE";
const DEFAULT_COPY_BUFFER_SIZE: usize = 8 * 1024;
const MIN_COPY_BUFFER_SIZE: usize = 4 * 1024;
const MAX_COPY_BUFFER_SIZE: usize = 1024 * 1024;

static COPY_BUFFER_SIZE: OnceLock<usize> = OnceLock::new();

pub(crate) async fn copy_bidirectional<A, B>(
    left: &mut A,
    right: &mut B,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let size = configured_copy_buffer_size();
    tokio::io::copy_bidirectional_with_sizes(left, right, size, size).await
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
