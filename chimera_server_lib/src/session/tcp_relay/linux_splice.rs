use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};

use tokio::io::unix::AsyncFd;

pub(super) struct SpliceRelay {
    pub(super) left_to_right: SpliceDirection,
    pub(super) right_to_left: SpliceDirection,
}

impl SpliceRelay {
    pub(super) fn new(
        left_fd: RawFd,
        right_fd: RawFd,
        requested_pipe_size: usize,
    ) -> io::Result<Self> {
        let left = Arc::new(AsyncFd::new(duplicate_fd(left_fd)?)?);
        let right = Arc::new(AsyncFd::new(duplicate_fd(right_fd)?)?);
        Ok(Self {
            left_to_right: SpliceDirection::with_endpoints(
                Arc::clone(&left),
                Arc::clone(&right),
                requested_pipe_size,
            )?,
            right_to_left: SpliceDirection::with_endpoints(
                right,
                left,
                requested_pipe_size,
            )?,
        })
    }

    pub(super) async fn run(self) -> io::Result<(u64, u64)> {
        let Self {
            left_to_right,
            right_to_left,
        } = self;
        tokio::try_join!(left_to_right.run(), right_to_left.run())
    }
}

pub(super) struct SpliceDirection {
    pub(super) source: Arc<AsyncFd<OwnedFd>>,
    pub(super) destination: Arc<AsyncFd<OwnedFd>>,
    pub(super) pipe_read: OwnedFd,
    pub(super) pipe_write: OwnedFd,
    pipe_capacity: usize,
}

impl SpliceDirection {
    pub(super) fn new(
        source_fd: RawFd,
        destination_fd: RawFd,
        requested_pipe_size: usize,
    ) -> io::Result<Self> {
        Self::with_endpoints(
            Arc::new(AsyncFd::new(duplicate_fd(source_fd)?)?),
            Arc::new(AsyncFd::new(duplicate_fd(destination_fd)?)?),
            requested_pipe_size,
        )
    }

    fn with_endpoints(
        source: Arc<AsyncFd<OwnedFd>>,
        destination: Arc<AsyncFd<OwnedFd>>,
        requested_pipe_size: usize,
    ) -> io::Result<Self> {
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

    pub(super) async fn run(self) -> io::Result<u64> {
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

fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

pub(super) fn nonblocking_pipe(
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
    let actual_capacity = if requested_capacity > current_capacity {
        let resized = unsafe {
            libc::fcntl(
                pipe_write.as_raw_fd(),
                libc::F_SETPIPE_SZ,
                requested_capacity as libc::c_int,
            )
        };
        if resized > 0 {
            resized as usize
        } else {
            current_capacity
        }
    } else {
        current_capacity
    };
    Ok((pipe_read, pipe_write, actual_capacity))
}

pub(super) fn pipe_capacity(fd: RawFd) -> io::Result<usize> {
    let capacity = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
    if capacity < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(capacity as usize)
}

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
