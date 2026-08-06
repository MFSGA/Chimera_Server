use std::io;

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;

pub fn configure_listener(
    socket: &tokio::net::TcpSocket,
    value: i32,
) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        crate::util::socket::configure_tcp_fast_open(socket.as_raw_fd(), value)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (socket, value);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcpFastOpen is currently supported only on Linux and Android",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;

    use tokio::net::TcpSocket;

    use super::*;

    fn tcp_fast_open(fd: std::os::fd::RawFd) -> io::Result<i32> {
        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_FASTOPEN,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    #[test]
    fn configures_tcp_fast_open_before_bind() {
        let socket = TcpSocket::new_v4().unwrap();
        configure_listener(&socket, 256).unwrap();
        assert_eq!(tcp_fast_open(socket.as_raw_fd()).unwrap(), 256);
    }

    #[test]
    fn explicitly_disables_tcp_fast_open() {
        let socket = TcpSocket::new_v4().unwrap();
        configure_listener(&socket, 256).unwrap();
        configure_listener(&socket, 0).unwrap();
        assert_eq!(tcp_fast_open(socket.as_raw_fd()).unwrap(), 0);
    }
}
