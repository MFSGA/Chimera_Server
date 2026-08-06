use std::io;

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;

pub fn configure_listener(socket: &tokio::net::TcpSocket) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        crate::util::socket::configure_ipv6_only(socket.as_raw_fd())
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "v6only is currently supported only on Linux and Android",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;

    use tokio::net::TcpSocket;

    use super::*;

    fn ipv6_only(fd: std::os::fd::RawFd) -> io::Result<i32> {
        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IPV6_V6ONLY,
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
    fn configures_ipv6_only_before_bind() {
        let socket = TcpSocket::new_v6().unwrap();
        configure_listener(&socket).unwrap();
        assert_eq!(ipv6_only(socket.as_raw_fd()).unwrap(), 1);
    }

    #[test]
    fn rejects_ipv4_socket() {
        let socket = TcpSocket::new_v4().unwrap();
        assert!(configure_listener(&socket).is_err());
    }
}
