use std::io;

#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;

pub fn configure_listener(
    socket: &tokio::net::TcpSocket,
    value: i32,
) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        crate::util::socket::configure_tcp_max_seg(socket.as_raw_fd(), value)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (socket, value);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcpMaxSeg is currently supported only on Linux and Android",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;

    use tokio::net::{TcpSocket, TcpStream};

    use super::*;

    fn max_seg(fd: std::os::fd::RawFd) -> io::Result<i32> {
        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    #[tokio::test]
    async fn configures_tcp_max_seg_before_listen() {
        let socket = TcpSocket::new_v4().unwrap();
        configure_listener(&socket, 1200).unwrap();
        assert_eq!(max_seg(socket.as_raw_fd()).unwrap(), 1200);

        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(128).unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (stream, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap().unwrap();
        assert!(max_seg(stream.as_raw_fd()).unwrap() <= 1200);
    }
}
