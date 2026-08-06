use std::io;

use async_trait::async_trait;

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

#[derive(Debug)]
pub struct TcpKeepAliveServerHandler {
    idle_secs: i32,
    interval_secs: i32,
    inner: Box<dyn TcpServerHandler>,
}

impl TcpKeepAliveServerHandler {
    pub fn new(
        idle_secs: i32,
        interval_secs: i32,
        inner: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            idle_secs,
            interval_secs,
            inner,
        }
    }

    fn configure_stream(&self, stream: &dyn AsyncStream) -> io::Result<()> {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let fd = stream.raw_tcp_fd().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TCP keepalive requires a raw TCP stream",
                )
            })?;
            crate::util::socket::configure_tcp_keepalive(
                fd,
                self.idle_secs,
                self.interval_secs,
            )
        }

        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let _ = stream;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP keepalive sockopt is currently supported only on Linux and Android",
            ))
        }
    }

    async fn setup(
        &self,
        stream: Box<dyn AsyncStream>,
        context: Option<TcpServerConnectionContext>,
    ) -> io::Result<TcpServerSetupResult> {
        self.configure_stream(stream.as_ref())?;
        match context {
            Some(context) => {
                self.inner
                    .setup_server_stream_with_context(stream, context)
                    .await
            }
            None => self.inner.setup_server_stream(stream).await,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TcpKeepAliveServerHandler {
    fn requires_original_destination(&self) -> bool {
        self.inner.requires_original_destination()
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup(server_stream, None).await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup(server_stream, Some(context)).await
    }
}

#[cfg(all(test, any(target_os = "android", target_os = "linux")))]
mod tests {
    use std::os::fd::AsRawFd;

    use async_trait::async_trait;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[derive(Debug)]
    struct NoopHandler;

    #[async_trait]
    impl TcpServerHandler for NoopHandler {
        async fn setup_server_stream(
            &self,
            _server_stream: Box<dyn AsyncStream>,
        ) -> io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    fn socket_option(
        fd: std::os::fd::RawFd,
        level: libc::c_int,
        option: libc::c_int,
    ) -> io::Result<libc::c_int> {
        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` point to writable storage for this call.
        let result = unsafe {
            libc::getsockopt(
                fd,
                level,
                option,
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
    async fn configures_and_disables_linux_tcp_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (stream, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap().unwrap();
        let fd = stream.as_raw_fd();

        let handler = TcpKeepAliveServerHandler::new(11, 7, Box::new(NoopHandler));
        handler.configure_stream(&stream).unwrap();
        assert_eq!(
            socket_option(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            1
        );
        assert_eq!(
            socket_option(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE).unwrap(),
            11
        );
        assert_eq!(
            socket_option(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL).unwrap(),
            7
        );

        let handler = TcpKeepAliveServerHandler::new(-1, -1, Box::new(NoopHandler));
        handler.configure_stream(&stream).unwrap();
        assert_eq!(
            socket_option(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE).unwrap(),
            0
        );
    }
}
