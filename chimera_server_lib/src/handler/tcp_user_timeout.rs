use std::io;

use async_trait::async_trait;

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

#[derive(Debug)]
pub struct TcpUserTimeoutServerHandler {
    timeout_ms: i32,
    inner: Box<dyn TcpServerHandler>,
}

impl TcpUserTimeoutServerHandler {
    pub fn new(timeout_ms: i32, inner: Box<dyn TcpServerHandler>) -> Self {
        Self { timeout_ms, inner }
    }

    fn configure_stream(&self, stream: &dyn AsyncStream) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let fd = stream.raw_tcp_fd().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TCP_USER_TIMEOUT requires a raw TCP stream",
                )
            })?;
            crate::util::socket::configure_tcp_user_timeout(fd, self.timeout_ms)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tcpUserTimeout is currently supported only on Linux",
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
impl TcpServerHandler for TcpUserTimeoutServerHandler {
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

#[cfg(all(test, target_os = "linux"))]
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

    #[tokio::test]
    async fn configures_linux_tcp_user_timeout_in_milliseconds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (stream, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap().unwrap();
        let handler =
            TcpUserTimeoutServerHandler::new(12_345, Box::new(NoopHandler));
        handler.configure_stream(&stream).unwrap();

        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(value, 12_345);
    }
}
