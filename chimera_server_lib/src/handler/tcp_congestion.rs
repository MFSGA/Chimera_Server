use std::io;

use async_trait::async_trait;

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

#[derive(Debug)]
pub struct TcpCongestionServerHandler {
    algorithm: String,
    inner: Box<dyn TcpServerHandler>,
}

impl TcpCongestionServerHandler {
    pub fn new(algorithm: String, inner: Box<dyn TcpServerHandler>) -> Self {
        Self { algorithm, inner }
    }

    fn configure_stream(&self, stream: &dyn AsyncStream) -> io::Result<()> {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let fd = stream.raw_tcp_fd().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TCP_CONGESTION requires a raw TCP stream",
                )
            })?;
            crate::util::socket::configure_tcp_congestion(fd, &self.algorithm)
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            let _ = stream;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tcpCongestion is currently supported only on Linux and Android",
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
impl TcpServerHandler for TcpCongestionServerHandler {
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

    fn congestion_algorithm(stream: &TcpStream) -> io::Result<String> {
        let mut value = [0u8; 64];
        let mut length = value.len() as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_TCP,
                libc::TCP_CONGESTION,
                value.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        let length = (length as usize).min(value.len());
        let bytes = &value[..length];
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    #[tokio::test]
    async fn configures_linux_tcp_congestion_algorithm() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (stream, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap().unwrap();
        let algorithm = congestion_algorithm(&stream).unwrap();
        let handler = TcpCongestionServerHandler::new(
            algorithm.clone(),
            Box::new(NoopHandler),
        );
        handler.configure_stream(&stream).unwrap();
        assert_eq!(congestion_algorithm(&stream).unwrap(), algorithm);
    }

    #[test]
    fn rejects_nul_in_congestion_algorithm() {
        let error = crate::util::socket::configure_tcp_congestion(-1, "cubic\0bbr")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
