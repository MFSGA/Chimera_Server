use async_trait::async_trait;

use crate::{
    async_stream::AsyncStream,
    config::server_config::DokodemoDoorConfig,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
    traffic::TrafficContext,
};

#[derive(Debug)]
pub struct DokodemoDoorTcpHandler {
    config: DokodemoDoorConfig,
    inbound_tag: String,
}

impl DokodemoDoorTcpHandler {
    pub fn new(config: DokodemoDoorConfig, inbound_tag: &str) -> Self {
        Self {
            config,
            inbound_tag: inbound_tag.to_string(),
        }
    }

    fn setup_result(
        &self,
        server_stream: Box<dyn AsyncStream>,
        remote_location: crate::address::NetLocation,
    ) -> TcpServerSetupResult {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: None,
            traffic_context: Some(
                TrafficContext::new("dokodemo-door")
                    .with_user_level(self.config.user_level)
                    .with_inbound_tag(self.inbound_tag.clone()),
            ),
        }
    }
}

#[async_trait]
impl TcpServerHandler for DokodemoDoorTcpHandler {
    fn requires_original_destination(&self) -> bool {
        self.config.follow_redirect
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if self.config.follow_redirect {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dokodemo-door followRedirect requires TCP connection context",
            ));
        }

        Ok(self.setup_result(server_stream, self.config.target.clone()))
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        let remote_location = if self.config.follow_redirect {
            context.original_destination.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "dokodemo-door original destination is unavailable",
                )
            })?
        } else {
            self.config.target.clone()
        };

        Ok(self.setup_result(server_stream, remote_location))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};

    use crate::{
        address::{Address, NetLocation},
        async_stream::AsyncPing,
    };

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    fn handler(follow_redirect: bool) -> DokodemoDoorTcpHandler {
        DokodemoDoorTcpHandler::new(
            DokodemoDoorConfig {
                target: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80),
                follow_redirect,
                user_level: 7,
            },
            "dokodemo",
        )
    }

    #[tokio::test]
    async fn follow_redirect_uses_original_destination() {
        let original_destination =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(203, 0, 113, 8)), 443);
        let (_client, server) = duplex(64);
        let result = handler(true)
            .setup_server_stream_with_context(
                Box::new(TestStream(server)),
                TcpServerConnectionContext {
                    original_destination: Some(original_destination.clone()),
                    ..TcpServerConnectionContext::default()
                },
            )
            .await
            .expect("followRedirect should accept original destination");

        match result {
            TcpServerSetupResult::TcpForward {
                remote_location,
                traffic_context,
                ..
            } => {
                assert_eq!(remote_location, original_destination);
                assert_eq!(
                    traffic_context
                        .expect("dokodemo traffic context")
                        .user_level,
                    7
                );
            }
            _ => panic!("dokodemo followRedirect returned a non-TCP result"),
        }
    }

    #[tokio::test]
    async fn follow_redirect_rejects_missing_original_destination() {
        let (_client, server) = duplex(64);
        let error = match handler(true)
            .setup_server_stream_with_context(
                Box::new(TestStream(server)),
                TcpServerConnectionContext::default(),
            )
            .await
        {
            Ok(_) => panic!("missing original destination must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable);
    }
}
