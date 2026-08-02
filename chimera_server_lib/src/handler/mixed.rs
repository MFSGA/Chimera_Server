use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use crate::{
    async_stream::AsyncStream,
    config::server_config::{HttpUser, SocksUserStore},
    handler::{
        http::HttpTcpServerHandler,
        socks::SocksTcpServerHandler,
        tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    },
    util::prefixed_stream::PrefixedStream,
};

const SOCKS5_VERSION: u8 = 0x05;

#[derive(Debug)]
pub struct MixedTcpServerHandler {
    http: HttpTcpServerHandler,
    socks: SocksTcpServerHandler,
}

impl MixedTcpServerHandler {
    pub fn new(
        accounts: SocksUserStore,
        udp_enabled: bool,
        inbound_tag: &str,
    ) -> Self {
        let http_accounts = accounts
            .snapshot()
            .into_iter()
            .map(|account| HttpUser {
                username: account.username,
                password: account.password,
            })
            .collect();
        Self {
            http: HttpTcpServerHandler::new(http_accounts, false, inbound_tag),
            socks: SocksTcpServerHandler::new(accounts, inbound_tag, udp_enabled),
        }
    }
}

#[async_trait]
impl TcpServerHandler for MixedTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let first = server_stream.read_u8().await?;
        let stream: Box<dyn AsyncStream> =
            Box::new(PrefixedStream::new(vec![first], server_stream));
        if first == SOCKS5_VERSION {
            self.socks.setup_server_stream(stream).await
        } else {
            self.http.setup_server_stream(stream).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use crate::{
        async_stream::{AsyncPing, AsyncStream},
        config::server_config::SocksUserStore,
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::MixedTcpServerHandler;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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

    #[tokio::test]
    async fn detects_http_connect() {
        let handler = MixedTcpServerHandler::new(
            SocksUserStore::new(Vec::new()),
            false,
            "mixed-in",
        );
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .unwrap();
        let TcpServerSetupResult::TcpForward {
            remote_location, ..
        } = result
        else {
            panic!("mixed HTTP returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:443");
    }

    #[tokio::test]
    async fn detects_socks5() {
        let handler = MixedTcpServerHandler::new(
            SocksUserStore::new(Vec::new()),
            false,
            "mixed-in",
        );
        let (mut client, server) = duplex(1024);
        client.write_all(&[5, 1, 0]).await.unwrap();
        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
        });
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let result = setup.await.unwrap().unwrap();
        let TcpServerSetupResult::TcpForward {
            remote_location, ..
        } = result
        else {
            panic!("mixed SOCKS returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "127.0.0.1:80");
    }
}
