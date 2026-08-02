use std::{collections::HashMap, io, time::Duration};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_HEADER_BYTES: usize = 12 * 1024;

#[derive(Debug)]
pub struct HttpUpgradeTcpServerHandler {
    host: Option<String>,
    path: String,
    inner: Box<dyn TcpServerHandler>,
}

impl HttpUpgradeTcpServerHandler {
    pub fn new(
        host: Option<String>,
        path: String,
        inner: Box<dyn TcpServerHandler>,
    ) -> Self {
        Self {
            host: host.map(|value| value.trim().to_ascii_lowercase()),
            path: normalize_path(path),
            inner,
        }
    }

    async fn upgrade(&self, stream: &mut Box<dyn AsyncStream>) -> io::Result<()> {
        let request = timeout(HANDSHAKE_TIMEOUT, read_http_header(stream))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTPUpgrade handshake timed out",
                )
            })??;
        let (method, target, version, headers) = parse_request(&request)?;
        if method != "GET" || version != "HTTP/1.1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTPUpgrade requires GET over HTTP/1.1",
            ));
        }
        let path = target.split(['?', '#']).next().unwrap_or(target);
        if path != self.path {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("HTTPUpgrade path mismatch: {path}"),
            ));
        }
        if let Some(expected) = &self.host {
            let actual = headers.get("host").map(String::as_str).unwrap_or("");
            if !http_host_matches(actual, expected) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("HTTPUpgrade host mismatch: {actual}"),
                ));
            }
        }
        if headers
            .get("connection")
            .map(|value| value.trim().eq_ignore_ascii_case("upgrade"))
            != Some(true)
            || headers
                .get("upgrade")
                .map(|value| value.trim().eq_ignore_ascii_case("websocket"))
                != Some(true)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unrecognized HTTPUpgrade request",
            ));
        }

        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await?;
        stream.flush().await
    }
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_context(
            server_stream,
            TcpServerConnectionContext::default(),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        self.upgrade(&mut server_stream).await?;
        self.inner
            .setup_server_stream_with_context(server_stream, context)
            .await
    }
}

async fn read_http_header(stream: &mut Box<dyn AsyncStream>) -> io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(512);
    while header.len() < MAX_HEADER_BYTES {
        let byte = stream.read_u8().await?;
        header.push(byte);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTPUpgrade headers exceed 12288 bytes",
    ))
}

fn parse_request(
    request: &[u8],
) -> io::Result<(&str, &str, &str, HashMap<String, String>)> {
    let request = std::str::from_utf8(request).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTPUpgrade header encoding: {error}"),
        )
    })?;
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTPUpgrade request line",
        ));
    }
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok((method, target, version, headers))
}

fn normalize_path(path: String) -> String {
    let path = path.trim();
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn http_host_matches(actual: &str, expected: &str) -> bool {
    let actual = actual.trim().to_ascii_lowercase();
    if actual == expected {
        return true;
    }
    if expected.starts_with('[') {
        return actual
            .strip_suffix(']')
            .is_some_and(|value| format!("{value}]") == expected);
    }
    actual
        .split_once(':')
        .map(|(host, _)| host == expected)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use crate::{
        address::{Address, NetLocation},
        async_stream::{AsyncPing, AsyncStream},
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::HttpUpgradeTcpServerHandler;

    #[derive(Debug)]
    struct Inner;

    #[async_trait]
    impl TcpServerHandler for Inner {
        async fn setup_server_stream(
            &self,
            stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            Ok(TcpServerSetupResult::TcpForward {
                remote_location: NetLocation::new(
                    Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    443,
                ),
                stream,
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context: None,
            })
        }
    }

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
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

    #[tokio::test]
    async fn upgrades_and_preserves_first_protocol_bytes() {
        let handler = HttpUpgradeTcpServerHandler::new(
            Some("example.com".into()),
            "upgrade".into(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                b"GET /upgrade?x=1 HTTP/1.1\r\n\
                  Host: example.com:80\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\nprotocol",
            )
            .await
            .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("HTTPUpgrade handshake");
        let mut response = vec![0u8; 77];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 101 Switching Protocols")
        );
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("expected forwarded upgraded stream");
        };
        let mut protocol = [0u8; 8];
        stream.read_exact(&mut protocol).await.unwrap();
        assert_eq!(&protocol, b"protocol");
    }

    #[tokio::test]
    async fn rejects_wrong_path() {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/expected".into(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(1024);
        client
            .write_all(
                b"GET /wrong HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("wrong path must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("path mismatch"));
    }
}
