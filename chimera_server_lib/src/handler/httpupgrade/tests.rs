use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
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

use super::{
    HttpUpgradeTcpServerHandler, http_host_matches, trusted_forwarded_peer,
};

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

#[derive(Debug)]
struct TimeoutManagingInner;

#[async_trait]
impl TcpServerHandler for TimeoutManagingInner {
    fn manages_handshake_timeout(&self) -> bool {
        true
    }

    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        Inner.setup_server_stream(stream).await
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

#[test]
fn honors_xray_trusted_forwarded_headers() {
    let headers = HashMap::from([
        (
            "x-forwarded-for".to_string(),
            "203.0.113.77, 198.51.100.2".to_string(),
        ),
        ("x-trusted-cdn".to_string(), "yes".to_string()),
        ("host".to_string(), "example.com".to_string()),
    ]);
    assert_eq!(
        trusted_forwarded_peer(&headers, &[]),
        None,
        "current Xray requires an explicit trusted-XFF marker configuration",
    );
    assert_eq!(
        trusted_forwarded_peer(&headers, &["X-Missing".into()]),
        None
    );
    assert_eq!(
        trusted_forwarded_peer(&headers, &["X-Trusted-CDN".into()]),
        Some("203.0.113.77:0".parse().unwrap())
    );
    assert_eq!(
        trusted_forwarded_peer(&headers, &[" X-Trusted-CDN ".into()]),
        None
    );
    assert_eq!(
        trusted_forwarded_peer(&headers, &["Host".into()]),
        None,
        "Xray's http.ReadRequest removes Host from req.Header before trusted marker checks",
    );
}

#[tokio::test]
async fn preserves_xray_httpupgrade_host_text() {
    let handler = HttpUpgradeTcpServerHandler::new(
        Some(" Example.COM ".into()),
        "/upgrade".into(),
        false,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
            .write_all(
                b"GET /upgrade HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("Xray does not trim configured HTTPUpgrade host text"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("host mismatch"));
}

#[test]
fn matches_xray_ipv6_httpupgrade_host_authorities() {
    assert!(http_host_matches("[::1]:443", "::1"));
    assert!(http_host_matches("[::1]:80", "::1"));
    assert!(!http_host_matches("::1", "::1"));
    assert!(!http_host_matches("[::1]", "::1"));
    assert!(!http_host_matches("[::2]:443", "::1"));
    assert!(http_host_matches("Example.COM:443", "example.com"));
    assert!(http_host_matches("ä.example", "Ä.example"));
    assert!(http_host_matches("σ.example", "Σ.example"));
    assert!(http_host_matches("i.example", "İ.example"));
    assert!(!http_host_matches("i\u{307}.example", "İ.example"));
}

#[test]
fn propagates_inner_handshake_timeout_ownership() {
    let unmanaged = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        false,
        Vec::new(),
        Box::new(Inner),
    );
    assert!(!unmanaged.manages_handshake_timeout());

    let managed = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        false,
        Vec::new(),
        Box::new(TimeoutManagingInner),
    );
    assert!(managed.manages_handshake_timeout());
}

#[tokio::test]
async fn applies_xray_four_second_header_timeout() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        false,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();

    let setup = tokio::spawn(async move {
        handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
    });
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    assert!(
        !setup.is_finished(),
        "HTTPUpgrade timeout must not fire before Xray's four-second window"
    );

    let result = tokio::time::timeout(Duration::from_secs(1), setup)
        .await
        .expect("HTTPUpgrade timeout should fire near four seconds")
        .unwrap();
    let error = match result {
        Ok(_) => panic!("partial HTTPUpgrade request must time out"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn rejects_headers_beyond_current_xray_12_kib_limit() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        false,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(128 * 1024);
    let large_value = "A".repeat(64 * 1024);
    let request = format!(
        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Large: {large_value}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => {
            panic!("current Xray rejects HTTPUpgrade headers beyond 12 KiB")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn drops_buffered_first_protocol_bytes_like_xray_v26_2_6() {
    let handler = HttpUpgradeTcpServerHandler::new(
        Some("example.com".into()),
        "upgrade".into(),
        false,
        Vec::new(),
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

    let mut buffered = [0u8; 8];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            stream.read_exact(&mut buffered),
        )
        .await
        .is_err(),
        "Xray drops inner bytes buffered by http.ReadRequest"
    );

    client.write_all(b"late").await.unwrap();
    let mut late = [0u8; 4];
    stream.read_exact(&mut late).await.unwrap();
    assert_eq!(&late, b"late");
}

#[tokio::test]
async fn accepts_xray_httpupgrade_methods_and_http_versions() {
    for request_line in [
        "POST /upgrade HTTP/1.0",
        "FOO /upgrade HTTP/9.9",
        "F~O /upgrade HTTP/1.1",
        "F!O /upgrade HTTP/1.1",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray accepts any parsed method and one-digit HTTP version");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
        let mut response = vec![0u8; 77];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 101 Switching Protocols")
        );
    }

    for request_line in [
        "GET /upgrade HTTP/1.10",
        "GET /upgrade BLAH",
        "GET  /upgrade HTTP/1.1",
        "GET /upgrade  HTTP/1.1",
        "GET\t/upgrade HTTP/1.1",
        "GET /upgrade\tHTTP/1.1",
        "F@O /upgrade HTTP/1.1",
        "F:O /upgrade HTTP/1.1",
        "F,O /upgrade HTTP/1.1",
        "F/O /upgrade HTTP/1.1",
        "F\\O /upgrade HTTP/1.1",
        "F[O /upgrade HTTP/1.1",
        "F]O /upgrade HTTP/1.1",
        "F{O /upgrade HTTP/1.1",
        "F}O /upgrade HTTP/1.1",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("Xray http.ReadRequest rejects malformed HTTP versions")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[test]
fn rejects_request_target_control_bytes_like_xray_v26_2_6() {
    for control in [b'\t', 0x00, 0x1f, 0x7f, 0x0b] {
        let mut request = b"GET /up".to_vec();
        request.push(control);
        request.extend_from_slice(
                b"grade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
        let error = super::parse_request(&request).expect_err(
            "Xray http.ReadRequest rejects control bytes in request-target",
        );
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[test]
fn rejects_non_ascii_header_names_like_xray_v26_2_6() {
    for name in ["X-Ä", "X-é"] {
        let request = format!(
            "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{name}: ok\r\n\r\n"
        );
        let error = super::parse_request(request.as_bytes())
            .expect_err("Xray http.ReadRequest rejects non-ASCII MIME header names");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    super::parse_request(
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX Foo: ok\r\n\r\n",
        )
        .expect("Xray v26.2.6 still accepts an ASCII space in an unrelated header name");
}

#[tokio::test]
async fn accepts_bare_lf_http_headers_like_xray_v26_2_6() {
    for request in [
            b"GET /upgrade HTTP/1.1\nHost: localhost\nConnection: Upgrade\nUpgrade: websocket\n\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\n\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray http.ReadRequest accepts bare LF line endings");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }
}

#[tokio::test]
async fn keeps_first_duplicate_upgrade_headers_like_xray_v26_2_6() {
    for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nConnection: nope\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: nope\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray uses the first duplicate HTTPUpgrade header value");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }

    for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: nope\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: nope\r\nUpgrade: websocket\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects when the first duplicate header is invalid"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
}

#[tokio::test]
async fn rejects_duplicate_host_headers_like_xray_v26_2_6() {
    for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nHost: wrong.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                Some("localhost".into()),
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray http.ReadRequest rejects duplicate Host headers"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "too many Host headers");
        }
}

#[tokio::test]
async fn validates_content_length_like_xray_v26_2_6() {
    for extra_headers in [
        "Content-Length: 0\r\n",
        "Content-Length:   0  \r\n",
        "Content-Length: 00\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length: 0\r\nContent-Length:   0  \r\n",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra_headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray accepts valid HTTP Content-Length forms");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }

    for extra_headers in [
        "Content-Length: +0\r\n",
        "Content-Length: -0\r\n",
        "Content-Length: nope\r\n",
        "Content-Length: 0, 0\r\n",
        "Content-Length: 0\r\nContent-Length: 00\r\n",
        "Content-Length: 0\r\nContent-Length: 1\r\n",
        "Content-Length: 0\r\n 0\r\n",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra_headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("Xray rejects malformed HTTP Content-Length headers")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn validates_transfer_encoding_like_xray_v26_2_6() {
    for extra_headers in [
        "Transfer-Encoding: chunked\r\n",
        "Transfer-Encoding: Chunked\r\n",
        "Transfer-Encoding:   chunked  \r\n",
        "Transfer-Encoding:\r\n chunked\r\n",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra_headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray accepts a single chunked transfer encoding");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }

    for extra_headers in [
        "Transfer-Encoding:\r\n",
        "Transfer-Encoding: identity\r\n",
        "Transfer-Encoding: gzip\r\n",
        "Transfer-Encoding: chunked;foo\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
        "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra_headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray rejects unsupported HTTP transfer encodings"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn validates_chunked_trailers_like_xray_v26_2_6() {
    for extra_headers in [
        "Trailer: Content-Length\r\n",
        "Trailer: Transfer-Encoding\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Host\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo, X-Bar\r\n",
        "Transfer-Encoding: chunked\r\nTrailer:\r\n",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra_headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray accepts non-forbidden trailer declarations");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }

    for extra_headers in [
        "Transfer-Encoding: chunked\r\nTrailer: Content-Length\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Transfer-Encoding\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Trailer\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo, Content-Length\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo\r\nTrailer: Content-Length\r\n",
        "Transfer-Encoding: chunked\r\nTrailer:\r\n Content-Length\r\n",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{extra_headers}\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray rejects forbidden chunked trailer keys"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn matches_xray_httpupgrade_mime_header_parsing() {
    for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection:\r\n Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade:\r\n websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nBad Header: ok\r\nX-Test: a\tb\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: \xff\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: \x80\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nConnection: nope\r\n more\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUpgrade: nope\r\n more\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let result = handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .expect("Xray accepts folded MIME header values");
            assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
            let mut response = vec![0u8; 77];
            client.read_exact(&mut response).await.unwrap();
            assert!(
                String::from_utf8_lossy(&response)
                    .starts_with("HTTP/1.1 101 Switching Protocols")
            );
        }

    for request in [
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection : Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nBadHeader\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nBad\tHeader: ok\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: a\x0bb\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: a\x00b\r\n\r\n".as_slice(),
            b"GET /upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Test: a\x7fb\r\n\r\n".as_slice(),
        ] {
            let handler = HttpUpgradeTcpServerHandler::new(
                None,
                "/upgrade".into(),
                false,
                Vec::new(),
                Box::new(Inner),
            );
            let (mut client, server) = duplex(4096);
            client.write_all(request).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!("Xray rejects malformed HTTPUpgrade MIME headers"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }
}

#[tokio::test]
async fn matches_xray_absolute_form_request_targets() {
    for request_line in [
        "GET http://example.com/upgrade HTTP/1.1",
        "GET HTTP://example.com/upgrade HTTP/1.1",
        "GET ftp://example.com/upgrade HTTP/1.1",
        "GET http://user@example.com/upgrade HTTP/1.1",
        "GET http://user:pass@example.com/upgrade HTTP/1.1",
        "GET http://user@@example.com/upgrade HTTP/1.1",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            Some("example.com".into()),
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: wrong.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray uses absolute request-target authority and path");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
        let mut response = vec![0u8; 77];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response)
                .starts_with("HTTP/1.1 101 Switching Protocols")
        );
    }

    for request_line in [
        "GET http://wrong.example/upgrade HTTP/1.1",
        "GET http://example.com/wrong HTTP/1.1",
        "GET http://example.com/upgrade#fragment HTTP/1.1",
        "GET http://exa%ZZmple.com/upgrade HTTP/1.1",
        "GET http://user%ZZ@example.com/upgrade HTTP/1.1",
    ] {
        let handler = HttpUpgradeTcpServerHandler::new(
            Some("example.com".into()),
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "{request_line}\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        assert!(
            handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
                .is_err(),
            "Xray rejects mismatched absolute-form authority or path"
        );
    }
}

#[tokio::test]
async fn rejects_literal_request_target_fragments_like_xray_v26_2_6() {
    for target in ["/upgrade#fragment", "/upgrade?x=1#fragment"] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            false,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
                .write_all(
                    format!(
                        "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("Xray rejects literal fragments in HTTP request-targets")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade#fragment".into(),
        false,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
            .write_all(
                b"GET /upgrade%23fragment HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("percent-encoded hash remains an ordinary Xray path byte");
    assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
}

#[tokio::test]
async fn preserves_xray_httpupgrade_path_whitespace() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "ws ".into(),
        false,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(
            b"GET /ws%20 HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("percent-encoded Xray HTTPUpgrade path should match");
    assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    let mut response = vec![0u8; 77];
    client.read_exact(&mut response).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response)
            .starts_with("HTTP/1.1 101 Switching Protocols")
    );
}

#[tokio::test]
async fn proxy_protocol_does_not_inherit_websocket_four_second_timeout() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client.write_all(b"PROXY ").await.unwrap();

    let setup = tokio::spawn(async move {
        handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
    });
    tokio::time::sleep(Duration::from_millis(4_100)).await;
    assert!(
        !setup.is_finished(),
        "Xray system listener keeps a partial PROXY header pending past four seconds"
    );

    client
        .write_all(
            b"TCP4 198.51.100.7 203.0.113.9 45678 443\r\n\
                  GET /upgrade HTTP/1.1\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();
    let result = setup
        .await
        .unwrap()
        .expect("HTTPUpgrade with delayed PROXY v1");
    let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result else {
        panic!("expected peer address override");
    };
    assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
    assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
}

#[tokio::test]
async fn accepts_proxy_protocol_v1_and_overrides_peer_address() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(
            b"PROXY TCP4 198.51.100.7 203.0.113.9 45678 443\r\n\
                  GET /upgrade HTTP/1.1\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
        )
        .await
        .unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("HTTPUpgrade with PROXY v1");
    let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result else {
        panic!("expected peer address override");
    };
    assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
    assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
}

#[tokio::test]
async fn proxy_protocol_v1_spacing_matches_xray_v26_2_6() {
    let request = b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(b"PROXY TCP4 198.51.100.7 203.0.113.9 45678 443 EXTRA\r\n")
        .await
        .unwrap();
    client.write_all(request).await.unwrap();
    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("Xray v26.2.6 ignores trailing PROXY v1 tokens");
    let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result else {
        panic!("expected peer address override");
    };
    assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
    assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));

    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(b"PROXY  TCP4 198.51.100.7 203.0.113.9 45678 443\r\n")
        .await
        .unwrap();
    client.write_all(request).await.unwrap();
    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("Xray v26.2.6 rejects repeated spaces in PROXY v1"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("PROXY protocol v1 family"));
}

#[tokio::test]
async fn proxy_protocol_v1_signature_prefix_matches_xray_v26_2_6() {
    let request = b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

    for prefix in ["PROXYjunk", "PROXY:"] {
        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client
            .write_all(
                format!("{prefix} TCP4 198.51.100.7 203.0.113.9 45678 443\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        client.write_all(request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray v26.2.6 only checks the five-byte PROXY v1 prefix");
        let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result
        else {
            panic!("expected peer address override");
        };
        assert_eq!(peer_addr, "198.51.100.7:45678".parse().unwrap());
        assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
    }

    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(b"proxy TCP4 198.51.100.7 203.0.113.9 45678 443\r\n")
        .await
        .unwrap();
    client.write_all(request).await.unwrap();
    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("Xray v26.2.6 keeps the PROXY signature case-sensitive"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("missing required PROXY"));
}

#[tokio::test]
async fn proxy_protocol_v1_length_limit_matches_xray_v26_2_6() {
    let request = b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

    for (line_len, should_accept) in [(107usize, true), (108usize, false)] {
        let mut proxy = b"PROXY UNKNOWN ".to_vec();
        proxy.extend(std::iter::repeat_n(
            b'A',
            line_len - proxy.len() - b"\r\n".len(),
        ));
        proxy.extend_from_slice(b"\r\n");
        assert_eq!(proxy.len(), line_len);

        let handler = HttpUpgradeTcpServerHandler::new(
            None,
            "/upgrade".into(),
            true,
            Vec::new(),
            Box::new(Inner),
        );
        let (mut client, server) = duplex(4096);
        client.write_all(&proxy).await.unwrap();
        client.write_all(request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await;
        if should_accept {
            assert!(
                result.is_ok(),
                "Xray v26.2.6 accepts a {line_len}-byte PROXY v1 line"
            );
        } else {
            let error = match result {
                Ok(_) => panic!("Xray v26.2.6 rejects byte 108"),
                Err(error) => error,
            };
            assert!(
                error
                    .to_string()
                    .contains("PROXY protocol v1 header is too long")
            );
        }
    }
}

#[tokio::test]
async fn accepts_proxy_protocol_v2_and_overrides_peer_address() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    request.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
    request.extend_from_slice(&[198, 51, 100, 8]);
    request.extend_from_slice(&[203, 0, 113, 10]);
    request.extend_from_slice(&45679u16.to_be_bytes());
    request.extend_from_slice(&443u16.to_be_bytes());
    request.extend_from_slice(
            b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );
    client.write_all(&request).await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("HTTPUpgrade with PROXY v2");
    let TcpServerSetupResult::PeerAddrOverride { peer_addr, inner } = result else {
        panic!("expected peer address override");
    };
    assert_eq!(peer_addr, "198.51.100.8:45679".parse().unwrap());
    assert!(matches!(*inner, TcpServerSetupResult::TcpForward { .. }));
}

#[tokio::test]
async fn proxy_ipv4_mapped_ipv6_is_canonicalized_like_xray_v26_2_6() {
    let request =
            b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    client
        .write_all(b"PROXY TCP6 ::ffff:203.0.113.7 ::1 12345 80\r\n")
        .await
        .unwrap();
    client.write_all(request).await.unwrap();
    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("Xray accepts mapped IPv6 in PROXY v1 TCP6");
    let TcpServerSetupResult::PeerAddrOverride { peer_addr, .. } = result else {
        panic!("expected peer address override");
    };
    assert_eq!(peer_addr, "203.0.113.7:12345".parse().unwrap());

    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );
    let (mut client, server) = duplex(4096);
    let mut proxy = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    proxy.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
    proxy.extend_from_slice(
        &"::ffff:203.0.113.7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    proxy.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    proxy.extend_from_slice(&12345u16.to_be_bytes());
    proxy.extend_from_slice(&80u16.to_be_bytes());
    proxy.extend_from_slice(request);
    client.write_all(&proxy).await.unwrap();
    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("Xray accepts mapped IPv6 in PROXY v2 IPv6 family");
    let TcpServerSetupResult::PeerAddrOverride { peer_addr, .. } = result else {
        panic!("expected peer address override");
    };
    assert_eq!(peer_addr, "203.0.113.7:12345".parse().unwrap());
}

#[tokio::test]
async fn proxy_v2_local_validates_known_family_length_like_xray_v26_2_6() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );

    for family_protocol in [0x11, 0x13] {
        let (mut client, server) = duplex(4096);
        let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        request.extend_from_slice(&[0x20, family_protocol, 0x00, 0x00]);
        request.extend_from_slice(
                b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
        client.write_all(&request).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("Xray v26.2.6 rejects short LOCAL IPv4 blocks"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("PROXY protocol v2 LOCAL address length")
        );
    }

    let (mut client, server) = duplex(4096);
    let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    request.extend_from_slice(&[0x20, 0x13, 0x00, 0x0c]);
    request.extend_from_slice(&[0; 12]);
    request.extend_from_slice(
            b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );
    client.write_all(&request).await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("Xray v26.2.6 accepts LOCAL IPv4 blocks once length is sufficient");
    assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
}

#[tokio::test]
async fn proxy_v2_non_ip_families_match_xray_v26_2_6() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/upgrade".into(),
        true,
        Vec::new(),
        Box::new(Inner),
    );

    for (family_protocol, payload) in
        [(0x01, Vec::new()), (0x40, Vec::new()), (0x31, vec![0; 216])]
    {
        let (mut client, server) = duplex(4096);
        let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        request.extend_from_slice(&[
            0x21,
            family_protocol,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ]);
        request.extend_from_slice(&payload);
        request.extend_from_slice(
                b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
        client.write_all(&request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("Xray v26.2.6 accepts non-IP PROXY v2 family combinations");
        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }

    for family_protocol in [0x00, 0x41] {
        let (mut client, server) = duplex(4096);
        let mut request = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        request.extend_from_slice(&[0x21, family_protocol, 0x00, 0x00]);
        request.extend_from_slice(
                b"GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
        client.write_all(&request).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("Xray v26.2.6 rejects this PROXY v2 family combination")
            }
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("unsupported PROXY protocol v2 address family")
        );
    }
}

#[tokio::test]
async fn rejects_wrong_path() {
    let handler = HttpUpgradeTcpServerHandler::new(
        None,
        "/expected".into(),
        false,
        Vec::new(),
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
