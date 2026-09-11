use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
};

use crate::{
    async_stream::{AsyncPing, AsyncStream},
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};

use super::{
    WebsocketServerTarget, WebsocketTcpServerHandler,
    XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT, xray_websocket_host_matches,
    xray_websocket_request_path,
};

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

#[derive(Debug)]
struct Inner {
    manages_handshake_timeout: bool,
}

#[async_trait]
impl TcpServerHandler for Inner {
    fn manages_handshake_timeout(&self) -> bool {
        self.manages_handshake_timeout
    }

    async fn setup_server_stream(
        &self,
        _server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        unreachable!("handshake ownership test does not enter the inner handler")
    }
}

#[derive(Debug)]
struct AcceptingInner;

#[derive(Debug)]
struct CapturingInner {
    captured: Arc<Mutex<Vec<u8>>>,
}

#[derive(Debug)]
struct ContextCapturingInner {
    captured_peer: Arc<Mutex<Option<SocketAddr>>>,
}

#[async_trait]
impl TcpServerHandler for AcceptingInner {
    async fn setup_server_stream(
        &self,
        _server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[async_trait]
impl TcpServerHandler for CapturingInner {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut data = [0u8; 4];
        server_stream.read_exact(&mut data).await?;
        self.captured.lock().unwrap().extend_from_slice(&data);
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[async_trait]
impl TcpServerHandler for ContextCapturingInner {
    async fn setup_server_stream(
        &self,
        _server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        unreachable!("context-aware setup should be used")
    }

    async fn setup_server_stream_with_context(
        &self,
        _server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        *self.captured_peer.lock().unwrap() = context.peer_addr;
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

fn target(manages_handshake_timeout: bool) -> WebsocketServerTarget {
    WebsocketServerTarget {
        matching_path: None,
        matching_headers: None,
        xray_mismatch_404: false,
        trusted_x_forwarded_for: Vec::new(),
        accept_proxy_protocol: false,
        heartbeat_period: 0,
        handler: Box::new(Inner {
            manages_handshake_timeout,
        }),
    }
}

fn accepting_handler() -> WebsocketTcpServerHandler {
    WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
        matching_path: Some("/".to_string()),
        matching_headers: None,
        xray_mismatch_404: false,
        trusted_x_forwarded_for: Vec::new(),
        accept_proxy_protocol: false,
        heartbeat_period: 0,
        handler: Box::new(AcceptingInner),
    }])
}

async fn run_handshake(
    request: &str,
) -> (std::io::Result<TcpServerSetupResult>, String) {
    run_handshake_bytes(request.as_bytes()).await
}

async fn run_handshake_bytes(
    request: &[u8],
) -> (std::io::Result<TcpServerSetupResult>, String) {
    let (client, mut peer) = tokio::io::duplex(8192);
    let handler = accepting_handler();
    let task = tokio::spawn(async move {
        handler
            .setup_server_stream(Box::new(TestStream(client)))
            .await
    });
    peer.write_all(request).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (task.await.unwrap(), String::from_utf8(response).unwrap())
}

#[tokio::test]
async fn websocket_rejects_pipelined_frame_before_upgrade_like_xray_v26_2_6() {
    let mut request = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: example.com\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    )
    .as_bytes()
    .to_vec();
    request.extend_from_slice(&[0x82, 0x81, 1, 2, 3, 4, b'A' ^ 1]);

    let (result, response) = run_handshake_bytes(&request).await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("pipelined WebSocket data must abort the upgrade"),
    };
    assert_eq!(
        error.to_string(),
        "websocket: client sent data before handshake is complete"
    );
    assert!(response.is_empty(), "Xray closes without a 101 response");
}

#[test]
fn websocket_request_path_matches_xray_query_absolute_and_escape_semantics() {
    assert_eq!(xray_websocket_request_path("/ws").unwrap(), b"/ws");
    assert_eq!(xray_websocket_request_path("/ws?foo=bar").unwrap(), b"/ws");
    assert_eq!(xray_websocket_request_path("/ws?").unwrap(), b"/ws");
    assert_eq!(
        xray_websocket_request_path("http://example.com/ws?foo=bar").unwrap(),
        b"/ws"
    );
    assert_eq!(
        xray_websocket_request_path("https://example.com/ws?foo=bar").unwrap(),
        b"/ws"
    );
    assert_eq!(
        xray_websocket_request_path("ftp://example.com/ws?foo=bar").unwrap(),
        b"/ws"
    );
    assert_eq!(
        xray_websocket_request_path("HTTP://user@example.com/ws?foo=bar").unwrap(),
        b"/ws"
    );
    assert_eq!(
        xray_websocket_request_path("http://example.com").unwrap(),
        b""
    );
    assert_eq!(xray_websocket_request_path("http:/ws").unwrap(), b"/ws");
    assert_eq!(xray_websocket_request_path("foo:/ws?x=1").unwrap(), b"/ws");
    assert_eq!(xray_websocket_request_path("http:ws").unwrap(), b"http:ws");
    assert_eq!(
        xray_websocket_request_path("http://example.com?foo=bar").unwrap(),
        b""
    );
    assert_eq!(xray_websocket_request_path("http:///ws").unwrap(), b"/ws");
    assert_eq!(xray_websocket_request_path("http://@/ws").unwrap(), b"/ws");
    assert_eq!(
        xray_websocket_request_path("http://user@/ws").unwrap(),
        b"/ws"
    );
    assert_eq!(
        xray_websocket_request_path("/ws%3Ffoo=bar").unwrap(),
        b"/ws?foo=bar"
    );
    assert_eq!(
        xray_websocket_request_path("/ws%2Ffoo").unwrap(),
        b"/ws/foo"
    );
    assert_eq!(
        xray_websocket_request_path("/ws%252Ffoo").unwrap(),
        b"/ws%2Ffoo"
    );
    assert!(xray_websocket_request_path("/ws%ZZfoo").is_err());
    assert_eq!(
        xray_websocket_request_path("/ws/foo?x=%ZZ").unwrap(),
        b"/ws/foo"
    );
    assert_eq!(
        xray_websocket_request_path("/ws#frag").unwrap(),
        b"/ws#frag"
    );
}

#[tokio::test]
async fn websocket_xray_path_matching_decodes_percent_escapes() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for (target, expected_status) in [
        ("/ws/foo", "101 Switching Protocols"),
        ("http:/ws/foo", "101 Switching Protocols"),
        ("foo:/ws/foo?x=1", "101 Switching Protocols"),
        ("http:ws/foo", "404 Not Found"),
        ("/ws%2Ffoo", "101 Switching Protocols"),
        ("/ws%252Ffoo", "404 Not Found"),
        ("/ws%ZZfoo", "400 Bad Request"),
        (
            "http://example.com/ws%2Ffoo?x=%ZZ",
            "101 Switching Protocols",
        ),
    ] {
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws/foo".to_string()),
            matching_headers: None,
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let _ = task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")),
            "{target}: {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_xray_non_utf8_target_does_not_alias_replacement_character() {
    let key = b"dGhlIHNhbXBsZSBub25jZQ==";
    for (target, expected_status) in [
        (b"/socks\xff".as_slice(), "404 Not Found"),
        ("/socks\u{fffd}".as_bytes(), "101 Switching Protocols"),
    ] {
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
        request.extend_from_slice(key);
        request.extend_from_slice(b"\r\nSec-WebSocket-Version: 13\r\n\r\n");

        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/socks\u{fffd}".to_string()),
            matching_headers: None,
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(&request).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let _ = task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")),
            "{target:?}: {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_xray_hierarchical_uri_preserves_non_utf8_path_bytes() {
    let key = b"dGhlIHNhbXBsZSBub25jZQ==";
    for (target, expected_status) in [
        (b"http://example.com/ws\xff".as_slice(), "404 Not Found"),
        (
            "http://example.com/ws\u{fffd}".as_bytes(),
            "101 Switching Protocols",
        ),
        (b"foo:/ws\xff".as_slice(), "404 Not Found"),
        ("foo:/ws\u{fffd}".as_bytes(), "101 Switching Protocols"),
    ] {
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
        request.extend_from_slice(key);
        request.extend_from_slice(b"\r\nSec-WebSocket-Version: 13\r\n\r\n");

        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws\u{fffd}".to_string()),
            matching_headers: None,
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(&request).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let _ = task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")),
            "{target:?}: {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_xray_absolute_uri_rejects_non_ascii_userinfo() {
    let key = b"dGhlIHNhbXBsZSBub25jZQ==";
    for target in [
        b"http://user\xff@example.com/ws".as_slice(),
        "http://user\u{fffd}@example.com/ws".as_bytes(),
        "http://\u{00e9}@example.com/ws".as_bytes(),
    ] {
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
        request.extend_from_slice(key);
        request.extend_from_slice(b"\r\nSec-WebSocket-Version: 13\r\n\r\n");

        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: Some(HashMap::from([(
                "host".to_string(),
                "example.com".to_string(),
            )])),
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(&request).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let _ = task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{target:?}: {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_xray_non_utf8_request_target_reaches_path_matching() {
    let key = b"dGhlIHNhbXBsZSBub25jZQ==";
    for target in [b"/socks\xff".as_slice(), b"/sock\xc3(".as_slice()] {
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
        request.extend_from_slice(key);
        request.extend_from_slice(b"\r\nSec-WebSocket-Version: 13\r\n\r\n");

        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/socks".to_string()),
            matching_headers: None,
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(&request).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let _ = task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{target:?}: {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_matches_xray_request_target_paths() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for target in [
        "/?foo=bar",
        "http://example.com/?foo=bar",
        "https://example.com/?foo=bar",
        "http:///",
        "http://@/",
        "http://user@/",
    ] {
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&request).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    for target in ["http://example.com", "http://example.com?foo=bar"] {
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&request).await;
        assert!(result.is_err(), "{target}");
        assert!(response.is_empty(), "{target}: {response:?}");
    }
}

#[tokio::test]
async fn websocket_xray_request_target_validation_precedes_header_semantics() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let cases = [
        (
            format!(
                "GET /ws HTTP/2.0\r\nHost: bad host\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            "HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version\r\n",
        ),
        (
            format!(
                "GET /ws%ZZ HTTP/1.1\r\nHost: bad host\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            "HTTP/1.1 400 Bad Request\r\n",
        ),
        (
            format!(
                "GET /ws%ZZ HTTP/1.1\r\nHost: example.com\r\nContent-Length: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ),
            "HTTP/1.1 400 Bad Request\r\n",
        ),
    ];

    for (request, expected_prefix) in cases {
        let (result, response) = run_handshake(&request).await;
        assert!(result.is_err());
        assert!(
            response.starts_with(expected_prefix),
            "expected {expected_prefix:?}, got {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_matches_xray_request_line_semantics() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let headers = format!(
        "Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );

    for version in ["HTTP/1.0", "HTTP/1.1", "HTTP/1.2"] {
        let (result, response) =
            run_handshake(&format!("GET / {version}\r\n{headers}")).await;
        assert!(result.is_ok(), "{version}");
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    for host in [
        "a\"b",
        "a#b",
        "a/b",
        "a<b",
        "a>b",
        "a?b",
        "a@b",
        "a\\b",
        "a^b",
        "a`b",
        "a{b",
        "a|b",
        "a}b",
        "a b",
        "a\tb",
        "exam�ple.com",
    ] {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&request).await;
        assert!(result.is_err(), "{host:?}");
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request: malformed Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: malformed Host header",
            "{host:?}"
        );
    }

    for host in [
        "", "a!b", "a$b", "a%b", "a&b", "a'b", "a(b", "a)b", "a*b", "a+b", "a,b",
        "a-b", "a.b", "a:b", "a;b", "a=b", "a[b", "a]b", "a_b", "a~b",
    ] {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&request).await;
        assert!(result.is_ok(), "{host:?}: {response:?}");
        assert!(
            response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{host:?}: {response:?}"
        );
    }

    let mut raw_non_ascii_host = b"GET / HTTP/1.1\r\nHost: exam".to_vec();
    raw_non_ascii_host.push(0xff);
    raw_non_ascii_host.extend_from_slice(
        format!(
            "ple.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    );
    let (result, response) = run_handshake_bytes(&raw_non_ascii_host).await;
    assert!(result.is_err());
    assert_eq!(
        response,
        "HTTP/1.1 400 Bad Request: malformed Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: malformed Host header"
    );

    let headers_without_host = format!(
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let (result, response) =
        run_handshake(&format!("GET / HTTP/1.0\r\n{headers_without_host}")).await;
    assert!(result.is_ok());
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    for version in ["HTTP/1.1", "HTTP/1.2"] {
        let (result, response) =
            run_handshake(&format!("GET / {version}\r\n{headers_without_host}"))
                .await;
        assert!(result.is_err(), "{version}");
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request: missing required Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: missing required Host header"
        );
    }

    for method in ["POST", "PUT", "G!T", "G~T"] {
        let (result, response) =
            run_handshake(&format!("{method} / HTTP/1.1\r\n{headers}")).await;
        assert!(result.is_err());
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(response.ends_with("\r\n\r\nMethod Not Allowed\n"));
    }

    for version in ["HTTP/0.9", "HTTP/2.0", "HTTP/9.9"] {
        let (result, response) =
            run_handshake(&format!("GET / {version}\r\n{headers}")).await;
        assert!(result.is_err());
        assert!(response.starts_with(
            "HTTP/1.1 505 HTTP Version Not Supported: unsupported protocol version\r\n"
        ));
    }

    for request_line in [
        "GET  / HTTP/1.1",
        "GET\t/\tHTTP/1.1",
        "GET / HTTP/1.x",
        "GET / HTTP/1.10",
        "GET / HTTP/01.1",
        "GET / HTTP/1.01",
        "G@T / HTTP/1.1",
        "G:T / HTTP/1.1",
        "G,T / HTTP/1.1",
        "G/T / HTTP/1.1",
        "G\\T / HTTP/1.1",
        "G[T / HTTP/1.1",
        "G{T / HTTP/1.1",
        "GET http://exa%ZZmple.com/ HTTP/1.1",
        "GET http://exa%65mple.com/ HTTP/1.1",
        "GET http://example%2Ecom/ HTTP/1.1",
        "GET http://user%ZZ@example.com/ HTTP/1.1",
        "GET http://u\"ser@example.com/ HTTP/1.1",
        "GET http://u#ser@example.com/ HTTP/1.1",
        "GET http://u<ser@example.com/ HTTP/1.1",
        "GET http://u>ser@example.com/ HTTP/1.1",
        "GET http://u[ser@example.com/ HTTP/1.1",
        "GET http://u\\ser@example.com/ HTTP/1.1",
        "GET http://u]ser@example.com/ HTTP/1.1",
        "GET http://u^ser@example.com/ HTTP/1.1",
        "GET http://u`ser@example.com/ HTTP/1.1",
        "GET http://u{ser@example.com/ HTTP/1.1",
        "GET http://u|ser@example.com/ HTTP/1.1",
        "GET http://u}ser@example.com/ HTTP/1.1",
        "GET http://example.com:bad/ HTTP/1.1",
        "GET http://example.com:+80/ HTTP/1.1",
        "GET http://example.com:-1/ HTTP/1.1",
        "GET http://[::1]:bad/ HTTP/1.1",
        "GET http://[::1/ HTTP/1.1",
        "GET http://[]/ HTTP/1.1",
        "GET http://[abc]/ HTTP/1.1",
        "GET http://[::1]x/ HTTP/1.1",
        "GET http://exa[mple.com/ HTTP/1.1",
        "GET http://exa#mple.com/ HTTP/1.1",
        "GET http://exa\\mple.com/ HTTP/1.1",
        "GET http://exa^mple.com/ HTTP/1.1",
        "GET http://exa`mple.com/ HTTP/1.1",
        "GET http://exa{mple.com/ HTTP/1.1",
        "GET http://exa|mple.com/ HTTP/1.1",
        "GET http://exa}mple.com/ HTTP/1.1",
        "GET http://[fe80::1%25eth%2F]/ HTTP/1.1",
        "GET http://[fe80::1%25eth%3F]/ HTTP/1.1",
        "GET http://[fe80::1%25eth%23]/ HTTP/1.1",
        "GET http://[fe80::1%25eth%00]/ HTTP/1.1",
        "GET http://[fe80::1%25eth%7F]/ HTTP/1.1",
        "GET ws HTTP/1.1",
        "GET ws?x HTTP/1.1",
        "GET ?x HTTP/1.1",
        "GET #x HTTP/1.1",
        "GET 1a:b HTTP/1.1",
        "GET a_b:c HTTP/1.1",
        "GET /w\0s HTTP/1.1",
        "GET /w\x0bs HTTP/1.1",
        "GET /w\x1fs HTTP/1.1",
        "GET /w\x7fs HTTP/1.1",
    ] {
        let (result, response) =
            run_handshake(&format!("{request_line}\r\n{headers}")).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
        );
    }

    for request_target in ["*", "a:b", "a+b:c", "a-b:c", "a.b:c", "example.com:80"] {
        let (result, response) =
            run_handshake(&format!("GET {request_target} HTTP/1.1\r\n{headers}"))
                .await;
        assert!(result.is_err(), "{request_target}");
        assert!(response.is_empty(), "{request_target}: {response:?}");
    }

    for request_target in [
        "http://example.com/?x=%ZZ",
        "http://user%40name@example.com/",
        "http://user%2Fpass@example.com/",
        "http://u!$&'()*+,-.:;=_~ser@example.com/",
        "http://u@ser@example.com/",
        "http://u%22%23%5B%5C%5D%5E%60%7B%7C%7Dser@example.com/",
        "http://example.com:/",
        "http://example.com:99999/",
        "http://[::1]:/",
        "http://[::1]:80/",
        "http://[::ffff:192.0.2.1]/",
        "http://[fe80::1%25eth0]/",
        "http://[fe80::1%25eth%30]/",
        "http://[fe80::1%25eth%2D0]/",
        "http://[fe80::1%25%41]/",
        "http://[fe80::1%25eth%5B]/",
        "http://[fe80::1%25eth%5D]/",
        "http://[fe80::1%25eth%3A]/",
        "http://[fe80::1%25eth%20]/",
        "http://exam%C3%A9ple.com/",
        "http://exam%FFple.com/",
    ] {
        let (result, response) =
            run_handshake(&format!("GET {request_target} HTTP/1.1\r\n{headers}"))
                .await;
        assert!(result.is_ok(), "{request_target}");
        assert!(
            response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{request_target}"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_validates_header_names_like_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let suffix = format!(
        "Upgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );

    let (result, response) = run_handshake(&format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n{suffix}"
    ))
    .await;
    assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

    let (result, response) = run_handshake(&format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection : Upgrade\r\n{suffix}"
    ))
    .await;
    assert!(result.is_err());
    assert_eq!(
        response,
        "HTTP/1.1 400 Bad Request: invalid header name\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: invalid header name"
    );

    for invalid_header in
        ["Connection\t: Upgrade", "Connec@tion: Upgrade", "X Foo: ok"]
    {
        let (result, response) = run_handshake(&format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\n{invalid_header}\r\nConnection: Upgrade\r\n{suffix}"
        ))
        .await;
        assert!(result.is_err(), "{invalid_header}");
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "{invalid_header}"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_accepts_folded_headers_like_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for request in [
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection:\r\n Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade:\r\n websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key:\r\n {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
    ] {
        let (result, response) = run_handshake(&request).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    let orphan = format!(
        "GET / HTTP/1.1\r\n continuation\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let (result, response) = run_handshake(&orphan).await;
    assert!(result.is_err());
    assert_eq!(
        response,
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
    );
}

#[tokio::test]
async fn websocket_handshake_validates_header_values_like_xray_v26_2_6() {
    let base = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Test: ";

    for value in [b"ok".as_slice(), b"a\tb", b"\x80", b"\xff"] {
        let mut request = base.to_vec();
        request.extend_from_slice(value);
        request.extend_from_slice(b"\r\n\r\n");
        let (result, response) = run_handshake_bytes(&request).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    for value in [b"a\x0bb".as_slice(), b"a\x00b", b"a\x7fb"] {
        let mut request = base.to_vec();
        request.extend_from_slice(value);
        request.extend_from_slice(b"\r\n\r\n");
        let (result, response) = run_handshake_bytes(&request).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_rejects_duplicate_host_like_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for hosts in [
        "Host: example.com\r\nHost: example.com\r\n",
        "Host: example.com\r\nHost: wrong.com\r\n",
        "Host: wrong.com\r\nHost: example.com\r\n",
    ] {
        let request = format!(
            "GET / HTTP/1.1\r\n{hosts}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (result, response) = run_handshake(&request).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_validates_content_length_like_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let base = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );

    for content_length in [
        "Content-Length: 0\r\n",
        "Content-Length: 00\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length:   0  \r\nContent-Length:\t0\t\r\n",
        "Content-Length: 9223372036854775807\r\n",
    ] {
        let (result, response) =
            run_handshake(&format!("{base}{content_length}\r\n")).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    for content_length in [
        "Content-Length:\r\n",
        "Content-Length: nope\r\n",
        "Content-Length: +0\r\n",
        "Content-Length: -0\r\n",
        "Content-Length: 0, 0\r\n",
        "Content-Length: 0\r\nContent-Length: 00\r\n",
        "Content-Length: 0\r\nContent-Length: 1\r\n",
        "Content-Length: 9223372036854775808\r\n",
    ] {
        let (result, response) =
            run_handshake(&format!("{base}{content_length}\r\n")).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_validates_transfer_encoding_like_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let base = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );

    for transfer_encoding in [
        "",
        "Transfer-Encoding: chunked\r\n",
        "Transfer-Encoding: Chunked\r\n",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let (result, response) =
            run_handshake(&format!("{base}{transfer_encoding}\r\n")).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    for transfer_encoding in [
        "Transfer-Encoding:\r\n",
        "Transfer-Encoding: identity\r\n",
        "Transfer-Encoding: gzip\r\n",
        "Transfer-Encoding: chunked;foo\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let (result, response) =
            run_handshake(&format!("{base}{transfer_encoding}\r\n")).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nUnsupported transfer encoding"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_validates_chunked_trailers_like_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let base = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );

    for trailers in [
        "Trailer: Content-Length\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Host\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo, X-Bar\r\n",
    ] {
        let (result, response) =
            run_handshake(&format!("{base}{trailers}\r\n")).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }

    for trailers in [
        "Transfer-Encoding: chunked\r\nTrailer: Content-Length\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Transfer-Encoding\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: Trailer\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo, Content-Length\r\n",
        "Transfer-Encoding: chunked\r\nTrailer: X-Foo\r\nTrailer: Content-Length\r\n",
    ] {
        let (result, response) =
            run_handshake(&format!("{base}{trailers}\r\n")).await;
        assert!(result.is_err());
        assert_eq!(
            response,
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
        );
    }
}

#[tokio::test]
async fn websocket_handshake_matches_xray_header_budget() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let base = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
    );

    let large_but_valid = format!("{base}X-Fill: {}\r\n\r\n", "a".repeat(12_000));
    let (result, response) = run_handshake(&large_but_valid).await;
    assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

    let many_headers = format!(
        "{base}{}\r\n",
        (0..100)
            .map(|index| format!("X-{index}: a\r\n"))
            .collect::<String>()
    );
    let (result, response) = run_handshake(&many_headers).await;
    assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));

    let oversized = format!("{base}X-Fill: {}\r\n\r\n", "a".repeat(13_000));
    let (result, response) = run_handshake(&oversized).await;
    assert!(result.is_err());
    assert_eq!(
        response,
        "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large"
    );
}

#[tokio::test]
async fn websocket_handshake_validates_xray_upgrade_headers() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let valid = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let (result, response) = run_handshake(&valid).await;
    assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(!response.contains("Host: example.com\r\n"));
    assert!(!response.contains("Sec-WebSocket-Version: 13\r\n"));

    for invalid in [
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 12\r\n\r\n"
        ),
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n".to_string(),
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n".to_string(),
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key:\r\nSec-WebSocket-Version: 13\r\n\r\n".to_string(),
    ] {
        let (result, response) = run_handshake(&invalid).await;
        assert!(result.is_err());
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(response.contains("Sec-Websocket-Version: 13\r\n"));
        assert!(response.ends_with("\r\n\r\nBad Request\n"));
    }
}

#[tokio::test]
async fn websocket_x_forwarded_for_overrides_inner_peer_like_xray() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let captured_peer = Arc::new(Mutex::new(None));
    let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
        matching_path: Some("/".to_string()),
        matching_headers: None,
        xray_mismatch_404: false,
        trusted_x_forwarded_for: vec!["X-Trusted-CDN".to_string()],
        accept_proxy_protocol: false,
        heartbeat_period: 0,
        handler: Box::new(ContextCapturingInner {
            captured_peer: captured_peer.clone(),
        }),
    }]);
    let task = tokio::spawn(async move {
        handler
            .setup_server_stream_with_context(
                Box::new(TestStream(client)),
                TcpServerConnectionContext {
                    peer_addr: Some("127.0.0.1:45678".parse().unwrap()),
                    ..Default::default()
                },
            )
            .await
    });

    peer.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "X-Forwarded-For: 203.0.113.77, 198.51.100.2\r\n",
            "X-Trusted-CDN: present\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();

    assert!(matches!(
        task.await.unwrap(),
        Ok(TcpServerSetupResult::AlreadyHandled)
    ));
    assert!(
        String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 101 Switching Protocols\r\n")
    );
    assert_eq!(
        *captured_peer.lock().unwrap(),
        Some("203.0.113.77:0".parse().unwrap())
    );
}

#[test]
fn websocket_x_forwarded_for_matches_xray_first_ip_rules() {
    use super::xray_websocket_forwarded_peer;

    for (value, expected) in [
        ("203.0.113.77, 198.51.100.2", Some("203.0.113.77:0")),
        (" 203.0.113.77 ", Some("203.0.113.77:0")),
        ("[2001:db8::1]", Some("[2001:db8::1]:0")),
        ("[::ffff:192.0.2.1]", Some("192.0.2.1:0")),
        ("example.com, 203.0.113.77", None),
        (" [2001:db8::1] ", None),
    ] {
        let headers = HashMap::from([
            ("x-forwarded-for".to_string(), vec![value.to_string()]),
            ("x-trusted-cdn".to_string(), vec![String::new()]),
        ]);
        assert_eq!(
            xray_websocket_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
            expected.map(|value| value.parse().unwrap()),
            "{value}"
        );
    }

    let untrusted_headers = HashMap::from([(
        "x-forwarded-for".to_string(),
        vec!["203.0.113.77".to_string()],
    )]);
    assert_eq!(xray_websocket_forwarded_peer(&untrusted_headers, &[]), None);

    let mut headers = HashMap::from([(
        "x-forwarded-for".to_string(),
        vec!["203.0.113.77".to_string()],
    )]);
    assert_eq!(
        xray_websocket_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
        None
    );
    headers.insert("x-trusted-cdn".to_string(), vec![String::new()]);
    assert_eq!(
        xray_websocket_forwarded_peer(&headers, &["X-Trusted-CDN".to_string()]),
        Some("203.0.113.77:0".parse().unwrap())
    );
    assert_eq!(
        xray_websocket_forwarded_peer(&headers, &[" X-Trusted-CDN ".to_string()]),
        None
    );
    assert_eq!(
        xray_websocket_forwarded_peer(&headers, &["X-Forwarded-For".to_string()]),
        Some("203.0.113.77:0".parse().unwrap())
    );
    headers.insert("host".to_string(), vec!["example.com".to_string()]);
    assert_eq!(
        xray_websocket_forwarded_peer(&headers, &["Host".to_string()]),
        None
    );
}

#[tokio::test]
async fn websocket_handshake_matches_xray_early_data_subprotocol() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
        matching_path: Some("/".to_string()),
        matching_headers: None,
        xray_mismatch_404: false,
        trusted_x_forwarded_for: Vec::new(),
        accept_proxy_protocol: false,
        heartbeat_period: 0,
        handler: Box::new(CapturingInner {
            captured: captured.clone(),
        }),
    }]);
    let task = tokio::spawn(async move {
        handler
            .setup_server_stream(Box::new(TestStream(client)))
            .await
    });

    let request = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: example.com\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Protocol: cGluZw==\r\n",
        "\r\n"
    );
    peer.write_all(request.as_bytes()).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();

    assert!(matches!(
        task.await.unwrap(),
        Ok(TcpServerSetupResult::AlreadyHandled)
    ));
    assert_eq!(&*captured.lock().unwrap(), b"ping");
    let response = String::from_utf8(response).unwrap();
    assert!(response.contains("Sec-WebSocket-Protocol: cGluZw==\r\n"));
}

#[tokio::test]
async fn websocket_handshake_matches_xray_duplicate_header_semantics() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let other_key = "MDEyMzQ1Njc4OWFiY2RlZg==";

    let valid_first_key = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Key: bad\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let (result, response) = run_handshake(&valid_first_key).await;
    assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
    assert!(
        response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
    );

    let invalid_first_key = format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: bad\r\nSec-WebSocket-Key: {other_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let (result, response) = run_handshake(&invalid_first_key).await;
    assert!(result.is_err());
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    for request in [
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 12\r\n\r\n"
        ),
        format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: nope\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
    ] {
        let (result, response) = run_handshake(&request).await;
        assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    }
}

#[tokio::test]
async fn websocket_xray_path_mismatch_returns_not_found_without_changing_generic_targets()
 {
    let request = concat!(
        "GET /other HTTP/1.1\r\n",
        "Host: example.com\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );

    for (xray_mismatch_404, expect_404) in [(true, true), (false, false)] {
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: None,
            xray_mismatch_404,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let result = task.await.unwrap();
        assert!(result.is_err());

        if expect_404 {
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
            assert!(response.contains("Content-Length: 0\r\n"));
            assert!(response.ends_with("\r\n\r\n"));
        } else {
            assert!(response.is_empty());
        }
    }
}

#[tokio::test]
async fn websocket_xray_target_mismatch_precedes_method_validation() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for (path, host, expected_status) in [
        ("/ws", "example.com", "405 Method Not Allowed"),
        ("/wrong", "example.com", "404 Not Found"),
        ("/ws", "wrong.example", "404 Not Found"),
    ] {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: Some(HashMap::from([(
                "host".to_string(),
                "example.com".to_string(),
            )])),
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(task.await.unwrap().is_err());
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")),
            "{path} {host}: {response:?}"
        );
    }
}

#[tokio::test]
async fn websocket_absolute_request_target_host_matches_xray_v26_2_6() {
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    for (target, host_header, configured_host, expect_ok) in [
        (
            "http://example.com/ws",
            "wrong.example",
            "example.com",
            true,
        ),
        ("ftp://example.com/ws", "wrong.example", "example.com", true),
        (
            "HTTP://example.com/ws",
            "wrong.example",
            "example.com",
            true,
        ),
        (
            "http://user@example.com/ws",
            "wrong.example",
            "example.com",
            true,
        ),
        (
            "http://wrong.example/ws",
            "example.com",
            "example.com",
            false,
        ),
        (
            "http://exam%C3%A9ple.com/ws",
            "wrong.example",
            "examéple.com",
            true,
        ),
        (
            "http://exam%FFple.com/ws",
            "wrong.example",
            "exam�ple.com",
            true,
        ),
    ] {
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: Some(HashMap::from([(
                "host".to_string(),
                configured_host.to_string(),
            )])),
            xray_mismatch_404: true,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let result = task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        if expect_ok {
            assert!(result.is_ok(), "{target}");
            assert!(
                response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
                "{target}"
            );
        } else {
            assert!(result.is_err(), "{target}");
            assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        }
    }
}

#[test]
fn websocket_xray_host_matching_matches_xray_v26_2_6() {
    assert!(xray_websocket_host_matches("example.com", "example.com"));
    assert!(xray_websocket_host_matches("EXAMPLE.COM", "example.com"));
    assert!(xray_websocket_host_matches(
        "example.com:443",
        "example.com"
    ));
    assert!(xray_websocket_host_matches("[::1]:443", "::1"));
    assert!(!xray_websocket_host_matches("example.com", " Example.COM "));
    assert!(!xray_websocket_host_matches("[::1]", "::1"));
}

#[tokio::test]
async fn websocket_xray_host_mismatch_returns_not_found_without_changing_generic_targets()
 {
    let request = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: wrong.example\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );

    for (xray_mismatch_404, expect_404) in [(true, true), (false, false)] {
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/ws".to_string()),
            matching_headers: Some(HashMap::from([(
                "host".to_string(),
                "expected.example".to_string(),
            )])),
            xray_mismatch_404,
            trusted_x_forwarded_for: Vec::new(),
            accept_proxy_protocol: false,
            heartbeat_period: 0,
            handler: Box::new(AcceptingInner),
        }]);
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });

        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let result = task.await.unwrap();
        assert!(result.is_err());

        if expect_404 {
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
            assert!(response.contains("Content-Length: 0\r\n"));
        } else {
            assert!(response.is_empty());
        }
    }
}

#[test]
fn websocket_propagates_inner_handshake_timeout_ownership() {
    let handler = WebsocketTcpServerHandler::new(vec![target(true)]);
    assert!(handler.manages_handshake_timeout());
    assert_eq!(
        handler
            .pre_transport_handshake_timeout(&TcpServerConnectionContext::default()),
        Some(XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT)
    );

    let handler = WebsocketTcpServerHandler::new(vec![target(true), target(false)]);
    assert!(!handler.manages_handshake_timeout());

    let handler = WebsocketTcpServerHandler::new(Vec::new());
    assert!(!handler.manages_handshake_timeout());
}
