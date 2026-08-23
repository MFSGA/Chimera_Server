use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use tokio::{io::AsyncWriteExt, time::timeout};
use tracing::debug;

use crate::{
    async_stream::AsyncStream,
    handler::{
        tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
        ws::{parsed_http::ParsedHttpData, websocket_stream::WebsocketStream},
    },
    util::prefixed_stream::PrefixedStream,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub xray_mismatch_404: bool,
    pub handler: Box<dyn TcpServerHandler>,
}

const XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug)]
pub struct WebsocketTcpServerHandler {
    server_targets: Vec<WebsocketServerTarget>,
}

impl WebsocketTcpServerHandler {
    pub fn new(server_targets: Vec<WebsocketServerTarget>) -> Self {
        Self { server_targets }
    }
}

#[async_trait]
impl TcpServerHandler for WebsocketTcpServerHandler {
    fn manages_handshake_timeout(&self) -> bool {
        !self.server_targets.is_empty()
            && self
                .server_targets
                .iter()
                .all(|target| target.handler.manages_handshake_timeout())
    }

    fn pre_transport_handshake_timeout(
        &self,
        _context: &TcpServerConnectionContext,
    ) -> Option<Duration> {
        Some(XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT)
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_context(
            server_stream,
            TcpServerConnectionContext::default(),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        mut context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        tracing::debug!("WebsocketTcpServerHandler setup_server_stream");
        let ParsedHttpData {
            first_line,
            headers: request_headers,
            line_reader,
        } = timeout(
            XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT,
            ParsedHttpData::parse(&mut server_stream),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "WebSocket handshake timed out",
            )
        })??;

        let (method, request_target) =
            match parse_xray_websocket_request_line(&first_line) {
                Ok(parsed) => parsed,
                Err(WebsocketRequestLineError::Malformed) => {
                    write_xray_bad_request_line(&mut server_stream).await?;
                    return Err(std::io::Error::other(
                        "malformed HTTP request line",
                    ));
                }
                Err(WebsocketRequestLineError::UnsupportedVersion) => {
                    write_xray_unsupported_http_version(&mut server_stream).await?;
                    return Err(std::io::Error::other(
                        "unsupported HTTP protocol version",
                    ));
                }
            };
        if method != "GET" {
            write_xray_method_not_allowed(&mut server_stream).await?;
            return Err(std::io::Error::other("websocket method is not GET"));
        }
        let request_path = xray_websocket_request_path(request_target);
        debug!("request path is {}", request_path);
        let websocket_key = request_headers
            .get("sec-websocket-key")
            .and_then(|values| values.first())
            .cloned();
        let websocket_early_data = request_headers
            .get("sec-websocket-protocol")
            .and_then(|values| values.first())
            .and_then(|value| decode_xray_websocket_early_data(value));
        if let Some(peer_addr) = xray_websocket_forwarded_peer(&request_headers) {
            context.peer_addr = Some(peer_addr);
        }
        if !header_contains_token(&request_headers, "upgrade", "websocket")
            || !header_contains_token(&request_headers, "connection", "upgrade")
            || !header_contains_token(
                &request_headers,
                "sec-websocket-version",
                "13",
            )
            || !websocket_key.as_deref().is_some_and(valid_websocket_key)
        {
            write_bad_websocket_request(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid websocket handshake"));
        }
        let websocket_key = websocket_key.expect("validated websocket key");

        let mut saw_xray_mismatch = false;
        'outer: for server_target in self.server_targets.iter() {
            debug!("checking server target {:?}", server_target);
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                xray_mismatch_404,
                handler,
            } = server_target;
            debug!("matching path is {:?} {:?}", matching_path, &request_path);
            if let Some(path) = matching_path
                && path != &request_path
            {
                debug!("path not match");
                saw_xray_mismatch |= *xray_mismatch_404;
                continue;
            }
            debug!("matching headers is {:?}", matching_headers);
            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers
                        .get(header_key)
                        .and_then(|values| values.first())
                        != Some(header_val)
                    {
                        saw_xray_mismatch |= *xray_mismatch_404;
                        continue 'outer;
                    }
                }
            }

            let websocket_key_response =
                create_websocket_key_response(websocket_key);

            let mut http_response = format!(
                concat!(
                    "HTTP/1.1 101 Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "Sec-WebSocket-Accept: {}\r\n"
                ),
                websocket_key_response,
            );
            if websocket_early_data.is_some()
                && let Some(protocol) = request_headers
                    .get("sec-websocket-protocol")
                    .and_then(|values| values.first())
            {
                http_response.push_str("Sec-WebSocket-Protocol: ");
                http_response.push_str(protocol);
                http_response.push_str("\r\n");
            }
            http_response.push_str("\r\n");

            server_stream.write_all(http_response.as_bytes()).await?;

            let websocket_stream: Box<dyn AsyncStream> =
                Box::new(WebsocketStream::new(
                    server_stream,
                    false,
                    line_reader.unparsed_data(),
                ));
            let websocket_stream =
                if let Some(early_data) = websocket_early_data.clone() {
                    Box::new(PrefixedStream::new(early_data, websocket_stream))
                        as Box<dyn AsyncStream>
                } else {
                    websocket_stream
                };

            let mut target_setup_result = handler
                .setup_server_stream_with_context(websocket_stream, context.clone())
                .await;

            if let Ok(ref mut setup_result) = target_setup_result {
                setup_result.set_need_initial_flush(true);
                debug!("todo override_proxy_provider_unspecified");
            }

            return target_setup_result;
        }

        if saw_xray_mismatch {
            write_xray_websocket_not_found(&mut server_stream).await?;
        }
        Err(std::io::Error::other("No matching websocket targets"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebsocketRequestLineError {
    Malformed,
    UnsupportedVersion,
}

fn parse_xray_websocket_request_line(
    line: &str,
) -> Result<(&str, &str), WebsocketRequestLineError> {
    let (method, rest) = line
        .split_once(' ')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    let (request_target, version) = rest
        .split_once(' ')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    if method.is_empty()
        || request_target.is_empty()
        || version.is_empty()
        || method.bytes().any(|byte| byte.is_ascii_whitespace())
        || request_target
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
        || version.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WebsocketRequestLineError::Malformed);
    }

    let version = version
        .strip_prefix("HTTP/")
        .ok_or(WebsocketRequestLineError::Malformed)?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(WebsocketRequestLineError::Malformed)?;
    if major.len() != 1
        || minor.len() != 1
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WebsocketRequestLineError::Malformed);
    }
    if major != "1" {
        return Err(WebsocketRequestLineError::UnsupportedVersion);
    }

    Ok((method, request_target))
}

fn xray_websocket_request_path(request_target: &str) -> String {
    let origin_target = if let Some(rest) = request_target.strip_prefix("http://") {
        rest.find('/').map_or("/", |path_start| &rest[path_start..])
    } else if let Some(rest) = request_target.strip_prefix("https://") {
        rest.find('/').map_or("/", |path_start| &rest[path_start..])
    } else {
        request_target
    };

    origin_target
        .split_once('?')
        .map_or(origin_target, |(path, _)| path)
        .to_string()
}

fn header_contains_token(
    headers: &HashMap<String, Vec<String>>,
    name: &str,
    token: &str,
) -> bool {
    headers.get(name).is_some_and(|values| {
        values.iter().any(|value| {
            value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case(token))
        })
    })
}

fn valid_websocket_key(key: &str) -> bool {
    BASE64.decode(key).is_ok_and(|decoded| decoded.len() == 16)
}

fn xray_websocket_forwarded_peer(
    headers: &HashMap<String, Vec<String>>,
) -> Option<SocketAddr> {
    let first = headers.get("x-forwarded-for")?.first()?.split(',').next()?;
    let mut candidate = first;
    if candidate.starts_with('[') && candidate.ends_with(']') {
        candidate = &candidate[1..candidate.len() - 1];
    }
    if candidate
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || candidate
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        candidate = candidate.trim();
    }

    let ip = candidate.parse::<IpAddr>().ok()?;
    let ip = match ip {
        IpAddr::V6(ipv6) => {
            ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4)
        }
        ip => ip,
    };
    Some(SocketAddr::new(ip, 0))
}

fn decode_xray_websocket_early_data(value: &str) -> Option<Vec<u8>> {
    let normalized = value.replace('+', "-").replace('/', "_").replace('=', "");
    URL_SAFE_NO_PAD
        .decode(normalized)
        .ok()
        .filter(|decoded| !decoded.is_empty())
}

async fn write_xray_websocket_not_found(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    let response = format!(
        concat!(
            "HTTP/1.1 404 Not Found\r\n",
            "Date: {}\r\n",
            "Content-Length: 0\r\n",
            "\r\n"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_xray_method_not_allowed(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const BODY: &str = "Method Not Allowed\n";
    let response = format!(
        concat!(
            "HTTP/1.1 405 Method Not Allowed\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Sec-Websocket-Version: 13\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Date: {}\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
        BODY.len(),
        BODY,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_xray_bad_request_line(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
        )
        .await?;
    stream.flush().await
}

async fn write_xray_unsupported_http_version(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const STATUS: &str =
        "505 HTTP Version Not Supported: unsupported protocol version";
    let response = format!(
        "HTTP/1.1 {STATUS}\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n{STATUS}"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

async fn write_bad_websocket_request(
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    const BODY: &str = "Bad Request\n";
    let response = format!(
        concat!(
            "HTTP/1.1 400 Bad Request\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Sec-Websocket-Version: 13\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Date: {}\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}"
        ),
        httpdate::fmt_http_date(SystemTime::now()),
        BODY.len(),
        BODY,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}

#[cfg(test)]
mod tests {
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
        XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT, xray_websocket_request_path,
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
            handler: Box::new(AcceptingInner),
        }])
    }

    async fn run_handshake(
        request: &str,
    ) -> (std::io::Result<TcpServerSetupResult>, String) {
        let (client, mut peer) = tokio::io::duplex(8192);
        let handler = accepting_handler();
        let task = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(TestStream(client)))
                .await
        });
        peer.write_all(request.as_bytes()).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        (task.await.unwrap(), String::from_utf8(response).unwrap())
    }

    #[test]
    fn websocket_request_path_matches_xray_query_and_absolute_form() {
        assert_eq!(xray_websocket_request_path("/ws"), "/ws");
        assert_eq!(xray_websocket_request_path("/ws?foo=bar"), "/ws");
        assert_eq!(xray_websocket_request_path("/ws?"), "/ws");
        assert_eq!(
            xray_websocket_request_path("http://example.com/ws?foo=bar"),
            "/ws"
        );
        assert_eq!(
            xray_websocket_request_path("https://example.com/ws?foo=bar"),
            "/ws"
        );
        assert_eq!(
            xray_websocket_request_path("/ws%3Ffoo=bar"),
            "/ws%3Ffoo=bar"
        );
        assert_eq!(xray_websocket_request_path("/ws#frag"), "/ws#frag");
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_request_target_paths() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for target in [
            "/?foo=bar",
            "http://example.com/?foo=bar",
            "https://example.com/?foo=bar",
        ] {
            let request = format!(
                "GET {target} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            let (result, response) = run_handshake(&request).await;
            assert!(matches!(result, Ok(TcpServerSetupResult::AlreadyHandled)));
            assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
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

        for method in ["POST", "PUT"] {
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
        ] {
            let (result, response) =
                run_handshake(&format!("{request_line}\r\n{headers}")).await;
            assert!(result.is_err());
            assert_eq!(
                response,
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request"
            );
        }
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
            let headers = HashMap::from([(
                "x-forwarded-for".to_string(),
                vec![value.to_string()],
            )]);
            assert_eq!(
                xray_websocket_forwarded_peer(&headers),
                expected.map(|value| value.parse().unwrap()),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_early_data_subprotocol() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/".to_string()),
            matching_headers: None,
            xray_mismatch_404: false,
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
            response
                .contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
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
            let handler =
                WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
                    matching_path: Some("/ws".to_string()),
                    matching_headers: None,
                    xray_mismatch_404,
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
            let handler =
                WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
                    matching_path: Some("/ws".to_string()),
                    matching_headers: Some(HashMap::from([(
                        "host".to_string(),
                        "expected.example".to_string(),
                    )])),
                    xray_mismatch_404,
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
            handler.pre_transport_handshake_timeout(
                &TcpServerConnectionContext::default()
            ),
            Some(XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT)
        );

        let handler =
            WebsocketTcpServerHandler::new(vec![target(true), target(false)]);
        assert!(!handler.manages_handshake_timeout());

        let handler = WebsocketTcpServerHandler::new(Vec::new());
        assert!(!handler.manages_handshake_timeout());
    }
}
