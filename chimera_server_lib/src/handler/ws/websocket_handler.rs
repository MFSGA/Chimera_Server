use std::{
    collections::HashMap,
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
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        tracing::debug!("WebsocketTcpServerHandler setup_server_stream");
        let ParsedHttpData {
            mut first_line,
            headers: mut request_headers,
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

        let request_path = {
            if !first_line.ends_with(" HTTP/1.0")
                && !first_line.ends_with(" HTTP/1.1")
            {
                return Err(std::io::Error::other(format!(
                    "invalid http request version: {}",
                    first_line
                )));
            }

            if !first_line.starts_with("GET ") {
                return Err(std::io::Error::other(format!(
                    "invalid http request: {}",
                    first_line
                )));
            }

            first_line.truncate(first_line.len() - 9);

            xray_websocket_request_path(&first_line[4..])
        };
        debug!("request path is {}", request_path);
        let websocket_key = request_headers
            .remove("sec-websocket-key")
            .and_then(|values| values.into_iter().next())
            .ok_or_else(|| std::io::Error::other("missing websocket key header"))?;
        let websocket_early_data = request_headers
            .get("sec-websocket-protocol")
            .and_then(|values| values.first())
            .and_then(|value| decode_xray_websocket_early_data(value));
        if !header_contains_token(&request_headers, "upgrade", "websocket")
            || !header_contains_token(&request_headers, "connection", "upgrade")
            || !header_contains_token(
                &request_headers,
                "sec-websocket-version",
                "13",
            )
            || !valid_websocket_key(&websocket_key)
        {
            write_bad_websocket_request(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid websocket handshake"));
        }

        'outer: for server_target in self.server_targets.iter() {
            debug!("checking server target {:?}", server_target);
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                handler,
            } = server_target;
            debug!("matching path is {:?} {:?}", matching_path, &request_path);
            if let Some(path) = matching_path
                && path != &request_path
            {
                debug!("path not match");
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

        Err(std::io::Error::other("No matching websocket targets"))
    }
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

fn decode_xray_websocket_early_data(value: &str) -> Option<Vec<u8>> {
    let normalized = value.replace('+', "-").replace('/', "_").replace('=', "");
    URL_SAFE_NO_PAD
        .decode(normalized)
        .ok()
        .filter(|decoded| !decoded.is_empty())
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

    fn target(manages_handshake_timeout: bool) -> WebsocketServerTarget {
        WebsocketServerTarget {
            matching_path: None,
            matching_headers: None,
            handler: Box::new(Inner {
                manages_handshake_timeout,
            }),
        }
    }

    fn accepting_handler() -> WebsocketTcpServerHandler {
        WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/".to_string()),
            matching_headers: None,
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
        ] {
            let (result, response) = run_handshake(&invalid).await;
            assert!(result.is_err());
            assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
            assert!(response.contains("Sec-Websocket-Version: 13\r\n"));
            assert!(response.ends_with("\r\n\r\nBad Request\n"));
        }
    }

    #[tokio::test]
    async fn websocket_handshake_matches_xray_early_data_subprotocol() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            matching_path: Some("/".to_string()),
            matching_headers: None,
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
