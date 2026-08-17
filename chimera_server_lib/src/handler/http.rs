use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::server_config::HttpUser,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
    util::prefixed_stream::PrefixedStream,
};

const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct HttpTcpServerHandler {
    accounts: Vec<HttpUser>,
    allow_transparent: bool,
    inbound_tag: String,
}

impl HttpTcpServerHandler {
    pub fn new(
        accounts: Vec<HttpUser>,
        allow_transparent: bool,
        inbound_tag: &str,
    ) -> Self {
        Self {
            accounts,
            allow_transparent,
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let request_line =
            read_http_line(&mut server_stream, MAX_REQUEST_LINE_BYTES).await?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || method.is_empty()
            || target.is_empty()
            || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid HTTP proxy request line: {request_line}"),
            ));
        }

        let mut header_bytes = 0usize;
        let mut authenticated_user = None;
        let mut host_header = None;
        let mut forwarded_headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut proxy_keep_alive = false;
        let mut proxy_connection_seen = false;
        let mut request_content_length = None;
        let mut request_transfer_encoding = false;
        let mut chunked_transfer_encoding = false;
        loop {
            let line = read_http_line(&mut server_stream, MAX_HEADER_BYTES).await?;
            header_bytes = header_bytes.saturating_add(line.len() + 2);
            if header_bytes > MAX_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP proxy headers exceed 16384 bytes",
                ));
            }
            if line.is_empty() {
                break;
            }

            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("proxy-authorization") {
                authenticated_user = self.authenticate_basic(value);
                continue;
            }
            if name.eq_ignore_ascii_case("proxy-connection") {
                if !proxy_connection_seen {
                    proxy_keep_alive = value.eq_ignore_ascii_case("keep-alive");
                    proxy_connection_seen = true;
                }
                continue;
            }
            if name.eq_ignore_ascii_case("proxy-authenticate")
                || name.eq_ignore_ascii_case("te")
                || name.eq_ignore_ascii_case("trailers")
                || name.eq_ignore_ascii_case("upgrade")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                connection_hop_headers.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_ascii_lowercase),
                );
                continue;
            }
            if name.eq_ignore_ascii_case("host") {
                host_header = Some(value.to_string());
            }
            if name.eq_ignore_ascii_case("content-length") {
                let length = value.parse::<u64>().map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP Content-Length {value}: {error}"),
                    )
                })?;
                match request_content_length {
                    Some(previous) if previous != length => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "conflicting HTTP Content-Length headers",
                        ));
                    }
                    Some(_) => continue,
                    None => request_content_length = Some(length),
                }
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if request_transfer_encoding
                    || !value.eq_ignore_ascii_case("chunked")
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unsupported HTTP Transfer-Encoding",
                    ));
                }
                request_transfer_encoding = true;
                chunked_transfer_encoding = true;
            }
            forwarded_headers.push(line);
        }

        if !self.accounts.is_empty() && authenticated_user.is_none() {
            let response = format!(
                "{version} 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
            );
            server_stream.write_all(response.as_bytes()).await?;
            server_stream.flush().await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "missing or invalid HTTP proxy authentication",
            ));
        }

        let traffic_context = Some(
            authenticated_user
                .map(|identity| {
                    TrafficContext::new("http")
                        .with_identity(identity)
                        .with_inbound_tag(self.inbound_tag.clone())
                })
                .unwrap_or_else(|| {
                    TrafficContext::new("http")
                        .with_inbound_tag(self.inbound_tag.clone())
                }),
        );

        if method.eq_ignore_ascii_case("CONNECT") {
            let remote_location =
                NetLocation::from_str(target, None).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP CONNECT authority {target}: {error}"),
                    )
                })?;
            let response = format!("{version} 200 Connection established\r\n\r\n")
                .into_bytes()
                .into_boxed_slice();
            return Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: server_stream,
                need_initial_flush: true,
                connection_success_response: Some(response),
                traffic_context,
            });
        }

        let (remote_location, origin_target) = if target.starts_with("http://") {
            parse_absolute_http_target(target)?
        } else if target.starts_with("https://") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTPS absolute-form requests must use CONNECT",
            ));
        } else if self.allow_transparent && target.starts_with('/') {
            let host = host_header.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "transparent HTTP request requires a Host header",
                )
            })?;
            let remote_location =
                NetLocation::from_str(host, Some(80)).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid HTTP Host header {host}: {error}"),
                    )
                })?;
            (remote_location, target.to_string())
        } else {
            let response = format!(
                "{version} 400 Bad Request\r\n\
                 Connection: close\r\n\
                 Proxy-Connection: close\r\n\
                 Content-Length: 0\r\n\r\n"
            );
            server_stream.write_all(response.as_bytes()).await?;
            server_stream.flush().await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HTTP proxy request must use an absolute http:// URI unless allowTransparent is enabled",
            ));
        };

        let mut initial_request = format!("{method} {origin_target} {version}\r\n");
        for line in forwarded_headers {
            let header_name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if connection_hop_headers
                .iter()
                .any(|name| name == &header_name)
                || (chunked_transfer_encoding && header_name == "content-length")
            {
                continue;
            }
            initial_request.push_str(&line);
            initial_request.push_str("\r\n");
        }
        initial_request.push_str("Connection: close\r\n\r\n");

        let bodyless_plain_request = request_content_length.unwrap_or(0) == 0
            && !request_transfer_encoding
            && (method.eq_ignore_ascii_case("GET")
                || method.eq_ignore_ascii_case("HEAD"));
        if proxy_keep_alive && bodyless_plain_request {
            return Ok(TcpServerSetupResult::HttpPlainForward {
                remote_location,
                stream: server_stream,
                request_head: initial_request.into_bytes().into_boxed_slice(),
                request_method: method.to_string(),
                keep_alive: proxy_keep_alive,
                next_handler: Box::new(self.clone()),
                traffic_context,
            });
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(PrefixedStream::new(
                initial_request.into_bytes(),
                server_stream,
            )),
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
    }
}

fn parse_absolute_http_target(
    target: &str,
) -> std::io::Result<(NetLocation, String)> {
    let remainder = target.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP proxy target must start with http://",
        )
    })?;
    let split = remainder
        .char_indices()
        .find_map(|(index, value)| matches!(value, '/' | '?').then_some(index));
    let (authority, path) = match split {
        Some(index) => {
            let tail = &remainder[index..];
            let path = if tail.starts_with('?') {
                format!("/{tail}")
            } else {
                tail.to_string()
            };
            (&remainder[..index], path)
        }
        None => (remainder, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP absolute URI is missing an authority",
        ));
    }
    let remote_location =
        NetLocation::from_str(authority, Some(80)).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid HTTP absolute URI authority {authority}: {error}"),
            )
        })?;
    Ok((remote_location, path))
}

impl HttpTcpServerHandler {
    fn authenticate_basic(&self, value: &str) -> Option<String> {
        let mut parts = value.split_whitespace();
        let scheme = parts.next()?;
        let token = parts.next()?;
        if parts.next().is_some() || !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = BASE64.decode(token).ok()?;
        let decoded = std::str::from_utf8(&decoded).ok()?;
        let (username, password) = decoded.split_once(':')?;
        self.accounts
            .iter()
            .find(|account| {
                account.username == username && account.password == password
            })
            .map(|account| account.username.clone())
    }
}

async fn read_http_line<S>(
    stream: &mut S,
    max_bytes: usize,
) -> std::io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        line.push(byte);
        if line.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy line is too long",
            ));
        }
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("HTTP proxy line is not UTF-8: {error}"),
                )
            });
        }
    }
}

pub(crate) async fn relay_plain_http_response<R, W>(
    upstream: &mut R,
    downstream: &mut W,
    request_method: &str,
) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let status_line =
            read_http_line(upstream, MAX_RESPONSE_HEADER_BYTES).await?;
        let status_code = parse_http_status_code(&status_line)?;
        let mut header_bytes = 0usize;
        let mut headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut content_length = None;
        let mut content_length_valid = true;
        let mut transfer_encoding = false;

        loop {
            let line = read_http_line(upstream, MAX_RESPONSE_HEADER_BYTES).await?;
            header_bytes = header_bytes.saturating_add(line.len() + 2);
            if header_bytes > MAX_RESPONSE_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP proxy response headers exceed 65536 bytes",
                ));
            }
            if line.is_empty() {
                break;
            }

            let Some((name, value)) = line.split_once(':') else {
                headers.push((String::new(), line));
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "connection" {
                connection_hop_headers.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_ascii_lowercase),
                );
            } else if name == "content-length" {
                match value.parse::<u64>() {
                    Ok(length) => match content_length {
                        Some(previous) if previous != length => {
                            content_length_valid = false;
                        }
                        None => content_length = Some(length),
                        _ => {}
                    },
                    Err(_) => content_length_valid = false,
                }
            } else if name == "transfer-encoding" {
                transfer_encoding = true;
            }
            headers.push((name, line));
        }

        if (100..200).contains(&status_code) {
            write_http_header_block(downstream, &status_line, &headers).await?;
            continue;
        }

        let no_body = request_method.eq_ignore_ascii_case("HEAD")
            || matches!(status_code, 204 | 304);
        let body_length = if no_body {
            Some(0)
        } else if !transfer_encoding && content_length_valid {
            content_length
        } else {
            None
        };

        let mut response_head = format!("{status_line}\r\n");
        for (name, line) in headers {
            let strip_static = matches!(
                name.as_str(),
                "proxy-connection"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
                    | "upgrade"
            ) || (name == "transfer-encoding"
                && body_length.is_some());
            if name == "connection"
                || (body_length.is_some() && name == "keep-alive")
                || strip_static
                || connection_hop_headers.iter().any(|hop| hop == &name)
            {
                continue;
            }
            response_head.push_str(&line);
            response_head.push_str("\r\n");
        }
        if body_length.is_some() {
            response_head.push_str(
                "Connection: keep-alive\r\n\
                 Keep-Alive: timeout=60\r\n\
                 Proxy-Connection: keep-alive\r\n",
            );
        } else {
            response_head.push_str("Connection: close\r\n");
        }
        response_head.push_str("\r\n");
        downstream.write_all(response_head.as_bytes()).await?;

        if let Some(length) = body_length {
            let mut body = upstream.take(length);
            let copied = tokio::io::copy(&mut body, downstream).await?;
            if copied != length {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HTTP proxy upstream response body ended early",
                ));
            }
        } else {
            tokio::io::copy(upstream, downstream).await?;
        }
        downstream.flush().await?;
        return Ok(body_length.is_some());
    }
}

fn parse_http_status_code(status_line: &str) -> std::io::Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid HTTP proxy upstream status line: {status_line}"),
        ));
    }
    status.parse::<u16>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid HTTP proxy upstream status code {status}: {error}"),
        )
    })
}

async fn write_http_header_block<W>(
    writer: &mut W,
    status_line: &str,
    headers: &[(String, String)],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(status_line.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    for (_, line) in headers {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\r\n").await?;
    }
    writer.write_all(b"\r\n").await
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };

    use crate::{
        async_stream::{AsyncPing, AsyncStream},
        config::server_config::HttpUser,
        handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    };

    use super::{HttpTcpServerHandler, relay_plain_http_response};

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
    async fn connect_preserves_early_tunnel_bytes() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-in");
        let request =
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nearly";
        let (mut client, server) = duplex(1024);
        client.write_all(request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("CONNECT should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("HTTP CONNECT returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:443");
        assert_eq!(
            connection_success_response.as_deref(),
            Some(b"HTTP/1.1 200 Connection established\r\n\r\n".as_slice())
        );
        assert_eq!(
            traffic_context.unwrap().inbound_tag.as_deref(),
            Some("http-in")
        );
        let mut early = [0u8; 5];
        stream.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
    }

    #[tokio::test]
    async fn basic_auth_sets_user_identity() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-auth",
        );
        let token = BASE64.encode("alice:secret");
        let request = format!(
            "CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        let (mut client, server) = duplex(1024);
        client.write_all(request.as_bytes()).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("authenticated CONNECT should succeed");
        let TcpServerSetupResult::TcpForward {
            traffic_context, ..
        } = result
        else {
            panic!("HTTP CONNECT returned non-TCP result");
        };
        assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn absolute_form_request_is_rewritten_and_proxy_headers_are_removed() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-forward",
        );
        let token = BASE64.encode("alice:secret");
        let request = format!(
            "POST http://example.com:8080/upload?q=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             Proxy-Authorization: Basic {token}\r\n\
             Proxy-Authenticate: Basic realm=\"upstream\"\r\n\
             TE: trailers\r\n\
             Trailers: X-Checksum\r\n\
             Upgrade: websocket\r\n\
             X-Remove-Early: hidden\r\n\
             Proxy-Connection: keep-alive\r\n\
             Connection: keep-alive, X-Remove-Early, x-remove-late\r\n\
             X-Test: forwarded\r\n\
             X-Remove-Late: hidden-too\r\n\r\nbody"
        );
        let (mut client, server) = duplex(4096);
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("absolute-form HTTP proxy request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            connection_success_response,
            traffic_context,
            ..
        } = result
        else {
            panic!("HTTP forward returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:8080");
        assert!(connection_success_response.is_none());
        assert_eq!(traffic_context.unwrap().identity.as_deref(), Some("alice"));
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "POST /upload?q=1 HTTP/1.1\r\n\
             Host: example.com:8080\r\n\
             X-Test: forwarded\r\n\
             Connection: close\r\n\r\nbody"
        );
    }

    #[tokio::test]
    async fn chunked_request_drops_conflicting_content_length_like_xray() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-chunked");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 99\r\n\
Transfer-Encoding: chunked\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("chunked HTTP proxy request should succeed");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding: chunked\r\n\
Connection: close\r\n\r\n\
4\r\ntest\r\n0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn unsupported_transfer_encoding_is_rejected_like_xray() {
        for transfer_encoding in [
            "gzip",
            "chunked, gzip",
            "gzip, chunked",
            "chunked\r\nTransfer-Encoding: chunked",
        ] {
            let handler = HttpTcpServerHandler::new(
                Vec::new(),
                false,
                "http-transfer-encoding",
            );
            let request = format!(
                "POST http://example.com/upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: {transfer_encoding}\r\n\r\n\
                 4\r\ntest\r\n0\r\n\r\n"
            );
            let (mut client, server) = duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!(
                    "unsupported Transfer-Encoding {transfer_encoding:?} must be rejected"
                ),
                Err(error) => error,
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                error
                    .to_string()
                    .contains("unsupported HTTP Transfer-Encoding")
            );
        }
    }

    #[tokio::test]
    async fn duplicate_content_length_is_collapsed_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Content-Length: 4\r\n\r\nbody";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("matching duplicate Content-Length should succeed");
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result else {
            panic!("HTTP forward returned non-TCP result");
        };
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "POST /upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Connection: close\r\n\r\nbody"
        );
    }

    #[tokio::test]
    async fn conflicting_content_length_is_rejected_like_xray() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), false, "http-content-length");
        let request = b"POST http://example.com/upload HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Length: 4\r\n\
Content-Length: 5\r\n\r\nbody";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("conflicting Content-Length must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("conflicting HTTP Content-Length")
        );
    }

    #[tokio::test]
    async fn keep_alive_get_uses_plain_http_forward() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-keepalive");
        let request = b"GET http://example.com/one HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Proxy-Connection: keep-alive\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("keep-alive GET should use the plain HTTP relay");
        let TcpServerSetupResult::HttpPlainForward {
            remote_location,
            request_head,
            request_method,
            keep_alive,
            traffic_context,
            ..
        } = result
        else {
            panic!("keep-alive GET returned non-HTTP plain result");
        };
        assert_eq!(remote_location.to_string(), "example.com:80");
        assert_eq!(request_method, "GET");
        assert!(keep_alive);
        assert_eq!(
            traffic_context.unwrap().inbound_tag.as_deref(),
            Some("http-keepalive")
        );
        assert_eq!(
            request_head.as_ref(),
            b"GET /one HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn plain_http_response_with_content_length_is_reusable() {
        let upstream_response = b"HTTP/1.1 100 Continue\r\nX-Early: yes\r\n\r\n\
                                  HTTP/1.1 200 OK\r\n\
                                  Content-Length: 5\r\n\
                                  Connection: close, X-Remove\r\n\
                                  Keep-Alive: timeout=5\r\n\
                                  X-Remove: hidden\r\n\
                                  X-Keep: visible\r\n\r\nhello";
        let (mut upstream_client, mut upstream_server) = duplex(4096);
        upstream_client.write_all(upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(4096);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 100 Continue\r\nX-Early: yes\r\n\r\n\
             HTTP/1.1 200 OK\r\n\
             Content-Length: 5\r\n\
             X-Keep: visible\r\n\
             Connection: keep-alive\r\n\
             Keep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn plain_http_response_without_length_closes_connection() {
        let upstream_response = b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nhello";
        let (mut upstream_client, mut upstream_server) = duplex(2048);
        upstream_client.write_all(upstream_response).await.unwrap();
        upstream_client.shutdown().await.unwrap();
        let (mut downstream_client, mut downstream_server) = duplex(2048);

        let reusable = relay_plain_http_response(
            &mut upstream_server,
            &mut downstream_server,
            "GET",
        )
        .await
        .unwrap();
        assert!(!reusable);
        downstream_server.shutdown().await.unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            String::from_utf8(response).unwrap(),
            "HTTP/1.1 200 OK\r\nX-Test: yes\r\nConnection: close\r\n\r\nhello"
        );
    }

    #[tokio::test]
    async fn transparent_origin_form_uses_host_header() {
        let handler =
            HttpTcpServerHandler::new(Vec::new(), true, "http-transparent");
        let request = b"GET /health HTTP/1.1\r\nHost: example.com:8081\r\n\r\n";
        let (mut client, server) = duplex(2048);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("transparent HTTP request should succeed");
        let TcpServerSetupResult::TcpForward {
            remote_location,
            mut stream,
            ..
        } = result
        else {
            panic!("transparent HTTP returned non-TCP result");
        };
        assert_eq!(remote_location.to_string(), "example.com:8081");
        let mut forwarded = Vec::new();
        stream.read_to_end(&mut forwarded).await.unwrap();
        assert_eq!(
            String::from_utf8(forwarded).unwrap(),
            "GET /health HTTP/1.1\r\n\
             Host: example.com:8081\r\n\
             Connection: close\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn origin_form_requires_allow_transparent() {
        let handler = HttpTcpServerHandler::new(Vec::new(), false, "http-proxy");
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("origin-form request must require transparent mode"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("allowTransparent"));
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 400 Bad Request\r\n\
              Connection: close\r\n\
              Proxy-Connection: close\r\n\
              Content-Length: 0\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn missing_auth_returns_407() {
        let handler = HttpTcpServerHandler::new(
            vec![HttpUser {
                username: "alice".into(),
                password: "secret".into(),
            }],
            false,
            "http-auth",
        );
        let (mut client, server) = duplex(2048);
        client
            .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("missing auth must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(
            response,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
        );
    }
}
