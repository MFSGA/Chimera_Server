use std::collections::BTreeSet;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::server_config::HttpUser,
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
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
    user_level: u32,
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
            user_level: 0,
        }
    }

    pub fn with_user_level(mut self, user_level: u32) -> Self {
        self.user_level = user_level;
        self
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    fn manages_handshake_timeout(&self) -> bool {
        true
    }

    fn pre_transport_handshake_timeout(
        &self,
        context: &TcpServerConnectionContext,
    ) -> Option<std::time::Duration> {
        context
            .inbound_handshake_runtime()
            .map(|runtime| runtime.xray_handshake_timeout_for_level(self.user_level))
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_inner(server_stream).await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        let Some(runtime) = context.inbound_handshake_runtime() else {
            return self.setup_server_stream_inner(server_stream).await;
        };
        let timeout = runtime.xray_handshake_timeout_for_level(self.user_level);
        tokio::time::timeout(timeout, self.setup_server_stream_inner(server_stream))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP handshake timed out",
                )
            })?
    }
}

impl HttpTcpServerHandler {
    async fn setup_server_stream_inner(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let request_line =
            read_http_line(&mut server_stream, MAX_REQUEST_LINE_BYTES).await?;
        let (method, target, version) = parse_http_request_line(&request_line)?;

        let mut header_bytes = 0usize;
        let mut authenticated_user = None;
        let mut proxy_authorization_seen = false;
        let mut host_header = None;
        let mut host_header_seen = false;
        let mut forwarded_headers = Vec::new();
        let mut connection_hop_headers = Vec::new();
        let mut proxy_keep_alive = false;
        let mut proxy_connection_seen = false;
        let mut request_content_length = None;
        let mut request_transfer_encoding = false;
        let mut chunked_transfer_encoding = false;
        let mut request_trailer_values = Vec::new();
        let mut header_lines: Vec<String> = Vec::new();
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
            if line.starts_with([' ', '\t']) {
                let previous = header_lines.last_mut().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "HTTP header continuation has no preceding field",
                    )
                })?;
                previous.push(' ');
                previous.push_str(line.trim());
            } else {
                header_lines.push(line);
            }
        }

        for line in header_lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "malformed HTTP header line",
                ));
            };
            if !is_http_header_name(name) {
                continue;
            }
            if has_invalid_http_header_value(value) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid control character in HTTP header value",
                ));
            }
            let value = value.trim();
            if name.eq_ignore_ascii_case("proxy-authorization") {
                if !proxy_authorization_seen {
                    authenticated_user = self.authenticate_basic(value);
                    proxy_authorization_seen = true;
                }
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
            if name.eq_ignore_ascii_case("trailer") {
                request_trailer_values.push(value.to_string());
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
                if host_header_seen {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "multiple HTTP Host headers",
                    ));
                }
                host_header_seen = true;
                host_header = Some(value.to_string());
            }
            if name.eq_ignore_ascii_case("content-length") {
                let length = parse_http_content_length(value)?;
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
                forwarded_headers.push(format!("Content-Length: {length}"));
                continue;
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
                        .with_user_level(self.user_level)
                })
                .unwrap_or_else(|| {
                    TrafficContext::new("http")
                        .with_inbound_tag(self.inbound_tag.clone())
                        .with_user_level(self.user_level)
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

        let (remote_location, origin_target, absolute_authority) = if target
            .starts_with("http://")
        {
            let (remote_location, origin_target, authority) =
                parse_absolute_http_target(target, "http://", 80)?;
            (remote_location, origin_target, Some(authority))
        } else if target.starts_with("https://") {
            let (remote_location, origin_target, authority) =
                parse_absolute_http_target(target, "https://", 443)?;
            (remote_location, origin_target, Some(authority))
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
            (remote_location, target.to_string(), None)
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

        let request_trailer_names = if chunked_transfer_encoding {
            let mut names = BTreeSet::new();
            for value in request_trailer_values {
                names.extend(parse_http_request_trailer_names(&value)?);
            }
            names
        } else {
            BTreeSet::new()
        };

        let http_10_chunked = version == "HTTP/1.0" && chunked_transfer_encoding;
        let forwarded_version = if http_10_chunked { "HTTP/1.1" } else { version };
        let mut initial_request =
            format!("{method} {origin_target} {forwarded_version}\r\n");
        if let Some(authority) = absolute_authority.as_deref() {
            initial_request.push_str("Host: ");
            initial_request.push_str(authority);
            initial_request.push_str("\r\n");
        }
        for line in forwarded_headers {
            let header_name = line
                .split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if (absolute_authority.is_some() && header_name == "host")
                || connection_hop_headers
                    .iter()
                    .any(|name| name == &header_name)
                || (chunked_transfer_encoding && header_name == "content-length")
                || (http_10_chunked && header_name == "transfer-encoding")
            {
                continue;
            }
            initial_request.push_str(&line);
            initial_request.push_str("\r\n");
        }
        if http_10_chunked {
            initial_request.push_str("Content-Length: 0\r\n");
        } else if chunked_transfer_encoding && !request_trailer_names.is_empty() {
            initial_request.push_str("Trailer: ");
            initial_request.push_str(
                &request_trailer_names
                    .iter()
                    .map(|name| canonical_http_header_name(name))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            initial_request.push_str("\r\n");
        }
        initial_request.push_str("Connection: close\r\n\r\n");

        let bodyless_plain_request = request_content_length.unwrap_or(0) == 0
            && !request_transfer_encoding
            && (method.eq_ignore_ascii_case("GET")
                || method.eq_ignore_ascii_case("HEAD"));
        if http_10_chunked || (proxy_keep_alive && bodyless_plain_request) {
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

        let stream: Box<dyn AsyncStream> = if chunked_transfer_encoding {
            Box::new(ChunkedRequestStream::new(
                initial_request.into_bytes(),
                server_stream,
                request_trailer_names.into_iter().collect(),
            ))
        } else {
            Box::new(PrefixedStream::new(
                initial_request.into_bytes(),
                server_stream,
            ))
        };
        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream,
            need_initial_flush: false,
            connection_success_response: None,
            traffic_context,
        })
    }
}

impl HttpTcpServerHandler {
    fn authenticate_basic(&self, value: &str) -> Option<String> {
        let token = value.strip_prefix("Basic ")?;
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

#[cfg(test)]
mod tests;

mod request;
#[cfg(test)]
use request::parse_absolute_http_authority;
mod response;

use request::{
    ChunkedRequestStream, canonical_http_header_name, has_invalid_http_header_value,
    is_http_header_name, parse_absolute_http_target, parse_http_content_length,
    parse_http_request_line, parse_http_request_trailer_names,
};
pub(crate) use response::relay_plain_http_response;
