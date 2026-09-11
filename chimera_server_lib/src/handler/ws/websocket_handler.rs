use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use tokio::{io::AsyncWriteExt, time::timeout};
use tracing::debug;

mod request;
mod response;

use request::{
    WebsocketRequestLineError, decode_xray_websocket_early_data,
    header_contains_token, parse_xray_websocket_request_line,
    raw_xray_request_target, valid_websocket_key, valid_xray_chunked_trailers,
    valid_xray_content_length, valid_xray_host_header, valid_xray_transfer_encoding,
    websocket_request_path_raw,
    xray_websocket_absolute_authority_has_non_ascii_userinfo,
    xray_websocket_absolute_host, xray_websocket_forwarded_peer,
    xray_websocket_host_matches, xray_websocket_request_path_raw_bytes,
};
use response::{
    create_websocket_key_response, write_bad_websocket_request,
    write_xray_bad_request_line, write_xray_invalid_header_name,
    write_xray_malformed_host, write_xray_method_not_allowed,
    write_xray_missing_host, write_xray_unsupported_http_version,
    write_xray_unsupported_transfer_encoding, write_xray_websocket_header_too_large,
    write_xray_websocket_not_found,
};

use crate::{
    async_stream::AsyncStream,
    handler::{
        proxy_protocol::read_proxy_protocol,
        tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
        },
        ws::{
            parsed_http::{ParsedHttpData, ParsedHttpError},
            websocket_stream::WebsocketStream,
        },
    },
    util::prefixed_stream::PrefixedStream,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub xray_mismatch_404: bool,
    pub trusted_x_forwarded_for: Vec<String>,
    pub accept_proxy_protocol: bool,
    pub heartbeat_period: u32,
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
        if self
            .server_targets
            .iter()
            .any(|target| target.accept_proxy_protocol)
        {
            match read_proxy_protocol(&mut server_stream).await {
                Ok(Some(peer_addr)) => context.peer_addr = Some(peer_addr),
                Ok(None) => {}
                Err(error) => {
                    write_xray_bad_request_line(&mut server_stream).await?;
                    return Err(error);
                }
            }
        }
        let parsed = timeout(
            XRAY_WEBSOCKET_HANDSHAKE_TIMEOUT,
            ParsedHttpData::parse(&mut server_stream),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "WebSocket handshake timed out",
            )
        })?;
        let ParsedHttpData {
            first_line,
            first_line_raw,
            headers: request_headers,
            line_reader,
        } = match parsed {
            Ok(parsed) => parsed,
            Err(ParsedHttpError::Io(error)) => return Err(error),
            Err(ParsedHttpError::HeaderTooLarge) => {
                write_xray_websocket_header_too_large(&mut server_stream).await?;
                return Err(std::io::Error::other(
                    "websocket request header is too large",
                ));
            }
            Err(ParsedHttpError::InvalidHeaderName { trailing_space }) => {
                if trailing_space {
                    write_xray_invalid_header_name(&mut server_stream).await?;
                } else {
                    write_xray_bad_request_line(&mut server_stream).await?;
                }
                return Err(std::io::Error::other("invalid HTTP header name"));
            }
            Err(ParsedHttpError::InvalidHeaderValue) => {
                write_xray_bad_request_line(&mut server_stream).await?;
                return Err(std::io::Error::other("invalid HTTP header value"));
            }
        };

        let (method, request_target, host_required) =
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
        let raw_request_target = raw_xray_request_target(&first_line_raw)
            .unwrap_or(request_target.as_bytes());
        if xray_websocket_absolute_authority_has_non_ascii_userinfo(
            raw_request_target,
        ) {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("non-ASCII absolute URI userinfo"));
        }
        let raw_request_path = websocket_request_path_raw(request_target);
        let xray_request_path = match xray_websocket_request_path_raw_bytes(
            request_target,
            raw_request_target,
        ) {
            Ok(path) => path,
            Err(()) => {
                write_xray_bad_request_line(&mut server_stream).await?;
                return Err(std::io::Error::other(
                    "malformed request target escape",
                ));
            }
        };

        if !valid_xray_content_length(&request_headers) {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid Content-Length header"));
        }

        if !valid_xray_transfer_encoding(&request_headers) {
            write_xray_unsupported_transfer_encoding(&mut server_stream).await?;
            return Err(std::io::Error::other("unsupported transfer encoding"));
        }
        if !valid_xray_chunked_trailers(&request_headers) {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("invalid chunked trailer"));
        }

        if request_headers
            .get("host")
            .is_some_and(|values| values.len() > 1)
        {
            write_xray_bad_request_line(&mut server_stream).await?;
            return Err(std::io::Error::other("too many Host headers"));
        }
        if request_headers
            .get("host")
            .and_then(|values| values.first())
            .is_some_and(|host| !valid_xray_host_header(host))
        {
            write_xray_malformed_host(&mut server_stream).await?;
            return Err(std::io::Error::other("malformed Host header"));
        }

        let request_host = request_headers
            .get("host")
            .and_then(|values| values.first())
            .map(String::as_str);
        if host_required && request_host.is_none() {
            write_xray_missing_host(&mut server_stream).await?;
            return Err(std::io::Error::other("missing required Host header"));
        }
        let absolute_host = xray_websocket_absolute_host(request_target);
        let effective_host = absolute_host.as_deref().or(request_host);
        debug!(
            "request path is {}",
            String::from_utf8_lossy(&xray_request_path)
        );
        let websocket_key = request_headers
            .get("sec-websocket-key")
            .and_then(|values| values.first())
            .cloned();
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
                trusted_x_forwarded_for,
                accept_proxy_protocol: _,
                heartbeat_period,
                handler,
            } = server_target;
            debug!(
                "matching path is {:?} {:?}",
                matching_path,
                String::from_utf8_lossy(&xray_request_path)
            );
            if let Some(path) = matching_path
                && if *xray_mismatch_404 {
                    path.as_bytes() != xray_request_path.as_slice()
                } else {
                    path != &raw_request_path
                }
            {
                debug!("path not match");
                saw_xray_mismatch |= *xray_mismatch_404;
                continue;
            }
            debug!("matching headers is {:?}", matching_headers);
            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    let matches = if *xray_mismatch_404 && header_key == "host" {
                        effective_host.is_some_and(|actual| {
                            xray_websocket_host_matches(actual, header_val)
                        })
                    } else {
                        request_headers
                            .get(header_key)
                            .and_then(|values| values.first())
                            .is_some_and(|actual| actual == header_val)
                    };
                    if !matches {
                        saw_xray_mismatch |= *xray_mismatch_404;
                        continue 'outer;
                    }
                }
            }

            if method != "GET" {
                write_xray_method_not_allowed(&mut server_stream).await?;
                return Err(std::io::Error::other("websocket method is not GET"));
            }

            if let Some(peer_addr) = xray_websocket_forwarded_peer(
                &request_headers,
                trusted_x_forwarded_for,
            ) {
                context.peer_addr = Some(peer_addr);
            }

            // Gorilla v1.5.3 rejects a WebSocket upgrade when net/http has
            // already buffered bytes beyond the HTTP request headers. Xray
            // v26.2.6 therefore closes without a 101 response instead of
            // treating pipelined bytes as the first WebSocket frame.
            if !line_reader.unparsed_data().is_empty() {
                return Err(std::io::Error::other(
                    "websocket: client sent data before handshake is complete",
                ));
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
                Box::new(WebsocketStream::new_with_heartbeat(
                    server_stream,
                    false,
                    &[],
                    *heartbeat_period,
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

#[cfg(test)]
use request::xray_websocket_request_path;

#[cfg(test)]
mod tests;
