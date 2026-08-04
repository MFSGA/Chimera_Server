use std::collections::{HashMap, HashSet};

use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;

use super::{parsed_http::ParsedHttpData, websocket_stream::WebsocketStream};

#[derive(Debug, Clone)]
pub(crate) struct WebsocketClientConfig {
    host: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl WebsocketClientConfig {
    pub(crate) fn compile(
        host: Option<&str>,
        path: Option<&str>,
        headers: &HashMap<String, String>,
        fallback_host: &str,
        accept_proxy_protocol: bool,
        heartbeat_period: u32,
        outbound_tag: &str,
    ) -> Result<Self, String> {
        if accept_proxy_protocol {
            return Err(format!(
                "outbound {outbound_tag} WebSocket acceptProxyProtocol is server-only"
            ));
        }
        if heartbeat_period != 0 {
            return Err(format!(
                "outbound {outbound_tag} WebSocket heartbeatPeriod is not supported yet"
            ));
        }

        let mut normalized_headers = Vec::with_capacity(headers.len());
        let mut seen_headers = HashSet::with_capacity(headers.len());
        let mut header_host = None;
        for (name, value) in headers {
            validate_header_name(name, outbound_tag)?;
            validate_header_value(value, outbound_tag)?;
            let normalized = name.trim().to_ascii_lowercase();
            if !seen_headers.insert(normalized.clone()) {
                return Err(format!(
                    "outbound {outbound_tag} has duplicate WebSocket header {normalized}"
                ));
            }
            if normalized == "host" {
                header_host = Some(value.trim().to_string());
                continue;
            }
            if is_reserved_header(&normalized) {
                return Err(format!(
                    "outbound {outbound_tag} cannot override reserved WebSocket header {name}"
                ));
            }
            normalized_headers
                .push((name.trim().to_string(), value.trim().to_string()));
        }

        let host = host
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or(header_host)
            .unwrap_or_else(|| fallback_host.to_string());
        validate_header_value(&host, outbound_tag)?;
        if host.is_empty() {
            return Err(format!(
                "outbound {outbound_tag} WebSocket host must not be empty"
            ));
        }

        let mut path = path.unwrap_or("/").trim().to_string();
        if path.is_empty() {
            path.push('/');
        } else if !path.starts_with('/') {
            path.insert(0, '/');
        }
        if path.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
            return Err(format!(
                "outbound {outbound_tag} WebSocket path contains invalid whitespace or control bytes"
            ));
        }
        if path_has_early_data(&path) {
            return Err(format!(
                "outbound {outbound_tag} WebSocket early data is not supported yet"
            ));
        }

        Ok(Self {
            host,
            path,
            headers: normalized_headers,
        })
    }

    pub(crate) async fn connect(
        &self,
        mut stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let websocket_key = BASE64.encode(nonce);

        let mut request = format!(
            concat!(
                "GET {} HTTP/1.1\r\n",
                "Host: {}\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Key: {}\r\n",
                "Sec-WebSocket-Version: 13\r\n"
            ),
            self.path, self.host, websocket_key,
        );
        for (name, value) in &self.headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let ParsedHttpData {
            first_line,
            headers,
            line_reader,
        } = ParsedHttpData::parse(&mut stream).await?;
        if !first_line.starts_with("HTTP/1.1 101 ") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("WebSocket upgrade rejected with response {first_line}"),
            ));
        }
        if !header_contains_token(&headers, "upgrade", "websocket") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket response is missing Upgrade: websocket",
            ));
        }
        if !header_contains_token(&headers, "connection", "upgrade") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket response is missing Connection: Upgrade",
            ));
        }

        let expected_accept = create_websocket_accept(&websocket_key);
        let actual_accept = headers
            .get("sec-websocket-accept")
            .map(String::as_str)
            .unwrap_or_default();
        if actual_accept != expected_accept {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WebSocket response contains an invalid Sec-WebSocket-Accept",
            ));
        }

        Ok(Box::new(WebsocketStream::new(
            stream,
            true,
            line_reader.unparsed_data(),
        )))
    }
}

fn validate_header_name(name: &str, outbound_tag: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(format!(
            "outbound {outbound_tag} has invalid WebSocket header name {name}"
        ));
    }
    Ok(())
}

fn validate_header_value(value: &str, outbound_tag: &str) -> Result<(), String> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(format!(
            "outbound {outbound_tag} WebSocket header value contains forbidden control bytes"
        ));
    }
    Ok(())
}

fn is_reserved_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "upgrade"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-accept"
            | "sec-websocket-protocol"
    )
}

fn path_has_early_data(path: &str) -> bool {
    let Some((_, query)) = path.split_once('?') else {
        return false;
    };
    query.split('&').any(|pair| {
        pair.split_once('=')
            .map(|(key, value)| key.eq_ignore_ascii_case("ed") && !value.is_empty())
            .unwrap_or_else(|| pair.eq_ignore_ascii_case("ed"))
    })
}

fn header_contains_token(
    headers: &HashMap<String, String>,
    name: &str,
    expected: &str,
) -> bool {
    headers.get(name).is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case(expected))
    })
}

fn create_websocket_accept(key: &str) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WS_GUID);
    BASE64.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_normalized_path_host_and_custom_headers() {
        let config = WebsocketClientConfig::compile(
            Some("ws.example"),
            Some("proxy"),
            &HashMap::from([("X-Test".into(), "value".into())]),
            "fallback.example",
            false,
            0,
            "proxy",
        )
        .expect("valid WebSocket settings should compile");

        assert_eq!(config.host, "ws.example");
        assert_eq!(config.path, "/proxy");
        assert_eq!(config.headers, vec![("X-Test".into(), "value".into())]);
    }

    #[test]
    fn rejects_reserved_headers_and_early_data() {
        assert!(
            WebsocketClientConfig::compile(
                None,
                Some("/?ed=2048"),
                &HashMap::new(),
                "fallback.example",
                false,
                0,
                "proxy",
            )
            .unwrap_err()
            .contains("early data")
        );
        assert!(
            WebsocketClientConfig::compile(
                None,
                None,
                &HashMap::from([("Upgrade".into(), "other".into())]),
                "fallback.example",
                false,
                0,
                "proxy",
            )
            .unwrap_err()
            .contains("reserved")
        );
    }
}
