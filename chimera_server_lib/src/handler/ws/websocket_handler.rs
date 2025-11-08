use std::collections::HashMap;

use async_trait::async_trait;
use aws_lc_rs::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use crate::{
    async_stream::AsyncStream,
    handler::{
        tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
        ws::{parsed_http::ParsedHttpData, websocket_stream::WebsocketStream},
    },
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub handler: Box<dyn TcpServerHandler>,
}

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
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        tracing::debug!("WebsocketTcpServerHandler setup_server_stream");
        let ParsedHttpData {
            mut first_line,
            headers: mut request_headers,
            line_reader,
        } = ParsedHttpData::parse(&mut server_stream).await?;

        let request_path = {
            if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("invalid http request version: {}", first_line),
                ));
            }

            if !first_line.starts_with("GET ") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("invalid http request: {}", first_line),
                ));
            }

            first_line.truncate(first_line.len() - 9);

            first_line.split_off(4)
        };
        debug!("request path is {}", request_path);
        let websocket_key = request_headers.remove("sec-websocket-key").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "missing websocket key header")
        })?;

        'outer: for server_target in self.server_targets.iter() {
            debug!("checking server target {:?}", server_target);
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                handler,
            } = server_target;
            debug!("matching path is {:?} {:?}", matching_path, &request_path);
            if let Some(path) = matching_path {
                if path != &request_path {
                    debug!("path not match");
                    continue;
                }
            }
            debug!("matching headers is {:?}", matching_headers);
            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers.get(header_key) != Some(header_val) {
                        continue 'outer;
                    }
                }
            }

            let websocket_key_response = create_websocket_key_response(websocket_key);

            let host_response_header = match request_headers.get("host") {
                Some(v) => format!("Host: {}\r\n", v),
                None => "".to_string(),
            };

            let websocket_version_response_header =
                match request_headers.get("sec-websocket_version") {
                    Some(v) => format!("Sec-WebSocket-Version: {}\r\n", v),
                    None => "".to_string(),
                };

            let http_response = format!(
                concat!(
                    "HTTP/1.1 101 Switching Protocol\r\n",
                    "{}",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "{}",
                    "Sec-WebSocket-Accept: {}\r\n",
                    "\r\n"
                ),
                host_response_header, websocket_version_response_header, websocket_key_response,
            );

            server_stream.write_all(http_response.as_bytes()).await?;

            let websocket_stream = Box::new(WebsocketStream::new(
                server_stream,
                false,
                line_reader.unparsed_data(),
            ));

            let mut target_setup_result = handler.setup_server_stream(websocket_stream).await;

            if let Ok(ref mut setup_result) = target_setup_result {
                setup_result.set_need_initial_flush(true);
                debug!("todo override_proxy_provider_unspecified");
            }

            return target_setup_result;
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No matching websocket targets",
        ))
    }
}

fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}
