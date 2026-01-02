use std::collections::HashMap;

use crate::config::{rule::RuleConfig, server_config::ws::WebsocketServerConfig};

mod websocket_handler;

mod parsed_http;

mod websocket_stream;

pub use websocket_handler::{WebsocketServerTarget, WebsocketTcpServerHandler};

use super::tcp::tcp_handler_util::create_tcp_server_handler;

pub fn create_websocket_server_target(
    websocket_server_config: WebsocketServerConfig,
    inbound_tag: &str,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
) -> WebsocketServerTarget {
    let WebsocketServerConfig {
        matching_path,
        matching_headers,
        protocol,
    } = websocket_server_config;

    let matching_headers = matching_headers.map(|h| {
        h.into_iter()
            .map(|(mut key, val)| {
                key.make_ascii_lowercase();
                (key, val)
            })
            .collect::<HashMap<_, _>>()
    });

    let handler = create_tcp_server_handler(protocol, inbound_tag, rules_stack);

    WebsocketServerTarget {
        matching_path,
        matching_headers,
        handler,
    }
}
