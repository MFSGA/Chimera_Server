#[cfg(feature = "reality")]
use crate::handler::reality::RealityServerHandler;
#[cfg(feature = "ws")]
use crate::handler::ws::{create_websocket_server_target, WebsocketTcpServerHandler};
#[cfg(feature = "tls")]
use crate::{config::server_config::TlsServerConfig, handler::tls::TlsServerHandler};
use crate::{
    config::{rule::RuleConfig, server_config::ServerProxyConfig},
    handler::{socks::SocksTcpServerHandler, vless_handler::VlessTcpHandler},
};

use super::tcp_handler::TcpServerHandler;

pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    inbound_tag: &str,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
) -> Box<dyn TcpServerHandler> {
    match server_proxy_config {
        ServerProxyConfig::Vless {
            user_id,
            user_label,
        } => Box::new(VlessTcpHandler::new(&user_id, &user_label, inbound_tag)),

        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => {
            let server_targets = targets
                .into_vec()
                .into_iter()
                .map(|config| create_websocket_server_target(config, inbound_tag, rules_stack))
                .collect::<Vec<_>>();
            Box::new(WebsocketTcpServerHandler::new(server_targets))
        }
        #[cfg(feature = "trojan")]
        ServerProxyConfig::Trojan { users, fallbacks } => Box::new(
            crate::handler::trojan::TrojanTcpHandler::new(users, fallbacks, inbound_tag),
        ),
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            let TlsServerConfig {
                certificate_path,
                private_key_path,
                alpn_protocols,
                inner,
            } = tls_config;
            let inner_handler = create_tcp_server_handler(*inner, inbound_tag, rules_stack);
            Box::new(
                TlsServerHandler::new(
                    certificate_path,
                    private_key_path,
                    alpn_protocols,
                    inner_handler,
                )
                .expect("failed to initialize TLS handler"),
            )
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            let inner_handler = create_tcp_server_handler(
                (*reality_config.inner).clone(),
                inbound_tag,
                rules_stack,
            );
            Box::new(RealityServerHandler::new(reality_config, inner_handler))
        }
        ServerProxyConfig::Socks { accounts } => {
            Box::new(SocksTcpServerHandler::new(accounts, inbound_tag))
        }
        ServerProxyConfig::Xhttp { .. } => {
            panic!("Xhttp server should not be served via TCP handler")
        }

        unknown_config => {
            panic!("Unsupported TCP proxy config: {:?}", unknown_config)
        }
    }
}
