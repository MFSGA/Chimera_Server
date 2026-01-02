use crate::{
    config::{
        rule::RuleConfig,
        server_config::{ServerProxyConfig, TlsServerConfig},
    },
    handler::{
        reality::RealityServerHandler,
        socks::SocksTcpServerHandler,
        tls::TlsServerHandler,
        trojan::TrojanTcpHandler,
        vless_handler::VlessTcpHandler,
        ws::{create_websocket_server_target, WebsocketTcpServerHandler},
    },
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

        ServerProxyConfig::Websocket { targets } => {
            let server_targets = targets
                .into_vec()
                .into_iter()
                .map(|config| create_websocket_server_target(config, inbound_tag, rules_stack))
                .collect::<Vec<_>>();
            Box::new(WebsocketTcpServerHandler::new(server_targets))
        }
        ServerProxyConfig::Trojan { users } => Box::new(TrojanTcpHandler::new(users, inbound_tag)),
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
