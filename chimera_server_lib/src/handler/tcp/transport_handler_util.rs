use std::io::{Error, ErrorKind, Result};

use crate::{
    config::{rule::RuleConfig, server_config::ServerProxyConfig},
    handler::tcp::tcp_handler::TcpServerHandler,
};

#[cfg(feature = "httpupgrade")]
use crate::handler::httpupgrade::HttpUpgradeTcpServerHandler;
#[cfg(feature = "reality")]
use crate::handler::reality::{
    RealityServerHandler, RealityVisionVlessServerHandler,
};
#[cfg(feature = "ws")]
use crate::handler::ws::{
    WebsocketTcpServerHandler, create_websocket_server_target,
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TlsServerConfig, handler::tls::TlsServerHandler,
};

use super::tcp_handler_util::create_tcp_protocol_handler;

/// Compile the stream/security wrappers surrounding a TCP proxy protocol.
///
/// `ServerProxyConfig` remains the compatibility-facing compiled config shape,
/// but runtime composition is centralized here: protocol construction is a
/// leaf operation and transport/security layers wrap that leaf explicitly.
#[allow(clippy::only_used_in_recursion)]
pub(crate) fn create_tcp_transport_handler(
    server_proxy_config: ServerProxyConfig,
    inbound_tag: &str,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
) -> Result<Box<dyn TcpServerHandler>> {
    #[cfg(not(feature = "ws"))]
    let _ = rules_stack;

    match server_proxy_config {
        #[cfg(feature = "ws")]
        ServerProxyConfig::Websocket { targets } => {
            let server_targets = targets
                .into_vec()
                .into_iter()
                .map(|config| {
                    create_websocket_server_target(config, inbound_tag, rules_stack)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Box::new(WebsocketTcpServerHandler::new(server_targets)))
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            let inner = create_tcp_transport_handler(
                *config.inner,
                inbound_tag,
                rules_stack,
            )?;
            Ok(Box::new(HttpUpgradeTcpServerHandler::new(
                config.host,
                config.path,
                config.accept_proxy_protocol,
                config.trusted_x_forwarded_for,
                inner,
            )))
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            let TlsServerConfig {
                certificates,
                alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
                server_name,
                inner,
            } = tls_config;
            #[cfg(feature = "vless")]
            if let ServerProxyConfig::Vless { users, fallbacks } = inner.as_ref() {
                return Ok(Box::new(TlsServerHandler::new_vision_vless(
                    certificates,
                    alpn_protocols,
                    enable_session_resumption,
                    reject_unknown_sni,
                    min_version,
                    max_version,
                    server_name,
                    users,
                    fallbacks,
                    inbound_tag,
                )?));
            }

            let inner_handler =
                create_tcp_transport_handler(*inner, inbound_tag, rules_stack)?;
            Ok(Box::new(TlsServerHandler::new(
                certificates,
                alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
                server_name,
                inner_handler,
            )?))
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            #[cfg(feature = "vless")]
            if let ServerProxyConfig::Vless { users, fallbacks } =
                reality_config.inner.as_ref()
            {
                return Ok(Box::new(RealityVisionVlessServerHandler::new(
                    reality_config.clone(),
                    users.clone(),
                    fallbacks.clone(),
                    inbound_tag,
                )));
            }

            let inner_handler = create_tcp_transport_handler(
                (*reality_config.inner).clone(),
                inbound_tag,
                rules_stack,
            )?;
            Ok(Box::new(RealityServerHandler::new(
                reality_config,
                inner_handler,
            )))
        }
        ServerProxyConfig::Xhttp { .. } => Err(Error::new(
            ErrorKind::InvalidInput,
            "Xhttp server should not be served via TCP handler",
        )),
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(_) => Err(Error::new(
            ErrorKind::InvalidInput,
            "gRPC server requires the gRPC listener transport",
        )),
        protocol => create_tcp_protocol_handler(protocol, inbound_tag),
    }
}
