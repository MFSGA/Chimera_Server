use std::io::{Error, ErrorKind, Result};

#[cfg(feature = "reality")]
use crate::handler::reality::{
    RealityServerHandler, RealityVisionVlessServerHandler,
};
#[cfg(feature = "vless")]
use crate::handler::vless_handler::{
    VisionVlessTcpHandler, VlessTcpHandler, users_require_vision,
};
#[cfg(feature = "vmess")]
use crate::handler::vmess::vmess_handler::VmessTcpServerHandler;
#[cfg(feature = "ws")]
use crate::handler::ws::{
    WebsocketTcpServerHandler, create_websocket_server_target,
};
#[cfg(feature = "tls")]
use crate::{
    config::server_config::TlsServerConfig, handler::tls::TlsServerHandler,
};
use crate::{
    config::{rule::RuleConfig, server_config::ServerProxyConfig},
    handler::dokodemo::DokodemoDoorTcpHandler,
    handler::socks::SocksTcpServerHandler,
};

use super::tcp_handler::TcpServerHandler;

#[allow(clippy::only_used_in_recursion)]
pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    inbound_tag: &str,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
) -> Result<Box<dyn TcpServerHandler>> {
    match server_proxy_config {
        #[cfg(feature = "vless")]
        ServerProxyConfig::Vless { users } => {
            if users_require_vision(&users) {
                Ok(Box::new(VisionVlessTcpHandler::new(&users, inbound_tag)))
            } else {
                Ok(Box::new(VlessTcpHandler::new(&users, inbound_tag)))
            }
        }

        #[cfg(feature = "vmess")]
        ServerProxyConfig::Vmess { users } => {
            let n_users = users.len();
            if n_users != 1 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "VmessTcpServerHandler currently requires exactly 1 user (got {n_users})"
                    ),
                ));
            }
            let user = &users[0];
            Ok(Box::new(VmessTcpServerHandler::new(
                &user.cipher,
                &user.user_id,
                false,
                inbound_tag,
                &user.user_label,
            )))
        }

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
        #[cfg(feature = "trojan")]
        ServerProxyConfig::Trojan { users, fallbacks } => {
            Ok(Box::new(crate::handler::trojan::TrojanTcpHandler::new(
                users,
                fallbacks,
                inbound_tag,
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
            let inner_handler =
                create_tcp_server_handler(*inner, inbound_tag, rules_stack)?;
            let tls_handler = TlsServerHandler::new(
                certificates,
                alpn_protocols,
                enable_session_resumption,
                reject_unknown_sni,
                min_version,
                max_version,
                server_name,
                inner_handler,
            )?;
            Ok(Box::new(tls_handler))
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            #[cfg(feature = "vless")]
            let vision_users = match reality_config.inner.as_ref() {
                ServerProxyConfig::Vless { users }
                    if users_require_vision(users) =>
                {
                    Some(users.clone())
                }
                _ => None,
            };

            #[cfg(feature = "vless")]
            if let Some(users) = vision_users {
                return Ok(Box::new(RealityVisionVlessServerHandler::new(
                    reality_config,
                    users,
                    inbound_tag,
                )));
            }

            let inner_handler = create_tcp_server_handler(
                (*reality_config.inner).clone(),
                inbound_tag,
                rules_stack,
            )?;
            Ok(Box::new(RealityServerHandler::new(
                reality_config,
                inner_handler,
            )))
        }
        // SOCKS5 UDP ASSOCIATE uses this TCP handler as its control channel.
        ServerProxyConfig::Socks {
            accounts,
            udp_enabled,
        } => Ok(Box::new(SocksTcpServerHandler::new(
            accounts,
            inbound_tag,
            udp_enabled,
        ))),
        ServerProxyConfig::DokodemoDoor { config } => {
            Ok(Box::new(DokodemoDoorTcpHandler::new(config, inbound_tag)))
        }
        ServerProxyConfig::Xhttp { .. } => Err(Error::new(
            ErrorKind::InvalidInput,
            "Xhttp server should not be served via TCP handler",
        )),

        #[allow(unreachable_patterns)]
        unknown_config => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Unsupported TCP proxy config: {unknown_config:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        address::{Address, NetLocation},
        config::server_config::{DokodemoDoorConfig, XhttpServerConfig},
    };

    use super::*;

    #[cfg(feature = "vmess")]
    #[test]
    fn vmess_tcp_handler_rejects_multiple_users_without_panicking() {
        let err = create_tcp_server_handler(
            ServerProxyConfig::Vmess {
                users: vec![
                    crate::config::server_config::VmessUser {
                        user_id: "3ac9b383-75a1-431c-8184-106c80eb2273".into(),
                        user_label: "user-a".into(),
                        cipher: "auto".into(),
                    },
                    crate::config::server_config::VmessUser {
                        user_id: "e041e73e-a0a0-49f5-9754-6401aa621fb7".into(),
                        user_label: "user-b".into(),
                        cipher: "auto".into(),
                    },
                ],
            },
            "vmess-multi",
            &mut Vec::new(),
        )
        .expect_err("multiple vmess users should return an error");

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("requires exactly 1 user (got 2)"));
    }

    #[test]
    fn xhttp_tcp_handler_returns_error_without_panicking() {
        let err = create_tcp_server_handler(
            ServerProxyConfig::Xhttp {
                config: XhttpServerConfig {
                    host: Some("example.com".into()),
                    path: "/xhttp".into(),
                    min_padding: 0,
                    max_padding: 0,
                    max_each_post_bytes: 1_000_000,
                    max_buffered_posts: 30,
                    session_ttl_secs: 30,
                },
                inner: Box::new(ServerProxyConfig::DokodemoDoor {
                    config: DokodemoDoorConfig {
                        target: NetLocation::new(
                            Address::from("127.0.0.1").expect("valid address"),
                            80,
                        ),
                        follow_redirect: false,
                    },
                }),
            },
            "xhttp",
            &mut Vec::new(),
        )
        .expect_err("xhttp should not be constructed by tcp handler");

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("Xhttp server should not be served via TCP handler")
        );
    }
}
