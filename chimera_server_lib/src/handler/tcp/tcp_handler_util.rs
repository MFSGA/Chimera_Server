use std::io::{Error, ErrorKind, Result};

#[cfg(feature = "http")]
use crate::handler::http::HttpTcpServerHandler;
#[cfg(feature = "httpupgrade")]
use crate::handler::httpupgrade::HttpUpgradeTcpServerHandler;
#[cfg(feature = "mixed")]
use crate::handler::mixed::MixedTcpServerHandler;
#[cfg(feature = "reality")]
use crate::handler::reality::RealityServerHandler;
#[cfg(all(feature = "reality", feature = "vless"))]
use crate::handler::reality::RealityVisionVlessServerHandler;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::ShadowsocksTcpServerHandler;
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
    handler::proxy_protocol::ProxyProtocolServerHandler,
    handler::socks::SocksTcpServerHandler,
    handler::tcp_keepalive::TcpKeepAliveServerHandler,
    handler::tcp_user_timeout::TcpUserTimeoutServerHandler,
};

use super::tcp_handler::TcpServerHandler;

#[allow(clippy::only_used_in_recursion)]
pub fn create_tcp_server_handler(
    server_proxy_config: ServerProxyConfig,
    inbound_tag: &str,
    rules_stack: &mut Vec<Vec<RuleConfig>>,
) -> Result<Box<dyn TcpServerHandler>> {
    #[cfg(not(any(feature = "ws", feature = "tls", feature = "reality")))]
    let _ = rules_stack;

    match server_proxy_config {
        ServerProxyConfig::ProxyProtocol { inner } => {
            let inner = create_tcp_server_handler(*inner, inbound_tag, rules_stack)?;
            Ok(Box::new(ProxyProtocolServerHandler::new(inner)))
        }
        ServerProxyConfig::TcpKeepAlive {
            idle_secs,
            interval_secs,
            inner,
        } => {
            let inner = create_tcp_server_handler(*inner, inbound_tag, rules_stack)?;
            Ok(Box::new(TcpKeepAliveServerHandler::new(
                idle_secs,
                interval_secs,
                inner,
            )))
        }
        ServerProxyConfig::TcpUserTimeout { timeout_ms, inner } => {
            let inner = create_tcp_server_handler(*inner, inbound_tag, rules_stack)?;
            Ok(Box::new(TcpUserTimeoutServerHandler::new(
                timeout_ms, inner,
            )))
        }
        #[cfg(feature = "vless")]
        ServerProxyConfig::Vless { users, fallbacks } => {
            if users_require_vision(&users) {
                Ok(Box::new(VisionVlessTcpHandler::new(&users, inbound_tag)))
            } else {
                Ok(Box::new(VlessTcpHandler::new_with_fallbacks(
                    &users,
                    &fallbacks,
                    inbound_tag,
                )))
            }
        }

        #[cfg(feature = "vmess")]
        ServerProxyConfig::Vmess { users } => {
            if users.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "VmessTcpServerHandler requires at least 1 user",
                ));
            }
            Ok(Box::new(VmessTcpServerHandler::new(
                users,
                true,
                inbound_tag,
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
            #[cfg(feature = "vless")]
            if let ServerProxyConfig::Vless { users, fallbacks } = inner.as_ref()
                && users_require_vision(users)
            {
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
            let vision_config = match reality_config.inner.as_ref() {
                ServerProxyConfig::Vless { users, fallbacks }
                    if users_require_vision(users) =>
                {
                    Some((users.clone(), fallbacks.clone()))
                }
                _ => None,
            };

            #[cfg(feature = "vless")]
            if let Some((users, fallbacks)) = vision_config {
                return Ok(Box::new(RealityVisionVlessServerHandler::new(
                    reality_config,
                    users,
                    fallbacks,
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
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, identity } => Ok(Box::new(
            ShadowsocksTcpServerHandler::new(users, identity, inbound_tag)?,
        )),
        #[cfg(feature = "http")]
        ServerProxyConfig::Http {
            accounts,
            allow_transparent,
            user_level,
        } => Ok(Box::new(HttpTcpServerHandler::new(
            accounts,
            allow_transparent,
            inbound_tag,
            user_level,
        ))),
        #[cfg(feature = "mixed")]
        ServerProxyConfig::Mixed {
            accounts,
            udp_enabled,
        } => Ok(Box::new(MixedTcpServerHandler::new(
            accounts,
            udp_enabled,
            inbound_tag,
        ))),
        // SOCKS5 UDP ASSOCIATE uses this TCP handler as its control channel.
        ServerProxyConfig::Socks {
            accounts,
            udp_enabled,
            user_level,
        } => Ok(Box::new(SocksTcpServerHandler::new(
            accounts,
            inbound_tag,
            udp_enabled,
            user_level,
        ))),
        ServerProxyConfig::DokodemoDoor { config } => {
            Ok(Box::new(DokodemoDoorTcpHandler::new(config, inbound_tag)))
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            let inner =
                create_tcp_server_handler(*config.inner, inbound_tag, rules_stack)?;
            Ok(Box::new(HttpUpgradeTcpServerHandler::new(
                config.host,
                config.path,
                inner,
            )))
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
    fn vmess_tcp_handler_accepts_multiple_users() {
        let handler = create_tcp_server_handler(
            ServerProxyConfig::Vmess {
                users: vec![
                    crate::config::server_config::VmessUser {
                        user_id: "3ac9b383-75a1-431c-8184-106c80eb2273".into(),
                        user_label: "user-a".into(),
                        user_level: 0,
                        cipher: "auto".into(),
                    },
                    crate::config::server_config::VmessUser {
                        user_id: "e041e73e-a0a0-49f5-9754-6401aa621fb7".into(),
                        user_label: "user-b".into(),
                        user_level: 0,
                        cipher: "auto".into(),
                    },
                ],
            },
            "vmess-multi",
            &mut Vec::new(),
        );

        assert!(handler.is_ok());
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn vmess_tcp_handler_rejects_empty_user_list() {
        let err = create_tcp_server_handler(
            ServerProxyConfig::Vmess { users: Vec::new() },
            "vmess-empty",
            &mut Vec::new(),
        )
        .expect_err("empty vmess users should return an error");

        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("requires at least 1 user"));
    }

    #[test]
    fn xhttp_tcp_handler_returns_error_without_panicking() {
        let err = create_tcp_server_handler(
            ServerProxyConfig::Xhttp {
                config: XhttpServerConfig {
                    mode: crate::config::server_config::XhttpMode::Auto,
                    host: Some("example.com".into()),
                    path: "/xhttp".into(),
                    min_padding: 0,
                    max_padding: 0,
                    max_each_post_bytes: 1_000_000,
                    max_buffered_posts: 30,
                    session_ttl_secs: 30,
                    stream_up_server_secs: (20, 80),
                    server_max_header_bytes: 8192,
                    padding_obfs_mode: false,
                    padding_key: "x_padding".into(),
                    padding_header: "X-Padding".into(),
                    padding_placement:
                        crate::config::server_config::XhttpPaddingPlacement::QueryInHeader,
                    padding_method:
                        crate::config::server_config::XhttpPaddingMethod::RepeatX,
                    no_grpc_header: false,
                    no_sse_header: false,
                    uplink_http_method: "POST".into(),
                    min_posts_interval_ms: (30, 30),
                    session_placement:
                        crate::config::server_config::XhttpPlacement::Path,
                    session_key: String::new(),
                    seq_placement:
                        crate::config::server_config::XhttpPlacement::Path,
                    seq_key: String::new(),
                    uplink_data_placement:
                        crate::config::server_config::XhttpDataPlacement::Auto,
                    uplink_data_key: "X-Data".into(),
                },
                inner: Box::new(ServerProxyConfig::DokodemoDoor {
                    config: DokodemoDoorConfig {
                        target: NetLocation::new(
                            Address::from("127.0.0.1").expect("valid address"),
                            80,
                        ),
                        follow_redirect: false,
                        user_level: 0,
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
