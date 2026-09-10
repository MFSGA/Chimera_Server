use crate::config::server_config::{ServerProxyConfig, XhttpServerConfig};

#[cfg(feature = "grpc_transport")]
use crate::config::server_config::GrpcServerConfig;
#[cfg(feature = "reality")]
use crate::config::server_config::RealityTransportConfig;
#[cfg(feature = "tls")]
use crate::config::server_config::TlsServerConfig;

/// Security selected for a listener transport after the recursive compatibility
/// config has been classified once at the server boundary.
#[derive(Debug, Clone)]
pub(super) enum ListenerSecurityPlan {
    None,
    #[cfg(feature = "tls")]
    Tls(TlsServerConfig),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone)]
pub(super) struct GrpcListenerPlan {
    pub config: GrpcServerConfig,
    pub protocol: ServerProxyConfig,
    pub security: ListenerSecurityPlan,
}

#[derive(Debug, Clone)]
pub(super) struct XhttpListenerPlan {
    pub config: XhttpServerConfig,
    pub protocol: ServerProxyConfig,
    pub security: ListenerSecurityPlan,
}

#[derive(Debug, Clone)]
pub(super) enum InboundListenerPlan {
    Stream,
    #[cfg(feature = "grpc_transport")]
    Grpc(Box<GrpcListenerPlan>),
    Xhttp(Box<XhttpListenerPlan>),
}

/// Classify the compiled compatibility shape into one listener transport.
///
/// Xray selects one effective transport plus one security layer. Config
/// builders retain `ServerProxyConfig` wrappers for compatibility during the
/// migration, but runtime startup must not recursively rediscover that choice
/// in multiple transport modules.
pub(super) fn compile_listener_plan(
    protocol: &ServerProxyConfig,
) -> InboundListenerPlan {
    match protocol {
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            InboundListenerPlan::Grpc(Box::new(GrpcListenerPlan {
                config: config.clone(),
                protocol: (*config.inner).clone(),
                security: ListenerSecurityPlan::None,
            }))
        }
        ServerProxyConfig::Xhttp { config, inner } => {
            InboundListenerPlan::Xhttp(Box::new(XhttpListenerPlan {
                config: config.clone(),
                protocol: (**inner).clone(),
                security: ListenerSecurityPlan::None,
            }))
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls) => match tls.inner.as_ref() {
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                InboundListenerPlan::Grpc(Box::new(GrpcListenerPlan {
                    config: config.clone(),
                    protocol: (*config.inner).clone(),
                    security: ListenerSecurityPlan::Tls(tls.clone()),
                }))
            }
            ServerProxyConfig::Xhttp { config, inner } => {
                InboundListenerPlan::Xhttp(Box::new(XhttpListenerPlan {
                    config: config.clone(),
                    protocol: (**inner).clone(),
                    security: ListenerSecurityPlan::Tls(tls.clone()),
                }))
            }
            _ => InboundListenerPlan::Stream,
        },
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
            #[cfg(feature = "grpc_transport")]
            ServerProxyConfig::Grpc(config) => {
                InboundListenerPlan::Grpc(Box::new(GrpcListenerPlan {
                    config: config.clone(),
                    protocol: (*config.inner).clone(),
                    security: ListenerSecurityPlan::Reality(reality.clone()),
                }))
            }
            ServerProxyConfig::Xhttp { config, inner } => {
                InboundListenerPlan::Xhttp(Box::new(XhttpListenerPlan {
                    config: config.clone(),
                    protocol: (**inner).clone(),
                    security: ListenerSecurityPlan::Reality(reality.clone()),
                }))
            }
            _ => InboundListenerPlan::Stream,
        },
        _ => InboundListenerPlan::Stream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{Address, NetLocation},
        config::server_config::{DokodemoDoorConfig, SocksUserStore},
    };

    fn socks() -> ServerProxyConfig {
        ServerProxyConfig::Socks {
            accounts: SocksUserStore::new(Vec::new()),
            udp_enabled: false,
            udp_response_ip: None,
            user_level: 0,
        }
    }

    #[test]
    fn plain_protocol_compiles_to_stream_listener() {
        assert!(matches!(
            compile_listener_plan(&socks()),
            InboundListenerPlan::Stream
        ));
    }

    #[cfg(feature = "grpc_transport")]
    #[test]
    fn grpc_wrapper_compiles_to_one_transport_and_leaf_protocol() {
        let protocol = ServerProxyConfig::Grpc(GrpcServerConfig {
            service_name: String::new(),
            multi_mode: false,
            idle_timeout: 0,
            health_check_timeout: 0,
            trusted_x_forwarded_for: Vec::new(),
            inner: Box::new(socks()),
        });
        let InboundListenerPlan::Grpc(plan) = compile_listener_plan(&protocol)
        else {
            panic!("expected gRPC listener plan");
        };
        assert!(matches!(plan.protocol, ServerProxyConfig::Socks { .. }));
        assert!(matches!(plan.security, ListenerSecurityPlan::None));
    }

    #[test]
    fn xhttp_wrapper_compiles_to_one_transport_and_leaf_protocol() {
        let protocol = ServerProxyConfig::Xhttp {
            config: crate::config::server_config::XhttpServerConfig {
                mode: crate::config::server_config::XhttpMode::Auto,
                host: None,
                path: "/".into(),
                trusted_x_forwarded_for: Vec::new(),
                min_padding: 100,
                max_padding: 1000,
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
                session_placement: crate::config::server_config::XhttpPlacement::Path,
                session_key: String::new(),
                seq_placement: crate::config::server_config::XhttpPlacement::Path,
                seq_key: String::new(),
                uplink_data_placement: crate::config::server_config::XhttpDataPlacement::Auto,
                uplink_data_key: "X-Data".into(),
                xray_congestion: None,
                xray_brutal_up: None,
                xray_max_idle_timeout_secs: None,
                xray_max_incoming_streams: None,
                xray_init_stream_receive_window: None,
                xray_max_stream_receive_window: None,
                xray_init_connection_receive_window: None,
                xray_max_connection_receive_window: None,
                xray_disable_path_mtu_discovery: None,
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
        };
        let InboundListenerPlan::Xhttp(plan) = compile_listener_plan(&protocol)
        else {
            panic!("expected XHTTP listener plan");
        };
        assert!(matches!(
            plan.protocol,
            ServerProxyConfig::DokodemoDoor { .. }
        ));
        assert!(matches!(plan.security, ListenerSecurityPlan::None));
    }
}
