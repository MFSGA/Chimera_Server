use super::proto::xray::app::proxyman::command::handler_service_server::HandlerService;
use super::*;
#[cfg(feature = "shadowsocks")]
use crate::config::server_config::ShadowsocksServerIdentity;
#[cfg(feature = "trojan")]
use crate::config::server_config::TrojanUser;
#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "hysteria")]
use crate::config::server_config::{
    Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig,
};
use crate::{
    address::{Address, BindLocation, NetLocation},
    config::{
        Transport,
        server_config::{ServerConfig, SocksUser, XhttpServerConfig},
    },
    runtime::OutboundSummary,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    time::Duration,
};
use tonic::{Code, Request};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    runtime: RuntimeState,
    inbound_tag: String,
    outbound_tag: String,
}

fn unique_tag(prefix: &str) -> String {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{id}")
}

fn free_localhost_port() -> u16 {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn build_fixture() -> Fixture {
    let inbound_tag = unique_tag("inbound");
    let outbound_tag = unique_tag("outbound");

    let bind_location = BindLocation::Address(NetLocation::new(
        Address::Ipv4(Ipv4Addr::LOCALHOST),
        1080,
    ));
    let protocol = ServerProxyConfig::Socks {
        accounts: vec![SocksUser {
            username: unique_tag("user-a"),
            password: "pass-a".to_string(),
        }]
        .into(),
        udp_enabled: false,
        udp_response_ip: None,
        user_level: 0,
    };
    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location,
        protocol,
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };

    let outbound = OutboundSummary {
        tag: outbound_tag.clone(),
        protocol: "freedom".to_string(),
        proxy_settings_type: None,
        proxy_settings_value: None,
        sender_settings_type: None,
        sender_settings_value: None,
    };

    let runtime = RuntimeState::new(vec![inbound], vec![outbound]);
    Fixture {
        runtime,
        inbound_tag,
        outbound_tag,
    }
}

fn localhost_ip_payload() -> IpOrDomainPayload {
    IpOrDomainPayload {
        address: Some(ip_or_domain_payload::Address::Ip(
            Ipv4Addr::LOCALHOST.octets().to_vec(),
        )),
    }
}

fn build_add_inbound_request(
    tag: &str,
    port: u16,
) -> proto::xray::app::proxyman::command::AddInboundRequest {
    let mut accounts = std::collections::HashMap::new();
    accounts.insert(unique_tag("user"), "pass".to_string());
    proto::xray::app::proxyman::command::AddInboundRequest {
        inbound: Some(proto::xray::core::InboundHandlerConfig {
            tag: tag.to_string(),
            receiver_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_APP_RECEIVER_CONFIG.to_string(),
                value: ReceiverConfigPayload {
                    port_list: Some(PortListPayload {
                        range: vec![PortRangePayload {
                            from: port as u32,
                            to: port as u32,
                        }],
                    }),
                    listen: Some(localhost_ip_payload()),
                    stream_settings: None,
                }
                .encode_to_vec(),
            }),
            proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_SOCKS_SERVER_CONFIG.to_string(),
                value: SocksServerConfigPayload {
                    auth_type: 1,
                    accounts,
                    address: None,
                    udp_enabled: false,
                    user_level: 0,
                }
                .encode_to_vec(),
            }),
        }),
    }
}

fn build_receiver_settings(
    port: u16,
    stream_settings: Option<StreamConfigPayload>,
) -> proto::xray::common::serial::TypedMessage {
    proto::xray::common::serial::TypedMessage {
        r#type: TYPE_APP_RECEIVER_CONFIG.to_string(),
        value: ReceiverConfigPayload {
            port_list: Some(PortListPayload {
                range: vec![PortRangePayload {
                    from: port as u32,
                    to: port as u32,
                }],
            }),
            listen: Some(localhost_ip_payload()),
            stream_settings,
        }
        .encode_to_vec(),
    }
}

fn build_add_outbound_request(
    tag: &str,
) -> proto::xray::app::proxyman::command::AddOutboundRequest {
    proto::xray::app::proxyman::command::AddOutboundRequest {
        outbound: Some(proto::xray::core::OutboundHandlerConfig {
            tag: tag.to_string(),
            sender_settings: None,
            proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_FREEDOM_CONFIG.to_string(),
                value: FreedomConfigPayload {}.encode_to_vec(),
            }),
            expire: 0,
            comment: String::new(),
        }),
    }
}

#[test]
fn handler_accepts_executable_socks_outbound() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let config = SocksClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(localhost_ip_payload()),
            port: 1080,
            user: None,
        }),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "socks-outbound".to_string(),
            proxy_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_SOCKS_CLIENT_CONFIG.to_string(),
                value: config.encode_to_vec(),
            }),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("SOCKS outbound should be executable");

    assert_eq!(outbound.tag, "socks-outbound");
    assert_eq!(outbound.protocol, "socks");
    assert_eq!(
        outbound.proxy_settings_type.as_deref(),
        Some(TYPE_PROXY_SOCKS_CLIENT_CONFIG)
    );
}

#[cfg(feature = "vless")]
#[test]
fn handler_accepts_raw_vless_outbound_and_rejects_dynamic_transport() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let config = VlessOutboundConfigPayload {
        vnext: Some(SocksServerEndpointPayload {
            address: Some(localhost_ip_payload()),
            port: 1234,
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: "vless@example.test".into(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: VlessOutboundAccountPayload {
                        id: "3ac9b383-75a1-431c-8184-106c80eb2273".into(),
                        flow: String::new(),
                        encryption: "none".into(),
                    }
                    .encode_to_vec(),
                }),
            }),
        }),
    };
    let proxy_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_PROXY_VLESS_OUTBOUND_CONFIG.to_string(),
        value: config.encode_to_vec(),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "vless-outbound".into(),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("raw VLESS outbound should be executable");
    assert_eq!(outbound.protocol, "vless");
    assert_eq!(
        outbound.proxy_settings_type.as_deref(),
        Some(TYPE_PROXY_VLESS_OUTBOUND_CONFIG)
    );

    let error = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "secure-vless".into(),
            sender_settings: Some(proto::xray::common::serial::TypedMessage {
                r#type: "xray.app.proxyman.SenderConfig".into(),
                value: Vec::new(),
            }),
            proxy_settings: Some(proxy_settings),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect_err("dynamic VLESS transport must fail closed");
    assert_eq!(error.code(), Code::Unimplemented);
}

#[cfg(all(feature = "trojan", feature = "reality"))]
#[test]
fn handler_accepts_reality_trojan_outbound() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let config = TrojanClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(localhost_ip_payload()),
            port: 443,
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: "trojan-reality@example.test".into(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                    value: TrojanAccountPayload {
                        password: "secret".into(),
                    }
                    .encode_to_vec(),
                }),
            }),
        }),
    };
    let proxy_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string(),
        value: config.encode_to_vec(),
    };
    let reality_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
        value: RealityConfigPayload {
            fingerprint: "chrome".into(),
            server_name: "reality.example.test".into(),
            public_key: vec![7; 32],
            short_id: vec![0, 1, 2, 3, 4, 5, 6, 7],
            spider_x: "/".into(),
            ..RealityConfigPayload::default()
        }
        .encode_to_vec(),
    };
    let sender_settings = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "tcp".into(),
                transport_settings: Vec::new(),
                security_type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                security_settings: vec![reality_settings],
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "reality-trojan".into(),
            sender_settings: Some(sender_settings),
            proxy_settings: Some(proxy_settings),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan REALITY senderSettings should be accepted");
    assert_eq!(outbound.protocol, "trojan");
    assert_eq!(
        outbound.sender_settings_type.as_deref(),
        Some("xray.app.proxyman.SenderConfig")
    );
}

#[cfg(all(feature = "trojan", feature = "reality", feature = "grpc_transport"))]
#[test]
fn handler_accepts_grpc_reality_trojan_outbound() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let proxy_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string(),
        value: TrojanClientConfigPayload {
            server: Some(SocksServerEndpointPayload {
                address: Some(localhost_ip_payload()),
                port: 443,
                user: Some(proto::xray::common::protocol::User {
                    level: 0,
                    email: "trojan-grpc-reality@example.test".into(),
                    account: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                        value: TrojanAccountPayload {
                            password: "secret".into(),
                        }
                        .encode_to_vec(),
                    }),
                }),
            }),
        }
        .encode_to_vec(),
    };
    let grpc_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_GRPC_CONFIG.to_string(),
        value: GrpcConfigPayload {
            authority: "grpc.example.test".into(),
            service_name: "GunService".into(),
            multi_mode: false,
            idle_timeout: 0,
            health_check_timeout: 0,
            permit_without_stream: false,
            initial_windows_size: 0,
            user_agent: "chimera-test".into(),
        }
        .encode_to_vec(),
    };
    let reality_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
        value: RealityConfigPayload {
            fingerprint: "chrome".into(),
            server_name: "reality.example.test".into(),
            public_key: vec![7; 32],
            short_id: vec![0, 1, 2, 3, 4, 5, 6, 7],
            spider_x: "/".into(),
            ..RealityConfigPayload::default()
        }
        .encode_to_vec(),
    };
    let sender_settings = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "grpc".into(),
                transport_settings: vec![TransportConfigPayload {
                    settings: Some(grpc_settings),
                    protocol_name: "grpc".into(),
                }],
                security_type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                security_settings: vec![reality_settings],
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "grpc-reality-trojan".into(),
            sender_settings: Some(sender_settings),
            proxy_settings: Some(proxy_settings),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan gRPC REALITY senderSettings should be accepted");
    assert_eq!(outbound.protocol, "trojan");
    assert_eq!(
        outbound.sender_settings_type.as_deref(),
        Some("xray.app.proxyman.SenderConfig")
    );
}

#[cfg(all(feature = "trojan", feature = "tls", feature = "ws"))]
#[test]
fn handler_accepts_raw_tls_and_websocket_trojan_outbounds() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let config = TrojanClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(localhost_ip_payload()),
            port: 443,
            user: Some(proto::xray::common::protocol::User {
                level: 0,
                email: "trojan@example.test".into(),
                account: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                    value: TrojanAccountPayload {
                        password: "secret".into(),
                    }
                    .encode_to_vec(),
                }),
            }),
        }),
    };
    let proxy_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string(),
        value: config.encode_to_vec(),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "trojan-outbound".into(),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("raw Trojan outbound should be executable");
    assert_eq!(outbound.protocol, "trojan");
    assert_eq!(
        outbound.proxy_settings_type.as_deref(),
        Some(TYPE_PROXY_TROJAN_CLIENT_CONFIG)
    );

    let tls_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_TLS_CONFIG.to_string(),
        value: TlsConfigPayload {
            certificate: Vec::new(),
            server_name: "trojan.example.test".into(),
            next_protocol: vec!["http/1.1".into()],
            disable_system_root: false,
        }
        .encode_to_vec(),
    };
    let sender_settings = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "tcp".into(),
                transport_settings: Vec::new(),
                security_type: TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                security_settings: vec![tls_settings],
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let secure = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "secure-trojan".into(),
            sender_settings: Some(sender_settings),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan TLS senderSettings should be accepted");
    assert_eq!(secure.protocol, "trojan");
    assert_eq!(
        secure.sender_settings_type.as_deref(),
        Some("xray.app.proxyman.SenderConfig")
    );

    let websocket_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_WEBSOCKET_CONFIG.to_string(),
        value: WebsocketConfigPayload {
            host: "ws.example.test".into(),
            path: "/trojan".into(),
            header: std::collections::HashMap::from([(
                "X-Test".into(),
                "chimera".into(),
            )]),
            accept_proxy_protocol: false,
            ed: 0,
            heartbeat_period: 30,
        }
        .encode_to_vec(),
    };
    let websocket_sender = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "websocket".into(),
                transport_settings: vec![TransportConfigPayload {
                    settings: Some(websocket_settings),
                    protocol_name: "websocket".into(),
                }],
                security_type: String::new(),
                security_settings: Vec::new(),
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let websocket = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "websocket-trojan".into(),
            sender_settings: Some(websocket_sender),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan WebSocket senderSettings should be accepted");
    assert_eq!(websocket.protocol, "trojan");

    let early_data_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_WEBSOCKET_CONFIG.to_string(),
        value: WebsocketConfigPayload {
            host: String::new(),
            path: "/trojan".into(),
            header: std::collections::HashMap::new(),
            accept_proxy_protocol: false,
            ed: 16,
            heartbeat_period: 0,
        }
        .encode_to_vec(),
    };
    let early_data_sender = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "websocket".into(),
                transport_settings: vec![TransportConfigPayload {
                    settings: Some(early_data_settings),
                    protocol_name: "websocket".into(),
                }],
                security_type: String::new(),
                security_settings: Vec::new(),
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let early_data = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "early-data-trojan".into(),
            sender_settings: Some(early_data_sender),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("Trojan WebSocket early-data should be accepted");
    assert_eq!(early_data.protocol, "trojan");

    let unsupported_sender = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "xhttp".into(),
                transport_settings: Vec::new(),
                security_type: String::new(),
                security_settings: Vec::new(),
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let error = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "unsupported-trojan".into(),
            sender_settings: Some(unsupported_sender),
            proxy_settings: Some(proxy_settings),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect_err("unsupported Trojan transport must fail closed");
    assert_eq!(error.code(), Code::Unimplemented);
}

#[cfg(all(feature = "trojan", feature = "httpupgrade"))]
#[test]
fn handler_accepts_httpupgrade_trojan_outbound_with_early_data() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let proxy_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string(),
        value: TrojanClientConfigPayload {
            server: Some(SocksServerEndpointPayload {
                address: Some(localhost_ip_payload()),
                port: 443,
                user: Some(proto::xray::common::protocol::User {
                    level: 0,
                    email: "trojan-httpupgrade@example.test".into(),
                    account: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                        value: TrojanAccountPayload {
                            password: "secret".into(),
                        }
                        .encode_to_vec(),
                    }),
                }),
            }),
        }
        .encode_to_vec(),
    };
    let transport_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_TRANSPORT_HTTPUPGRADE_CONFIG.to_string(),
        value: HttpUpgradeConfigPayload {
            host: "upgrade.example.test".into(),
            path: "/trojan".into(),
            header: std::collections::HashMap::from([(
                "X-Test".into(),
                "chimera".into(),
            )]),
            accept_proxy_protocol: false,
            ed: 1,
        }
        .encode_to_vec(),
    };
    let sender_settings = proto::xray::common::serial::TypedMessage {
        r#type: "xray.app.proxyman.SenderConfig".into(),
        value: SenderConfigPayload {
            stream_settings: Some(StreamConfigPayload {
                protocol_name: "httpupgrade".into(),
                transport_settings: vec![TransportConfigPayload {
                    settings: Some(transport_settings),
                    protocol_name: "httpupgrade".into(),
                }],
                security_type: String::new(),
                security_settings: Vec::new(),
                quic_params: None,
            }),
        }
        .encode_to_vec(),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "httpupgrade-trojan".into(),
            sender_settings: Some(sender_settings),
            proxy_settings: Some(proxy_settings),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan HTTPUpgrade early-data should be accepted");
    assert_eq!(outbound.protocol, "trojan");
    assert_eq!(
        outbound.sender_settings_type.as_deref(),
        Some("xray.app.proxyman.SenderConfig")
    );
}

#[cfg(all(feature = "trojan", feature = "grpc_transport"))]
#[test]
fn handler_accepts_grpc_trojan_outbound_modes_and_tuning() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let proxy_settings = proto::xray::common::serial::TypedMessage {
        r#type: TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string(),
        value: TrojanClientConfigPayload {
            server: Some(SocksServerEndpointPayload {
                address: Some(localhost_ip_payload()),
                port: 443,
                user: Some(proto::xray::common::protocol::User {
                    level: 0,
                    email: "trojan-grpc@example.test".into(),
                    account: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                        value: TrojanAccountPayload {
                            password: "secret".into(),
                        }
                        .encode_to_vec(),
                    }),
                }),
            }),
        }
        .encode_to_vec(),
    };
    let sender = |config: GrpcConfigPayload| {
        let transport_settings = proto::xray::common::serial::TypedMessage {
            r#type: TYPE_TRANSPORT_GRPC_CONFIG.to_string(),
            value: config.encode_to_vec(),
        };
        proto::xray::common::serial::TypedMessage {
            r#type: "xray.app.proxyman.SenderConfig".into(),
            value: SenderConfigPayload {
                stream_settings: Some(StreamConfigPayload {
                    protocol_name: "grpc".into(),
                    transport_settings: vec![TransportConfigPayload {
                        settings: Some(transport_settings),
                        protocol_name: "grpc".into(),
                    }],
                    security_type: String::new(),
                    security_settings: Vec::new(),
                    quic_params: None,
                }),
            }
            .encode_to_vec(),
        }
    };
    let baseline = GrpcConfigPayload {
        authority: "grpc.example.test".into(),
        service_name: "GunService".into(),
        multi_mode: false,
        idle_timeout: 0,
        health_check_timeout: 0,
        permit_without_stream: false,
        initial_windows_size: 0,
        user_agent: "chimera-test".into(),
    };
    let outbound = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "grpc-trojan".into(),
            sender_settings: Some(sender(baseline.clone())),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan gRPC Tun should be accepted");
    assert_eq!(outbound.protocol, "trojan");
    assert_eq!(
        outbound.sender_settings_type.as_deref(),
        Some("xray.app.proxyman.SenderConfig")
    );

    let mut multi_mode = baseline.clone();
    multi_mode.multi_mode = true;
    let multi = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "grpc-multimode-trojan".into(),
            sender_settings: Some(sender(multi_mode)),
            proxy_settings: Some(proxy_settings.clone()),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan gRPC TunMulti should be accepted");
    assert_eq!(multi.protocol, "trojan");
    assert!(multi.sender_settings_value.is_some());

    let mut tuned = baseline;
    tuned.idle_timeout = 10;
    tuned.health_check_timeout = 7;
    tuned.permit_without_stream = true;
    tuned.initial_windows_size = 1 << 20;
    let tuned = service
        .parse_add_outbound(proto::xray::core::OutboundHandlerConfig {
            tag: "grpc-tuned-trojan".into(),
            sender_settings: Some(sender(tuned)),
            proxy_settings: Some(proxy_settings),
            ..proto::xray::core::OutboundHandlerConfig::default()
        })
        .expect("dynamic Trojan gRPC keepalive/window tuning should be accepted");
    assert_eq!(tuned.protocol, "trojan");
    assert!(tuned.sender_settings_value.is_some());
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn handler_alter_trojan_users_does_not_restart_listener() {
    let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = occupied.local_addr().unwrap().port();
    let inbound_tag = unique_tag("trojan-no-restart-inbound");
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Trojan {
                users: Vec::new(),
                fallbacks: Vec::new(),
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    let abort_handle = placeholder_task.abort_handle();
    runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(runtime.clone());
    let added_email = unique_tag("trojan-dynamic-user");
    let operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 7,
            email: added_email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                value: TrojanAccountPayload {
                    password: "  dynamic-password  ".to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("Trojan user update must not rebind the occupied listener");

    assert!(!abort_handle.is_finished());
    let updated = runtime.inbound_by_tag(&inbound_tag).unwrap();
    let ServerProxyConfig::Trojan { users, .. } = updated.protocol else {
        panic!("expected trojan inbound");
    };
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email.as_deref(), Some(added_email.as_str()));
    assert_eq!(users[0].password, "  dynamic-password  ");
    assert_eq!(users[0].user_level, 7);
    assert!(runtime.stop_inbound_tasks(&inbound_tag).await);
}

#[cfg(feature = "vmess")]
#[tokio::test]
async fn handler_alter_vmess_users_does_not_restart_listener() {
    let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = occupied.local_addr().unwrap().port();
    let inbound_tag = unique_tag("vmess-no-restart-inbound");
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Vmess { users: Vec::new() },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    let abort_handle = placeholder_task.abort_handle();
    runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(runtime.clone());
    let added_email = unique_tag("vmess-dynamic-user");
    let operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: added_email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                value: VmessAccountPayload {
                    id: "3ac9b383-75a1-431c-8184-106c80eb2273".to_string(),
                    security_settings: Some(VmessSecurityConfigPayload {
                        r#type: 3,
                    }),
                    tests_enabled: String::new(),
                }
                .encode_to_vec(),
            }),
        }),
    };

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("VMess user update must not rebind the occupied listener");

    assert!(!abort_handle.is_finished());
    let updated = runtime.inbound_by_tag(&inbound_tag).unwrap();
    let ServerProxyConfig::Vmess { users } = updated.protocol else {
        panic!("expected vmess inbound");
    };
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].user_label, added_email);
    assert!(runtime.stop_inbound_tasks(&inbound_tag).await);
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn handler_alter_vless_users_does_not_restart_listener() {
    let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = occupied.local_addr().unwrap().port();
    let inbound_tag = unique_tag("no-restart-inbound");
    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location: BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            port,
        )),
        protocol: ServerProxyConfig::Vless {
            users: Vec::new(),
            fallbacks: Vec::new(),
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![inbound], Vec::new());
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    let abort_handle = placeholder_task.abort_handle();
    runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(runtime.clone());
    let added_email = unique_tag("dynamic-user");
    let operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: added_email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                    flow: String::new(),
                }
                .encode_to_vec(),
            }),
        }),
    };

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("VLESS user update must not rebind the occupied listener");

    assert!(!abort_handle.is_finished());
    let updated = runtime.inbound_by_tag(&inbound_tag).unwrap();
    let ServerProxyConfig::Vless { users, .. } = updated.protocol else {
        panic!("expected vless inbound");
    };
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].user_label, added_email);
    assert!(runtime.stop_inbound_tasks(&inbound_tag).await);
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn handler_vless_vision_mode_change_does_not_restart_listener() {
    let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = occupied.local_addr().unwrap().port();
    let inbound_tag = unique_tag("vision-restart-inbound");
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Vless {
                users: Vec::new(),
                fallbacks: Vec::new(),
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    let abort_handle = placeholder_task.abort_handle();
    runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(runtime.clone());
    let operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: unique_tag("vision-user"),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                    flow: "xtls-rprx-vision".to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("Xray VLESS AddUser must not restart the listener");

    assert!(!abort_handle.is_finished());
    let current = runtime.inbound_by_tag(&inbound_tag).unwrap();
    let ServerProxyConfig::Vless { users, .. } = current.protocol else {
        panic!("expected VLESS inbound");
    };
    assert_eq!(users[0].flow, "xtls-rprx-vision");
    assert!(runtime.stop_inbound_tasks(&inbound_tag).await);
}

#[tokio::test]
async fn handler_empty_alter_keeps_registered_listener() {
    let fixture = build_fixture();
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    fixture
        .runtime
        .register_inbound_tasks(&fixture.inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(fixture.runtime.clone());

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: fixture.inbound_tag.clone(),
                operation: None,
            },
        ))
        .await
        .expect("empty operation should be idempotent");

    assert!(
        fixture
            .runtime
            .stop_inbound_tasks(&fixture.inbound_tag)
            .await
    );
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn handler_alter_inbound_reaches_xhttp_inner_users() {
    let inbound_tag = unique_tag("xhttp-vless-inbound");
    let inbound = ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                free_localhost_port(),
            )),
            protocol: ServerProxyConfig::Xhttp {
                config: XhttpServerConfig {
                    mode: crate::config::server_config::XhttpMode::Auto,
                    host: None,
                    path: "/control".to_string(),
                    trusted_x_forwarded_for: Vec::new(),
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
                inner: Box::new(ServerProxyConfig::Vless {
                    users: Vec::new(),
                    fallbacks: Vec::new(),
                }),
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        };
    let runtime = RuntimeState::new(vec![inbound], Vec::new());
    let service = HandlerServiceImpl::new(runtime);
    let email = unique_tag("xhttp-user");
    let operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                    flow: String::new(),
                }
                .encode_to_vec(),
            }),
        }),
    };

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("xhttp add user should reach inner protocol");
    let users = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag,
                email: String::new(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .users;

    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, email);
}

#[test]
fn handler_preserves_xray_socks_grpc_fields() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let parsed = service
        .parse_add_inbound_protocol(&HandlerServiceImpl::typed_message(
            TYPE_PROXY_SOCKS_SERVER_CONFIG,
            SocksServerConfigPayload {
                auth_type: 2,
                accounts: std::collections::HashMap::from([(
                    "alice".to_string(),
                    "secret".to_string(),
                )]),
                address: Some(localhost_ip_payload()),
                udp_enabled: true,
                user_level: 7,
            },
        ))
        .expect("SOCKS server config should parse");
    let ServerProxyConfig::Socks {
        accounts,
        udp_enabled,
        udp_response_ip,
        user_level,
    } = &parsed
    else {
        panic!("expected SOCKS inbound config");
    };
    assert!(!accounts.auth_required());
    assert_eq!(accounts.snapshot()[0].username, "alice");
    assert!(*udp_enabled);
    assert_eq!(udp_response_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(*user_level, 7);

    let (_, encoded) = service.encode_inbound_protocol_layers(&parsed);
    let encoded = encoded.expect("SOCKS settings should encode");
    let socks = SocksServerConfigPayload::decode(encoded.value.as_slice())
        .expect("decode SOCKS settings");
    assert_eq!(socks.auth_type, 0);
    assert_eq!(
        socks.accounts.get("alice").map(String::as_str),
        Some("secret")
    );
    assert_eq!(socks.address, Some(localhost_ip_payload()));
    assert!(socks.udp_enabled);
}

#[tokio::test]
async fn handler_lists_inbounds() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());

    let response = service
        .list_inbounds(Request::new(
            proto::xray::app::proxyman::command::ListInboundsRequest {
                is_only_tags: false,
            },
        ))
        .await
        .expect("list_inbounds failed")
        .into_inner();
    assert_eq!(response.inbounds.len(), 1);
    let inbound = &response.inbounds[0];
    assert_eq!(inbound.tag, fixture.inbound_tag);

    let receiver_settings = inbound
        .receiver_settings
        .as_ref()
        .expect("receiver settings should be echoed");
    assert_eq!(receiver_settings.r#type, TYPE_APP_RECEIVER_CONFIG);
    let receiver = ReceiverConfigPayload::decode(receiver_settings.value.as_slice())
        .expect("decode receiver settings");
    let ports = receiver.port_list.expect("receiver ports");
    assert_eq!(ports.range.len(), 1);
    assert_eq!(ports.range[0].from, 1080);
    assert_eq!(ports.range[0].to, 1080);
    assert_eq!(receiver.listen, Some(localhost_ip_payload()));

    let proxy_settings = inbound
        .proxy_settings
        .as_ref()
        .expect("proxy settings should be echoed");
    assert_eq!(proxy_settings.r#type, TYPE_PROXY_SOCKS_SERVER_CONFIG);
    let socks = SocksServerConfigPayload::decode(proxy_settings.value.as_slice())
        .expect("decode socks settings");
    assert_eq!(socks.auth_type, 1);
    assert_eq!(socks.accounts.len(), 1);
    assert!(socks.accounts.values().any(|password| password == "pass-a"));
}

#[tokio::test]
async fn handler_lists_inbounds_only_tags_omits_settings() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());

    let response = service
        .list_inbounds(Request::new(
            proto::xray::app::proxyman::command::ListInboundsRequest {
                is_only_tags: true,
            },
        ))
        .await
        .expect("list_inbounds failed")
        .into_inner();
    assert_eq!(response.inbounds.len(), 1);
    let inbound = &response.inbounds[0];
    assert_eq!(inbound.tag, fixture.inbound_tag);
    assert!(inbound.receiver_settings.is_none());
    assert!(inbound.proxy_settings.is_none());
}

#[tokio::test]
async fn handler_lists_outbounds() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());

    let response = service
        .list_outbounds(Request::new(
            proto::xray::app::proxyman::command::ListOutboundsRequest {},
        ))
        .await
        .expect("list_outbounds failed")
        .into_inner();
    assert_eq!(response.outbounds.len(), 1);
    let outbound = &response.outbounds[0];
    assert_eq!(outbound.tag, fixture.outbound_tag);
    assert!(outbound.sender_settings.is_none());
    let proxy_settings = outbound
        .proxy_settings
        .as_ref()
        .expect("proxy settings should be echoed");
    assert_eq!(proxy_settings.r#type, TYPE_PROXY_FREEDOM_CONFIG);
    FreedomConfigPayload::decode(proxy_settings.value.as_slice())
        .expect("decode freedom settings");
}

#[tokio::test]
async fn handler_methods_without_support_return_errors() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());

    let err = service
        .add_inbound(Request::new(
            proto::xray::app::proxyman::command::AddInboundRequest::default(),
        ))
        .await
        .expect_err("expected add_inbound to validate request");
    assert_eq!(err.code(), Code::InvalidArgument);

    let err = service
        .remove_inbound(Request::new(
            proto::xray::app::proxyman::command::RemoveInboundRequest {
                tag: "missing-inbound".to_string(),
            },
        ))
        .await
        .expect_err("expected remove_inbound to report not found");
    assert_eq!(err.code(), Code::Unknown);

    let err = service
        .add_outbound(Request::new(
            proto::xray::app::proxyman::command::AddOutboundRequest::default(),
        ))
        .await
        .expect_err("expected add_outbound to validate request");
    assert_eq!(err.code(), Code::InvalidArgument);

    let err = service
        .remove_outbound(Request::new(
            proto::xray::app::proxyman::command::RemoveOutboundRequest {
                tag: "missing-outbound".to_string(),
            },
        ))
        .await
        .expect_err("expected remove_outbound to report not found");
    assert_eq!(err.code(), Code::NotFound);

    let err = service
        .alter_outbound(Request::new(
            proto::xray::app::proxyman::command::AlterOutboundRequest::default(),
        ))
        .await
        .expect_err("expected alter_outbound to be unimplemented");
    assert_eq!(err.code(), Code::Unimplemented);

    let err = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: fixture.inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect_err("SOCKS should not expose Xray UserManager");
    assert_eq!(err.code(), Code::Unknown);
    assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);

    let err = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: fixture.inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect_err("SOCKS should not expose Xray UserManager count");
    assert_eq!(err.code(), Code::Unknown);
    assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);
}

#[tokio::test]
async fn handler_adds_inbound_and_outbound() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());
    let added_inbound = unique_tag("added-inbound");
    let added_outbound = unique_tag("added-outbound");
    let added_inbound_port = free_localhost_port();

    service
        .add_inbound(Request::new(build_add_inbound_request(
            &added_inbound,
            added_inbound_port,
        )))
        .await
        .expect("add_inbound should succeed");
    assert!(fixture.runtime.inbound_by_tag(&added_inbound).is_some());

    tokio::time::sleep(Duration::from_millis(50)).await;
    let stream = tokio::net::TcpStream::connect(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        added_inbound_port,
    ))
    .await
    .expect("added inbound listener should accept connections");
    drop(stream);

    let inbounds = service
        .list_inbounds(Request::new(
            proto::xray::app::proxyman::command::ListInboundsRequest {
                is_only_tags: true,
            },
        ))
        .await
        .expect("list_inbounds after add failed")
        .into_inner();
    assert!(
        inbounds
            .inbounds
            .iter()
            .any(|item| item.tag == added_inbound)
    );

    service
        .add_outbound(Request::new(build_add_outbound_request(&added_outbound)))
        .await
        .expect("add_outbound should succeed");

    let outbounds = service
        .list_outbounds(Request::new(
            proto::xray::app::proxyman::command::ListOutboundsRequest {},
        ))
        .await
        .expect("list_outbounds after add failed")
        .into_inner();
    assert!(
        outbounds
            .outbounds
            .iter()
            .any(|item| item.tag == added_outbound)
    );

    service
        .remove_inbound(Request::new(
            proto::xray::app::proxyman::command::RemoveInboundRequest {
                tag: added_inbound.clone(),
            },
        ))
        .await
        .expect("remove_inbound after add failed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = tokio::net::TcpStream::connect(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        added_inbound_port,
    ))
    .await
    .expect_err("removed inbound listener should stop accepting connections");
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::TimedOut
    ));
}

#[tokio::test]
async fn handler_allows_multiple_untagged_inbounds_but_cannot_remove_by_empty_tag() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());
    let first_port = free_localhost_port();
    let second_port = free_localhost_port();

    service
        .add_inbound(Request::new(build_add_inbound_request("", first_port)))
        .await
        .expect("first untagged AddInbound should succeed");
    service
        .add_inbound(Request::new(build_add_inbound_request("", second_port)))
        .await
        .expect("second untagged AddInbound should succeed");

    let listed = service
        .list_inbounds(Request::new(
            proto::xray::app::proxyman::command::ListInboundsRequest {
                is_only_tags: true,
            },
        ))
        .await
        .expect("list untagged inbounds")
        .into_inner();
    assert_eq!(
        listed
            .inbounds
            .iter()
            .filter(|item| item.tag.is_empty())
            .count(),
        2
    );

    for port in [first_port, second_port] {
        tokio::net::TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .await
            .expect("untagged listener should accept connections");
    }

    let error = service
        .remove_inbound(Request::new(
            proto::xray::app::proxyman::command::RemoveInboundRequest {
                tag: String::new(),
            },
        ))
        .await
        .expect_err("Xray does not address untagged inbounds by empty tag");
    assert_eq!(error.code(), Code::Unknown);

    assert_eq!(
        fixture
            .runtime
            .inbounds()
            .iter()
            .filter(|item| item.tag.is_empty())
            .count(),
        2
    );
    assert_eq!(fixture.runtime.inbound_manager().stop_all_tasks().await, 2);
}

#[cfg(all(feature = "vless", feature = "ws", feature = "tls"))]
#[test]
fn handler_parse_add_inbound_supports_vless_websocket_tls() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime);
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "vless-user@example.com".to_string(),
        account: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
            value: VlessAccountPayload {
                id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                flow: String::new(),
            }
            .encode_to_vec(),
        }),
    };
    let inbound = proto::xray::core::InboundHandlerConfig {
        tag: unique_tag("vless"),
        receiver_settings: Some(build_receiver_settings(
            2080,
            Some(StreamConfigPayload {
                protocol_name: "websocket".to_string(),
                transport_settings: vec![TransportConfigPayload {
                    protocol_name: "websocket".to_string(),
                    settings: Some(proto::xray::common::serial::TypedMessage {
                        r#type: TYPE_TRANSPORT_WEBSOCKET_CONFIG.to_string(),
                        value: WebsocketConfigPayload {
                            host: "example.com".to_string(),
                            path: "/ws".to_string(),
                            header: std::collections::HashMap::from([(
                                "X-Test".to_string(),
                                "ignored-inbound".to_string(),
                            )]),
                            accept_proxy_protocol: false,
                            ed: 0,
                            heartbeat_period: 0,
                        }
                        .encode_to_vec(),
                    }),
                }],
                security_type: "tls".to_string(),
                security_settings: vec![proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                    value: TlsConfigPayload {
                        certificate: vec![TlsCertificatePayload {
                            certificate: Vec::new(),
                            key: Vec::new(),
                            certificate_path: "/tmp/test-cert.pem".to_string(),
                            key_path: "/tmp/test-key.pem".to_string(),
                        }],
                        server_name: String::new(),
                        next_protocol: vec![
                            "h2".to_string(),
                            "http/1.1".to_string(),
                        ],
                        disable_system_root: false,
                    }
                    .encode_to_vec(),
                }],
                quic_params: None,
            }),
        )),
        proxy_settings: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_VLESS_INBOUND_CONFIG.to_string(),
            value: VlessInboundConfigPayload {
                clients: vec![user],
            }
            .encode_to_vec(),
        }),
    };

    let parsed = service
        .parse_add_inbound(inbound)
        .expect("vless websocket tls inbound should parse");
    assert_eq!(parsed.transport, Transport::Tcp);
    match parsed.protocol {
        ServerProxyConfig::Tls(tls) => {
            assert_eq!(tls.certificates.len(), 1);
            let certificate = &tls.certificates[0];
            assert_eq!(
                certificate.certificate_path.as_deref(),
                Some("/tmp/test-cert.pem")
            );
            assert_eq!(certificate.key_path.as_deref(), Some("/tmp/test-key.pem"));
            assert_eq!(tls.alpn_protocols, vec!["h2", "http/1.1"]);
            match tls.inner.as_ref() {
                ServerProxyConfig::Websocket { targets } => match targets.as_ref() {
                    OneOrSome::One(target) => {
                        assert_eq!(target.matching_path.as_deref(), Some("/ws"));
                        let matching_headers = target
                            .matching_headers
                            .as_ref()
                            .expect("websocket host should be preserved");
                        assert_eq!(
                            matching_headers.get("host").map(String::as_str),
                            Some("example.com")
                        );
                        assert!(!matching_headers.contains_key("X-Test"));
                        assert!(!matching_headers.contains_key("x-test"));
                        match &target.protocol {
                            ServerProxyConfig::Vless { users, .. } => {
                                assert_eq!(users.len(), 1);
                                assert_eq!(
                                    users[0].user_id,
                                    "5df5643d-4e28-4399-bb9e-22014a2d3246"
                                );
                                assert_eq!(
                                    users[0].user_label,
                                    "vless-user@example.com"
                                );
                            }
                            other => {
                                panic!("unexpected inner protocol: {other:?}")
                            }
                        }
                    }
                    other => {
                        panic!("unexpected websocket target layout: {other:?}")
                    }
                },
                other => panic!("unexpected tls inner protocol: {other:?}"),
            }
        }
        other => panic!("unexpected protocol: {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn handler_parse_add_inbound_supports_xhttp_and_round_trips_settings() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "xhttp-user@example.com".to_string(),
        account: Some(HandlerServiceImpl::typed_message(
            TYPE_PROXY_VLESS_ACCOUNT,
            VlessAccountPayload {
                id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                flow: String::new(),
            },
        )),
    };
    let inbound = proto::xray::core::InboundHandlerConfig {
        tag: unique_tag("xhttp"),
        receiver_settings: Some(build_receiver_settings(
            2081,
            Some(StreamConfigPayload {
                protocol_name: "xhttp".to_string(),
                transport_settings: vec![TransportConfigPayload {
                    protocol_name: "xhttp".to_string(),
                    settings: Some(HandlerServiceImpl::typed_message(
                        TYPE_TRANSPORT_XHTTP_CONFIG,
                        XhttpConfigPayload {
                            path: "/api".to_string(),
                            mode: "packet-up".to_string(),
                            x_padding_bytes: Some(XhttpRangePayload {
                                from: 42,
                                to: 84,
                            }),
                            sc_max_buffered_posts: 9,
                            uplink_http_method: "get".to_string(),
                            ..XhttpConfigPayload::default()
                        },
                    )),
                }],
                security_type: String::new(),
                security_settings: Vec::new(),
                quic_params: Some(QuicParamsPayload {
                    congestion: "bbr".to_string(),
                    bbr_profile: String::new(),
                    init_stream_receive_window: 32_768,
                    max_stream_receive_window: 65_536,
                    init_connection_receive_window: 32_768,
                    max_connection_receive_window: 131_072,
                    max_idle_timeout: 10,
                    keep_alive_period: 5,
                    disable_path_mtu_discovery: true,
                    max_incoming_streams: 16,
                }),
            }),
        )),
        proxy_settings: Some(HandlerServiceImpl::typed_message(
            TYPE_PROXY_VLESS_INBOUND_CONFIG,
            VlessInboundConfigPayload {
                clients: vec![user],
            },
        )),
    };

    let parsed = service
        .parse_add_inbound(inbound)
        .expect("xhttp inbound should parse");
    assert_eq!(parsed.transport, Transport::Tcp);
    let ServerProxyConfig::Xhttp { config, inner } = &parsed.protocol else {
        panic!("expected xhttp protocol");
    };
    assert_eq!(config.path, "/api/");
    assert_eq!(config.min_padding, 42);
    assert_eq!(config.max_padding, 84);
    assert_eq!(config.max_buffered_posts, 9);
    assert_eq!(config.uplink_http_method, "GET");
    assert_eq!(config.xray_max_idle_timeout_secs, Some(10));
    assert_eq!(config.xray_max_incoming_streams, Some(16));
    assert_eq!(config.xray_max_stream_receive_window, Some(65_536));
    assert_eq!(config.xray_disable_path_mtu_discovery, Some(true));
    assert!(
        matches!(inner.as_ref(), ServerProxyConfig::Vless { users, .. } if users.len() == 1)
    );

    let encoded = service.encode_inbound_config(&parsed);
    let receiver = ReceiverConfigPayload::decode(
        encoded
            .receiver_settings
            .expect("receiver settings")
            .value
            .as_slice(),
    )
    .expect("receiver settings should decode");
    let stream = receiver.stream_settings.expect("stream settings");
    let transport = stream
        .transport_settings
        .iter()
        .find(|item| item.protocol_name == "xhttp")
        .and_then(|item| item.settings.as_ref())
        .expect("xhttp transport settings should be echoed");
    let echoed = XhttpConfigPayload::decode(transport.value.as_slice())
        .expect("xhttp settings should decode");
    assert_eq!(echoed.path, "/api/");
    assert_eq!(echoed.mode, "packet-up");
    assert_eq!(
        stream.quic_params.expect("quic params").max_idle_timeout,
        10
    );
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn handler_add_inbound_starts_xhttp_listener() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let service = HandlerServiceImpl::new(runtime.clone());
    let tag = unique_tag("xhttp-runtime");
    let port = free_localhost_port();
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "xhttp-runtime-user@example.com".to_string(),
        account: Some(HandlerServiceImpl::typed_message(
            TYPE_PROXY_VLESS_ACCOUNT,
            VlessAccountPayload {
                id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                flow: String::new(),
            },
        )),
    };
    let request = proto::xray::app::proxyman::command::AddInboundRequest {
        inbound: Some(proto::xray::core::InboundHandlerConfig {
            tag: tag.clone(),
            receiver_settings: Some(build_receiver_settings(
                port,
                Some(StreamConfigPayload {
                    protocol_name: "xhttp".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_XHTTP_CONFIG,
                            XhttpConfigPayload {
                                path: "/control".to_string(),
                                ..XhttpConfigPayload::default()
                            },
                        )),
                    }],
                    security_type: String::new(),
                    security_settings: Vec::new(),
                    quic_params: None,
                }),
            )),
            proxy_settings: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_VLESS_INBOUND_CONFIG,
                VlessInboundConfigPayload {
                    clients: vec![user],
                },
            )),
        }),
    };

    service
        .add_inbound(Request::new(request))
        .await
        .expect("xhttp AddInbound should start");
    let inbound = runtime
        .inbound_by_tag(&tag)
        .expect("xhttp inbound should be registered");
    assert!(matches!(inbound.protocol, ServerProxyConfig::Xhttp { .. }));

    let added_email = unique_tag("xhttp-added-user");
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: added_email.clone(),
            account: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_VLESS_ACCOUNT,
                VlessAccountPayload {
                    id: "bcd643ce-d9c8-50bb-b026-89d256010162".to_string(),
                    flow: String::new(),
                },
            )),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: tag.clone(),
                operation: Some(HandlerServiceImpl::typed_message(
                    TYPE_ADD_USER_OPERATION,
                    add_operation,
                )),
            },
        ))
        .await
        .expect("xhttp add user should update the shared VLESS user store");
    let users = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("xhttp users should be available after add")
        .into_inner()
        .users;
    assert_eq!(users.len(), 2);
    assert!(users.iter().any(|user| user.email == added_email));

    let remove_operation =
        proto::xray::app::proxyman::command::RemoveUserOperation {
            email: added_email.clone(),
        };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: tag.clone(),
                operation: Some(HandlerServiceImpl::typed_message(
                    TYPE_REMOVE_USER_OPERATION,
                    remove_operation,
                )),
            },
        ))
        .await
        .expect("xhttp remove user should update the shared VLESS user store");
    let users = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("xhttp users should be available after remove")
        .into_inner()
        .users;
    assert_eq!(users.len(), 1);
    assert!(!users.iter().any(|user| user.email == added_email));
    assert!(runtime.stop_inbound_tasks(&tag).await);
    assert!(runtime.remove_inbound(&tag).is_some());
}

#[cfg(all(feature = "vless", feature = "tls"))]
#[test]
fn handler_parse_add_inbound_supports_xhttp_tls_h3() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "xhttp-tls-user@example.com".to_string(),
        account: Some(HandlerServiceImpl::typed_message(
            TYPE_PROXY_VLESS_ACCOUNT,
            VlessAccountPayload {
                id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                flow: String::new(),
            },
        )),
    };
    let parsed = service
        .parse_add_inbound(proto::xray::core::InboundHandlerConfig {
            tag: unique_tag("xhttp-tls"),
            receiver_settings: Some(build_receiver_settings(
                2443,
                Some(StreamConfigPayload {
                    protocol_name: "xhttp".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_XHTTP_CONFIG,
                            XhttpConfigPayload {
                                path: "/h3".to_string(),
                                ..XhttpConfigPayload::default()
                            },
                        )),
                    }],
                    security_type: "tls".to_string(),
                    security_settings: vec![HandlerServiceImpl::typed_message(
                        TYPE_TRANSPORT_TLS_CONFIG,
                        TlsConfigPayload {
                            certificate: vec![TlsCertificatePayload {
                                certificate: b"inline-certificate".to_vec(),
                                key: b"inline-private-key".to_vec(),
                                certificate_path: String::new(),
                                key_path: String::new(),
                            }],
                            server_name: String::new(),
                            next_protocol: vec!["h3".to_string()],
                            disable_system_root: false,
                        },
                    )],
                    quic_params: None,
                }),
            )),
            proxy_settings: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_VLESS_INBOUND_CONFIG,
                VlessInboundConfigPayload {
                    clients: vec![user],
                },
            )),
        })
        .expect("xhttp TLS inbound should parse");

    let ServerProxyConfig::Tls(tls) = parsed.protocol else {
        panic!("expected TLS outer layer");
    };
    assert_eq!(tls.alpn_protocols, vec!["h3"]);
    assert!(matches!(
        tls.inner.as_ref(),
        ServerProxyConfig::Xhttp { config, inner }
            if config.path == "/h3/"
                && matches!(inner.as_ref(), ServerProxyConfig::Vless { users, .. } if users.len() == 1)
    ));
}

#[cfg(all(feature = "vless", feature = "tls"))]
#[tokio::test]
async fn handler_add_inbound_starts_xhttp_h3_listener() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default();
    let generated = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate test certificate");
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let service = HandlerServiceImpl::new(runtime.clone());
    let tag = unique_tag("xhttp-h3-runtime");
    let request = proto::xray::app::proxyman::command::AddInboundRequest {
        inbound: Some(proto::xray::core::InboundHandlerConfig {
            tag: tag.clone(),
            receiver_settings: Some(build_receiver_settings(
                free_localhost_port(),
                Some(StreamConfigPayload {
                    protocol_name: "xhttp".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_XHTTP_CONFIG,
                            XhttpConfigPayload {
                                path: "/h3".to_string(),
                                ..XhttpConfigPayload::default()
                            },
                        )),
                    }],
                    security_type: "tls".to_string(),
                    security_settings: vec![HandlerServiceImpl::typed_message(
                        TYPE_TRANSPORT_TLS_CONFIG,
                        TlsConfigPayload {
                            certificate: vec![TlsCertificatePayload {
                                certificate: generated.cert.pem().into_bytes(),
                                key: generated
                                    .signing_key
                                    .serialize_pem()
                                    .into_bytes(),
                                certificate_path: String::new(),
                                key_path: String::new(),
                            }],
                            server_name: String::new(),
                            next_protocol: vec!["h3".to_string()],
                            disable_system_root: false,
                        },
                    )],
                    quic_params: Some(QuicParamsPayload {
                        congestion: String::new(),
                        bbr_profile: String::new(),
                        init_stream_receive_window: 2 * 1024 * 1024,
                        max_stream_receive_window: 6 * 1024 * 1024,
                        init_connection_receive_window: 3 * 1024 * 1024,
                        max_connection_receive_window: 15 * 1024 * 1024,
                        max_idle_timeout: 30,
                        keep_alive_period: 5,
                        disable_path_mtu_discovery: false,
                        max_incoming_streams: 16,
                    }),
                }),
            )),
            proxy_settings: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_VLESS_INBOUND_CONFIG,
                VlessInboundConfigPayload {
                    clients: vec![proto::xray::common::protocol::User {
                        level: 0,
                        email: "xhttp-h3-user@example.com".to_string(),
                        account: Some(HandlerServiceImpl::typed_message(
                            TYPE_PROXY_VLESS_ACCOUNT,
                            VlessAccountPayload {
                                id: "9199ca5b-1850-4ae6-a4fa-fd6384073692"
                                    .to_string(),
                                flow: String::new(),
                            },
                        )),
                    }],
                },
            )),
        }),
    };

    service
        .add_inbound(Request::new(request))
        .await
        .expect("xhttp H3 AddInbound should start");
    assert!(runtime.inbound_by_tag(&tag).is_some());
    assert!(runtime.stop_inbound_tasks(&tag).await);
    assert!(runtime.remove_inbound(&tag).is_some());
}

#[cfg(all(feature = "vless", feature = "reality"))]
#[test]
fn handler_parse_add_inbound_supports_xhttp_reality() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "xhttp-reality-user@example.com".to_string(),
        account: Some(HandlerServiceImpl::typed_message(
            TYPE_PROXY_VLESS_ACCOUNT,
            VlessAccountPayload {
                id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                flow: String::new(),
            },
        )),
    };
    let parsed = service
        .parse_add_inbound(proto::xray::core::InboundHandlerConfig {
            tag: unique_tag("xhttp-reality"),
            receiver_settings: Some(build_receiver_settings(
                2443,
                Some(StreamConfigPayload {
                    protocol_name: "xhttp".to_string(),
                    transport_settings: vec![TransportConfigPayload {
                        protocol_name: "xhttp".to_string(),
                        settings: Some(HandlerServiceImpl::typed_message(
                            TYPE_TRANSPORT_XHTTP_CONFIG,
                            XhttpConfigPayload {
                                path: "/reality".to_string(),
                                ..XhttpConfigPayload::default()
                            },
                        )),
                    }],
                    security_type: "reality".to_string(),
                    security_settings: vec![HandlerServiceImpl::typed_message(
                        TYPE_TRANSPORT_REALITY_CONFIG,
                        RealityConfigPayload {
                            dest: "www.example.com:443".to_string(),
                            server_names: vec!["www.example.com".to_string()],
                            private_key: vec![7; 32],
                            min_client_ver: Vec::new(),
                            max_client_ver: Vec::new(),
                            max_time_diff: 30,
                            short_ids: vec![vec![1, 2, 3, 4, 5, 6, 7, 8]],
                            ..RealityConfigPayload::default()
                        },
                    )],
                    quic_params: None,
                }),
            )),
            proxy_settings: Some(HandlerServiceImpl::typed_message(
                TYPE_PROXY_VLESS_INBOUND_CONFIG,
                VlessInboundConfigPayload {
                    clients: vec![user],
                },
            )),
        })
        .expect("xhttp Reality inbound should parse");

    let ServerProxyConfig::Reality(reality) = parsed.protocol else {
        panic!("expected Reality outer layer");
    };
    assert_eq!(reality.dest.to_string(), "www.example.com:443");
    assert!(matches!(
        reality.inner.as_ref(),
        ServerProxyConfig::Xhttp { config, inner }
            if config.path == "/reality/"
                && matches!(inner.as_ref(), ServerProxyConfig::Vless { users, .. } if users.len() == 1)
    ));
}

#[cfg(feature = "vmess")]
#[test]
fn handler_parse_add_inbound_supports_vmess() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime);
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "vmess-user@example.com".to_string(),
        account: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
            value: VmessAccountPayload {
                id: "test-vmess-user".to_string(),
                security_settings: Some(VmessSecurityConfigPayload { r#type: 3 }),
                tests_enabled: String::new(),
            }
            .encode_to_vec(),
        }),
    };
    let inbound = proto::xray::core::InboundHandlerConfig {
        tag: unique_tag("vmess"),
        receiver_settings: Some(build_receiver_settings(2444, None)),
        proxy_settings: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_VMESS_INBOUND_CONFIG.to_string(),
            value: VmessInboundConfigPayload { users: vec![user] }.encode_to_vec(),
        }),
    };

    let parsed = service
        .parse_add_inbound(inbound)
        .expect("vmess inbound should parse");
    match parsed.protocol {
        ServerProxyConfig::Vmess { users } => {
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].user_label, "vmess-user@example.com");
            assert_eq!(users[0].user_id, "321d83eb-74db-554a-a630-0ad214dc332b");
            assert_eq!(users[0].cipher, "aes-128-gcm");
        }
        other => panic!("unexpected protocol: {other:?}"),
    }
}

#[cfg(all(feature = "trojan", feature = "reality"))]
#[test]
fn handler_parse_add_inbound_supports_trojan_reality() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime);
    let user = proto::xray::common::protocol::User {
        level: 0,
        email: "trojan-user@example.com".to_string(),
        account: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
            value: TrojanAccountPayload {
                password: "secret-password".to_string(),
            }
            .encode_to_vec(),
        }),
    };
    let inbound = proto::xray::core::InboundHandlerConfig {
        tag: unique_tag("trojan"),
        receiver_settings: Some(build_receiver_settings(
            2443,
            Some(StreamConfigPayload {
                protocol_name: "tcp".to_string(),
                transport_settings: Vec::new(),
                security_type: "reality".to_string(),
                security_settings: vec![proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                    value: RealityConfigPayload {
                        dest: "www.example.com:443".to_string(),
                        server_names: vec!["www.example.com".to_string()],
                        private_key: vec![7; 32],
                        min_client_ver: vec![1, 8, 0],
                        max_client_ver: vec![1, 8, 9],
                        max_time_diff: 30,
                        short_ids: vec![vec![1, 2, 3, 4, 5, 6, 7, 8]],
                        ..RealityConfigPayload::default()
                    }
                    .encode_to_vec(),
                }],
                quic_params: None,
            }),
        )),
        proxy_settings: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_TROJAN_SERVER_CONFIG.to_string(),
            value: TrojanServerConfigPayload {
                users: vec![user],
                fallbacks: vec![TrojanFallbackPayload {
                    dest: "fallback.example.com:8443".to_string(),
                }],
            }
            .encode_to_vec(),
        }),
    };

    let parsed = service
        .parse_add_inbound(inbound)
        .expect("trojan reality inbound should parse");
    match parsed.protocol {
        ServerProxyConfig::Reality(reality) => {
            assert_eq!(reality.dest.to_string(), "www.example.com:443");
            assert_eq!(reality.short_ids.len(), 1);
            assert_eq!(reality.max_time_diff, Some(30));
            assert_eq!(reality.min_client_version, Some([1, 8, 0]));
            assert_eq!(reality.max_client_version, Some([1, 8, 9]));
            match reality.inner.as_ref() {
                ServerProxyConfig::Trojan { users, fallbacks } => {
                    assert_eq!(users.len(), 1);
                    assert_eq!(
                        users[0].email.as_deref(),
                        Some("trojan-user@example.com")
                    );
                    assert_eq!(users[0].password, "secret-password");
                    assert_eq!(fallbacks.len(), 1);
                    assert_eq!(
                        fallbacks[0].dest.to_string(),
                        "fallback.example.com:8443"
                    );
                }
                other => panic!("unexpected reality inner protocol: {other:?}"),
            }
        }
        other => panic!("unexpected protocol: {other:?}"),
    }
}

#[cfg(feature = "vmess")]
#[tokio::test]
async fn handler_alter_inbound_adds_and_removes_vmess_users() {
    let inbound_tag = unique_tag("vmess-inbound");
    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location: BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            free_localhost_port(),
        )),
        protocol: ServerProxyConfig::Vmess {
            users: vec![VmessUser {
                user_id: "3ac9b383-75a1-431c-8184-106c80eb2273".to_string(),
                user_label: "first-vmess@example.com".to_string(),
                user_level: 0,
                cipher: "aes-128-gcm".to_string(),
            }],
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![inbound], Vec::new());
    let service = HandlerServiceImpl::new(runtime);

    let initial_users = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("vmess get users failed")
        .into_inner()
        .users;
    assert_eq!(initial_users.len(), 1);
    let initial_account = initial_users[0]
        .account
        .as_ref()
        .expect("VMess users must include account payload");
    assert_eq!(initial_account.r#type, TYPE_PROXY_VMESS_ACCOUNT);
    let initial_account =
        VmessAccountPayload::decode(initial_account.value.as_slice())
            .expect("decode VMess account");
    assert_eq!(initial_account.id, "3ac9b383-75a1-431c-8184-106c80eb2273");
    assert_eq!(
        initial_account
            .security_settings
            .map(|security| security.r#type),
        Some(3)
    );

    let email = unique_tag("vmess-user");
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VMESS_ACCOUNT.to_string(),
                value: VmessAccountPayload {
                    id: "short-id".to_string(),
                    security_settings: Some(VmessSecurityConfigPayload {
                        r#type: 4,
                    }),
                    tests_enabled: String::new(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("vmess add user should succeed");

    let users_after_add = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: email.clone(),
            },
        ))
        .await
        .expect("vmess get added user failed")
        .into_inner()
        .users;
    assert_eq!(users_after_add.len(), 1);
    let account = users_after_add[0]
        .account
        .as_ref()
        .expect("added VMess user must include account");
    let account = VmessAccountPayload::decode(account.value.as_slice())
        .expect("decode added VMess account");
    assert_eq!(account.id, "bcd643ce-d9c8-50bb-b026-89d256010162");
    assert_eq!(
        account.security_settings.map(|security| security.r#type),
        Some(4)
    );

    let remove_operation =
        proto::xray::app::proxyman::command::RemoveUserOperation {
            email: email.to_ascii_uppercase(),
        };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("vmess remove user should succeed case-insensitively");

    let count_after_remove = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag,
                email: String::new(),
            },
        ))
        .await
        .expect("vmess get users count after remove failed")
        .into_inner();
    assert_eq!(count_after_remove.count, 1);
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn handler_alter_inbound_adds_and_removes_vless_users() {
    let inbound_tag = unique_tag("vless-inbound");
    let bind_location = BindLocation::Address(NetLocation::new(
        Address::Ipv4(Ipv4Addr::LOCALHOST),
        1092,
    ));
    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location,
        protocol: ServerProxyConfig::Vless {
            users: vec![
                VlessUser {
                    user_id: "5df5643d-4e28-4399-bb9e-22014a2d3246".to_string(),
                    user_label: "first-user@example.com".to_string(),
                    user_level: 0,
                    flow: String::new(),
                },
                VlessUser {
                    user_id: "4571894c-7ece-4b27-a734-746330d1a984".to_string(),
                    user_label: "second-user@example.com".to_string(),
                    user_level: 0,
                    flow: "xtls-rprx-vision".to_string(),
                },
            ],
            fallbacks: Vec::new(),
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![inbound], Vec::new());
    let service = HandlerServiceImpl::new(runtime);

    let initial_users = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("vless get users failed")
        .into_inner()
        .users
        .into_iter()
        .map(|user| {
            let account = user.account.as_ref().map(|account| {
                VlessAccountPayload::decode(account.value.as_slice())
                    .expect("decode vless account from initial users")
            });
            (user.email, account)
        })
        .collect::<Vec<_>>();
    assert_eq!(initial_users.len(), 2);
    assert!(
        initial_users
            .iter()
            .any(|(email, _)| email == "first-user@example.com")
    );
    assert!(
        initial_users
            .iter()
            .any(|(email, _)| email == "second-user@example.com")
    );
    assert!(initial_users.iter().any(|(email, account)| {
        email == "first-user@example.com"
            && account
                .as_ref()
                .is_some_and(|account| account.flow.is_empty())
    }));
    assert!(initial_users.iter().any(|(email, account)| {
        email == "second-user@example.com"
            && account
                .as_ref()
                .is_some_and(|account| account.flow == "xtls-rprx-vision")
    }));

    let initial_count = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("vless get users count failed")
        .into_inner();
    assert_eq!(initial_count.count, 2);

    let email = unique_tag("vless-user");
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: "9199ca5b-1850-4ae6-a4fa-fd6384073692".to_string(),
                    flow: String::new(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("vless add user should succeed");

    let users_after_add = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("vless get users after add failed")
        .into_inner()
        .users
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(users_after_add.len(), 3);
    let added_user = users_after_add
        .iter()
        .find(|user| user.email == email)
        .expect("added vless user should be returned");
    let account = added_user
        .account
        .as_ref()
        .expect("returned vless user should include account");
    assert_eq!(account.r#type, TYPE_PROXY_VLESS_ACCOUNT);

    let count_after_add = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("vless get users count after add failed")
        .into_inner();
    assert_eq!(count_after_add.count, 3);

    let remove_operation =
        proto::xray::app::proxyman::command::RemoveUserOperation {
            email: email.clone(),
        };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("vless remove user should succeed");

    let users_after_remove = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("vless get users after remove failed")
        .into_inner()
        .users
        .into_iter()
        .map(|user| user.email)
        .collect::<Vec<_>>();
    assert_eq!(users_after_remove.len(), 2);
    assert!(
        !users_after_remove
            .iter()
            .any(|candidate| candidate == &email)
    );

    let count_after_remove = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag,
                email: String::new(),
            },
        ))
        .await
        .expect("vless get users count after remove failed")
        .into_inner();
    assert_eq!(count_after_remove.count, 2);
}

#[cfg(feature = "vless")]
#[tokio::test]
async fn handler_node_style_flow_on_empty_vless_inbound() {
    let inbound_tag = unique_tag("debug-vless");
    let username = unique_tag("debug-user");
    let user_id = "218b98f5-df92-43f9-8880-3be70912d79c".to_string();
    let inbound_port = free_localhost_port();

    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location: BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            inbound_port,
        )),
        protocol: ServerProxyConfig::Vless {
            users: vec![],
            fallbacks: Vec::new(),
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![inbound.clone()], Vec::new());
    let handles = start_servers(inbound, runtime.clone())
        .await
        .expect("start empty vless inbound");
    runtime.register_inbound_tasks(&inbound_tag, handles);
    let service = HandlerServiceImpl::new(runtime.clone());

    let users_before_add = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("empty vless get users before add failed")
        .into_inner()
        .users;
    assert!(users_before_add.is_empty());

    let count_before_add = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("empty vless get users count before add failed")
        .into_inner();
    assert_eq!(count_before_add.count, 0);

    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: username.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                value: VlessAccountPayload {
                    id: user_id.clone(),
                    flow: String::new(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("node-style add user should succeed");
    tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, inbound_port))
        .await
        .expect("vless listener should remain available after adding a user");

    let users_after_add = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("empty vless get users after add failed")
        .into_inner()
        .users;
    assert_eq!(users_after_add.len(), 1);
    assert_eq!(users_after_add[0].email, username);
    let account_after_add = users_after_add[0]
        .account
        .as_ref()
        .expect("node-style returned user should include account");
    assert_eq!(account_after_add.r#type, TYPE_PROXY_VLESS_ACCOUNT);
    let decoded_account =
        VlessAccountPayload::decode(account_after_add.value.as_slice())
            .expect("decode vless account from node-style response");
    assert_eq!(decoded_account.id, user_id);
    assert_eq!(decoded_account.flow, "");

    let count_after_add = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("empty vless get users count after add failed")
        .into_inner();
    assert_eq!(count_after_add.count, 1);

    let remove_operation =
        proto::xray::app::proxyman::command::RemoveUserOperation {
            email: users_after_add[0].email.clone(),
        };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("node-style remove user should succeed");
    tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, inbound_port))
        .await
        .expect("vless listener should remain available after removing a user");

    let users_after_remove = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("empty vless get users after remove failed")
        .into_inner()
        .users;
    assert!(users_after_remove.is_empty());

    let count_after_remove = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("empty vless get users count after remove failed")
        .into_inner();
    assert_eq!(count_after_remove.count, 0);
    runtime.stop_inbound_tasks(&inbound_tag).await;
}

#[tokio::test]
async fn handler_removes_inbound_and_outbound() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime.clone());

    service
        .remove_inbound(Request::new(
            proto::xray::app::proxyman::command::RemoveInboundRequest {
                tag: fixture.inbound_tag.clone(),
            },
        ))
        .await
        .expect("remove_inbound failed");
    assert!(
        fixture
            .runtime
            .inbound_by_tag(&fixture.inbound_tag)
            .is_none()
    );
    let inbounds = service
        .list_inbounds(Request::new(
            proto::xray::app::proxyman::command::ListInboundsRequest {
                is_only_tags: true,
            },
        ))
        .await
        .expect("list_inbounds after remove failed")
        .into_inner();
    assert!(inbounds.inbounds.is_empty());

    service
        .remove_outbound(Request::new(
            proto::xray::app::proxyman::command::RemoveOutboundRequest {
                tag: fixture.outbound_tag.clone(),
            },
        ))
        .await
        .expect("remove_outbound failed");
    let outbounds = service
        .list_outbounds(Request::new(
            proto::xray::app::proxyman::command::ListOutboundsRequest {},
        ))
        .await
        .expect("list_outbounds after remove failed")
        .into_inner();
    assert!(outbounds.outbounds.is_empty());
}

#[tokio::test]
async fn handler_alter_inbound_rejects_socks_user_manager_operations() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime);
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: unique_tag("email"),
            account: None,
        }),
    };

    let err = service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: fixture.inbound_tag,
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect_err("SOCKS should not expose Xray UserManager mutations");
    assert_eq!(err.code(), Code::Unknown);
    assert_eq!(err.message(), ERR_PROXY_NOT_USER_MANAGER);
}

#[cfg(feature = "trojan")]
#[test]
fn trojan_user_reads_hide_empty_email_and_preserve_level() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let protocol = ServerProxyConfig::Trojan {
        users: vec![
            TrojanUser {
                password: "anonymous".into(),
                email: None,
                user_level: 11,
            },
            TrojanUser {
                password: "visible".into(),
                email: Some("Visible@Example.com".into()),
                user_level: 7,
            },
        ],
        fallbacks: Vec::new(),
    };

    let users = service
        .get_user_manager_users(&protocol)
        .expect("Trojan exposes UserManager reads");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "Visible@Example.com");
    assert_eq!(users[0].level, 7);

    let identities = service
        .get_user_manager_identities(&protocol)
        .expect("Trojan exposes UserManager count");
    assert_eq!(identities, vec!["Visible@Example.com"]);
}

#[cfg(feature = "trojan")]
#[tokio::test]
async fn handler_alter_inbound_adds_and_removes_trojan_users() {
    let inbound_tag = unique_tag("trojan-inbound");
    let bind_location = BindLocation::Address(NetLocation::new(
        Address::Ipv4(Ipv4Addr::LOCALHOST),
        1091,
    ));
    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location,
        protocol: ServerProxyConfig::Trojan {
            users: vec![TrojanUser {
                password: "initial-password".to_string(),
                email: Some("initial-user".to_string()),
                user_level: 0,
            }],
            fallbacks: Vec::new(),
        },
        transport: Transport::Tcp,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![inbound], Vec::new());
    let service = HandlerServiceImpl::new(runtime);

    let email = unique_tag("trojan-user");
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                value: TrojanAccountPayload {
                    password: "added-password".to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("trojan add user should succeed");

    let users_after_add = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("trojan get users after add failed")
        .into_inner()
        .users
        .into_iter()
        .map(|user| user.email)
        .collect::<Vec<_>>();
    assert!(users_after_add.iter().any(|candidate| candidate == &email));

    let count_after_add = service
        .get_inbound_users_count(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: String::new(),
            },
        ))
        .await
        .expect("trojan get users count after add failed")
        .into_inner();
    assert_eq!(count_after_add.count, 2);

    let remove_operation =
        proto::xray::app::proxyman::command::RemoveUserOperation {
            email: email.clone(),
        };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("trojan remove user should succeed");

    let users_after_remove = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag,
                email: String::new(),
            },
        ))
        .await
        .expect("trojan get users after remove failed")
        .into_inner()
        .users
        .into_iter()
        .map(|user| user.email)
        .collect::<Vec<_>>();
    assert!(
        !users_after_remove
            .iter()
            .any(|candidate| candidate == &email)
    );
}

#[cfg(feature = "shadowsocks")]
#[test]
fn shadowsocks_user_mutations_match_xray_legacy_and_2022_semantics() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let legacy_user = |email: &str, level: u32, cipher_type: i32, password: &str| {
        proto::xray::common::protocol::User {
            level,
            email: email.to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_SHADOWSOCKS_ACCOUNT.to_string(),
                value: ShadowsocksAccountPayload {
                    password: password.to_string(),
                    cipher_type,
                    iv_check: false,
                }
                .encode_to_vec(),
            }),
        }
    };
    let mut legacy = ServerProxyConfig::Shadowsocks {
        users: vec![ShadowsocksUser {
            method: "aes-128-gcm".to_string(),
            password: "first-pass".to_string(),
            email: "shared@example.com".to_string(),
            user_level: 1,
        }],
        identity: None,
    };
    service
        .apply_add_user_to_protocol(
            &mut legacy,
            &legacy_user("shared@example.com", 7, 6, "second-pass"),
        )
        .expect("legacy Xray validator appends duplicate-email AEAD users");
    let ServerProxyConfig::Shadowsocks { users, .. } = &legacy else {
        unreachable!()
    };
    assert_eq!(users[1].method, "aes-256-gcm");
    let exposed = service.get_user_manager_users(&legacy).unwrap();
    assert_eq!(exposed[1].level, 7);
    service
        .apply_remove_user_from_protocol(&mut legacy, "SHARED@EXAMPLE.COM")
        .expect("legacy remove is case-insensitive");
    let key = "AAECAwQFBgcICQoLDA0ODw==";
    let mut modern = ServerProxyConfig::Shadowsocks {
        users: vec![ShadowsocksUser {
            method: "2022-blake3-aes-128-gcm".to_string(),
            password: key.to_string(),
            email: "Case@example.com".to_string(),
            user_level: 2,
        }],
        identity: Some(ShadowsocksServerIdentity {
            method: "2022-blake3-aes-128-gcm".to_string(),
            password: key.to_string(),
        }),
    };
    let modern_user = |email: &str| proto::xray::common::protocol::User {
        level: 3,
        email: email.to_string(),
        account: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_SHADOWSOCKS_2022_ACCOUNT.to_string(),
            value: Shadowsocks2022AccountPayload {
                key: key.to_string(),
            }
            .encode_to_vec(),
        }),
    };
    let error = service
        .apply_add_user_to_protocol(&mut modern, &modern_user("Case@example.com"))
        .expect_err("2022 rejects exact non-empty duplicate email");
    assert_eq!(error.code(), Code::AlreadyExists);
    service
        .apply_add_user_to_protocol(&mut modern, &modern_user("case@example.com"))
        .expect("2022 duplicate check is case-sensitive");
    service
        .apply_add_user_to_protocol(&mut modern, &modern_user(""))
        .expect("2022 allows empty email");
    service
        .apply_add_user_to_protocol(&mut modern, &modern_user(""))
        .expect("2022 allows repeated empty email");
}

#[cfg(feature = "shadowsocks")]
#[tokio::test]
async fn handler_alter_shadowsocks_users_does_not_restart_listener() {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind occupied Shadowsocks TCP port");
    let port = occupied.local_addr().unwrap().port();
    let inbound_tag = unique_tag("shadowsocks-no-restart-inbound");
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Shadowsocks {
                users: vec![ShadowsocksUser {
                    method: "aes-128-gcm".to_string(),
                    password: "initial-pass".to_string(),
                    email: "initial@example.com".to_string(),
                    user_level: 1,
                }],
                identity: None,
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    let abort_handle = placeholder_task.abort_handle();
    runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(runtime.clone());
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 9,
            email: "dynamic@example.com".to_string(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_SHADOWSOCKS_ACCOUNT.to_string(),
                value: ShadowsocksAccountPayload {
                    password: "dynamic-pass".to_string(),
                    cipher_type: 6,
                    iv_check: false,
                }
                .encode_to_vec(),
            }),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("Shadowsocks user update must not rebind occupied TCP port");
    assert!(!abort_handle.is_finished());
    assert!(runtime.stop_inbound_tasks(&inbound_tag).await);
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria_user_reads_include_empty_email_and_select_one_duplicate() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let config: Hysteria2ServerConfig = serde_json::from_value(serde_json::json!({
        "clients": [
            {
                "password": "transport-fallback",
                "email": null,
                "xray_transport_auth_fallback": true
            },
            {"password": "empty-email-auth", "email": null, "level": 7},
            {"password": "auth-a", "email": "shared@example.com", "level": 3},
            {"password": "auth-b", "email": "shared@example.com", "level": 4}
        ],
        "xrayCompat": true
    }))
    .expect("valid Hysteria2 user-manager config");
    let protocol = ServerProxyConfig::Hysteria2 { config };

    let users = service
        .get_user_manager_users(&protocol)
        .expect("Hysteria2 should expose a user manager");
    assert_eq!(users.len(), 3, "transport fallback must stay hidden");
    assert!(
        users
            .iter()
            .any(|user| user.email.is_empty() && user.level == 7),
        "Xray GetUsers includes empty-email validators and preserves level"
    );
    assert_eq!(
        users
            .iter()
            .filter(|user| user.email == "shared@example.com")
            .count(),
        2,
        "duplicate emails remain distinct auth-keyed users"
    );

    let identities = service
        .get_user_manager_identities(&protocol)
        .expect("Hysteria2 should expose a user count");
    assert_eq!(identities.len(), 3);
    assert!(identities.iter().any(String::is_empty));

    let selected = HandlerServiceImpl::select_user_manager_users(
        users,
        "shared@example.com",
        false,
    );
    assert_eq!(
        selected.len(),
        1,
        "Xray email-specific GetInboundUsers returns one GetUser result"
    );
    assert!(matches!(selected[0].level, 3 | 4));

    let dynamic = service
        .parse_hysteria_client(&proto::xray::common::protocol::User {
            level: 9,
            email: String::new(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                value: HysteriaAccountPayload {
                    auth: String::new(),
                }
                .encode_to_vec(),
            }),
        })
        .expect("Xray Hysteria AddUser permits empty email/auth fields");
    assert_eq!(dynamic.password, "");
    assert_eq!(dynamic.email, None);
    assert_eq!(dynamic.level, 9);
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria_user_mutations_match_xray_auth_key_semantics() {
    let service = HandlerServiceImpl::new(RuntimeState::new(Vec::new(), Vec::new()));
    let mut protocol = ServerProxyConfig::Hysteria2 {
        config: Hysteria2ServerConfig {
            clients: vec![Hysteria2Client {
                password: "transport-fallback".to_string(),
                email: None,
                level: 0,
                xray_uuid_route: false,
                xray_transport_auth_fallback: true,
            }],
            bandwidth: Hysteria2BandwidthConfig::default(),
            ignore_client_bandwidth: false,
            udp_enabled: true,
            xray_compat: true,
            xray_masquerade_string: None,
            xray_masquerade_file: None,
            xray_masquerade_proxy: None,
            xray_congestion: None,
            xray_bbr_profile: None,
            xray_brutal_up: None,
            xray_brutal_down: None,
            xray_max_idle_timeout_secs: None,
            xray_keep_alive_period_secs: None,
            xray_udp_idle_timeout_secs: None,
            xray_max_incoming_streams: None,
            xray_init_stream_receive_window: None,
            xray_max_stream_receive_window: None,
            xray_init_connection_receive_window: None,
            xray_max_connection_receive_window: None,
            xray_disable_path_mtu_discovery: None,
            udp_finalmask: None,
        },
    };
    let user = |email: &str, auth: &str| proto::xray::common::protocol::User {
        level: 0,
        email: email.to_string(),
        account: Some(proto::xray::common::serial::TypedMessage {
            r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
            value: HysteriaAccountPayload {
                auth: auth.to_string(),
            }
            .encode_to_vec(),
        }),
    };

    service
        .apply_add_user_to_protocol(
            &mut protocol,
            &user("shared@example.com", "auth-a"),
        )
        .expect("add first duplicate-email user");
    service
        .apply_add_user_to_protocol(
            &mut protocol,
            &user("shared@example.com", "auth-b"),
        )
        .expect("add second duplicate-email user");

    let ServerProxyConfig::Hysteria2 { config } = &protocol else {
        unreachable!("test protocol is hysteria2");
    };
    assert_eq!(
        config
            .clients
            .iter()
            .filter(|client| client.email.as_deref() == Some("shared@example.com"))
            .count(),
        2,
        "Xray allows different auth keys to share one email"
    );
    assert!(
        config
            .clients
            .iter()
            .any(|client| client.xray_transport_auth_fallback),
        "dynamic user updates must preserve transport fallback"
    );

    assert!(
        service
            .apply_remove_user_from_protocol(&mut protocol, "shared@example.com")
            .expect("remove one duplicate-email user")
    );
    let ServerProxyConfig::Hysteria2 { config } = &protocol else {
        unreachable!("test protocol is hysteria2");
    };
    assert_eq!(
        config
            .clients
            .iter()
            .filter(|client| client.email.as_deref() == Some("shared@example.com"))
            .count(),
        1,
        "Xray DelByEmail removes one matching auth entry, not all"
    );

    service
        .apply_add_user_to_protocol(
            &mut protocol,
            &user("replacement@example.com", "auth-b"),
        )
        .expect("replace existing auth key");
    let ServerProxyConfig::Hysteria2 { config } = &protocol else {
        unreachable!("test protocol is hysteria2");
    };
    assert_eq!(
        config
            .clients
            .iter()
            .filter(|client| !client.xray_transport_auth_fallback)
            .count(),
        1,
        "re-adding the same auth must replace its prior validator entry"
    );
    let auth_b = config
        .clients
        .iter()
        .find(|client| {
            client.password == "auth-b" && !client.xray_transport_auth_fallback
        })
        .expect("replacement auth should remain");
    assert_eq!(auth_b.email.as_deref(), Some("replacement@example.com"));
    assert!(
        service
            .apply_remove_user_from_protocol(&mut protocol, "missing@example.com")
            .expect("missing Hysteria user removal should remain idempotent"),
        "Xray treats a Hysteria remove miss as a handled no-op"
    );
}

#[cfg(feature = "hysteria")]
#[tokio::test]
async fn handler_alter_hysteria_users_does_not_restart_listener() {
    let occupied = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind occupied Hysteria UDP port");
    let port = occupied.local_addr().unwrap().port();
    let inbound_tag = unique_tag("hysteria-no-restart-inbound");
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: inbound_tag.clone(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                port,
            )),
            protocol: ServerProxyConfig::Hysteria2 {
                config: Hysteria2ServerConfig {
                    clients: Vec::new(),
                    bandwidth: Hysteria2BandwidthConfig::default(),
                    ignore_client_bandwidth: false,
                    udp_enabled: true,
                    xray_compat: true,
                    xray_masquerade_string: None,
                    xray_masquerade_file: None,
                    xray_masquerade_proxy: None,
                    xray_congestion: None,
                    xray_bbr_profile: None,
                    xray_brutal_up: None,
                    xray_brutal_down: None,
                    xray_max_idle_timeout_secs: None,
                    xray_keep_alive_period_secs: None,
                    xray_udp_idle_timeout_secs: None,
                    xray_max_incoming_streams: None,
                    xray_init_stream_receive_window: None,
                    xray_max_stream_receive_window: None,
                    xray_init_connection_receive_window: None,
                    xray_max_connection_receive_window: None,
                    xray_disable_path_mtu_discovery: None,
                    udp_finalmask: None,
                },
            },
            transport: Transport::Quic,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    let placeholder_task = tokio::spawn(std::future::pending::<()>());
    let abort_handle = placeholder_task.abort_handle();
    runtime.register_inbound_tasks(&inbound_tag, vec![placeholder_task]);
    let service = HandlerServiceImpl::new(runtime.clone());
    let email = unique_tag("hysteria-dynamic-user");
    let auth = "00112233-4455-6677-8899-aabbccddeeff";
    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 9,
            email: email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                value: HysteriaAccountPayload {
                    auth: auth.to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };

    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("Hysteria user update must not rebind the occupied UDP port");

    assert!(!abort_handle.is_finished());
    let updated = runtime.inbound_by_tag(&inbound_tag).unwrap();
    let ServerProxyConfig::Hysteria2 { config } = updated.protocol else {
        panic!("expected hysteria2 inbound");
    };
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(config.clients[0].password, auth);
    assert_eq!(config.clients[0].level, 9);
    assert!(runtime.stop_inbound_tasks(&inbound_tag).await);
}

#[cfg(feature = "hysteria")]
#[tokio::test]
async fn handler_alter_inbound_adds_and_removes_hysteria_users() {
    let inbound_tag = unique_tag("hysteria-inbound");
    let inbound = ServerConfig {
        tag: inbound_tag.clone(),
        bind_location: BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1093,
        )),
        protocol: ServerProxyConfig::Hysteria2 {
            config: Hysteria2ServerConfig {
                clients: vec![Hysteria2Client {
                    password: "initial-auth".to_string(),
                    email: Some("initial-user".to_string()),
                    level: 0,
                    xray_uuid_route: true,
                    xray_transport_auth_fallback: false,
                }],
                bandwidth: Hysteria2BandwidthConfig::default(),
                ignore_client_bandwidth: false,
                udp_enabled: true,
                xray_compat: false,
                xray_masquerade_string: None,
                xray_masquerade_file: None,
                xray_masquerade_proxy: None,
                xray_congestion: None,
                xray_bbr_profile: None,
                xray_brutal_up: None,
                xray_brutal_down: None,
                xray_max_idle_timeout_secs: None,
                xray_keep_alive_period_secs: None,
                xray_udp_idle_timeout_secs: None,
                xray_max_incoming_streams: None,
                xray_init_stream_receive_window: None,
                xray_max_stream_receive_window: None,
                xray_init_connection_receive_window: None,
                xray_max_connection_receive_window: None,
                xray_disable_path_mtu_discovery: None,
                udp_finalmask: None,
            },
        },
        transport: Transport::Quic,
        quic_settings: None,
        sniffing: None,
        tcp_socket_policy: None,
    };
    let runtime = RuntimeState::new(vec![inbound], Vec::new());
    let service = HandlerServiceImpl::new(runtime.clone());
    let email = unique_tag("hysteria-user");
    let auth = " added-auth ";

    let add_operation = proto::xray::app::proxyman::command::AddUserOperation {
        user: Some(proto::xray::common::protocol::User {
            level: 0,
            email: email.clone(),
            account: Some(proto::xray::common::serial::TypedMessage {
                r#type: TYPE_PROXY_HYSTERIA_ACCOUNT.to_string(),
                value: HysteriaAccountPayload {
                    auth: auth.to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_ADD_USER_OPERATION.to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("hysteria add user should succeed");

    let users_after_add = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag.clone(),
                email: email.clone(),
            },
        ))
        .await
        .expect("hysteria get users after add failed")
        .into_inner()
        .users;
    assert_eq!(users_after_add.len(), 1);
    let account = users_after_add[0]
        .account
        .as_ref()
        .expect("hysteria user should include an account");
    assert_eq!(account.r#type, TYPE_PROXY_HYSTERIA_ACCOUNT);
    let account = HysteriaAccountPayload::decode(account.value.as_slice())
        .expect("decode hysteria account");
    assert_eq!(account.auth, auth);
    let updated = runtime
        .inbound_by_tag(&inbound_tag)
        .expect("updated hysteria inbound should remain registered");
    let ServerProxyConfig::Hysteria2 { config } = updated.protocol else {
        panic!("expected hysteria2 inbound");
    };
    let added_client = config
        .clients
        .iter()
        .find(|client| client.email.as_deref() == Some(email.as_str()))
        .expect("added hysteria user should be in runtime config");
    assert!(!added_client.xray_transport_auth_fallback);

    let remove_operation =
        proto::xray::app::proxyman::command::RemoveUserOperation {
            email: email.clone(),
        };
    service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: inbound_tag.clone(),
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_REMOVE_USER_OPERATION.to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            },
        ))
        .await
        .expect("hysteria remove user should succeed");

    let users_after_remove = service
        .get_inbound_users(Request::new(
            proto::xray::app::proxyman::command::GetInboundUserRequest {
                tag: inbound_tag,
                email,
            },
        ))
        .await
        .expect("hysteria get users after remove failed")
        .into_inner()
        .users;
    assert!(users_after_remove.is_empty());
}

#[tokio::test]
async fn handler_alter_inbound_rejects_unknown_operation_type() {
    let fixture = build_fixture();
    let service = HandlerServiceImpl::new(fixture.runtime);

    let err = service
        .alter_inbound(Request::new(
            proto::xray::app::proxyman::command::AlterInboundRequest {
                tag: fixture.inbound_tag,
                operation: Some(proto::xray::common::serial::TypedMessage {
                    r#type: "xray.app.proxyman.command.UnknownOperation".to_string(),
                    value: vec![1, 2, 3],
                }),
            },
        ))
        .await
        .expect_err("expected invalid argument for unknown operation");
    assert_eq!(err.code(), Code::InvalidArgument);
}
