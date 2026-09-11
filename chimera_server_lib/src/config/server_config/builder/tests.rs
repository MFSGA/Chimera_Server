use super::*;

#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;

fn inbound_for_protocol(protocol: &str) -> InboudItem {
    serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": protocol,
        "tag": format!("{protocol}-planned")
    }))
    .expect("valid inbound item")
}

#[test]
fn tcp_sockopt_preserves_xray_congestion_and_validates_brutal_v2() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-brutal",
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "sockopt": {
                "tcpCongestion": "brutal",
                "tcpBrutalRate": "150mbps",
                "tcpBrutalCwndGain": 20
            }
        }
    }))
    .expect("valid TCP Brutal inbound");
    let config = ServerConfig::try_from(inbound)
        .expect("TCP Brutal socket policy should build");
    let policy = config
        .tcp_socket_policy
        .expect("TCP socket policy should be retained");
    assert_eq!(policy.congestion, "brutal");
    let brutal = policy.brutal.expect("Brutal settings should be retained");
    assert_eq!(brutal.rate_bytes_per_sec, 18_750_000);
    assert_eq!(brutal.cwnd_gain, 20);

    let bbr: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10001,
        "protocol": "socks",
        "tag": "socks-bbr",
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "sockopt": { "tcpCongestion": "bbr" }
        }
    }))
    .expect("valid BBR inbound");
    let bbr = ServerConfig::try_from(bbr).expect("Xray tcpCongestion should build");
    let policy = bbr
        .tcp_socket_policy
        .expect("BBR policy should be retained");
    assert_eq!(policy.congestion, "bbr");
    assert!(policy.brutal.is_none());
}

#[test]
fn tcp_sockopt_preserves_xray_listener_and_connection_options() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "::1",
        "port": 10002,
        "protocol": "socks",
        "tag": "socks-sockopt",
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "sockopt": {
                "tcpFastOpen": true,
                "tcpKeepAliveIdle": 11,
                "tcpKeepAliveInterval": 7,
                "tcpUserTimeout": 12345,
                "tcpWindowClamp": 32768,
                "tcpMaxSeg": 1200,
                "tcpMptcp": true,
                "v6only": true,
                "interface": "lo",
                "mark": 17,
                "tproxy": "redirect",
                "customSockopt": [{
                    "system": "linux",
                    "network": "tcp",
                    "level": "1",
                    "opt": "2",
                    "value": "1",
                    "type": "int"
                }]
            }
        }
    }))
    .expect("Xray TCP socket options should deserialize");
    let config = ServerConfig::try_from(inbound)
        .expect("Xray TCP socket options should build");
    let policy = config
        .tcp_socket_policy
        .expect("TCP socket policy should be retained");
    assert_eq!(policy.fast_open, Some(256));
    assert_eq!(policy.keep_alive_idle, 11);
    assert_eq!(policy.keep_alive_interval, 7);
    assert_eq!(policy.user_timeout_ms, Some(12345));
    assert_eq!(policy.window_clamp, Some(32768));
    assert_eq!(policy.max_seg, Some(1200));
    assert!(policy.multipath);
    assert!(policy.ipv6_only);
    assert_eq!(policy.bind_interface.as_deref(), Some("lo"));
    assert_eq!(policy.mark, Some(17));
    assert!(policy.transparent);
    assert_eq!(policy.custom_sockopt.len(), 1);
}

#[test]
fn receive_original_destination_rejects_tcp_transport() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10003,
        "protocol": "socks",
        "tag": "socks-origdst-invalid",
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "sockopt": {"receiveOriginalDestAddress": true}
        }
    }))
    .expect("receiveOriginalDestAddress should deserialize before validation");
    let error = ServerConfig::try_from(inbound)
        .expect_err("receiveOriginalDestAddress must not become a TCP no-op");
    assert!(error.to_string().contains("receiveOriginalDestAddress"));
}

#[test]
fn tcp_brutal_sockopt_rejects_missing_or_mismatched_rate() {
    for sockopt in [
        serde_json::json!({ "tcpCongestion": "brutal" }),
        serde_json::json!({
            "tcpCongestion": "bbr",
            "tcpBrutalRate": "150mbps"
        }),
        serde_json::json!({ "tcpBrutalRate": "150mbps" }),
    ] {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "socks",
            "tag": "socks-invalid-brutal",
            "settings": {},
            "streamSettings": {
                "network": "tcp",
                "sockopt": sockopt
            }
        }))
        .expect("socket policy should deserialize before validation");
        let error = ServerConfig::try_from(inbound)
            .expect_err("invalid TCP Brutal socket policy must be rejected");
        assert!(error.to_string().contains("tcpBrutal"), "{error}");
    }
}

#[cfg(feature = "ws")]
#[test]
fn websocket_network_uses_default_settings_when_omitted_like_xray() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-ws-defaults",
        "settings": {},
        "streamSettings": {"network": "ws", "security": "none"}
    }))
    .expect("valid WebSocket inbound without wsSettings");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray creates default WebSocket settings when omitted");
    let ServerProxyConfig::Websocket { targets } = config.protocol else {
        panic!("expected WebSocket transport wrapper");
    };
    let OneOrSome::One(target) = *targets else {
        panic!("expected one WebSocket target");
    };
    assert_eq!(target.matching_path.as_deref(), Some("/"));
    assert!(matches!(target.protocol, ServerProxyConfig::Socks { .. }));
}

#[cfg(all(feature = "grpc_transport", feature = "ws"))]
#[test]
fn selected_grpc_network_ignores_unrelated_websocket_settings_like_xray() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-grpc-ignore-ws",
        "settings": {},
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "wsSettings": {"path": "/must-not-run"},
            "grpcSettings": {"serviceName": "selected"}
        }
    }))
    .expect("valid gRPC inbound with unrelated wsSettings");

    let config = ServerConfig::try_from(inbound)
        .expect("only the selected Xray transport should be compiled");
    let ServerProxyConfig::Grpc(config) = config.protocol else {
        panic!("expected gRPC transport wrapper");
    };
    assert_eq!(config.service_name, "selected");
    assert!(matches!(*config.inner, ServerProxyConfig::Socks { .. }));
}

#[cfg(feature = "ws")]
#[test]
fn tcp_network_ignores_unrelated_websocket_settings_like_xray() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-tcp-ignore-ws",
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "security": "none",
            "wsSettings": {"path": "/must-not-run"}
        }
    }))
    .expect("valid raw TCP inbound with unrelated wsSettings");

    let config = ServerConfig::try_from(inbound)
        .expect("unselected WebSocket settings must not affect raw TCP");
    assert!(matches!(config.protocol, ServerProxyConfig::Socks { .. }));
}

#[cfg(feature = "grpc_transport")]
#[test]
fn grpc_network_uses_empty_xray_defaults_when_settings_are_omitted() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-grpc-defaults",
        "settings": {},
        "streamSettings": {"network": "grpc", "security": "none"}
    }))
    .expect("valid gRPC inbound without grpcSettings");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray creates default gRPC settings when omitted");
    let ServerProxyConfig::Grpc(config) = config.protocol else {
        panic!("expected gRPC transport wrapper");
    };
    assert!(config.service_name.is_empty());
    assert_eq!(config.idle_timeout, 0);
    assert_eq!(config.health_check_timeout, 0);
    assert!(matches!(*config.inner, ServerProxyConfig::Socks { .. }));
}

#[cfg(feature = "httpupgrade")]
#[test]
fn httpupgrade_network_uses_default_settings_when_omitted_like_xray() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-httpupgrade-defaults",
        "settings": {},
        "streamSettings": {"network": "httpupgrade", "security": "none"}
    }))
    .expect("valid HTTPUpgrade inbound without settings");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray creates default HTTPUpgrade settings when omitted");
    let ServerProxyConfig::HttpUpgrade(config) = config.protocol else {
        panic!("expected HTTPUpgrade transport wrapper");
    };
    assert!(config.host.is_none());
    assert_eq!(config.path, "/");
    assert!(matches!(*config.inner, ServerProxyConfig::Socks { .. }));
}

#[cfg(feature = "vless")]
#[test]
fn xhttp_alias_uses_default_settings_when_omitted_like_xray() {
    for network in ["xhttp", "splithttp"] {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "vless",
            "tag": format!("vless-{network}-defaults"),
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {"network": network, "security": "none"}
        }))
        .expect("valid XHTTP inbound without xhttpSettings");

        let config = ServerConfig::try_from(inbound)
            .expect("Xray creates default XHTTP settings when omitted");
        let ServerProxyConfig::Xhttp { config, inner } = config.protocol else {
            panic!("expected XHTTP transport wrapper for {network}");
        };
        assert_eq!(config.mode, crate::config::server_config::XhttpMode::Auto);
        assert_eq!(config.path, "/");
        assert!(matches!(*inner, ServerProxyConfig::Vless { .. }));
    }
}

#[cfg(feature = "grpc_transport")]
#[test]
fn grpc_inbound_preserves_xray_custom_service_name() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-grpc-custom",
        "settings": {},
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {
                "serviceName": "/my/sample path/tun service|multi service"
            }
        }
    }))
    .expect("valid gRPC custom service inbound");
    let config =
        ServerConfig::try_from(inbound).expect("custom gRPC service should build");
    match config.protocol {
        ServerProxyConfig::Grpc(config) => {
            assert_eq!(
                config.service_name,
                "/my/sample path/tun service|multi service"
            );
        }
        other => panic!("expected gRPC protocol, got {other:?}"),
    }
}

#[cfg(feature = "grpc_transport")]
#[test]
fn grpc_inbound_accepts_empty_service_name_like_xray_v26_2_6() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-grpc-empty",
        "settings": {},
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {
                "serviceName": ""
            }
        }
    }))
    .expect("valid empty gRPC service inbound");
    let config = ServerConfig::try_from(inbound)
        .expect("Xray accepts an explicitly empty gRPC serviceName");
    match config.protocol {
        ServerProxyConfig::Grpc(config) => {
            assert!(config.service_name.is_empty())
        }
        other => panic!("expected gRPC protocol, got {other:?}"),
    }
}

#[cfg(feature = "grpc_transport")]
#[test]
fn grpc_inbound_preserves_multi_mode() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "socks",
        "tag": "socks-grpc-multi",
        "settings": {},
        "streamSettings": {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {
                "serviceName": "chimera-multi",
                "multiMode": true,
                "idleTimeout": 7,
                "healthCheckTimeout": 3
            },
            "sockopt": {
                "trustedXForwardedFor": ["X-Trusted-CDN"]
            }
        }
    }))
    .expect("valid gRPC multiMode inbound");
    let config =
        ServerConfig::try_from(inbound).expect("gRPC multiMode should build");
    match config.protocol {
        ServerProxyConfig::Grpc(config) => {
            assert_eq!(config.service_name, "chimera-multi");
            assert!(config.multi_mode);
            assert_eq!(config.idle_timeout, 7);
            assert_eq!(config.health_check_timeout, 3);
            assert_eq!(
                config.trusted_x_forwarded_for,
                vec!["X-Trusted-CDN".to_string()]
            );
            assert!(matches!(*config.inner, ServerProxyConfig::Socks { .. }));
        }
        other => panic!("expected gRPC protocol, got {other:?}"),
    }
}

#[cfg(feature = "hysteria")]
fn hysteria2_inbound_with_finalmask_settings(
    final_mask: serde_json::Value,
) -> InboudItem {
    serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "hysteria2",
        "tag": "hysteria2-finalmask",
        "settings": {
            "clients": [{ "auth": "secret" }]
        },
        "streamSettings": {
            "network": "hysteria2",
            "security": "tls",
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "cert.pem",
                    "keyFile": "key.pem"
                }]
            },
            "finalmask": final_mask
        }
    }))
    .expect("valid hysteria2 inbound")
}

#[cfg(feature = "hysteria")]
fn hysteria2_inbound_with_finalmask_quic_params(
    quic_params: serde_json::Value,
) -> InboudItem {
    hysteria2_inbound_with_finalmask_settings(serde_json::json!({
        "quicParams": quic_params
    }))
}

#[cfg(feature = "hysteria")]
fn hysteria2_inbound_with_finalmask(
    max_idle_timeout: i64,
    max_incoming_streams: i64,
) -> InboudItem {
    hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
        "maxIdleTimeout": max_idle_timeout,
        "maxIncomingStreams": max_incoming_streams
    }))
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_accepts_xray_transport_auth_without_users() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "hysteria2",
        "tag": "hysteria2-transport-auth",
        "settings": {
            "version": 2
        },
        "streamSettings": {
            "network": "hysteria2",
            "security": "tls",
            "tlsSettings": {
                "certificates": [{
                    "certificateFile": "cert.pem",
                    "keyFile": "key.pem"
                }]
            },
            "hysteriaSettings": {
                "version": 2,
                "auth": "transport-auth-token"
            }
        }
    }))
    .expect("valid Xray hysteria2 transport auth inbound");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray transport-level auth should satisfy Hysteria2 authentication");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            assert_eq!(config.clients.len(), 1);
            assert_eq!(config.clients[0].password, "transport-auth-token");
            assert_eq!(config.clients[0].email, None);
            assert!(config.xray_compat);
        }
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_rejects_unsupported_active_transport_features() {
    for udp_hop in [
        serde_json::json!({"ports": 443}),
        serde_json::json!({"ports": "443,8443"}),
        serde_json::json!({"interval": 5}),
        serde_json::json!({"interval": "5-10"}),
    ] {
        let err =
            ServerConfig::try_from(hysteria2_inbound_with_finalmask_quic_params(
                serde_json::json!({"udpHop": udp_hop}),
            ))
            .expect_err("configured Xray UDP hop must fail explicitly");
        assert!(err.to_string().contains("udpHop"), "{err}");
    }

    for inert_udp_hop in [
        serde_json::json!({}),
        serde_json::json!({"ports": 0, "interval": 0}),
        serde_json::json!({"ports": "", "interval": "0-0"}),
    ] {
        ServerConfig::try_from(hysteria2_inbound_with_finalmask_quic_params(
            serde_json::json!({"udpHop": inert_udp_hop}),
        ))
        .expect("empty/inert Xray UDP hop should remain compatible");
    }

    let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask_settings(
        serde_json::json!({"tcp": [{"type": "unsupported-mask"}]}),
    ))
    .expect_err("configured TCP finalmask chain must fail explicitly");
    assert!(err.to_string().contains("finalmask.tcp"), "{err}");

    let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask_settings(
        serde_json::json!({"udp": [{"type": "unsupported-mask"}]}),
    ))
    .expect_err("unknown UDP finalmask type must fail explicitly");
    assert!(err.to_string().contains("not implemented"), "{err}");
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_accepts_salamander_and_gecko_udp_masks() {
    use crate::config::server_config::Hysteria2UdpFinalMask;

    let config = ServerConfig::try_from(hysteria2_inbound_with_finalmask_settings(
        serde_json::json!({
            "udp": [{
                "type": "salamander",
                "settings": {"password": "secret"}
            }]
        }),
    ))
    .expect("single Xray Salamander UDP mask should build");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => assert!(matches!(
            config.udp_finalmask,
            Some(Hysteria2UdpFinalMask::Salamander { ref password })
                if password == "secret"
        )),
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }

    let config = ServerConfig::try_from(hysteria2_inbound_with_finalmask_settings(
        serde_json::json!({
            "udp": [{
                "type": "salamander",
                "settings": {
                    "password": "secret",
                    "packetSize": "600-1200"
                }
            }]
        }),
    ))
    .expect("Xray packetSize enables Gecko framing over Salamander");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => assert!(matches!(
            config.udp_finalmask,
            Some(Hysteria2UdpFinalMask::Gecko {
                ref password,
                min_packet_size: 600,
                max_packet_size: 1200,
            }) if password == "secret"
        )),
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_max_idle_timeout_matches_xray_default() {
    let config = ServerConfig::try_from(hysteria2_inbound_with_finalmask(0, 0))
        .expect("Xray zero maxIdleTimeout should use its default");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            assert_eq!(config.xray_max_idle_timeout_secs, Some(30));
            assert_eq!(config.xray_max_incoming_streams, Some(1024));
            assert_eq!(config.xray_disable_path_mtu_discovery, Some(false));
        }
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_rejects_out_of_range_max_idle_timeout() {
    let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask(3, 0))
        .expect_err("Xray rejects maxIdleTimeout below four seconds");
    assert!(err.to_string().contains("maxIdleTimeout"));
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_keep_alive_period_matches_xray_bounds() {
    for keep_alive_period in [0_u64, 2, 60] {
        let config =
            ServerConfig::try_from(hysteria2_inbound_with_finalmask_quic_params(
                serde_json::json!({ "keepAlivePeriod": keep_alive_period }),
            ))
            .expect("Xray accepts zero or bounded keepAlivePeriod");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(
                    config.xray_keep_alive_period_secs,
                    Some(keep_alive_period)
                );
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }
    }

    for keep_alive_period in [1, 61] {
        let err =
            ServerConfig::try_from(hysteria2_inbound_with_finalmask_quic_params(
                serde_json::json!({ "keepAlivePeriod": keep_alive_period }),
            ))
            .expect_err("Xray rejects out-of-range keepAlivePeriod");
        assert!(err.to_string().contains("keepAlivePeriod"));
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_max_incoming_streams_matches_xray_bounds() {
    let config =
        ServerConfig::try_from(hysteria2_inbound_with_finalmask(30, 1_i64 << 61))
            .expect(
                "large Xray maxIncomingStreams should clamp to QUIC stream limit",
            );
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            assert_eq!(config.xray_max_incoming_streams, Some(1_u64 << 60));
        }
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }

    let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask(30, 7))
        .expect_err("Xray rejects maxIncomingStreams below eight");
    assert!(err.to_string().contains("maxIncomingStreams"));
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_preserves_xray_path_mtu_discovery_flag() {
    let config = ServerConfig::try_from(
        hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
            "disablePathMTUDiscovery": true
        })),
    )
    .expect("valid Xray path MTU discovery setting should build");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            assert_eq!(config.xray_disable_path_mtu_discovery, Some(true));
        }
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_receive_windows_match_xray_bounds() {
    let config = ServerConfig::try_from(
        hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
            "initStreamReceiveWindow": 32768,
            "maxStreamReceiveWindow": 65536,
            "initConnectionReceiveWindow": 131072,
            "maxConnectionReceiveWindow": 262144
        })),
    )
    .expect("valid Xray Hysteria2 receive windows should build");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            assert_eq!(config.xray_init_stream_receive_window, Some(32_768));
            assert_eq!(config.xray_max_stream_receive_window, Some(65_536));
            assert_eq!(config.xray_init_connection_receive_window, Some(131_072));
            assert_eq!(config.xray_max_connection_receive_window, Some(262_144));
        }
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }

    for field in [
        "initStreamReceiveWindow",
        "maxStreamReceiveWindow",
        "initConnectionReceiveWindow",
        "maxConnectionReceiveWindow",
    ] {
        let mut params = serde_json::Map::new();
        params.insert(field.to_string(), serde_json::json!(16_383));
        let err =
            ServerConfig::try_from(hysteria2_inbound_with_finalmask_quic_params(
                serde_json::Value::Object(params),
            ))
            .expect_err("Xray rejects receive windows below 16384");
        assert!(err.to_string().contains(field), "{err}");
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_congestion_matches_xray_settings() {
    let config = ServerConfig::try_from(
        hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
            "congestion": "FORCE-BRUTAL",
            "bbrProfile": "AGGRESSIVE",
            "brutalUp": "8 mbps",
            "brutalDown": "0.5 mbps"
        })),
    )
    .expect("valid Xray Hysteria2 congestion settings should build");
    match config.protocol {
        ServerProxyConfig::Hysteria2 { config } => {
            assert_eq!(config.xray_congestion.as_deref(), Some("force-brutal"));
            assert_eq!(config.xray_bbr_profile.as_deref(), Some("aggressive"));
            assert_eq!(config.xray_brutal_up, Some(1024 * 1024));
            assert_eq!(config.xray_brutal_down, Some(65_536));
        }
        other => panic!("expected hysteria2 protocol, got {other:?}"),
    }
}

#[cfg(feature = "hysteria")]
#[test]
fn hysteria2_finalmask_congestion_rejects_xray_invalid_values() {
    for (params, expected) in [
        (serde_json::json!({"congestion": "cubic"}), "congestion"),
        (serde_json::json!({"bbrProfile": "turbo"}), "bbrProfile"),
        (
            serde_json::json!({
                "congestion": "bbr",
                "bbrProfile": "aggressive"
            }),
            "not supported when Xray may use BBR",
        ),
        (
            serde_json::json!({
                "congestion": "brutal",
                "bbrProfile": "conservative"
            }),
            "not supported when Xray may use BBR",
        ),
        (
            serde_json::json!({"congestion": "force-brutal"}),
            "requires brutalUp",
        ),
        (serde_json::json!({"brutalUp": "8 kbps"}), "brutalUp"),
        (serde_json::json!({"brutalDown": "8 kbps"}), "brutalDown"),
    ] {
        let err = ServerConfig::try_from(
            hysteria2_inbound_with_finalmask_quic_params(params),
        )
        .expect_err("invalid Xray congestion settings must be rejected");
        assert!(err.to_string().contains(expected), "{err}");
    }
}

#[cfg(feature = "http")]
#[test]
fn http_inbound_builds_without_accounts() {
    let config = ServerConfig::try_from(inbound_for_protocol("http"))
        .expect("HTTP CONNECT inbound should build");
    match config.protocol {
        ServerProxyConfig::Http {
            accounts,
            allow_transparent,
            user_level,
        } => {
            assert!(accounts.is_empty());
            assert!(!allow_transparent);
            assert_eq!(user_level, 0);
        }
        other => panic!("expected http protocol, got {other:?}"),
    }
}

#[cfg(feature = "http")]
#[test]
fn http_inbound_preserves_xray_user_level() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "http",
        "tag": "http-policy",
        "settings": {
            "userLevel": 7
        }
    }))
    .expect("valid HTTP policy inbound");
    let config = ServerConfig::try_from(inbound)
        .expect("Xray HTTP settings.userLevel should be accepted");
    match config.protocol {
        ServerProxyConfig::Http { user_level, .. } => assert_eq!(user_level, 7),
        other => panic!("expected http protocol, got {other:?}"),
    }
}

#[cfg(feature = "http")]
#[test]
fn http_inbound_preserves_allow_transparent() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "http",
        "tag": "http-transparent",
        "settings": {
            "allowTransparent": true
        }
    }))
    .expect("valid HTTP transparent inbound");
    let config = ServerConfig::try_from(inbound)
        .expect("transparent HTTP inbound should build");
    match config.protocol {
        ServerProxyConfig::Http {
            allow_transparent, ..
        } => assert!(allow_transparent),
        other => panic!("expected http protocol, got {other:?}"),
    }
}

#[cfg(feature = "mixed")]
#[test]
fn mixed_inbound_builds_with_noauth_defaults() {
    let config = ServerConfig::try_from(inbound_for_protocol("mixed"))
        .expect("mixed inbound should build");
    match config.protocol {
        ServerProxyConfig::Mixed {
            accounts,
            udp_enabled,
        } => {
            assert!(!accounts.auth_required());
            assert!(accounts.snapshot().is_empty());
            assert!(!udp_enabled);
        }
        other => panic!("expected mixed protocol, got {other:?}"),
    }
}

#[cfg(feature = "shadowsocks")]
#[test]
fn shadowsocks_inbound_builds_legacy_tcp() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "shadowsocks",
        "tag": "ss-in",
        "settings": {
            "method": "aes-128-gcm",
            "password": "secret",
            "email": "ss@example.test",
            "network": "tcp"
        }
    }))
    .expect("valid shadowsocks inbound");
    let config = ServerConfig::try_from(inbound)
        .expect("legacy Shadowsocks TCP should build");
    match config.protocol {
        ServerProxyConfig::Shadowsocks { users, identity } => {
            assert!(identity.is_none());
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].method, "aes-128-gcm");
            assert_eq!(users[0].password, "secret");
            assert_eq!(users[0].email, "ss@example.test");
        }
        other => panic!("expected shadowsocks protocol, got {other:?}"),
    }
}

#[cfg(feature = "shadowsocks")]
#[test]
fn shadowsocks_inbound_preserves_multiple_legacy_users() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "shadowsocks",
        "tag": "ss-multi-user",
        "settings": {
            "clients": [{
                "method": "aes-128-gcm",
                "password": "secret-a",
                "email": "a@example.test"
            }, {
                "method": "chacha20-ietf-poly1305",
                "password": "secret-b",
                "email": "b@example.test"
            }],
            "network": "tcp,udp"
        }
    }))
    .expect("valid Shadowsocks multi-user inbound");
    let config = ServerConfig::try_from(inbound)
        .expect("legacy Shadowsocks multi-user should build");
    match config.protocol {
        ServerProxyConfig::Shadowsocks { users, identity } => {
            assert!(identity.is_none());
            assert_eq!(users.len(), 2);
            assert_eq!(users[0].email, "a@example.test");
            assert_eq!(users[1].email, "b@example.test");
        }
        other => panic!("expected shadowsocks protocol, got {other:?}"),
    }
    assert_eq!(config.transport, Transport::TcpAndUdp);
}

#[cfg(feature = "shadowsocks")]
#[test]
fn shadowsocks_inbound_preserves_2022_multi_user_eih() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "shadowsocks",
        "tag": "ss-2022-multi-user",
        "settings": {
            "method": "2022-blake3-aes-128-gcm",
            "password": "AAECAwQFBgcICQoLDA0ODw==",
            "clients": [{
                "password": "EBESExQVFhcYGRobHB0eHw==",
                "email": "user-a@example.test"
            }, {
                "password": "ICEiIyQlJicoKSorLC0uLw==",
                "email": "user-b@example.test"
            }],
            "network": "tcp,udp"
        }
    }))
    .expect("valid Shadowsocks 2022 multi-user shape");
    let config =
        ServerConfig::try_from(inbound).expect("2022 multi-user EIH should build");
    match config.protocol {
        ServerProxyConfig::Shadowsocks { users, identity } => {
            assert_eq!(users.len(), 2);
            assert_eq!(users[0].method, "2022-blake3-aes-128-gcm");
            assert_eq!(users[0].email, "user-a@example.test");
            assert_eq!(users[1].email, "user-b@example.test");
            let identity = identity.expect("server EIH identity");
            assert_eq!(identity.method, "2022-blake3-aes-128-gcm");
            assert_eq!(identity.password, "AAECAwQFBgcICQoLDA0ODw==");
        }
        other => panic!("expected shadowsocks protocol, got {other:?}"),
    }
    assert_eq!(config.transport, Transport::TcpAndUdp);
}

#[cfg(feature = "shadowsocks")]
#[test]
fn shadowsocks_inbound_builds_tcp_and_udp_transport() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "shadowsocks",
        "tag": "ss-udp",
        "settings": {
            "method": "aes-128-gcm",
            "password": "secret",
            "network": "tcp,udp"
        }
    }))
    .expect("valid shadowsocks inbound shape");
    let config =
        ServerConfig::try_from(inbound).expect("Shadowsocks TCP+UDP should build");
    assert_eq!(config.transport, Transport::TcpAndUdp);
}

#[test]
fn inbound_builder_compiles_xray_sniffing_and_exclusions() {
    let inbound = serde_json::from_value::<InboudItem>(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "dokodemo-door",
        "tag": "dokodemo-sniff",
        "settings": {"address": "127.0.0.1", "port": 53},
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "https", "ssl"],
            "routeOnly": true,
            "domainsExcluded": ["domain:example.com", "regexp:^private\\."],
            "ipsExcluded": ["192.0.2.0/24"]
        }
    }))
    .expect("literal sniffing inbound should parse");
    let config = ServerConfig::try_from(inbound)
        .expect("Xray sniffing config should compile");
    let sniffing = config.sniffing.expect("compiled sniffing config");
    assert!(sniffing.enabled);
    assert!(sniffing.route_only);
    assert!(sniffing.dest_override_http);
    assert!(sniffing.dest_override_tls);
    assert!(sniffing.excludes_domain("api.example.com"));
    assert!(sniffing.excludes_domain("private.test"));
    assert!(!sniffing.excludes_domain("public.test"));
    assert!(sniffing.excludes_ip("192.0.2.7".parse().unwrap()));
    assert!(!sniffing.excludes_ip("198.51.100.7".parse().unwrap()));

    let quic_only = serde_json::from_value::<InboudItem>(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "dokodemo-door",
        "tag": "dokodemo-sniff-quic",
        "settings": {"address": "127.0.0.1", "port": 53},
        "sniffing": {"enabled": true, "destOverride": ["quic"]}
    }))
    .expect("literal QUIC compatibility sniffing inbound should parse");
    let quic_config = ServerConfig::try_from(quic_only)
        .expect("Xray QUIC destOverride should be accepted as a no-op");
    let quic_sniffing = quic_config.sniffing.expect("compiled QUIC sniffing config");
    assert!(quic_sniffing.enabled);
    assert!(!quic_sniffing.dest_override_http);
    assert!(!quic_sniffing.dest_override_tls);

    for sniffing in [
        serde_json::json!({"enabled": true, "metadataOnly": true}),
        serde_json::json!({"enabled": true, "destOverride": ["fakedns"]}),
        serde_json::json!({"enabled": true, "domainsExcluded": ["regexp:(invalid"]}),
        serde_json::json!({"enabled": true, "ipsExcluded": ["192.0.2.0/99"]}),
    ] {
        let inbound = serde_json::from_value::<InboudItem>(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-sniff-invalid",
            "settings": {"address": "127.0.0.1", "port": 53},
            "sniffing": sniffing
        }))
        .expect("literal invalid sniffing inbound should parse");
        let error = ServerConfig::try_from(inbound)
            .expect_err("unsupported or malformed sniffing must fail closed");
        assert!(error.to_string().contains("sniffing"));
    }
}

#[test]
fn dokodemo_door_udp_network_builds_udp_transport() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "dokodemo-door",
        "tag": "dokodemo-udp",
        "settings": {
            "address": "127.0.0.1",
            "port": 5353
        },
        "streamSettings": {
            "network": "udp"
        }
    }))
    .expect("valid dokodemo udp inbound item");

    let config = ServerConfig::try_from(inbound).expect("dokodemo udp should build");
    assert_eq!(config.transport, Transport::Udp);
    match config.protocol {
        ServerProxyConfig::DokodemoDoor { config } => {
            assert_eq!(config.target.port(), 5353);
        }
        other => panic!("expected dokodemo-door, got {other:?}"),
    }
}

#[test]
fn dokodemo_udp_preserves_generic_listener_sockopts() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10004,
        "protocol": "dokodemo-door",
        "tag": "dokodemo-udp-sockopt",
        "settings": {"address": "127.0.0.1", "port": 5353},
        "streamSettings": {
            "network": "udp",
            "sockopt": {
                "interface": "lo",
                "mark": 17,
                "tproxy": "redirect",
                "receiveOriginalDestAddress": true,
                "customSockopt": [{
                    "system": "linux",
                    "network": "udp4",
                    "level": "1",
                    "opt": "2",
                    "value": "1",
                    "type": "int"
                }]
            }
        }
    }))
    .expect("UDP listener sockopts should deserialize");
    let config = ServerConfig::try_from(inbound)
        .expect("generic UDP listener sockopts should build");
    let policy = config
        .tcp_socket_policy
        .expect("UDP listener policy should be retained");
    assert_eq!(policy.bind_interface.as_deref(), Some("lo"));
    assert_eq!(policy.mark, Some(17));
    assert!(policy.transparent);
    assert!(policy.receive_original_destination);
    assert_eq!(policy.custom_sockopt.len(), 1);
    assert!(!policy.has_tcp_only_options());

    let invalid: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10005,
        "protocol": "dokodemo-door",
        "tag": "dokodemo-udp-tcp-only-sockopt",
        "settings": {"address": "127.0.0.1", "port": 5353},
        "streamSettings": {
            "network": "udp",
            "sockopt": {"tcpFastOpen": true}
        }
    }))
    .expect("TCP-only UDP sockopt should deserialize before validation");
    let error = ServerConfig::try_from(invalid)
        .expect_err("TCP-only UDP listener option must fail closed");
    assert!(error.to_string().contains("TCP socket options"));
}

#[test]
fn dokodemo_door_rejects_udp_security_layers() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "dokodemo-door",
        "tag": "dokodemo-udp-tls",
        "settings": {
            "address": "127.0.0.1",
            "port": 5353
        },
        "streamSettings": {
            "network": "udp",
            "security": "tls"
        }
    }))
    .expect("valid dokodemo udp inbound item");

    let err = ServerConfig::try_from(inbound)
        .expect_err("udp security layers should be rejected");
    assert!(err.to_string().contains(
        "dokodemo-door udp transport does not support streamSettings.security"
    ));
}

#[test]
fn xray_internal_tunnel_uses_rewrite_address_and_dokodemo_semantics() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 62789,
        "protocol": "tunnel",
        "settings": {"rewriteAddress": "127.0.0.1"},
        "tag": "api"
    }))
    .expect("valid Xray internal tunnel inbound");

    let config =
        ServerConfig::try_from(inbound).expect("Xray internal tunnel should build");
    match config.protocol {
        ServerProxyConfig::DokodemoDoor { config } => {
            assert_eq!(config.target.port(), 62789);
            assert_eq!(config.target.address().to_string(), "127.0.0.1");
        }
        other => panic!("expected dokodemo-door semantics, got {other:?}"),
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
fn vless_reality_inbound(reality_settings: serde_json::Value) -> InboudItem {
    serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-reality-test",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "security": "reality",
            "realitySettings": reality_settings
        }
    }))
    .expect("valid vless reality inbound item")
}

#[cfg(all(feature = "reality", feature = "vless"))]
fn base_reality_settings() -> serde_json::Value {
    serde_json::json!({
        "show": false,
        "dest": "www.apple.com:443",
        "xver": 0,
        "serverNames": ["www.apple.com"],
        "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
        "shortIds": ["4ac97aaf8b9b0356"],
        "maxTimeDiff": 0,
        "minClient": "",
        "maxClient": ""
    })
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_preserves_multiple_clients() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-multi-user",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user-a@example.com"
                },
                {
                    "id": "e041e73e-a0a0-49f5-9754-6401aa621fb7",
                    "email": "user-b@example.com"
                }
            ],
            "decryption": "none"
        }
    }))
    .expect("valid vless inbound item");

    let config =
        ServerConfig::try_from(inbound).expect("vless inbound config should build");

    match config.protocol {
        ServerProxyConfig::Vless { users, .. } => {
            assert_eq!(users.len(), 2);
            assert_eq!(users[0].user_id, "3ac9b383-75a1-431c-8184-106c80eb2273");
            assert_eq!(users[0].user_label, "user-a@example.com");
            assert_eq!(users[0].flow, "");
            assert_eq!(users[1].user_id, "e041e73e-a0a0-49f5-9754-6401aa621fb7");
            assert_eq!(users[1].user_label, "user-b@example.com");
            assert_eq!(users[1].flow, "");
        }
        other => panic!("expected vless protocol, got {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_preserves_client_flow() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-vision-flow",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "vision-user@example.com",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": "www.apple.com:443",
                "xver": 0,
                "serverNames": ["www.apple.com"],
                "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                "shortIds": ["4ac97aaf8b9b0356"],
                "maxTimeDiff": 0,
                "minClient": "",
                "maxClient": ""
            }
        }
    }))
    .expect("valid vless inbound item");

    let config =
        ServerConfig::try_from(inbound).expect("vless inbound config should build");

    match config.protocol {
        ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
            ServerProxyConfig::Vless { users, .. } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].flow, "xtls-rprx-vision");
            }
            other => {
                panic!("expected vless protocol inside reality, got {other:?}")
            }
        },
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls) => match tls.inner.as_ref() {
            ServerProxyConfig::Vless { users, .. } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].flow, "xtls-rprx-vision");
            }
            other => panic!("expected vless protocol inside tls, got {other:?}"),
        },
        ServerProxyConfig::Vless { users, .. } => {
            assert_eq!(users.len(), 1);
            assert_eq!(users[0].flow, "xtls-rprx-vision");
        }
        other => panic!("expected vless protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn vless_reality_builder_preserves_cipher_suites() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-reality-cipher-suites",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": "www.apple.com:443",
                "xver": 0,
                "serverNames": ["www.apple.com"],
                "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                "shortIds": ["4ac97aaf8b9b0356"],
                "cipherSuites": [
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_AES_128_GCM_SHA256"
                ],
                "maxTimeDiff": 0,
                "minClient": "",
                "maxClient": ""
            }
        }
    }))
    .expect("valid vless inbound item");

    let config = ServerConfig::try_from(inbound)
        .expect("vless reality inbound config should build");

    match config.protocol {
        ServerProxyConfig::Reality(reality) => {
            assert_eq!(reality.min_client_version, None);
            assert_eq!(
                reality.cipher_suites,
                vec![
                    crate::reality::CipherSuite::CHACHA20_POLY1305_SHA256,
                    crate::reality::CipherSuite::AES_128_GCM_SHA256,
                ]
            );
            assert_eq!(
                reality.to_reality_server_config().cipher_suites,
                reality.cipher_suites
            );
        }
        other => panic!("expected reality protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn vless_reality_rejects_missing_short_ids() {
    let mut settings = base_reality_settings();
    settings
        .as_object_mut()
        .expect("reality settings object")
        .remove("shortIds");

    let err = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect_err("xray-compatible REALITY inbound requires shortIds");
    assert!(
        err.to_string()
            .contains("reality inbound requires at least one shortId")
    );
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn vless_reality_preserves_explicit_min_client_version() {
    let mut settings = base_reality_settings();
    settings["minClient"] = serde_json::json!("25.1.2");

    let config = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect("explicit minClient should override the Xray default");
    match config.protocol {
        ServerProxyConfig::Reality(reality) => {
            assert_eq!(reality.min_client_version, Some([25, 1, 2]));
        }
        other => panic!("expected reality protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn vless_reality_rejects_invalid_client_version_shape() {
    let mut settings = base_reality_settings();
    settings["minClient"] = serde_json::json!("1.8");

    let err = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect_err("minClient without patch component should fail");
    assert!(
        err.to_string()
            .contains("minClientVer must use major.minor.patch format")
    );
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn vless_reality_rejects_outbound_only_settings() {
    let mut settings = base_reality_settings();
    settings["publicKey"] = serde_json::json!("client-side-public-key");

    let err = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect_err("publicKey is not an inbound setting");
    assert!(
        err.to_string()
            .contains("reality publicKey is an outbound/client setting")
    );
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_inherits_settings_flow() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-settings-flow",
        "settings": {
            "flow": "xtls-rprx-vision",
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "inherited-flow@example.com"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": "www.apple.com:443",
                "xver": 0,
                "serverNames": ["www.apple.com"],
                "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                "shortIds": ["4ac97aaf8b9b0356"],
                "maxTimeDiff": 0,
                "minClient": "",
                "maxClient": ""
            }
        }
    }))
    .expect("valid vless inbound item");

    let config =
        ServerConfig::try_from(inbound).expect("vless inbound config should build");

    match config.protocol {
        ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
            ServerProxyConfig::Vless { users, .. } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].flow, "xtls-rprx-vision");
            }
            other => {
                panic!("expected vless protocol inside reality, got {other:?}")
            }
        },
        other => panic!("expected reality protocol, got {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_rejects_unknown_settings_flow() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-invalid-settings-flow",
        "settings": {
            "flow": "xtls-rprx-vision-udp443",
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "bad-settings-flow@example.com"
                }
            ],
            "decryption": "none"
        }
    }))
    .expect("valid vless inbound item");

    let err = ServerConfig::try_from(inbound)
        .expect_err("unsupported vless settings flow should fail validation");
    assert!(
        err.to_string()
            .contains("vless clients.flow doesn't support xtls-rprx-vision-udp443")
    );
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_rejects_unknown_client_flow() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-invalid-flow",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "bad-flow@example.com",
                    "flow": "xtls-rprx-vision-udp443"
                }
            ],
            "decryption": "none"
        }
    }))
    .expect("valid vless inbound item");

    let err = ServerConfig::try_from(inbound)
        .expect_err("unsupported vless flow should fail validation");
    assert!(
        err.to_string()
            .contains("vless clients.flow doesn't support xtls-rprx-vision-udp443")
    );
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_rejects_vision_without_tls_or_reality() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-vision-no-tls",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "vision-user@example.com",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "decryption": "none"
        }
    }))
    .expect("valid vless inbound item");

    let err = ServerConfig::try_from(inbound)
        .expect_err("vision without tls/reality should fail");
    assert!(err.to_string().contains(
        "xtls-rprx-vision requires streamSettings.security=tls or reality"
    ));
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_accepts_mixed_plain_and_vision_users() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "vless-mixed-flow-users",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "plain-user@example.com"
                },
                {
                    "id": "e041e73e-a0a0-49f5-9754-6401aa621fb7",
                    "email": "vision-user@example.com",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": "www.apple.com:443",
                "xver": 0,
                "serverNames": ["www.apple.com"],
                "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                "shortIds": ["4ac97aaf8b9b0356"],
                "maxTimeDiff": 0,
                "minClient": "",
                "maxClient": ""
            }
        }
    }))
    .expect("valid vless inbound item");

    let server_config = ServerConfig::try_from(inbound)
        .expect("mixed plain and vision users should build");
    assert_eq!(server_config.tag, "vless-mixed-flow-users");
}

#[cfg(all(feature = "vless", feature = "ws"))]
#[test]
fn vless_builder_rejects_vision_over_websocket() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-vision-ws",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "vision-user@example.com",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "host": "example.com",
                    "path": "/ws"
                },
                "tlsSettings": {
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .expect("valid vless inbound item");

    let err = ServerConfig::try_from(inbound)
        .expect_err("vision over websocket should fail");
    assert!(
        err.to_string()
            .contains("xtls-rprx-vision does not support websocket transport")
    );
}

#[cfg(all(feature = "tls", feature = "vless"))]
#[test]
fn vless_xhttp_accepts_http3_tls_configuration() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-http3",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                },
                "xhttpSettings": {
                    "path": "/xhttp"
                },
                "sockopt": {
                    "v6only": true,
                    "interface": "lo",
                    "mark": 17,
                    "tproxy": "redirect",
                    "customSockopt": [{
                        "system": "linux",
                        "network": "udp4",
                        "level": "1",
                        "opt": "2",
                        "value": "1",
                        "type": "int"
                    }]
                },
                "finalmask": {
                    "quicParams": {
                        "congestion": "RENO",
                        "maxIdleTimeout": 45,
                        "maxIncomingStreams": 64,
                        "initStreamReceiveWindow": 32768,
                        "maxStreamReceiveWindow": 65536,
                        "initConnectionReceiveWindow": 131072,
                        "maxConnectionReceiveWindow": 262144,
                        "disablePathMTUDiscovery": true
                    }
                }
            }
        }))
        .expect("valid inbound item");

    let server = ServerConfig::try_from(inbound)
        .expect("XHTTP/3 TLS configuration should build");
    let policy = server
        .tcp_socket_policy
        .as_ref()
        .expect("XHTTP/3 generic listener sockopts should be retained");
    assert!(policy.ipv6_only);
    assert_eq!(policy.bind_interface.as_deref(), Some("lo"));
    assert_eq!(policy.mark, Some(17));
    assert!(policy.transparent);
    assert_eq!(policy.custom_sockopt.len(), 1);
    assert!(!policy.has_tcp_only_options());
    let ServerProxyConfig::Tls(tls) = server.protocol else {
        panic!("expected TLS-wrapped XHTTP protocol");
    };
    assert_eq!(tls.alpn_protocols, vec!["h3"]);
    let ServerProxyConfig::Xhttp { config, .. } = *tls.inner else {
        panic!("expected XHTTP inside TLS");
    };
    assert_eq!(config.xray_congestion.as_deref(), Some("reno"));
    assert_eq!(config.xray_max_idle_timeout_secs, Some(45));
    assert_eq!(config.xray_max_incoming_streams, Some(64));
    assert_eq!(config.xray_init_stream_receive_window, Some(32_768));
    assert_eq!(config.xray_max_stream_receive_window, Some(65_536));
    assert_eq!(config.xray_init_connection_receive_window, Some(131_072));
    assert_eq!(config.xray_max_connection_receive_window, Some(262_144));
    assert_eq!(config.xray_disable_path_mtu_discovery, Some(true));
}

#[cfg(feature = "vless")]
fn xhttp_inbound_with_quic_params(quic_params: serde_json::Value) -> InboudItem {
    serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "xhttp-quic-params",
        "settings": {
            "clients": [{ "id": "3ac9b383-75a1-431c-8184-106c80eb2273" }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": { "path": "/xhttp" },
            "finalmask": { "quicParams": quic_params }
        }
    }))
    .expect("valid XHTTP inbound")
}

#[cfg(all(feature = "tls", feature = "vless"))]
#[test]
fn vless_xhttp_accepts_xray_force_brutal_configuration() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-force-brutal",
            "settings": {
                "clients": [{ "id": "3ac9b383-75a1-431c-8184-106c80eb2273" }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                },
                "xhttpSettings": { "path": "/xhttp" },
                "finalmask": {
                    "quicParams": {
                        "congestion": "force-brutal",
                        "brutalUp": "8 mbps"
                    }
                }
            }
        }))
        .expect("valid inbound item");

    let server = ServerConfig::try_from(inbound)
        .expect("Xray force-brutal XHTTP/3 configuration should build");
    let ServerProxyConfig::Tls(tls) = server.protocol else {
        panic!("expected TLS-wrapped XHTTP protocol");
    };
    let ServerProxyConfig::Xhttp { config, .. } = *tls.inner else {
        panic!("expected XHTTP inside TLS");
    };
    assert_eq!(config.xray_congestion.as_deref(), Some("force-brutal"));
    assert_eq!(config.xray_brutal_up, Some(1024 * 1024));
}

#[cfg(feature = "vless")]
#[test]
fn vless_xhttp_validates_xray_bbr_profile_without_fake_parity() {
    for (congestion, profile) in
        [("reno", "aggressive"), ("force-brutal", "conservative")]
    {
        let mut quic_params = serde_json::json!({
            "congestion": congestion,
            "bbrProfile": profile,
        });
        if congestion == "force-brutal" {
            quic_params["brutalUp"] = serde_json::json!("8 mbps");
        }
        let inbound = xhttp_inbound_with_quic_params(quic_params);
        ServerConfig::try_from(inbound)
            .expect("BBR profile is inert when Xray does not use BBR");
    }

    for profile in ["conservative", "aggressive"] {
        let inbound = xhttp_inbound_with_quic_params(serde_json::json!({
            "congestion": "bbr",
            "bbrProfile": profile,
        }));
        let err = ServerConfig::try_from(inbound).expect_err(
            "unsupported active Xray BBR profile must not be silently ignored",
        );
        assert!(
                err.to_string().contains(
                    "finalmask.quicParams.bbrProfile conservative/aggressive is not supported when Xray may use BBR"
                ),
                "unexpected error: {err}"
            );
    }

    let inbound = xhttp_inbound_with_quic_params(serde_json::json!({
        "bbrProfile": "turbo",
    }));
    let err = ServerConfig::try_from(inbound)
        .expect_err("Xray-invalid BBR profile must fail");
    assert!(
            err.to_string().contains(
                "finalmask.quicParams.bbrProfile must be one of conservative, standard, aggressive"
            ),
            "unexpected error: {err}"
        );
}

#[cfg(feature = "vless")]
#[test]
fn vless_xhttp_finalmask_keep_alive_period_matches_xray_bounds() {
    for keep_alive_period in [0_i64, 2, 60] {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-keepalive",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {
                    "path": "/xhttp"
                },
                "finalmask": {
                    "quicParams": {
                        "keepAlivePeriod": keep_alive_period
                    }
                }
            }
        }))
        .expect("valid inbound item");

        ServerConfig::try_from(inbound)
            .expect("Xray-valid XHTTP keepAlivePeriod should build");
    }

    for keep_alive_period in [1_i64, 61] {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-keepalive",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {
                    "path": "/xhttp"
                },
                "finalmask": {
                    "quicParams": {
                        "keepAlivePeriod": keep_alive_period
                    }
                }
            }
        }))
        .expect("valid inbound item");

        let err = ServerConfig::try_from(inbound)
            .expect_err("Xray-invalid XHTTP keepAlivePeriod should fail");
        assert!(
                err.to_string().contains(
                    "finalmask.quicParams.keepAlivePeriod must be 0 or between 2 and 60 seconds"
                ),
                "unexpected error: {err}"
            );
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn vless_xhttp_reality_builds_nested_protocol_chain() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 443,
        "protocol": "vless",
        "tag": "xhttp-reality",
        "settings": {
            "clients": [
                {
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "reality",
            "sockopt": {
                "trustedXForwardedFor": ["X-Trusted-CDN"]
            },
            "realitySettings": {
                "show": false,
                "dest": "www.apple.com:443",
                "xver": 0,
                "serverNames": ["www.apple.com"],
                "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                "shortIds": ["4ac97aaf8b9b0356"],
                "maxTimeDiff": 0,
                "minClient": "",
                "maxClient": ""
            },
            "xhttpSettings": {
                "host": "www.apple.com",
                "path": "/xhttp"
            }
        }
    }))
    .expect("valid inbound item");

    let config = ServerConfig::try_from(inbound).expect("xhttp reality config");

    match config.protocol {
        ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
            ServerProxyConfig::Xhttp { config, inner } => {
                assert_eq!(
                    config.trusted_x_forwarded_for,
                    vec!["X-Trusted-CDN".to_string()]
                );
                assert!(matches!(inner.as_ref(), ServerProxyConfig::Vless { .. }));
            }
            other => panic!("expected xhttp inside reality, got {other:?}"),
        },
        other => panic!("expected reality protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn reality_settings_accepts_ip_dest_with_explicit_server_names() {
    let mut settings = base_reality_settings();
    let settings_object = settings.as_object_mut().expect("reality settings object");
    settings_object.insert("dest".to_string(), serde_json::json!("127.0.0.1:9443"));
    settings_object.insert(
        "serverNames".to_string(),
        serde_json::json!(["www.apple.com"]),
    );

    let config = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect("ip dest with explicit serverNames should build reality config");

    match config.protocol {
        ServerProxyConfig::Reality(reality) => {
            assert_eq!(reality.dest.to_string(), "127.0.0.1:9443");
            assert_eq!(reality.server_names, vec!["www.apple.com".to_string()]);
        }
        other => panic!("expected reality protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn reality_settings_rejects_ip_dest_without_explicit_server_names() {
    let mut settings = base_reality_settings();
    let settings_object = settings.as_object_mut().expect("reality settings object");
    settings_object.insert("dest".to_string(), serde_json::json!("127.0.0.1:9443"));
    settings_object.remove("serverNames");

    let err = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect_err("ip dest without serverNames should fail");
    assert!(err.to_string().contains(
            "reality.dest may be an ip address only when realitySettings.serverNames is explicitly configured"
        ));
}

#[cfg(all(feature = "reality", feature = "vless"))]
#[test]
fn reality_settings_accepts_xray_target_alias() {
    let mut settings = base_reality_settings();
    let settings_object = settings.as_object_mut().expect("reality settings object");
    settings_object.remove("dest");
    settings_object.insert(
        "target".to_string(),
        serde_json::json!("www.example.com:8443"),
    );

    let config = ServerConfig::try_from(vless_reality_inbound(settings))
        .expect("target alias should build reality config");

    match config.protocol {
        ServerProxyConfig::Reality(reality) => {
            assert_eq!(reality.dest.to_string(), "www.example.com:8443");
        }
        other => panic!("expected reality protocol, got {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_requires_explicit_none_decryption() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10000,
        "protocol": "vless",
        "tag": "vless-missing-decryption",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }]
        }
    }))
    .expect("valid inbound json shape");

    let err = ServerConfig::try_from(inbound)
        .expect_err("missing vless decryption should fail");
    assert!(
        err.to_string()
            .contains("vless settings.decryption must be explicitly set to none")
    );
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_rejects_non_none_decryption() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10001,
        "protocol": "vless",
        "tag": "vless-invalid-decryption",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "aes-128-gcm"
        }
    }))
    .expect("valid inbound json shape");

    let err = ServerConfig::try_from(inbound)
        .expect_err("non-none vless decryption should fail");
    assert!(
        err.to_string()
            .contains("vless settings.decryption must be none")
    );
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_rejects_unknown_stream_security() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10002,
        "protocol": "vless",
        "tag": "vless-unknown-security",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "definitely-not-a-security-layer"
        }
    }))
    .expect("valid inbound json shape");

    let err = ServerConfig::try_from(inbound)
        .expect_err("unknown stream security must not downgrade to plaintext");
    assert!(err.to_string().contains(
        "unsupported streamSettings.security=definitely-not-a-security-layer"
    ));
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_accepts_dest_only_fallback() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10002,
        "protocol": "vless",
        "tag": "vless-fallbacks",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none",
            "fallbacks": [{ "dest": "127.0.0.1:8080", "xver": 0 }]
        }
    }))
    .expect("valid inbound json shape");

    let config = ServerConfig::try_from(inbound)
        .expect("dest-only VLESS fallback should build");
    match config.protocol {
        ServerProxyConfig::Vless { fallbacks, .. } => {
            assert_eq!(fallbacks.len(), 1);
            assert_eq!(fallbacks[0].dest.to_string(), "127.0.0.1:8080");
        }
        other => panic!("expected vless protocol, got {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_accepts_numeric_fallback_port() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10002,
        "protocol": "vless",
        "tag": "vless-numeric-fallback",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none",
            "fallbacks": [{ "dest": 8081 }]
        }
    }))
    .expect("valid inbound json shape");

    let config = ServerConfig::try_from(inbound)
        .expect("numeric VLESS fallback port should build");
    match config.protocol {
        ServerProxyConfig::Vless { fallbacks, .. } => {
            assert_eq!(fallbacks[0].dest.to_string(), "127.0.0.1:8081");
        }
        other => panic!("expected vless protocol, got {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_preserves_fallback_xver() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10002,
        "protocol": "vless",
        "tag": "vless-fallback-xver",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none",
            "fallbacks": [
                { "dest": 8081, "xver": 1 },
                { "dest": 8082, "xver": 2 }
            ]
        }
    }))
    .expect("valid inbound json shape");

    let config = ServerConfig::try_from(inbound)
        .expect("PROXY protocol fallback versions should build");
    match config.protocol {
        ServerProxyConfig::Vless { fallbacks, .. } => {
            assert_eq!(fallbacks[0].xver, 1);
            assert_eq!(fallbacks[1].xver, 2);
        }
        other => panic!("expected vless protocol, got {other:?}"),
    }
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_rejects_unknown_fallback_xver() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10002,
        "protocol": "vless",
        "tag": "vless-fallback-xver-invalid",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none",
            "fallbacks": [{ "dest": 8081, "xver": 3 }]
        }
    }))
    .expect("valid inbound json shape");

    let error =
        ServerConfig::try_from(inbound).expect_err("xver=3 must be rejected");
    assert!(
        error
            .to_string()
            .contains("vless fallback xver must be 0, 1, or 2; got 3")
    );
}

#[cfg(feature = "vless")]
#[test]
fn vless_builder_preserves_fallback_match_fields() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10002,
        "protocol": "vless",
        "tag": "vless-fallback-path",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none",
            "fallbacks": [{
                "name": "EXAMPLE.COM",
                "alpn": "H2",
                "dest": "127.0.0.1:8080",
                "path": "/fallback",
                "type": "tcp",
                "xver": 0
            }]
        }
    }))
    .expect("valid inbound json shape");

    let config = ServerConfig::try_from(inbound)
        .expect("VLESS fallback match fields should build");
    match config.protocol {
        ServerProxyConfig::Vless { fallbacks, .. } => {
            assert_eq!(fallbacks.len(), 1);
            assert_eq!(fallbacks[0].name, "example.com");
            assert_eq!(fallbacks[0].alpn, "h2");
            assert_eq!(fallbacks[0].path, "/fallback");
            assert_eq!(fallbacks[0].xver, 0);
        }
        other => panic!("expected vless protocol, got {other:?}"),
    }
}

#[cfg(feature = "vmess")]
#[test]
fn vmess_builder_defaults_security_to_auto() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10003,
        "protocol": "vmess",
        "tag": "vmess-auto-security",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                "email": "vmess@example.com"
            }]
        }
    }))
    .expect("valid vmess inbound item");

    let config =
        ServerConfig::try_from(inbound).expect("vmess inbound config should build");

    match config.protocol {
        ServerProxyConfig::Vmess { users } => {
            assert_eq!(users[0].cipher, "auto");
        }
        other => panic!("expected vmess protocol, got {other:?}"),
    }
}

#[cfg(feature = "vmess")]
#[test]
fn vmess_builder_preserves_client_security() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10004,
        "protocol": "vmess",
        "tag": "vmess-security",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                "security": "aes-128-gcm"
            }]
        }
    }))
    .expect("valid vmess inbound item");

    let config =
        ServerConfig::try_from(inbound).expect("vmess inbound config should build");

    match config.protocol {
        ServerProxyConfig::Vmess { users } => {
            assert_eq!(users[0].cipher, "aes-128-gcm");
        }
        other => panic!("expected vmess protocol, got {other:?}"),
    }
}

#[cfg(feature = "vmess")]
#[test]
fn vmess_builder_normalizes_xray_short_id() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10005,
        "protocol": "vmess",
        "tag": "vmess-short-id",
        "settings": {
            "clients": [{
                "id": "test-vmess-user"
            }]
        }
    }))
    .expect("valid vmess short-id inbound item");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray-compatible VMess short ID should build");

    match config.protocol {
        ServerProxyConfig::Vmess { users } => {
            assert_eq!(users[0].user_id, "321d83eb-74db-554a-a630-0ad214dc332b");
            assert_eq!(users[0].user_label, users[0].user_id);
        }
        other => panic!("expected vmess protocol, got {other:?}"),
    }
}

#[cfg(feature = "vmess")]
#[test]
fn vmess_builder_rejects_invalid_uuid_shape() {
    for invalid_id in [
        "",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10006,
            "protocol": "vmess",
            "tag": "vmess-invalid-id",
            "settings": {
                "clients": [{"id": invalid_id}]
            }
        }))
        .expect("vmess inbound JSON shape should deserialize");

        let error = ServerConfig::try_from(inbound)
            .expect_err("invalid VMess ID should be rejected");
        assert!(
            error.to_string().contains("invalid VMess UUID"),
            "unexpected error for {invalid_id:?}: {error}"
        );
    }
}

#[cfg(all(feature = "vless", feature = "httpupgrade"))]
#[test]
fn httpupgrade_accepts_xray_early_data_setting() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10007,
        "protocol": "vless",
        "tag": "vless-httpupgrade-ed",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "httpupgrade",
            "httpupgradeSettings": {
                "host": "example.com",
                "path": "/upgrade",
                "acceptProxyProtocol": true,
                "ed": 2048
            }
        }
    }))
    .expect("valid VLESS HTTPUpgrade inbound item");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray HTTPUpgrade ed should be accepted on inbound");

    match config.protocol {
        ServerProxyConfig::HttpUpgrade(httpupgrade) => {
            assert_eq!(httpupgrade.host.as_deref(), Some("example.com"));
            assert_eq!(httpupgrade.path, "/upgrade");
            assert!(httpupgrade.accept_proxy_protocol);
            assert!(matches!(
                httpupgrade.inner.as_ref(),
                ServerProxyConfig::Vless { .. }
            ));
        }
        other => panic!("expected HTTPUpgrade protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "vless", feature = "httpupgrade"))]
#[test]
fn httpupgrade_path_preserves_xray_whitespace() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10007,
        "protocol": "vless",
        "tag": "vless-httpupgrade-whitespace",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "httpupgrade",
            "httpupgradeSettings": {
                "host": " Example.COM ",
                "path": "ws "
            }
        }
    }))
    .expect("valid VLESS HTTPUpgrade inbound item");

    let config = ServerConfig::try_from(inbound)
        .expect("Xray HTTPUpgrade path whitespace should be preserved");

    match config.protocol {
        ServerProxyConfig::HttpUpgrade(httpupgrade) => {
            assert_eq!(httpupgrade.host.as_deref(), Some(" example.com "));
            assert_eq!(httpupgrade.path, "/ws ");
        }
        other => panic!("expected HTTPUpgrade protocol, got {other:?}"),
    }
}

#[cfg(feature = "ws")]
#[test]
fn websocket_path_matches_xray_normalization() {
    assert_eq!(normalize_xray_websocket_path(None), "/");
    assert_eq!(normalize_xray_websocket_path(Some(String::new())), "/");
    assert_eq!(
        normalize_xray_websocket_path(Some("chat".to_string())),
        "/chat"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat".to_string())),
        "/chat"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?ed=2048".to_string())),
        "/chat"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?%65d=2048".to_string())),
        "/chat"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("chat?ed=2048".to_string())),
        "/chat"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?foo=bar&ed=2048".to_string())),
        "/chat?foo=bar"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?ed=".to_string())),
        "/chat?ed="
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?ed=%".to_string())),
        "/chat?ed=%"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?ed=2048&bad%ZZ=x".to_string())),
        "/chat"
    );
    assert_eq!(
        normalize_xray_websocket_path(Some("/chat?ed=2048;bad".to_string())),
        "/chat?ed=2048;bad"
    );
}

#[cfg(all(feature = "vless", feature = "ws"))]
#[test]
fn websocket_settings_only_host_enters_matching_config() {
    let inbound: InboudItem = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1",
        "port": 10005,
        "protocol": "vless",
        "tag": "vless-ws-headers",
        "settings": {
            "clients": [{
                "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
            }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "ws",
            "wsSettings": {
                "host": " Example.COM ",
                "path": "/ws",
                "acceptProxyProtocol": false,
                "heartbeatPeriod": 7,
                "headers": {
                    "Host": "edge.example.com",
                    "X-Test": "ok"
                }
            },
            "sockopt": {
                "acceptProxyProtocol": true,
                "trustedXForwardedFor": ["X-Trusted-CDN"]
            }
        }
    }))
    .expect("valid vless websocket inbound item");

    let config = ServerConfig::try_from(inbound)
        .expect("vless websocket inbound config should build");

    match config.protocol {
        ServerProxyConfig::Websocket { targets } => match *targets {
            OneOrSome::One(target) => {
                assert_eq!(target.matching_path.as_deref(), Some("/ws"));
                let headers = target
                    .matching_headers
                    .expect("websocket host should be preserved");
                assert_eq!(headers.get("host"), Some(&" Example.COM ".to_string()));
                assert!(!headers.contains_key("x-test"));
                assert!(!headers.contains_key("Host"));
                assert_eq!(
                    target.trusted_x_forwarded_for,
                    vec!["X-Trusted-CDN".to_string()]
                );
                assert!(target.accept_proxy_protocol);
                assert_eq!(target.heartbeat_period, 7);
            }
            OneOrSome::Some(_) => panic!("expected one websocket target"),
        },
        other => panic!("expected websocket protocol, got {other:?}"),
    }
}

#[cfg(all(feature = "vless", feature = "ws"))]
#[test]
fn websocket_deprecated_header_host_preserves_xray_text_semantics() {
    fn matching_host(headers: serde_json::Value) -> Option<String> {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10005,
            "protocol": "vless",
            "tag": "vless-ws-header-fallback",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/ws",
                    "headers": headers
                }
            }
        }))
        .expect("valid vless websocket inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vless websocket inbound config should build");
        let ServerProxyConfig::Websocket { targets } = config.protocol else {
            panic!("expected websocket protocol");
        };
        let OneOrSome::One(target) = *targets else {
            panic!("expected one websocket target");
        };
        target
            .matching_headers
            .and_then(|headers| headers.get("host").cloned())
    }

    assert_eq!(
        matching_host(serde_json::json!({"Host": " Example.COM "})),
        Some(" Example.COM ".to_string())
    );
    assert_eq!(
        matching_host(serde_json::json!({"hOsT": "example.com"})),
        Some("example.com".to_string())
    );
    assert_eq!(
        matching_host(serde_json::json!({" Host ": "example.com"})),
        None
    );
    assert_eq!(matching_host(serde_json::json!({"Host": ""})), None);
}
