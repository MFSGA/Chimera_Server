use super::{RuntimeLifecycleState, RuntimeState};
use crate::{
    address::{BindLocation, NetLocation},
    config::{
        Transport,
        def::{PolicyConfig, PolicyLevelConfig, SystemPolicyConfig},
        rule::BalancerConfig,
        server_config::{ServerConfig, ServerProxyConfig, SocksUserStore},
    },
    routing_state::{OutboundObservation, RoutingState},
};
use std::{
    collections::HashMap,
    sync::{Arc, mpsc},
    time::Duration,
};

#[test]
fn runtime_lifecycle_transitions_are_monotonic() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    assert_eq!(runtime.lifecycle_state(), RuntimeLifecycleState::Starting);
    assert!(!runtime.is_ready());

    assert!(runtime.mark_running());
    assert_eq!(runtime.lifecycle_state(), RuntimeLifecycleState::Running);
    assert!(runtime.is_ready());
    assert!(!runtime.mark_running());

    assert!(runtime.begin_draining());
    assert_eq!(runtime.lifecycle_state(), RuntimeLifecycleState::Draining);
    assert!(!runtime.is_ready());
    assert!(!runtime.begin_draining());

    runtime.finish_shutdown(false);
    assert_eq!(runtime.lifecycle_state(), RuntimeLifecycleState::Stopped);
    assert!(!runtime.is_ready());
    assert!(!runtime.begin_draining());
}

#[test]
fn failed_shutdown_has_explicit_terminal_state() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    assert!(runtime.mark_running());
    assert!(runtime.begin_draining());
    runtime.finish_shutdown(true);
    assert_eq!(runtime.lifecycle_state(), RuntimeLifecycleState::Failed);
    assert!(!runtime.is_ready());
}

#[tokio::test]
async fn runtime_readiness_fails_when_listener_exits_unexpectedly() {
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: "failed-listener".to_string(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                10001,
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: SocksUserStore::new(Vec::new()),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    assert!(runtime.mark_running());
    runtime.register_inbound_tasks("failed-listener", vec![tokio::spawn(async {})]);
    tokio::task::yield_now().await;

    assert!(!runtime.is_ready());
    let failure = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.wait_for_inbound_failure(),
    )
    .await
    .expect("listener failure should reach runtime");
    assert_eq!(failure.tag, "failed-listener");
}

#[tokio::test]
async fn stopping_inbound_tasks_releases_listener_before_return() {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let address = listener.local_addr().expect("read test listener address");
    let task = tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: "listener-release".to_string(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                address.ip(),
                address.port(),
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: SocksUserStore::new(Vec::new()),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    runtime.register_inbound_tasks("listener-release", vec![task]);

    assert!(runtime.stop_inbound_tasks("listener-release").await);
    tokio::net::TcpListener::bind(address)
        .await
        .expect("listener should be released before stop returns");
}

#[test]
fn data_plane_capability_observes_live_policy_updates() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let data_plane = runtime.data_plane();
    let handshake = data_plane.inbound_handshake_runtime();
    assert_eq!(
        data_plane.xray_handshake_timeout_for_level(7),
        Duration::from_secs(60)
    );
    assert_eq!(
        handshake.xray_handshake_timeout_for_level(7),
        Duration::from_secs(60)
    );

    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            handshake: Some(5),
            ..PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));

    assert_eq!(
        data_plane.xray_handshake_timeout_for_level(7),
        Duration::from_secs(5)
    );
    assert_eq!(
        handshake.xray_handshake_timeout_for_level(7),
        Duration::from_secs(5)
    );
}

#[test]
fn xray_handshake_policy_uses_level_override_and_default() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    assert_eq!(
        runtime.xray_handshake_timeout_for_level(7),
        Duration::from_secs(60)
    );

    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            handshake: Some(5),
            ..PolicyLevelConfig::default()
        }),
    );
    levels.insert(
        8,
        Some(PolicyLevelConfig {
            handshake: Some(0),
            ..PolicyLevelConfig::default()
        }),
    );
    levels.insert(9, Some(PolicyLevelConfig::default()));
    levels.insert(10, None);
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));

    assert_eq!(
        runtime.xray_handshake_timeout_for_level(7),
        Duration::from_secs(5)
    );
    assert_eq!(runtime.xray_handshake_timeout_for_level(8), Duration::ZERO);
    assert_eq!(
        runtime.xray_handshake_timeout_for_level(9),
        Duration::from_secs(60)
    );
    assert_eq!(
        runtime.xray_handshake_timeout_for_level(10),
        Duration::from_secs(60)
    );
    assert_eq!(
        runtime.xray_handshake_timeout_for_level(11),
        Duration::from_secs(60)
    );
}

#[test]
fn xray_connection_idle_policy_uses_level_override_and_default() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    assert_eq!(
        runtime.xray_connection_idle_timeout_for_level(7),
        Duration::from_secs(300)
    );

    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            connection_idle: Some(5),
            ..PolicyLevelConfig::default()
        }),
    );
    levels.insert(
        8,
        Some(PolicyLevelConfig {
            connection_idle: Some(0),
            ..PolicyLevelConfig::default()
        }),
    );
    levels.insert(9, Some(PolicyLevelConfig::default()));
    levels.insert(10, None);
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));

    assert_eq!(
        runtime.xray_connection_idle_timeout_for_level(7),
        Duration::from_secs(5)
    );
    assert_eq!(
        runtime.xray_connection_idle_timeout_for_level(8),
        Duration::ZERO
    );
    assert_eq!(
        runtime.xray_connection_idle_timeout_for_level(9),
        Duration::from_secs(300)
    );
    assert_eq!(
        runtime.xray_connection_idle_timeout_for_level(10),
        Duration::from_secs(300)
    );
    assert_eq!(
        runtime.xray_connection_idle_timeout_for_level(11),
        Duration::from_secs(300)
    );
}

#[test]
fn xray_relay_policy_preserves_default_and_per_level_timeouts() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let defaults = runtime.policy_relay_timeouts(7);
    assert_eq!(defaults.connection_idle, Some(Duration::from_secs(300)));
    assert_eq!(defaults.uplink_only, Some(Duration::from_secs(1)));
    assert_eq!(defaults.downlink_only, Some(Duration::from_secs(1)));
    assert_eq!(defaults.buffer_size, None);

    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            connection_idle: Some(5),
            uplink_only: Some(6),
            downlink_only: Some(7),
            buffer_size: Some(64),
            ..PolicyLevelConfig::default()
        }),
    );
    levels.insert(
        8,
        Some(PolicyLevelConfig {
            connection_idle: Some(0),
            uplink_only: Some(0),
            downlink_only: Some(0),
            buffer_size: Some(-1),
            ..PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        ..PolicyConfig::default()
    }));

    let configured = runtime.policy_relay_timeouts(7);
    assert_eq!(configured.connection_idle, Some(Duration::from_secs(5)));
    assert_eq!(configured.uplink_only, Some(Duration::from_secs(6)));
    assert_eq!(configured.downlink_only, Some(Duration::from_secs(7)));
    assert_eq!(configured.buffer_size, Some(64 * 1024));

    let zeroed = runtime.policy_relay_timeouts(8);
    assert_eq!(zeroed.connection_idle, Some(Duration::ZERO));
    assert_eq!(zeroed.uplink_only, Some(Duration::ZERO));
    assert_eq!(zeroed.downlink_only, Some(Duration::ZERO));
    assert_eq!(zeroed.buffer_size, None);
}

#[test]
fn xray_stats_policy_uses_level_and_system_switches() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let default_user = runtime.policy_user_stats(7);
    assert!(!default_user.uplink);
    assert!(!default_user.downlink);
    assert!(!default_user.online);
    let default_system = runtime.policy_system_stats();
    assert!(!default_system.inbound_uplink);
    assert!(!default_system.inbound_downlink);
    assert!(!default_system.outbound_uplink);
    assert!(!default_system.outbound_downlink);

    let mut levels = HashMap::new();
    levels.insert(
        7,
        Some(PolicyLevelConfig {
            stats_user_uplink: true,
            stats_user_downlink: false,
            stats_user_online: true,
            ..PolicyLevelConfig::default()
        }),
    );
    runtime.replace_policy(Some(&PolicyConfig {
        levels,
        system: Some(SystemPolicyConfig {
            stats_inbound_uplink: false,
            stats_inbound_downlink: true,
            stats_outbound_uplink: true,
            stats_outbound_downlink: false,
        }),
    }));

    let user = runtime.policy_user_stats(7);
    assert!(user.uplink);
    assert!(!user.downlink);
    assert!(user.online);
    let missing = runtime.policy_user_stats(8);
    assert_eq!(missing, super::PolicyUserStats::default());

    let system = runtime.policy_system_stats();
    assert!(!system.inbound_uplink);
    assert!(system.inbound_downlink);
    assert!(system.outbound_uplink);
    assert!(!system.outbound_downlink);
}

#[test]
fn outbound_and_override_snapshots_are_copy_on_write() {
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![super::OutboundSummary {
            tag: "direct".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }],
    );
    let first_outbounds = runtime.outbound_snapshot();
    let second_outbounds = runtime.outbound_snapshot();
    assert!(Arc::ptr_eq(&first_outbounds, &second_outbounds));

    runtime
        .add_outbound(super::OutboundSummary {
            tag: "backup".into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        })
        .expect("add outbound");
    let replaced_outbounds = runtime.outbound_snapshot();
    assert!(!Arc::ptr_eq(&first_outbounds, &replaced_outbounds));
    assert_eq!(first_outbounds.len(), 1);
    assert_eq!(replaced_outbounds.len(), 2);

    let first_overrides = runtime.balancer_override_snapshot();
    runtime.set_balancer_override("auto", "backup");
    let replaced_overrides = runtime.balancer_override_snapshot();
    assert!(!Arc::ptr_eq(&first_overrides, &replaced_overrides));
    assert!(first_overrides.is_empty());
    assert_eq!(
        replaced_overrides.get("auto").map(String::as_str),
        Some("backup")
    );
}

#[test]
fn routing_publication_recompiles_balancer_targets_on_control_updates() {
    fn outbound(tag: &str) -> super::OutboundSummary {
        super::OutboundSummary {
            tag: tag.into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        }
    }

    let runtime = RuntimeState::new(
        Vec::new(),
        vec![outbound("direct-a"), outbound("backup")],
    );
    runtime.replace_routing(
        RoutingState::from_parts(
            Vec::new(),
            vec![BalancerConfig {
                tag: "auto".into(),
                outbound_selector: vec!["direct".into()],
                ..BalancerConfig::default()
            }],
        )
        .expect("compile routing balancer"),
    );

    let first = runtime.routing_publication();
    assert_eq!(first.balancer_targets["auto"].as_ref(), ["direct-a"]);

    runtime
        .add_outbound(outbound("direct-b"))
        .expect("add matching outbound");
    let added = runtime.routing_publication();
    assert!(!Arc::ptr_eq(&first, &added));
    assert_eq!(first.balancer_targets["auto"].as_ref(), ["direct-a"]);
    assert_eq!(
        added.balancer_targets["auto"].as_ref(),
        ["direct-a", "direct-b"]
    );
    runtime.record_outbound_observation(
        "direct-a",
        OutboundObservation {
            alive: true,
            delay_ms: 12,
            ..OutboundObservation::default()
        },
    );
    assert!(runtime.outbound_observation("direct-a").is_some());

    runtime
        .remove_outbound("direct-a")
        .expect("remove matching outbound");
    let removed = runtime.routing_publication();
    assert_eq!(removed.balancer_targets["auto"].as_ref(), ["direct-b"]);
    assert!(runtime.outbound_observation("direct-a").is_none());
}

#[test]
fn routing_reads_share_immutable_snapshots_until_publish() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let first = runtime.routing();
    let second = runtime.routing();
    assert!(Arc::ptr_eq(&first, &second));

    runtime.replace_routing(RoutingState::default());
    let replaced = runtime.routing();
    assert!(!Arc::ptr_eq(&first, &replaced));
}

#[test]
fn routing_update_compilation_does_not_hold_data_plane_write_lock() {
    let runtime = Arc::new(RuntimeState::new(Vec::new(), Vec::new()));
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let update_runtime = Arc::clone(&runtime);
    let update = std::thread::spawn(move || {
        update_runtime.with_routing_mut(|_| {
            started_tx.send(()).expect("signal update start");
            release_rx.recv().expect("release routing update");
        });
    });
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("routing update should start");

    let (read_tx, read_rx) = mpsc::channel();
    let read_runtime = Arc::clone(&runtime);
    let reader = std::thread::spawn(move || {
        let _ = read_runtime.routing();
        read_tx.send(()).expect("signal routing read");
    });
    let read_result = read_rx.recv_timeout(Duration::from_millis(200));

    release_tx.send(()).expect("release routing update");
    update.join().expect("routing update thread");
    reader.join().expect("routing reader thread");
    assert!(
        read_result.is_ok(),
        "data-plane routing reads must remain available while a control-plane update is prepared"
    );
}
