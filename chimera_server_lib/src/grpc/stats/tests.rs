use super::proto::xray::app::stats::command::stats_service_server::StatsService;
use super::*;
use crate::{
    address::{BindLocation, NetLocation},
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig, SocksUserStore},
    },
    traffic::{self, TrafficContext},
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicU64, Ordering},
};
use tonic::{Code, Request};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn unique_tag(prefix: &str) -> String {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{id}")
}

fn record_transfer(tag: &str, user: &str, upload: u64, download: u64) {
    let context = TrafficContext::new("test")
        .with_inbound_tag(tag)
        .with_identity(user);
    traffic::record_transfer(Some(context), upload, download);
}

fn name_inbound(tag: &str, suffix: &str) -> String {
    format!("inbound>>>{tag}>>>traffic>>>{suffix}")
}

#[test]
fn parse_traffic_counter_preserves_scope_key_and_terminal_direction() {
    let identity = "alice>>>traffic>>>uplink";
    assert!(matches!(
        parse_traffic_counter(&format!(
            "user>>>{identity}>>>traffic>>>downlink"
        )),
        Some(TrafficCounter::User {
            identity: parsed,
            upload: false
        }) if parsed == identity
    ));
    let empty_tag_name = format!("inbound>>>{}>>>traffic>>>uplink", "");
    assert!(matches!(
        parse_traffic_counter(&empty_tag_name),
        Some(TrafficCounter::Inbound {
            tag: "",
            upload: true
        })
    ));
    assert!(matches!(
        parse_traffic_counter("outbound>>>direct>>>traffic>>>downlink"),
        Some(TrafficCounter::Outbound {
            tag: "direct",
            upload: false
        })
    ));
    assert!(parse_traffic_counter("inbound>>>edge>>>traffic").is_none());
    assert!(parse_traffic_counter("unknown>>>edge>>>traffic>>>uplink").is_none());
}

#[tokio::test]
async fn registered_identity_is_visible_before_first_transfer() {
    let service = StatsServiceImpl::new();
    let user = unique_tag("configured-user");
    traffic::register_identity(user.clone());

    let response = service
        .query_stats(Request::new(
            proto::xray::app::stats::command::QueryStatsRequest {
                pattern: format!("user>>>{user}>>>traffic>>>"),
                reset: false,
            },
        ))
        .await
        .expect("query configured user stats failed")
        .into_inner();

    let stats = response
        .stat
        .into_iter()
        .map(|stat| (stat.name, stat.value))
        .collect::<HashMap<_, _>>();
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[&format!("user>>>{user}>>>traffic>>>uplink")], 0);
    assert_eq!(stats[&format!("user>>>{user}>>>traffic>>>downlink")], 0);
}

#[tokio::test]
async fn stats_get_stats_and_reset() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("inbound");
    let user = unique_tag("user");

    record_transfer(&tag, &user, 120, 450);

    let uplink = name_inbound(&tag, "uplink");
    let downlink = name_inbound(&tag, "downlink");

    let response = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink.clone(),
                reset: false,
            },
        ))
        .await
        .expect("get_stats uplink failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 120);

    let response = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: downlink.clone(),
                reset: false,
            },
        ))
        .await
        .expect("get_stats downlink failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 450);

    let response = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink.clone(),
                reset: true,
            },
        ))
        .await
        .expect("reset uplink failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 120);

    let response = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: downlink.clone(),
                reset: true,
            },
        ))
        .await
        .expect("reset downlink failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 450);

    record_transfer(&tag, &user, 30, 70);

    let response = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink.clone(),
                reset: false,
            },
        ))
        .await
        .expect("delta uplink failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 30);

    let response = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: downlink.clone(),
                reset: false,
            },
        ))
        .await
        .expect("delta downlink failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 70);
}

#[tokio::test]
async fn stats_get_single_user_counter_aggregates_inbounds_and_resets() {
    let service = StatsServiceImpl::new();
    let user = unique_tag("single-stat-user");
    let first_inbound = unique_tag("single-stat-inbound");
    let second_inbound = unique_tag("single-stat-inbound");
    traffic::register_identity(user.clone());

    let uplink_name = format!("user>>>{user}>>>traffic>>>uplink");
    let downlink_name = format!("user>>>{user}>>>traffic>>>downlink");
    let zero = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink_name.clone(),
                reset: false,
            },
        ))
        .await
        .expect("registered user stat should be visible")
        .into_inner();
    assert_eq!(zero.stat.expect("registered user counter").value, 0);

    record_transfer(&first_inbound, &user, 80, 120);
    record_transfer(&second_inbound, &user, 40, 60);

    let value = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink_name.clone(),
                reset: false,
            },
        ))
        .await
        .expect("user uplink stat should aggregate inbounds")
        .into_inner();
    assert_eq!(value.stat.expect("user uplink counter").value, 120);

    let reset_value = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink_name.clone(),
                reset: true,
            },
        ))
        .await
        .expect("user uplink reset should succeed")
        .into_inner();
    assert_eq!(reset_value.stat.expect("reset user counter").value, 120);

    record_transfer(&second_inbound, &user, 7, 11);
    let delta = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: uplink_name,
                reset: false,
            },
        ))
        .await
        .expect("user uplink delta should succeed")
        .into_inner();
    assert_eq!(delta.stat.expect("user uplink delta").value, 7);

    let downlink = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: downlink_name,
                reset: false,
            },
        ))
        .await
        .expect("user downlink stat should succeed")
        .into_inner();
    assert_eq!(downlink.stat.expect("user downlink counter").value, 191);

    let unknown = unique_tag("unknown-stat-user");
    let error = service
        .get_stats(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: format!("user>>>{unknown}>>>traffic>>>uplink"),
                reset: false,
            },
        ))
        .await
        .expect_err("unknown user counter should remain not found");
    assert_eq!(error.code(), Code::NotFound);
}

#[test]
#[ignore = "manual release-mode single-counter query probe"]
fn stats_single_counter_query_probe() {
    use std::{hint::black_box, time::Instant};

    const INBOUND_COUNT: usize = 128;
    const USER_COUNT: usize = 64;
    const ITERATIONS: usize = 50;

    let namespace = unique_tag("stats-query-probe");
    let users = (0..USER_COUNT)
        .map(|index| format!("{namespace}-user-{index}"))
        .collect::<Vec<_>>();

    for inbound_index in 0..INBOUND_COUNT {
        let inbound = format!("{namespace}-inbound-{inbound_index}");
        for user in &users {
            let context = TrafficContext::new("probe")
                .with_inbound_tag(&inbound)
                .with_identity(user);
            traffic::record_transfer(Some(context), 1, 2);
        }
    }

    let service = StatsServiceImpl::new();
    let counter_name = format!(
        "user>>>{}>>>traffic>>>uplink",
        users.last().expect("at least one probe user")
    );
    assert_eq!(service.current_stats()[&counter_name], INBOUND_COUNT as i64);
    assert_eq!(
        service.get_stat_value(&counter_name, false),
        Some(INBOUND_COUNT as i64)
    );

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        let current_stats = service.current_stats();
        let value = current_stats
            .get(&counter_name)
            .copied()
            .map(|value| value.saturating_sub(service.reset.read(&counter_name)));
        black_box(value);
    }
    let snapshot_elapsed = started.elapsed();

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(service.get_stat_value(&counter_name, false));
    }
    let direct_elapsed = started.elapsed();
    let speedup = snapshot_elapsed.as_secs_f64()
        / direct_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "inbounds={INBOUND_COUNT} users_per_inbound={USER_COUNT} iterations={ITERATIONS} full_snapshot={snapshot_elapsed:?} direct_counter={direct_elapsed:?} ratio={speedup:.2}x"
    );
}

#[tokio::test]
async fn stats_query_stats_pattern_and_reset() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("query");
    let user = unique_tag("user");

    record_transfer(&tag, &user, 50, 60);

    let response = service
        .query_stats(Request::new(
            proto::xray::app::stats::command::QueryStatsRequest {
                pattern: tag.clone(),
                reset: true,
            },
        ))
        .await
        .expect("query stats failed")
        .into_inner();

    let mut stats = HashMap::new();
    for stat in response.stat {
        stats.insert(stat.name, stat.value);
    }
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[&name_inbound(&tag, "uplink")], 50);
    assert_eq!(stats[&name_inbound(&tag, "downlink")], 60);

    record_transfer(&tag, &user, 7, 11);

    let response = service
        .query_stats(Request::new(
            proto::xray::app::stats::command::QueryStatsRequest {
                pattern: tag.clone(),
                reset: false,
            },
        ))
        .await
        .expect("query stats delta failed")
        .into_inner();

    let mut stats = HashMap::new();
    for stat in response.stat {
        stats.insert(stat.name, stat.value);
    }
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[&name_inbound(&tag, "uplink")], 7);
    assert_eq!(stats[&name_inbound(&tag, "downlink")], 11);
}

#[tokio::test]
async fn stats_query_outbound_traffic() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("outbound");
    let context = TrafficContext::new("test")
        .with_outbound_tag(&tag)
        .with_identity("outbound-user");
    traffic::record_transfer(Some(context), 17, 29);

    let response = service
        .query_stats(Request::new(
            proto::xray::app::stats::command::QueryStatsRequest {
                pattern: format!("outbound>>>{tag}>>>"),
                reset: false,
            },
        ))
        .await
        .expect("query outbound stats failed")
        .into_inner();
    let stats = response
        .stat
        .into_iter()
        .map(|stat| (stat.name, stat.value))
        .collect::<HashMap<_, _>>();

    assert_eq!(stats[&format!("outbound>>>{tag}>>>traffic>>>uplink")], 17);
    assert_eq!(stats[&format!("outbound>>>{tag}>>>traffic>>>downlink")], 29);
}

#[tokio::test]
async fn stats_online_counts_unique_ips() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("online");
    let user = unique_tag("user");

    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2));

    let ctx1 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(ip1);
    let _guard1 = traffic::register_connection(Some(&ctx1));
    let _guard2 = traffic::register_connection(Some(&ctx1));

    let ctx2 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(ip2);
    let _guard3 = traffic::register_connection(Some(&ctx2));

    let inbound_name = format!("inbound>>>{tag}>>>online");
    let response = service
        .get_stats_online(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: inbound_name,
                reset: false,
            },
        ))
        .await
        .expect("get_stats_online inbound failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 2);

    let user_name = format!("user>>>{user}>>>online");
    let response = service
        .get_stats_online(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: user_name,
                reset: false,
            },
        ))
        .await
        .expect("get_stats_online user failed")
        .into_inner();
    assert_eq!(response.stat.unwrap().value, 2);
}

#[tokio::test]
async fn stats_online_ip_list_contains_ips() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("iplist");
    let user = unique_tag("user");

    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 2, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 2, 1, 2));

    let ctx1 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(ip1);
    let _guard1 = traffic::register_connection(Some(&ctx1));

    let ctx2 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(ip2);
    let _guard2 = traffic::register_connection(Some(&ctx2));

    let inbound_name = format!("inbound>>>{tag}>>>online");
    let response = service
        .get_stats_online_ip_list(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: inbound_name,
                reset: false,
            },
        ))
        .await
        .expect("get_stats_online_ip_list failed")
        .into_inner();

    let ip1_key = ip1.to_string();
    let ip2_key = ip2.to_string();
    assert!(response.ips.contains_key(&ip1_key));
    assert!(response.ips.contains_key(&ip2_key));
    assert!(response.ips[&ip1_key] > 0);
}

#[tokio::test]
async fn stats_all_online_users_unique() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("users");
    let prefix = unique_tag("user");
    let user_a = format!("{prefix}-a");
    let user_b = format!("{prefix}-b");

    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 3, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 3, 1, 2));

    let ctx1 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user_a)
        .with_client_ip(ip1);
    let _guard1 = traffic::register_connection(Some(&ctx1));
    let _guard2 = traffic::register_connection(Some(&ctx1));

    let ctx2 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user_b)
        .with_client_ip(ip2);
    let _guard3 = traffic::register_connection(Some(&ctx2));

    let response = service
        .get_all_online_users(Request::new(
            proto::xray::app::stats::command::GetAllOnlineUsersRequest {},
        ))
        .await
        .expect("get_all_online_users failed")
        .into_inner();

    let matching: Vec<&String> = response
        .users
        .iter()
        .filter(|user| user.contains(&prefix))
        .collect();
    assert_eq!(matching.len(), 2);
    assert!(
        matching
            .iter()
            .any(|user| *user == &user_online_name(&user_a))
    );
    assert!(
        matching
            .iter()
            .any(|user| *user == &user_online_name(&user_b))
    );
}

#[tokio::test]
async fn stats_online_ignores_localhost_addresses() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("localhost");
    let user = unique_tag("user");

    let local_ctx = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let _local = traffic::register_connection(Some(&local_ctx));

    let err = service
        .get_stats_online(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: format!("user>>>{user}>>>online"),
                reset: false,
            },
        ))
        .await
        .expect_err("expected localhost-only online stats to be absent");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn stats_get_sys_stats_is_unavailable_until_runtime_is_ready() {
    let runtime = RuntimeState::new(Vec::new(), Vec::new());
    let service = StatsServiceImpl::with_runtime(runtime.clone());

    let request =
        || Request::new(proto::xray::app::stats::command::SysStatsRequest {});

    let starting = service
        .get_sys_stats(request())
        .await
        .expect_err("starting runtime must not report ready");
    assert_eq!(starting.code(), Code::Unavailable);

    assert!(runtime.mark_running());
    service
        .get_sys_stats(request())
        .await
        .expect("running runtime should report ready");

    assert!(runtime.begin_draining());
    let draining = service
        .get_sys_stats(request())
        .await
        .expect_err("draining runtime must not report ready");
    assert_eq!(draining.code(), Code::Unavailable);

    runtime.finish_shutdown(false);
    let stopped = service
        .get_sys_stats(request())
        .await
        .expect_err("stopped runtime must not report ready");
    assert_eq!(stopped.code(), Code::Unavailable);
}

#[tokio::test]
async fn stats_get_sys_stats_reports_unhealthy_inbound_identity() {
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: "failed-listener".to_string(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
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
    let generation = runtime
        .inbound_manager()
        .generation("failed-listener")
        .expect("inbound generation");
    assert!(runtime.mark_running());
    runtime.register_inbound_tasks("failed-listener", vec![tokio::spawn(async {})]);
    tokio::task::yield_now().await;
    let service = StatsServiceImpl::with_runtime(runtime);

    let error = service
        .get_sys_stats(Request::new(
            proto::xray::app::stats::command::SysStatsRequest {},
        ))
        .await
        .expect_err("failed inbound should make readiness unavailable");
    assert_eq!(error.code(), Code::Unavailable);
    assert!(error.message().contains("failed-listener"));
    assert!(error.message().contains(&generation.to_string()));
}

#[tokio::test]
async fn stats_get_sys_stats_reports_live_process_values() {
    let service = StatsServiceImpl::new();

    let response = service
        .get_sys_stats(Request::new(
            proto::xray::app::stats::command::SysStatsRequest {},
        ))
        .await
        .expect("get_sys_stats failed")
        .into_inner();

    #[cfg(target_os = "linux")]
    {
        assert!(response.num_goroutine > 0);
        assert!(response.sys >= response.alloc);
    }

    assert_eq!(response.num_gc, 0);
    assert_eq!(response.total_alloc, 0);
    assert_eq!(response.mallocs, 0);
    assert_eq!(response.frees, 0);
    assert_eq!(response.live_objects, 0);
    assert_eq!(response.pause_total_ns, 0);
}

#[tokio::test]
async fn stats_get_users_stats_includes_ips_and_traffic() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("userstats");
    let user = unique_tag("user");

    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 4, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 4, 1, 2));

    let ctx1 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(ip1);
    let _guard1 = traffic::register_connection(Some(&ctx1));
    let _guard2 = traffic::register_connection(Some(&ctx1));

    let ctx2 = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&user)
        .with_client_ip(ip2);
    let _guard3 = traffic::register_connection(Some(&ctx2));

    let idle_user = unique_tag("userstats-idle");
    let idle_context = TrafficContext::new("test")
        .with_inbound_tag(&tag)
        .with_identity(&idle_user)
        .with_client_ip(IpAddr::V4(Ipv4Addr::new(10, 4, 1, 3)));
    let _idle_guard = traffic::register_connection(Some(&idle_context));

    record_transfer(&tag, &user, 120, 450);
    record_transfer(&tag, &user, 30, 70);

    let response = service
        .get_users_stats(Request::new(
            proto::xray::app::stats::command::GetUsersStatsRequest {
                include_traffic: true,
                reset: false,
            },
        ))
        .await
        .expect("get_users_stats failed")
        .into_inner();

    let user_stat = response
        .users
        .iter()
        .find(|entry| entry.email == user)
        .expect("user stat not found");

    assert_eq!(user_stat.ips.len(), 2);
    assert!(
        user_stat
            .ips
            .iter()
            .any(|entry| entry.ip == ip1.to_string())
    );
    assert!(
        user_stat
            .ips
            .iter()
            .any(|entry| entry.ip == ip2.to_string())
    );

    let traffic = user_stat.traffic.as_ref().expect("traffic missing");
    assert_eq!(traffic.uplink, 150);
    assert_eq!(traffic.downlink, 520);

    let idle_stat = response
        .users
        .iter()
        .find(|entry| entry.email == idle_user)
        .expect("idle user stat not found");
    let idle_traffic = idle_stat.traffic.as_ref().expect("idle traffic missing");
    assert_eq!(idle_traffic.uplink, 0);
    assert_eq!(idle_traffic.downlink, 0);

    let response = service
        .get_users_stats(Request::new(
            proto::xray::app::stats::command::GetUsersStatsRequest {
                include_traffic: true,
                reset: true,
            },
        ))
        .await
        .expect("reset get_users_stats failed")
        .into_inner();

    let user_stat = response
        .users
        .iter()
        .find(|entry| entry.email == user)
        .expect("user stat not found after reset");
    let traffic = user_stat.traffic.as_ref().expect("traffic missing");
    assert_eq!(traffic.uplink, 150);
    assert_eq!(traffic.downlink, 520);

    record_transfer(&tag, &user, 5, 7);

    let response = service
        .get_users_stats(Request::new(
            proto::xray::app::stats::command::GetUsersStatsRequest {
                include_traffic: false,
                reset: true,
            },
        ))
        .await
        .expect("get_users_stats without traffic failed")
        .into_inner();
    let user_stat = response
        .users
        .iter()
        .find(|entry| entry.email == user)
        .expect("user stat not found without traffic");
    assert_eq!(user_stat.ips.len(), 2);
    assert!(user_stat.traffic.is_none());

    record_transfer(&tag, &user, 10, 20);

    let response = service
        .get_users_stats(Request::new(
            proto::xray::app::stats::command::GetUsersStatsRequest {
                include_traffic: true,
                reset: false,
            },
        ))
        .await
        .expect("delta get_users_stats failed")
        .into_inner();

    let user_stat = response
        .users
        .iter()
        .find(|entry| entry.email == user)
        .expect("user stat not found after delta");
    let traffic = user_stat.traffic.as_ref().expect("traffic missing");
    assert_eq!(traffic.uplink, 15);
    assert_eq!(traffic.downlink, 27);
}

#[tokio::test]
#[ignore = "manual release-mode GetUsersStats snapshot probe"]
async fn get_users_stats_without_traffic_probe() {
    use std::{collections::HashSet, hint::black_box, time::Instant};

    const INBOUND_COUNT: usize = 128;
    const USER_COUNT: usize = 64;
    const ITERATIONS: usize = 25;

    let namespace = unique_tag("get-users-stats-probe");
    let users = (0..USER_COUNT)
        .map(|index| format!("{namespace}-user-{index}"))
        .collect::<Vec<_>>();
    let mut connections = Vec::with_capacity(USER_COUNT);
    for (index, user) in users.iter().enumerate() {
        let context = TrafficContext::new("probe")
            .with_identity(user)
            .with_client_ip(IpAddr::V4(Ipv4Addr::new(
                198,
                18,
                0,
                (index + 1) as u8,
            )));
        connections.push(traffic::register_connection(Some(&context)));
    }

    for inbound_index in 0..INBOUND_COUNT {
        let inbound = format!("{namespace}-inbound-{inbound_index}");
        for user in &users {
            let context = TrafficContext::new("probe")
                .with_inbound_tag(&inbound)
                .with_identity(user);
            traffic::record_transfer(Some(context), 1, 2);
        }
    }

    let service = StatsServiceImpl::new();
    let request = || {
        Request::new(proto::xray::app::stats::command::GetUsersStatsRequest {
            include_traffic: false,
            reset: false,
        })
    };
    let response = service
        .get_users_stats(request())
        .await
        .expect("probe request should succeed")
        .into_inner();
    assert_eq!(response.users.len(), USER_COUNT);
    assert!(response.users.iter().all(|user| user.traffic.is_none()));

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        // This recreates the unconditional full-snapshot work performed by
        // the previous GetUsersStats implementation when traffic was omitted.
        black_box(service.current_stats());
        let response = service
            .get_users_stats(request())
            .await
            .expect("baseline probe request should succeed")
            .into_inner();
        black_box(response.users.len());
    }
    let previous_elapsed = started.elapsed();

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        let response = service
            .get_users_stats(request())
            .await
            .expect("optimized probe request should succeed")
            .into_inner();
        black_box(response.users.len());
    }
    let optimized_elapsed = started.elapsed();
    let ratio = previous_elapsed.as_secs_f64()
        / optimized_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "inbounds={INBOUND_COUNT} users_per_inbound={USER_COUNT} iterations={ITERATIONS} previous={previous_elapsed:?} optimized={optimized_elapsed:?} ratio={ratio:.2}x"
    );

    let identities = users.iter().cloned().collect::<HashSet<_>>();
    let selected = traffic::user_traffic_for(&identities);
    assert_eq!(selected.len(), USER_COUNT);
    assert!(selected.values().all(|totals| {
        *totals == (INBOUND_COUNT as u64, (INBOUND_COUNT * 2) as u64)
    }));

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(service.current_stats());
    }
    let full_snapshot_elapsed = started.elapsed();

    let started = Instant::now();
    for _ in 0..ITERATIONS {
        black_box(traffic::user_traffic_for(&identities));
    }
    let selected_users_elapsed = started.elapsed();
    let aggregation_ratio = full_snapshot_elapsed.as_secs_f64()
        / selected_users_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "inbounds={INBOUND_COUNT} users_per_inbound={USER_COUNT} iterations={ITERATIONS} full_stats_snapshot={full_snapshot_elapsed:?} selected_user_traffic={selected_users_elapsed:?} ratio={aggregation_ratio:.2}x"
    );
    drop(connections);
}

#[tokio::test]
async fn stats_invalid_online_name_returns_not_found() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("invalid");
    let name = format!("inbound>>>{tag}>>>traffic");
    let err = service
        .get_stats_online(Request::new(
            proto::xray::app::stats::command::GetStatsRequest { name, reset: false },
        ))
        .await
        .expect_err("expected not found");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn stats_online_without_matching_entries_returns_not_found() {
    let service = StatsServiceImpl::new();
    let tag = unique_tag("empty");

    let err = service
        .get_stats_online(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: format!("inbound>>>{tag}>>>online"),
                reset: false,
            },
        ))
        .await
        .expect_err("expected not found");
    assert_eq!(err.code(), Code::NotFound);

    let err = service
        .get_stats_online_ip_list(Request::new(
            proto::xray::app::stats::command::GetStatsRequest {
                name: format!("inbound>>>{tag}>>>online"),
                reset: false,
            },
        ))
        .await
        .expect_err("expected not found");
    assert_eq!(err.code(), Code::NotFound);
}
