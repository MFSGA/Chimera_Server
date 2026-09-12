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
    assert_eq!(traffic.uplink, 10);
    assert_eq!(traffic.downlink, 20);
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
