use super::proto;
use crate::traffic;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::{Instant, UNIX_EPOCH},
};
use tonic::{Request, Response, Status};

#[derive(Default)]
struct StatsReset {
    baselines: RwLock<HashMap<String, i64>>,
}

impl StatsReset {
    fn read(&self, name: &str) -> i64 {
        self.baselines
            .read()
            .ok()
            .and_then(|guard| guard.get(name).copied())
            .unwrap_or(0)
    }

    fn reset(&self, name: &str, value: i64) -> i64 {
        let mut guard = self
            .baselines
            .write()
            .expect("stats reset baselines poisoned");
        let base = guard.get(name).copied().unwrap_or(0);
        guard.insert(name.to_string(), value);
        value.saturating_sub(base)
    }
}
#[derive(Clone)]
pub(super) struct StatsServiceImpl {
    start_time: Instant,
    reset: Arc<StatsReset>,
}
impl StatsServiceImpl {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            reset: Arc::new(StatsReset::default()),
        }
    }
    fn current_stats(&self) -> HashMap<String, i64> {
        let snapshot = traffic::snapshot();
        let mut stats = HashMap::new();

        for (tag, totals) in snapshot.per_inbound {
            stats.insert(
                format!("inbound>>>{}>>>traffic>>>uplink", tag),
                totals.upload_bytes as i64,
            );
            stats.insert(
                format!("inbound>>>{}>>>traffic>>>downlink", tag),
                totals.download_bytes as i64,
            );
        }
        let mut user_totals: HashMap<String, traffic::TransferTotals> =
            HashMap::new();
        for ((_, identity), totals) in snapshot.per_inbound_user {
            let entry = user_totals.entry(identity).or_default();
            entry.upload_bytes =
                entry.upload_bytes.saturating_add(totals.upload_bytes);
            entry.download_bytes =
                entry.download_bytes.saturating_add(totals.download_bytes);
        }
        for (identity, totals) in user_totals {
            stats.insert(
                format!("user>>>{}>>>traffic>>>uplink", identity),
                totals.upload_bytes as i64,
            );
            stats.insert(
                format!("user>>>{}>>>traffic>>>downlink", identity),
                totals.download_bytes as i64,
            );
        }

        stats
    }

    fn get_stat_value(&self, name: &str, reset: bool) -> Option<i64> {
        let current_stats = self.current_stats();
        let value = current_stats.get(name).copied()?;
        if reset {
            Some(self.reset.reset(name, value))
        } else {
            let base = self.reset.read(name);
            Some(value.saturating_sub(base))
        }
    }

    fn online_stats(&self, name: &str) -> Option<i64> {
        let entries = traffic::active_connections();
        let online = parse_online_name(name)?;
        let mut ips = HashSet::new();
        match online {
            OnlineKey::Inbound(tag) => {
                for entry in entries {
                    if entry.inbound_tag.as_deref() == Some(&tag) {
                        if let Some(ip) = entry.client_ip {
                            ips.insert(ip.to_string());
                        }
                    }
                }
            }
            OnlineKey::User(identity) => {
                for entry in entries {
                    if entry.identity.as_deref() == Some(&identity) {
                        if let Some(ip) = entry.client_ip {
                            ips.insert(ip.to_string());
                        }
                    }
                }
            }
        }
        if ips.is_empty() {
            None
        } else {
            Some(ips.len() as i64)
        }
    }

    fn online_ip_list(&self, name: &str) -> Option<HashMap<String, i64>> {
        let entries = traffic::active_connections();
        let online = parse_online_name(name)?;
        let mut ips = HashMap::new();

        for entry in entries {
            let matches = match &online {
                OnlineKey::Inbound(tag) => {
                    entry.inbound_tag.as_deref() == Some(tag.as_str())
                }
                OnlineKey::User(identity) => {
                    entry.identity.as_deref() == Some(identity.as_str())
                }
            };

            if !matches {
                continue;
            }

            let Some(ip) = entry.client_ip else { continue };
            let timestamp = entry
                .started_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let entry_ts = ips.entry(ip.to_string()).or_insert(timestamp);
            if timestamp > *entry_ts {
                *entry_ts = timestamp;
            }
        }

        if ips.is_empty() { None } else { Some(ips) }
    }
}
#[tonic::async_trait]
impl proto::xray::app::stats::command::stats_service_server::StatsService
    for StatsServiceImpl
{
    async fn get_stats(
        &self,
        request: Request<proto::xray::app::stats::command::GetStatsRequest>,
    ) -> Result<Response<proto::xray::app::stats::command::GetStatsResponse>, Status>
    {
        let request = request.into_inner();
        let value = self
            .get_stat_value(&request.name, request.reset)
            .ok_or_else(|| {
                Status::not_found(format!("{} not found", request.name))
            })?;
        Ok(Response::new(
            proto::xray::app::stats::command::GetStatsResponse {
                stat: Some(proto::xray::app::stats::command::Stat {
                    name: request.name,
                    value,
                }),
            },
        ))
    }

    async fn get_stats_online(
        &self,
        request: Request<proto::xray::app::stats::command::GetStatsRequest>,
    ) -> Result<Response<proto::xray::app::stats::command::GetStatsResponse>, Status>
    {
        let request = request.into_inner();
        let value = self.online_stats(&request.name).ok_or_else(|| {
            Status::not_found(format!("{} not found", request.name))
        })?;
        Ok(Response::new(
            proto::xray::app::stats::command::GetStatsResponse {
                stat: Some(proto::xray::app::stats::command::Stat {
                    name: request.name,
                    value,
                }),
            },
        ))
    }

    async fn query_stats(
        &self,
        request: Request<proto::xray::app::stats::command::QueryStatsRequest>,
    ) -> Result<Response<proto::xray::app::stats::command::QueryStatsResponse>, Status>
    {
        let request = request.into_inner();
        let current_stats = self.current_stats();
        let pattern = request.pattern;
        let mut stats = Vec::new();
        for (name, value) in current_stats {
            if !pattern.is_empty() && !name.contains(&pattern) {
                continue;
            }
            let stat_value = if request.reset {
                self.reset.reset(&name, value)
            } else {
                let base = self.reset.read(&name);
                value.saturating_sub(base)
            };
            stats.push(proto::xray::app::stats::command::Stat {
                name,
                value: stat_value,
            });
        }
        Ok(Response::new(
            proto::xray::app::stats::command::QueryStatsResponse { stat: stats },
        ))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<proto::xray::app::stats::command::SysStatsRequest>,
    ) -> Result<Response<proto::xray::app::stats::command::SysStatsResponse>, Status>
    {
        let uptime = self.start_time.elapsed().as_secs() as u32;
        Ok(Response::new(
            proto::xray::app::stats::command::SysStatsResponse {
                num_goroutine: 0,
                num_gc: 0,
                alloc: 0,
                total_alloc: 0,
                sys: 0,
                mallocs: 0,
                frees: 0,
                live_objects: 0,
                pause_total_ns: 0,
                uptime,
            },
        ))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<proto::xray::app::stats::command::GetStatsRequest>,
    ) -> Result<
        Response<proto::xray::app::stats::command::GetStatsOnlineIpListResponse>,
        Status,
    > {
        let request = request.into_inner();
        let ips = self.online_ip_list(&request.name).ok_or_else(|| {
            Status::not_found(format!("{} not found", request.name))
        })?;
        Ok(Response::new(
            proto::xray::app::stats::command::GetStatsOnlineIpListResponse {
                name: request.name,
                ips,
            },
        ))
    }

    async fn get_all_online_users(
        &self,
        _request: Request<
            proto::xray::app::stats::command::GetAllOnlineUsersRequest,
        >,
    ) -> Result<
        Response<proto::xray::app::stats::command::GetAllOnlineUsersResponse>,
        Status,
    > {
        let entries = traffic::active_connections();
        let mut users = HashSet::new();
        for entry in entries {
            if let Some(identity) = entry.identity.as_ref() {
                users.insert(identity.clone());
            }
        }
        Ok(Response::new(
            proto::xray::app::stats::command::GetAllOnlineUsersResponse {
                users: users.into_iter().collect(),
            },
        ))
    }
}
enum OnlineKey {
    Inbound(String),
    User(String),
}

fn parse_online_name(name: &str) -> Option<OnlineKey> {
    let mut parts = name.split(">>>");
    let head = parts.next()?;
    let tag = parts.next()?;
    let tail = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if tail != "online" {
        return None;
    }
    match head {
        "inbound" => Some(OnlineKey::Inbound(tag.to_string())),
        "user" => Some(OnlineKey::User(tag.to_string())),
        _ => None,
    }
}
pub(super) fn build_service()
-> proto::xray::app::stats::command::stats_service_server::StatsServiceServer<
    StatsServiceImpl,
> {
    proto::xray::app::stats::command::stats_service_server::StatsServiceServer::new(
        StatsServiceImpl::new(),
    )
}

#[cfg(all(test, feature = "traffic"))]
mod tests {
    use super::proto::xray::app::stats::command::stats_service_server::StatsService;
    use super::*;
    use crate::traffic::{self, TrafficContext};
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
            .filter(|user| user.starts_with(&prefix))
            .collect();
        assert_eq!(matching.len(), 2);
        assert!(matching.iter().any(|user| *user == &user_a));
        assert!(matching.iter().any(|user| *user == &user_b));
    }

    #[tokio::test]
    async fn stats_invalid_online_name_returns_not_found() {
        let service = StatsServiceImpl::new();
        let tag = unique_tag("invalid");
        let name = format!("inbound>>>{tag}>>>traffic");
        let err = service
            .get_stats_online(Request::new(
                proto::xray::app::stats::command::GetStatsRequest {
                    name,
                    reset: false,
                },
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
}
