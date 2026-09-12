use super::proto;
use crate::{
    runtime::{RuntimeLifecycleState, RuntimeState},
    traffic,
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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
    runtime: Option<RuntimeState>,
}
impl StatsServiceImpl {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            reset: Arc::new(StatsReset::default()),
            runtime: None,
        }
    }

    fn with_runtime(runtime: RuntimeState) -> Self {
        Self {
            runtime: Some(runtime),
            ..Self::new()
        }
    }
    fn current_stats(&self) -> HashMap<String, i64> {
        let snapshot = traffic::snapshot();
        let mut stats = HashMap::new();

        for identity in snapshot.known_identities {
            stats
                .entry(format!("user>>>{identity}>>>traffic>>>uplink"))
                .or_insert(0);
            stats
                .entry(format!("user>>>{identity}>>>traffic>>>downlink"))
                .or_insert(0);
        }

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
        for (tag, totals) in snapshot.per_outbound {
            stats.insert(
                format!("outbound>>>{}>>>traffic>>>uplink", tag),
                totals.upload_bytes as i64,
            );
            stats.insert(
                format!("outbound>>>{}>>>traffic>>>downlink", tag),
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
                    if entry.inbound_tag.as_deref() == Some(&tag)
                        && let Some(ip) = entry.client_ip
                    {
                        if is_ignored_online_ip(ip) {
                            continue;
                        }
                        ips.insert(ip.to_string());
                    }
                }
            }
            OnlineKey::User(identity) => {
                for entry in entries {
                    if entry.identity.as_deref() == Some(&identity)
                        && let Some(ip) = entry.client_ip
                    {
                        if is_ignored_online_ip(ip) {
                            continue;
                        }
                        ips.insert(ip.to_string());
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
            if is_ignored_online_ip(ip) {
                continue;
            }
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

    fn collect_user_stats(&self) -> HashMap<String, UserStatsEntry> {
        let mut users = HashMap::new();
        for entry in traffic::active_connections() {
            let Some(identity) = entry.identity.as_ref() else {
                continue;
            };
            let Some(ip) = entry.client_ip else {
                continue;
            };

            let last_seen = entry
                .started_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            users
                .entry(identity.clone())
                .or_insert_with(|| UserStatsEntry::new(identity.clone()))
                .add_ip(ip.to_string(), last_seen);
        }
        users
    }

    fn user_traffic_value(
        &self,
        current_stats: &HashMap<String, i64>,
        email: &str,
        direction: &str,
        reset: bool,
    ) -> i64 {
        let name = format!("user>>>{email}>>>traffic>>>{direction}");
        match current_stats.get(&name).copied() {
            Some(value) => {
                if reset {
                    self.reset.reset(&name, value)
                } else {
                    value.saturating_sub(self.reset.read(&name))
                }
            }
            None => 0,
        }
    }

    fn sys_stats(&self) -> SysStatsSnapshot {
        let snapshot = SysStatsSnapshot {
            uptime: self.start_time.elapsed().as_secs() as u32,
            ..SysStatsSnapshot::default()
        };

        // Xray reads these values from the Go runtime. Rust doesn't expose
        // equivalent GC / allocator counters in std, so we only populate the
        // fields we can derive reliably from the current process and leave the
        // rest at 0 as an explicit compatibility fallback.
        #[cfg(target_os = "linux")]
        {
            let mut snapshot = snapshot;
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                if let Some(threads) = parse_status_kib_value(&status, "Threads:") {
                    snapshot.num_goroutine = threads as u32;
                }
                if let Some(alloc) = parse_status_kib_value(&status, "VmRSS:") {
                    snapshot.alloc = alloc.saturating_mul(1024);
                }
                if let Some(sys) = parse_status_kib_value(&status, "VmSize:") {
                    snapshot.sys = sys.saturating_mul(1024);
                }
            }
            snapshot
        }

        #[cfg(not(target_os = "linux"))]
        snapshot
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
            .ok_or_else(|| Status::not_found(not_found_message(&request.name)))?;
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
        let value = self
            .online_stats(&request.name)
            .ok_or_else(|| Status::not_found(not_found_message(&request.name)))?;
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
        if let Some(runtime) = &self.runtime {
            let lifecycle = runtime.lifecycle_state();
            if lifecycle != RuntimeLifecycleState::Running {
                return Err(Status::unavailable(format!(
                    "server is {}",
                    lifecycle.as_str()
                )));
            }
            if let Some(failure) = runtime.unhealthy_inbound() {
                return Err(Status::unavailable(format!(
                    "inbound {} generation {} is unhealthy",
                    failure.tag, failure.generation
                )));
            }
        }

        let stats = self.sys_stats();
        Ok(Response::new(
            proto::xray::app::stats::command::SysStatsResponse {
                num_goroutine: stats.num_goroutine,
                num_gc: stats.num_gc,
                alloc: stats.alloc,
                total_alloc: stats.total_alloc,
                sys: stats.sys,
                mallocs: stats.mallocs,
                frees: stats.frees,
                live_objects: stats.live_objects,
                pause_total_ns: stats.pause_total_ns,
                uptime: stats.uptime,
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
        let ips = self
            .online_ip_list(&request.name)
            .ok_or_else(|| Status::not_found(not_found_message(&request.name)))?;
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
            let Some(identity) = entry.identity.as_ref() else {
                continue;
            };
            let Some(ip) = entry.client_ip else {
                continue;
            };
            if is_ignored_online_ip(ip) {
                continue;
            }
            users.insert(user_online_name(identity));
        }
        Ok(Response::new(
            proto::xray::app::stats::command::GetAllOnlineUsersResponse {
                users: users.into_iter().collect(),
            },
        ))
    }

    async fn get_users_stats(
        &self,
        request: Request<proto::xray::app::stats::command::GetUsersStatsRequest>,
    ) -> Result<
        Response<proto::xray::app::stats::command::GetUsersStatsResponse>,
        Status,
    > {
        let request = request.into_inner();
        let current_stats = self.current_stats();
        let mut users = self.collect_user_stats();
        let mut response_users = Vec::with_capacity(users.len());

        for (email, mut user) in users.drain() {
            let mut ips = user
                .ips
                .drain()
                .map(|(ip, last_seen)| {
                    proto::xray::app::stats::command::OnlineIpEntry { ip, last_seen }
                })
                .collect::<Vec<_>>();
            ips.sort_by(|left, right| {
                left.ip
                    .cmp(&right.ip)
                    .then(left.last_seen.cmp(&right.last_seen))
            });

            let traffic = if request.include_traffic {
                let uplink = self.user_traffic_value(
                    &current_stats,
                    &email,
                    "uplink",
                    request.reset,
                );
                let downlink = self.user_traffic_value(
                    &current_stats,
                    &email,
                    "downlink",
                    request.reset,
                );
                Some(proto::xray::app::stats::command::TrafficUserStat {
                    uplink,
                    downlink,
                })
            } else {
                None
            };

            response_users.push(proto::xray::app::stats::command::UserStat {
                email: user.email,
                ips,
                traffic,
            });
        }

        response_users.sort_by(|left, right| left.email.cmp(&right.email));

        Ok(Response::new(
            proto::xray::app::stats::command::GetUsersStatsResponse {
                users: response_users,
            },
        ))
    }
}

#[derive(Default)]
struct SysStatsSnapshot {
    num_goroutine: u32,
    num_gc: u32,
    alloc: u64,
    total_alloc: u64,
    sys: u64,
    mallocs: u64,
    frees: u64,
    live_objects: u64,
    pause_total_ns: u64,
    uptime: u32,
}

enum OnlineKey {
    Inbound(String),
    User(String),
}

struct UserStatsEntry {
    email: String,
    ips: HashMap<String, i64>,
}

impl UserStatsEntry {
    fn new(email: String) -> Self {
        Self {
            email,
            ips: HashMap::new(),
        }
    }

    fn add_ip(&mut self, ip: String, last_seen: i64) {
        self.ips
            .entry(ip)
            .and_modify(|current| *current = (*current).max(last_seen))
            .or_insert(last_seen);
    }
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

fn is_ignored_online_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(addr) if addr == Ipv4Addr::LOCALHOST)
        || matches!(ip, IpAddr::V6(addr) if addr == Ipv6Addr::LOCALHOST)
}

fn user_online_name(identity: &str) -> String {
    format!("user>>>{identity}>>>online")
}

fn not_found_message(name: &str) -> String {
    format!("{name} not found.")
}

#[cfg(target_os = "linux")]
fn parse_status_kib_value(status: &str, key: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with(key))?;
    let value = line.split_ascii_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(value)
}

pub(super) fn build_service(
    runtime: RuntimeState,
) -> proto::xray::app::stats::command::stats_service_server::StatsServiceServer<
    StatsServiceImpl,
> {
    proto::xray::app::stats::command::stats_service_server::StatsServiceServer::new(
        StatsServiceImpl::with_runtime(runtime),
    )
}

#[cfg(all(test, feature = "traffic"))]
mod tests;
