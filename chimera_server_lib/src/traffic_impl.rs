use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        OnceLock, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::SystemTime,
};

#[derive(Debug, Clone)]
pub struct TrafficContext {
    pub protocol: &'static str,
    pub identity: Option<String>,
    pub inbound_tag: Option<String>,
    pub outbound_tag: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub user_level: u32,
    pub stats_user_uplink: Option<bool>,
    pub stats_user_downlink: Option<bool>,
    pub stats_user_online: Option<bool>,
    pub stats_inbound_uplink: Option<bool>,
    pub stats_inbound_downlink: Option<bool>,
    pub stats_outbound_uplink: Option<bool>,
    pub stats_outbound_downlink: Option<bool>,
}

impl TrafficContext {
    pub const fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            identity: None,
            inbound_tag: None,
            outbound_tag: None,
            client_ip: None,
            user_level: 0,
            stats_user_uplink: None,
            stats_user_downlink: None,
            stats_user_online: None,
            stats_inbound_uplink: None,
            stats_inbound_downlink: None,
            stats_outbound_uplink: None,
            stats_outbound_downlink: None,
        }
    }

    pub fn with_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    pub fn with_inbound_tag(mut self, tag: impl Into<String>) -> Self {
        self.inbound_tag = Some(tag.into());
        self
    }

    pub fn with_outbound_tag(mut self, tag: impl Into<String>) -> Self {
        self.outbound_tag = Some(tag.into());
        self
    }

    pub fn with_client_ip(mut self, ip: IpAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }

    pub fn with_user_level(mut self, level: u32) -> Self {
        self.user_level = level;
        self
    }

    pub fn set_user_stats_policy(
        &mut self,
        uplink: bool,
        downlink: bool,
        online: bool,
    ) {
        self.stats_user_uplink = Some(uplink);
        self.stats_user_downlink = Some(downlink);
        self.stats_user_online = Some(online);
    }

    pub fn set_system_stats_policy(
        &mut self,
        inbound_uplink: bool,
        inbound_downlink: bool,
        outbound_uplink: bool,
        outbound_downlink: bool,
    ) {
        self.stats_inbound_uplink = Some(inbound_uplink);
        self.stats_inbound_downlink = Some(inbound_downlink);
        self.stats_outbound_uplink = Some(outbound_uplink);
        self.stats_outbound_downlink = Some(outbound_downlink);
    }
}

impl Default for TrafficContext {
    fn default() -> Self {
        Self {
            protocol: "unknown",
            identity: None,
            inbound_tag: None,
            outbound_tag: None,
            client_ip: None,
            user_level: 0,
            stats_user_uplink: None,
            stats_user_downlink: None,
            stats_user_online: None,
            stats_inbound_uplink: None,
            stats_inbound_downlink: None,
            stats_outbound_uplink: None,
            stats_outbound_downlink: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransferTotals {
    pub connections: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl TransferTotals {
    fn accumulate(&mut self, upload: u64, download: u64) {
        self.connections = self.connections.saturating_add(1);
        self.upload_bytes = self.upload_bytes.saturating_add(upload);
        self.download_bytes = self.download_bytes.saturating_add(download);
    }

    fn merge(&mut self, other: &Self) {
        self.connections = self.connections.saturating_add(other.connections);
        self.upload_bytes = self.upload_bytes.saturating_add(other.upload_bytes);
        self.download_bytes =
            self.download_bytes.saturating_add(other.download_bytes);
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrafficSnapshot {
    pub total: TransferTotals,
    pub per_protocol: HashMap<String, TransferTotals>,
    pub per_identity: HashMap<(String, String), TransferTotals>,
    pub per_inbound: HashMap<String, TransferTotals>,
    pub per_outbound: HashMap<String, TransferTotals>,
    pub per_inbound_user: HashMap<(String, String), TransferTotals>,
    pub known_identities: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrafficRecordPlan<'a> {
    upload: u64,
    download: u64,
    protocol: &'static str,
    identity: Option<&'a str>,
    inbound_tag: Option<&'a str>,
    outbound_tag: Option<&'a str>,
    record_user: bool,
    user_upload: u64,
    user_download: u64,
    record_inbound: bool,
    inbound_upload: u64,
    inbound_download: u64,
    record_outbound: bool,
    outbound_upload: u64,
    outbound_download: u64,
}

fn plan_traffic_record<'a>(
    context: &'a TrafficContext,
    upload: u64,
    download: u64,
) -> TrafficRecordPlan<'a> {
    let record_user_uplink = context.stats_user_uplink.unwrap_or(true);
    let record_user_downlink = context.stats_user_downlink.unwrap_or(true);
    let record_inbound_uplink = context.stats_inbound_uplink.unwrap_or(true);
    let record_inbound_downlink = context.stats_inbound_downlink.unwrap_or(true);
    let record_outbound_uplink = context.stats_outbound_uplink.unwrap_or(true);
    let record_outbound_downlink = context.stats_outbound_downlink.unwrap_or(true);

    TrafficRecordPlan {
        upload,
        download,
        protocol: context.protocol,
        identity: context.identity.as_deref(),
        inbound_tag: context.inbound_tag.as_deref(),
        outbound_tag: context.outbound_tag.as_deref(),
        record_user: record_user_uplink || record_user_downlink,
        user_upload: if record_user_uplink { upload } else { 0 },
        user_download: if record_user_downlink { download } else { 0 },
        record_inbound: record_inbound_uplink || record_inbound_downlink,
        inbound_upload: if record_inbound_uplink { upload } else { 0 },
        inbound_download: if record_inbound_downlink { download } else { 0 },
        record_outbound: record_outbound_uplink || record_outbound_downlink,
        outbound_upload: if record_outbound_uplink { upload } else { 0 },
        outbound_download: if record_outbound_downlink {
            download
        } else {
            0
        },
    }
}

#[derive(Debug, Default)]
struct InboundStats {
    totals: TransferTotals,
    per_user: HashMap<String, TransferTotals>,
}

#[derive(Debug, Default)]
struct IdentityProtocolStats {
    totals: TransferTotals,
    per_identity: HashMap<String, TransferTotals>,
}

#[derive(Debug, Default)]
struct StatsInner {
    total: TransferTotals,
    per_protocol: HashMap<&'static str, TransferTotals>,
    per_identity: HashMap<&'static str, IdentityProtocolStats>,
    per_inbound: HashMap<String, InboundStats>,
    per_outbound: HashMap<String, TransferTotals>,
    known_identities: HashSet<String>,
}

fn accumulate_string_key(
    totals: &mut HashMap<String, TransferTotals>,
    key: &str,
    upload: u64,
    download: u64,
) -> bool {
    if let Some(existing) = totals.get_mut(key) {
        existing.accumulate(upload, download);
        return false;
    }
    let mut value = TransferTotals::default();
    value.accumulate(upload, download);
    totals.insert(key.to_owned(), value);
    true
}

fn accumulate_inbound(
    totals: &mut HashMap<String, InboundStats>,
    inbound: &str,
    identity: Option<&str>,
    inbound_totals: Option<(u64, u64)>,
    user_totals: Option<(u64, u64)>,
) {
    if inbound_totals.is_none() && (identity.is_none() || user_totals.is_none()) {
        return;
    }

    let stats = totals.entry(inbound.to_owned()).or_default();
    if let Some((upload, download)) = inbound_totals {
        stats.totals.accumulate(upload, download);
    }
    if let (Some(identity), Some((upload, download))) = (identity, user_totals) {
        accumulate_string_key(&mut stats.per_user, identity, upload, download);
    }
}

impl StatsInner {
    fn apply(&mut self, plan: TrafficRecordPlan<'_>) {
        let TrafficRecordPlan {
            upload,
            download,
            protocol,
            identity,
            inbound_tag,
            outbound_tag,
            record_user,
            user_upload,
            user_download,
            record_inbound,
            inbound_upload,
            inbound_download,
            record_outbound,
            outbound_upload,
            outbound_download,
        } = plan;

        self.total.accumulate(upload, download);
        if let Some(identity) = identity {
            let protocol_stats = self.per_identity.entry(protocol).or_default();
            protocol_stats.totals.accumulate(upload, download);
            if record_user {
                let identity_inserted = accumulate_string_key(
                    &mut protocol_stats.per_identity,
                    identity,
                    user_upload,
                    user_download,
                );
                if identity_inserted && !self.known_identities.contains(identity) {
                    self.known_identities.insert(identity.to_owned());
                }
            }
        } else {
            self.per_protocol
                .entry(protocol)
                .or_default()
                .accumulate(upload, download);
        }
        if let Some(tag) = inbound_tag {
            accumulate_inbound(
                &mut self.per_inbound,
                tag,
                identity,
                record_inbound.then_some((inbound_upload, inbound_download)),
                record_user.then_some((user_upload, user_download)),
            );
        }
        if record_outbound && let Some(tag) = outbound_tag {
            accumulate_string_key(
                &mut self.per_outbound,
                tag,
                outbound_upload,
                outbound_download,
            );
        }
    }

    fn snapshot(&self) -> TrafficSnapshot {
        let mut snapshot = TrafficSnapshot::default();
        merge_stats_into_snapshot(&mut snapshot, self);
        snapshot
    }
}

const TRAFFIC_SHARD_COUNT: usize = 32;

thread_local! {
    static TRAFFIC_SHARD_INDEX: Cell<Option<usize>> = const { Cell::new(None) };
}

fn merge_string_totals_map(
    target: &mut HashMap<String, TransferTotals>,
    source: &HashMap<String, TransferTotals>,
) {
    for (key, totals) in source {
        target.entry(key.clone()).or_default().merge(totals);
    }
}

fn merge_stats_into_snapshot(snapshot: &mut TrafficSnapshot, stats: &StatsInner) {
    snapshot.total.merge(&stats.total);
    for (protocol, totals) in &stats.per_protocol {
        snapshot
            .per_protocol
            .entry((*protocol).to_owned())
            .or_default()
            .merge(totals);
    }
    for (protocol, protocol_stats) in &stats.per_identity {
        snapshot
            .per_protocol
            .entry((*protocol).to_owned())
            .or_default()
            .merge(&protocol_stats.totals);
        for (identity, totals) in &protocol_stats.per_identity {
            snapshot
                .per_identity
                .entry(((*protocol).to_owned(), identity.clone()))
                .or_default()
                .merge(totals);
        }
    }
    for (inbound, inbound_stats) in &stats.per_inbound {
        if inbound_stats.totals.connections != 0 {
            snapshot
                .per_inbound
                .entry(inbound.clone())
                .or_default()
                .merge(&inbound_stats.totals);
        }
        for (identity, totals) in &inbound_stats.per_user {
            snapshot
                .per_inbound_user
                .entry((inbound.clone(), identity.clone()))
                .or_default()
                .merge(totals);
        }
    }
    merge_string_totals_map(&mut snapshot.per_outbound, &stats.per_outbound);
    snapshot
        .known_identities
        .extend(stats.known_identities.iter().cloned());
}

#[derive(Debug)]
struct TrafficRecorder {
    shards: [RwLock<StatsInner>; TRAFFIC_SHARD_COUNT],
    next_thread_shard: AtomicUsize,
}

impl Default for TrafficRecorder {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(StatsInner::default())),
            next_thread_shard: AtomicUsize::new(0),
        }
    }
}

impl TrafficRecorder {
    fn global() -> &'static TrafficRecorder {
        static INSTANCE: OnceLock<TrafficRecorder> = OnceLock::new();
        INSTANCE.get_or_init(TrafficRecorder::default)
    }

    fn current_thread_shard_index(&self) -> usize {
        TRAFFIC_SHARD_INDEX.with(|slot| {
            if let Some(index) = slot.get() {
                return index;
            }
            let index = self.next_thread_shard.fetch_add(1, Ordering::Relaxed)
                % TRAFFIC_SHARD_COUNT;
            slot.set(Some(index));
            index
        })
    }

    fn current_thread_shard(&self) -> &RwLock<StatsInner> {
        &self.shards[self.current_thread_shard_index()]
    }

    fn record(&self, context: &TrafficContext, upload: u64, download: u64) {
        let plan = plan_traffic_record(context, upload, download);
        let mut guard = self
            .current_thread_shard()
            .write()
            .expect("traffic stats shard poisoned");
        guard.apply(plan);
    }

    fn register_identity(&self, identity: impl Into<String>) {
        let identity = identity.into();
        if identity.is_empty() {
            return;
        }
        self.current_thread_shard()
            .write()
            .expect("traffic stats shard poisoned")
            .known_identities
            .insert(identity);
    }

    fn snapshot(&self) -> TrafficSnapshot {
        let mut snapshot = TrafficSnapshot::default();
        for shard in &self.shards {
            let guard = shard.read().expect("traffic stats shard poisoned");
            merge_stats_into_snapshot(&mut snapshot, &guard);
        }
        snapshot
    }
}

pub fn record_transfer(context: Option<TrafficContext>, upload: u64, download: u64) {
    match context.as_ref() {
        Some(context) => TrafficRecorder::global().record(context, upload, download),
        None => TrafficRecorder::global().record(
            &TrafficContext::default(),
            upload,
            download,
        ),
    }
}

pub fn record_transfer_ref(
    context: Option<&TrafficContext>,
    upload: u64,
    download: u64,
) {
    match context {
        Some(context) => TrafficRecorder::global().record(context, upload, download),
        None => TrafficRecorder::global().record(
            &TrafficContext::default(),
            upload,
            download,
        ),
    }
}

/// Register identities known from configuration before they generate traffic.
/// Xray exposes zero-valued user stats immediately, which lets panel clients
/// establish a baseline without dropping the first live sample.
pub fn register_identity(identity: impl Into<String>) {
    TrafficRecorder::global().register_identity(identity);
}

pub fn snapshot() -> TrafficSnapshot {
    TrafficRecorder::global().snapshot()
}

#[derive(Debug, Clone)]
pub struct ActiveConnectionSnapshot {
    pub inbound_tag: Option<String>,
    pub identity: Option<String>,
    pub client_ip: Option<IpAddr>,
    pub started_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveConnection {
    inbound_tag: Option<String>,
    identity: Option<String>,
    client_ip: Option<IpAddr>,
    started_at: SystemTime,
}

fn plan_active_connection(
    context: &TrafficContext,
    started_at: SystemTime,
) -> ActiveConnection {
    ActiveConnection {
        inbound_tag: context.inbound_tag.clone(),
        identity: if context.stats_user_online.unwrap_or(true) {
            context.identity.clone()
        } else {
            None
        },
        client_ip: context.client_ip,
        started_at,
    }
}

impl From<ActiveConnection> for ActiveConnectionSnapshot {
    fn from(entry: ActiveConnection) -> Self {
        Self {
            inbound_tag: entry.inbound_tag,
            identity: entry.identity,
            client_ip: entry.client_ip,
            started_at: entry.started_at,
        }
    }
}

#[derive(Debug, Default)]
struct ActiveConnections {
    next_id: AtomicU64,
    inner: RwLock<HashMap<u64, ActiveConnection>>,
}

impl ActiveConnections {
    fn global() -> &'static ActiveConnections {
        static INSTANCE: OnceLock<ActiveConnections> = OnceLock::new();
        INSTANCE.get_or_init(ActiveConnections::default)
    }

    fn insert(&self, entry: ActiveConnection) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.write().expect("active connections poisoned");
        guard.insert(id, entry);
        id
    }

    fn remove(&self, id: u64) {
        let mut guard = self.inner.write().expect("active connections poisoned");
        guard.remove(&id);
    }

    fn snapshot(&self) -> Vec<ActiveConnectionSnapshot> {
        let entries = {
            let guard = self.inner.read().expect("active connections poisoned");
            guard.values().cloned().collect::<Vec<_>>()
        };
        entries
            .into_iter()
            .map(ActiveConnectionSnapshot::from)
            .collect()
    }

    fn count(&self) -> usize {
        let guard = self.inner.read().expect("active connections poisoned");
        guard.len()
    }
}

#[derive(Debug)]
pub struct ConnectionGuard {
    id: Option<u64>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            ActiveConnections::global().remove(id);
        }
    }
}

pub fn register_connection(context: Option<&TrafficContext>) -> ConnectionGuard {
    let context = match context {
        Some(ctx) => ctx,
        None => {
            return ConnectionGuard { id: None };
        }
    };

    let entry = plan_active_connection(context, SystemTime::now());
    let id = ActiveConnections::global().insert(entry);
    ConnectionGuard { id: Some(id) }
}

pub fn active_connections() -> Vec<ActiveConnectionSnapshot> {
    ActiveConnections::global().snapshot()
}

pub fn active_connection_count() -> usize {
    ActiveConnections::global().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_record_plan_derives_all_index_keys_before_mutation() {
        let context = TrafficContext::new("vless")
            .with_identity("alice")
            .with_inbound_tag("in")
            .with_outbound_tag("out");
        let plan = plan_traffic_record(&context, 7, 11);

        assert_eq!(plan.upload, 7);
        assert_eq!(plan.download, 11);
        assert_eq!(plan.protocol, "vless");
        assert_eq!(plan.identity, Some("alice"));
        assert_eq!(plan.inbound_tag, Some("in"));
        assert_eq!(plan.outbound_tag, Some("out"));
    }

    #[test]
    fn applying_traffic_record_plan_updates_every_index_consistently() {
        let mut stats = StatsInner::default();
        stats.apply(plan_traffic_record(
            &TrafficContext::new("vmess")
                .with_identity("bob")
                .with_inbound_tag("edge")
                .with_outbound_tag("direct"),
            13,
            17,
        ));
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.total.connections, 1);
        assert_eq!(snapshot.total.upload_bytes, 13);
        assert_eq!(snapshot.total.download_bytes, 17);
        assert_eq!(snapshot.per_protocol["vmess"].upload_bytes, 13);
        assert_eq!(
            snapshot.per_identity[&("vmess".to_string(), "bob".to_string())]
                .download_bytes,
            17
        );
        assert_eq!(snapshot.per_inbound["edge"].connections, 1);
        assert_eq!(
            snapshot.per_inbound_user[&("edge".to_string(), "bob".to_string())]
                .connections,
            1
        );
        assert_eq!(snapshot.per_outbound["direct"].connections, 1);
        assert!(snapshot.known_identities.contains("bob"));
    }
    #[test]
    fn inbound_totals_and_users_share_internal_entry_without_changing_snapshot() {
        let mut stats = StatsInner::default();
        for context in [
            TrafficContext::new("vless")
                .with_identity("alice")
                .with_inbound_tag("edge"),
            TrafficContext::new("vless")
                .with_identity("bob")
                .with_inbound_tag("edge"),
            TrafficContext::new("dokodemo-door").with_inbound_tag("edge"),
        ] {
            stats.apply(plan_traffic_record(&context, 5, 7));
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.per_inbound["edge"].connections, 3);
        assert_eq!(snapshot.per_inbound["edge"].upload_bytes, 15);
        assert_eq!(snapshot.per_inbound["edge"].download_bytes, 21);
        assert_eq!(
            snapshot.per_inbound_user[&("edge".to_string(), "alice".to_string())]
                .connections,
            1
        );
        assert_eq!(
            snapshot.per_inbound_user[&("edge".to_string(), "bob".to_string())]
                .connections,
            1
        );
        assert_eq!(snapshot.per_inbound_user.len(), 2);
    }

    #[test]
    fn protocol_totals_and_identities_share_internal_entry_without_changing_snapshot()
     {
        let mut stats = StatsInner::default();
        for context in [
            TrafficContext::new("vless").with_identity("alice"),
            TrafficContext::new("vless").with_identity("bob"),
            TrafficContext::new("vless"),
        ] {
            stats.apply(plan_traffic_record(&context, 5, 7));
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.per_protocol["vless"].connections, 3);
        assert_eq!(snapshot.per_protocol["vless"].upload_bytes, 15);
        assert_eq!(snapshot.per_protocol["vless"].download_bytes, 21);
        assert_eq!(
            snapshot.per_identity[&("vless".to_string(), "alice".to_string())]
                .connections,
            1
        );
        assert_eq!(
            snapshot.per_identity[&("vless".to_string(), "bob".to_string())]
                .connections,
            1
        );
        assert_eq!(snapshot.per_identity.len(), 2);
    }

    #[test]
    fn known_identity_remains_deduplicated_across_protocol_maps() {
        let mut stats = StatsInner::default();
        stats.known_identities.insert("alice".to_owned());

        for protocol in ["vless", "shadowsocks"] {
            stats.apply(plan_traffic_record(
                &TrafficContext::new(protocol).with_identity("alice"),
                7,
                11,
            ));
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.known_identities.len(), 1);
        assert!(snapshot.known_identities.contains("alice"));
        assert_eq!(
            snapshot.per_identity[&("vless".to_string(), "alice".to_string())]
                .connections,
            1
        );
        assert_eq!(
            snapshot.per_identity[&("shadowsocks".to_string(), "alice".to_string())]
                .connections,
            1
        );
    }

    #[test]
    fn stats_policy_filters_user_and_system_dimensions_independently() {
        let mut stats = StatsInner::default();
        let mut context = TrafficContext::new("vless")
            .with_identity("alice")
            .with_inbound_tag("edge")
            .with_outbound_tag("direct");
        context.set_user_stats_policy(true, false, true);
        context.set_system_stats_policy(false, true, true, false);

        stats.apply(plan_traffic_record(&context, 100, 200));
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.total.upload_bytes, 100);
        assert_eq!(snapshot.total.download_bytes, 200);
        assert_eq!(snapshot.per_protocol["vless"].upload_bytes, 100);
        assert_eq!(snapshot.per_protocol["vless"].download_bytes, 200);

        let user =
            &snapshot.per_identity[&("vless".to_string(), "alice".to_string())];
        assert_eq!(user.upload_bytes, 100);
        assert_eq!(user.download_bytes, 0);

        let inbound = &snapshot.per_inbound["edge"];
        assert_eq!(inbound.upload_bytes, 0);
        assert_eq!(inbound.download_bytes, 200);
        let inbound_user =
            &snapshot.per_inbound_user[&("edge".to_string(), "alice".to_string())];
        assert_eq!(inbound_user.upload_bytes, 100);
        assert_eq!(inbound_user.download_bytes, 0);

        let outbound = &snapshot.per_outbound["direct"];
        assert_eq!(outbound.upload_bytes, 100);
        assert_eq!(outbound.download_bytes, 0);
    }

    #[test]
    fn disabled_system_stats_do_not_create_zero_valued_dimension_entries() {
        let mut stats = StatsInner::default();
        let mut context = TrafficContext::new("trojan")
            .with_identity("alice")
            .with_inbound_tag("edge")
            .with_outbound_tag("direct");
        context.set_user_stats_policy(true, true, false);
        context.set_system_stats_policy(false, false, false, false);

        stats.apply(plan_traffic_record(&context, 7, 11));
        let snapshot = stats.snapshot();

        assert!(!snapshot.per_inbound.contains_key("edge"));
        assert!(!snapshot.per_outbound.contains_key("direct"));
        assert!(
            snapshot
                .per_inbound_user
                .contains_key(&("edge".to_string(), "alice".to_string()))
        );
    }

    #[test]
    fn online_stats_policy_hides_identity_but_keeps_connection_metadata() {
        let started_at = SystemTime::UNIX_EPOCH;
        let mut context = TrafficContext::new("vless")
            .with_identity("alice")
            .with_inbound_tag("edge")
            .with_client_ip("192.0.2.1".parse().expect("test ip"));
        context.set_user_stats_policy(true, true, false);

        let hidden = plan_active_connection(&context, started_at);
        assert_eq!(hidden.inbound_tag.as_deref(), Some("edge"));
        assert_eq!(hidden.identity, None);
        assert_eq!(
            hidden.client_ip,
            Some("192.0.2.1".parse().expect("test ip"))
        );
        assert_eq!(hidden.started_at, started_at);

        context.set_user_stats_policy(true, true, true);
        let visible = plan_active_connection(&context, started_at);
        assert_eq!(visible.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn sharded_recorder_aggregates_concurrent_updates_exactly() {
        const WRITERS: usize = 8;
        const RECORDS_PER_WRITER: usize = 256;

        let recorder = std::sync::Arc::new(TrafficRecorder::default());
        let writers = (0..WRITERS)
            .map(|_| {
                let recorder = std::sync::Arc::clone(&recorder);
                std::thread::spawn(move || {
                    for _ in 0..RECORDS_PER_WRITER {
                        recorder.record(
                            &TrafficContext::new("vless")
                                .with_identity("alice")
                                .with_inbound_tag("edge")
                                .with_outbound_tag("direct"),
                            7,
                            11,
                        );
                    }
                })
            })
            .collect::<Vec<_>>();

        for writer in writers {
            writer.join().expect("traffic writer thread");
        }

        let expected_records = (WRITERS * RECORDS_PER_WRITER) as u64;
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.total.connections, expected_records);
        assert_eq!(snapshot.total.upload_bytes, expected_records * 7);
        assert_eq!(snapshot.total.download_bytes, expected_records * 11);
        assert_eq!(snapshot.per_protocol["vless"].connections, expected_records);
        assert_eq!(snapshot.per_inbound["edge"].connections, expected_records);
        assert_eq!(
            snapshot.per_outbound["direct"].connections,
            expected_records
        );
        assert_eq!(
            snapshot.per_identity[&("vless".to_string(), "alice".to_string())]
                .connections,
            expected_records
        );
        assert_eq!(
            snapshot.per_inbound_user[&("edge".to_string(), "alice".to_string())]
                .connections,
            expected_records
        );
        assert!(snapshot.known_identities.contains("alice"));
    }

    #[test]
    fn sharded_recorder_assigns_stable_shards_per_thread() {
        const WRITERS: usize = 8;

        let recorder = std::sync::Arc::new(TrafficRecorder::default());
        let writers = (0..WRITERS)
            .map(|_| {
                let recorder = std::sync::Arc::clone(&recorder);
                std::thread::spawn(move || {
                    let first = recorder.current_thread_shard_index();
                    let second = recorder.current_thread_shard_index();
                    assert_eq!(first, second);
                    first
                })
            })
            .collect::<Vec<_>>();
        let mut indices = writers
            .into_iter()
            .map(|writer| writer.join().expect("traffic writer thread"))
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();

        assert_eq!(indices.len(), WRITERS);
    }

    #[test]
    fn active_connection_plan_and_snapshot_conversion_are_pure() {
        let started_at = SystemTime::UNIX_EPOCH;
        let context = TrafficContext::new("vless")
            .with_identity("alice")
            .with_inbound_tag("edge")
            .with_client_ip("127.0.0.1".parse().expect("loopback ip"));
        let entry = plan_active_connection(&context, started_at);

        assert_eq!(entry.inbound_tag.as_deref(), Some("edge"));
        assert_eq!(entry.identity.as_deref(), Some("alice"));
        assert_eq!(entry.client_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(entry.started_at, started_at);

        let snapshot = ActiveConnectionSnapshot::from(entry);
        assert_eq!(snapshot.inbound_tag.as_deref(), Some("edge"));
        assert_eq!(snapshot.identity.as_deref(), Some("alice"));
        assert_eq!(snapshot.client_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(snapshot.started_at, started_at);
    }
}
