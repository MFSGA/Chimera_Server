use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
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
}

impl TrafficContext {
    pub const fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            identity: None,
            inbound_tag: None,
            outbound_tag: None,
            client_ip: None,
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
}

impl Default for TrafficContext {
    fn default() -> Self {
        Self {
            protocol: "unknown",
            identity: None,
            inbound_tag: None,
            outbound_tag: None,
            client_ip: None,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrafficRecordPlan {
    upload: u64,
    download: u64,
    protocol: String,
    known_identity: Option<String>,
    protocol_identity: Option<(String, String)>,
    inbound_tag: Option<String>,
    inbound_identity: Option<(String, String)>,
    outbound_tag: Option<String>,
}

fn plan_traffic_record(
    context: TrafficContext,
    upload: u64,
    download: u64,
) -> TrafficRecordPlan {
    let protocol = context.protocol.to_string();
    let known_identity = context.identity;
    let protocol_identity = known_identity
        .as_ref()
        .map(|identity| (protocol.clone(), identity.clone()));
    let inbound_identity = match (&context.inbound_tag, &known_identity) {
        (Some(tag), Some(identity)) => Some((tag.clone(), identity.clone())),
        _ => None,
    };

    TrafficRecordPlan {
        upload,
        download,
        protocol,
        known_identity,
        protocol_identity,
        inbound_tag: context.inbound_tag,
        inbound_identity,
        outbound_tag: context.outbound_tag,
    }
}

#[derive(Debug, Default)]
struct StatsInner {
    total: TransferTotals,
    per_protocol: HashMap<String, TransferTotals>,
    per_identity: HashMap<(String, String), TransferTotals>,
    per_inbound: HashMap<String, TransferTotals>,
    per_outbound: HashMap<String, TransferTotals>,
    per_inbound_user: HashMap<(String, String), TransferTotals>,
    known_identities: HashSet<String>,
}

impl StatsInner {
    fn apply(&mut self, plan: TrafficRecordPlan) {
        let TrafficRecordPlan {
            upload,
            download,
            protocol,
            known_identity,
            protocol_identity,
            inbound_tag,
            inbound_identity,
            outbound_tag,
        } = plan;

        self.total.accumulate(upload, download);
        if let Some(identity) = known_identity {
            self.known_identities.insert(identity);
        }
        self.per_protocol
            .entry(protocol)
            .or_default()
            .accumulate(upload, download);
        if let Some(key) = protocol_identity {
            self.per_identity
                .entry(key)
                .or_default()
                .accumulate(upload, download);
        }
        if let Some(tag) = inbound_tag {
            self.per_inbound
                .entry(tag)
                .or_default()
                .accumulate(upload, download);
        }
        if let Some(key) = inbound_identity {
            self.per_inbound_user
                .entry(key)
                .or_default()
                .accumulate(upload, download);
        }
        if let Some(tag) = outbound_tag {
            self.per_outbound
                .entry(tag)
                .or_default()
                .accumulate(upload, download);
        }
    }

    fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            total: self.total.clone(),
            per_protocol: self.per_protocol.clone(),
            per_identity: self.per_identity.clone(),
            per_inbound: self.per_inbound.clone(),
            per_outbound: self.per_outbound.clone(),
            per_inbound_user: self.per_inbound_user.clone(),
            known_identities: self.known_identities.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct TrafficRecorder {
    inner: RwLock<StatsInner>,
}

impl TrafficRecorder {
    fn global() -> &'static TrafficRecorder {
        static INSTANCE: OnceLock<TrafficRecorder> = OnceLock::new();
        INSTANCE.get_or_init(TrafficRecorder::default)
    }

    fn record(&self, context: TrafficContext, upload: u64, download: u64) {
        let plan = plan_traffic_record(context, upload, download);
        let mut guard = self.inner.write().expect("traffic stats poisoned");
        guard.apply(plan);
    }

    fn register_identity(&self, identity: impl Into<String>) {
        let identity = identity.into();
        if identity.is_empty() {
            return;
        }
        self.inner
            .write()
            .expect("traffic stats poisoned")
            .known_identities
            .insert(identity);
    }

    fn snapshot(&self) -> TrafficSnapshot {
        let guard = self.inner.read().expect("traffic stats poisoned");
        guard.snapshot()
    }
}

pub fn record_transfer(context: Option<TrafficContext>, upload: u64, download: u64) {
    let context = context.unwrap_or_default();
    TrafficRecorder::global().record(context, upload, download);
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

#[derive(Debug, Clone)]
struct ActiveConnection {
    inbound_tag: Option<String>,
    identity: Option<String>,
    client_ip: Option<IpAddr>,
    started_at: SystemTime,
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
        let guard = self.inner.read().expect("active connections poisoned");
        guard
            .values()
            .cloned()
            .map(|entry| ActiveConnectionSnapshot {
                inbound_tag: entry.inbound_tag,
                identity: entry.identity,
                client_ip: entry.client_ip,
                started_at: entry.started_at,
            })
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

    let entry = ActiveConnection {
        inbound_tag: context.inbound_tag.clone(),
        identity: context.identity.clone(),
        client_ip: context.client_ip,
        started_at: SystemTime::now(),
    };

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
        let plan = plan_traffic_record(
            TrafficContext::new("vless")
                .with_identity("alice")
                .with_inbound_tag("in")
                .with_outbound_tag("out"),
            7,
            11,
        );

        assert_eq!(plan.upload, 7);
        assert_eq!(plan.download, 11);
        assert_eq!(plan.protocol, "vless");
        assert_eq!(plan.known_identity.as_deref(), Some("alice"));
        assert_eq!(
            plan.protocol_identity,
            Some(("vless".to_string(), "alice".to_string()))
        );
        assert_eq!(plan.inbound_tag.as_deref(), Some("in"));
        assert_eq!(
            plan.inbound_identity,
            Some(("in".to_string(), "alice".to_string()))
        );
        assert_eq!(plan.outbound_tag.as_deref(), Some("out"));
    }

    #[test]
    fn applying_traffic_record_plan_updates_every_index_consistently() {
        let mut stats = StatsInner::default();
        stats.apply(plan_traffic_record(
            TrafficContext::new("vmess")
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
}
