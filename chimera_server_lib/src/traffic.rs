use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock, RwLock,
    },
    time::SystemTime,
};

#[derive(Debug, Clone)]
pub struct TrafficContext {
    pub protocol: &'static str,
    pub identity: Option<String>,
    pub inbound_tag: Option<String>,
    pub client_ip: Option<IpAddr>,
}

impl TrafficContext {
    pub const fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            identity: None,
            inbound_tag: None,
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
    pub per_inbound_user: HashMap<(String, String), TransferTotals>,
}

#[derive(Debug, Default)]
struct StatsInner {
    total: TransferTotals,
    per_protocol: HashMap<String, TransferTotals>,
    per_identity: HashMap<(String, String), TransferTotals>,
    per_inbound: HashMap<String, TransferTotals>,
    per_inbound_user: HashMap<(String, String), TransferTotals>,
}

impl StatsInner {
    fn record(&mut self, context: TrafficContext, upload: u64, download: u64) {
        self.total.accumulate(upload, download);

        let identity = context.identity.clone();
        let inbound_tag = context.inbound_tag.clone();

        let protocol_entry = self
            .per_protocol
            .entry(context.protocol.to_string())
            .or_default();
        protocol_entry.accumulate(upload, download);

        if let Some(identity) = identity.clone() {
            let key = (context.protocol.to_string(), identity);
            let entry = self.per_identity.entry(key).or_default();
            entry.accumulate(upload, download);
        }

        if let Some(tag) = inbound_tag {
            let inbound_entry = self.per_inbound.entry(tag.clone()).or_default();
            inbound_entry.accumulate(upload, download);

            if let Some(identity) = identity {
                let key = (tag, identity);
                let entry = self.per_inbound_user.entry(key).or_default();
                entry.accumulate(upload, download);
            }
        }
    }

    fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            total: self.total.clone(),
            per_protocol: self.per_protocol.clone(),
            per_identity: self.per_identity.clone(),
            per_inbound: self.per_inbound.clone(),
            per_inbound_user: self.per_inbound_user.clone(),
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
        let mut guard = self.inner.write().expect("traffic stats poisoned");
        guard.record(context, upload, download);
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
