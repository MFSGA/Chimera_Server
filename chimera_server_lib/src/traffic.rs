use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
};

#[derive(Debug, Clone)]
pub struct TrafficContext {
    pub protocol: &'static str,
    pub identity: Option<String>,
}

impl TrafficContext {
    pub const fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            identity: None,
        }
    }

    pub fn with_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }
}

impl Default for TrafficContext {
    fn default() -> Self {
        Self {
            protocol: "unknown",
            identity: None,
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
}

#[derive(Debug, Default)]
struct StatsInner {
    total: TransferTotals,
    per_protocol: HashMap<String, TransferTotals>,
    per_identity: HashMap<(String, String), TransferTotals>,
}

impl StatsInner {
    fn record(&mut self, context: TrafficContext, upload: u64, download: u64) {
        self.total.accumulate(upload, download);

        let protocol_entry = self
            .per_protocol
            .entry(context.protocol.to_string())
            .or_default();
        protocol_entry.accumulate(upload, download);

        if let Some(identity) = context.identity {
            let key = (context.protocol.to_string(), identity);
            let entry = self.per_identity.entry(key).or_default();
            entry.accumulate(upload, download);
        }
    }

    fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            total: self.total.clone(),
            per_protocol: self.per_protocol.clone(),
            per_identity: self.per_identity.clone(),
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
