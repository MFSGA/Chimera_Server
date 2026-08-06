use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

use super::{AccessContext, AccessIdentity, AccessTransport};

#[derive(Debug, Clone)]
pub struct TrafficContext {
    pub protocol: &'static str,
    pub identity: Option<String>,
    pub access_context: Option<Arc<AccessContext>>,
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
            access_context: None,
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

    fn access_context_mut(&mut self) -> &mut AccessContext {
        if self.access_context.is_none() {
            self.access_context = Some(Arc::new(AccessContext::default()));
        }
        Arc::make_mut(
            self.access_context
                .as_mut()
                .expect("access context initialized"),
        )
    }

    pub fn access_context(&self) -> Option<&AccessContext> {
        self.access_context.as_deref()
    }

    pub fn with_user_uuid(mut self, user_uuid: impl Into<String>) -> Self {
        self.access_context_mut().identity =
            Some(AccessIdentity::UserUuid(user_uuid.into()));
        self
    }

    pub fn with_protocol_identity(
        mut self,
        protocol_identity: impl Into<String>,
    ) -> Self {
        self.access_context_mut().identity =
            Some(AccessIdentity::Protocol(protocol_identity.into()));
        self
    }

    pub fn with_access_target(
        mut self,
        host: impl Into<String>,
        port: u16,
        transport: AccessTransport,
    ) -> Self {
        let context = self.access_context_mut();
        context.target_host = Some(host.into());
        context.target_port = Some(port);
        context.transport = transport;
        self
    }

    pub fn with_access_sni(mut self, sni: impl Into<String>) -> Self {
        self.access_context_mut().sni = Some(sni.into());
        self
    }

    pub fn set_access_sni(&mut self, sni: impl Into<String>) {
        self.access_context_mut().sni = Some(sni.into());
    }

    pub fn mark_tls_ech(&mut self) {
        let context = self.access_context_mut();
        context.tls_ech = true;
        context.sni = None;
    }

    pub fn with_access_http_host(mut self, host: impl Into<String>) -> Self {
        self.access_context_mut().http_host = Some(host.into());
        self
    }

    pub fn user_uuid(&self) -> Option<&str> {
        match self.access_context()?.identity.as_ref() {
            Some(AccessIdentity::UserUuid(value)) => Some(value),
            _ => None,
        }
    }

    pub fn protocol_identity(&self) -> Option<&str> {
        match self.access_context()?.identity.as_ref() {
            Some(AccessIdentity::Protocol(value)) => Some(value),
            _ => None,
        }
    }

    /// Returns the stable backend UUID when available, otherwise the protocol display identity.
    pub fn routing_identity(&self) -> Option<&str> {
        self.user_uuid().or(self.identity.as_deref())
    }

    pub fn set_user_uuid(&mut self, user_uuid: impl Into<String>) {
        self.access_context_mut().identity =
            Some(AccessIdentity::UserUuid(user_uuid.into()));
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

    pub fn with_client_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.client_ip = Some(addr.ip());
        self.access_context_mut().source_port = Some(addr.port());
        self
    }

    pub fn client_addr(&self) -> Option<std::net::SocketAddr> {
        Some(std::net::SocketAddr::new(
            self.client_ip?,
            self.access_context()?.source_port?,
        ))
    }

    pub fn with_user_level(mut self, level: u32) -> Self {
        self.user_level = level;
        self
    }

    pub fn set_user_stats_policy(
        &mut self,
        uplink: Option<bool>,
        downlink: Option<bool>,
        online: Option<bool>,
    ) {
        self.stats_user_uplink = uplink;
        self.stats_user_downlink = downlink;
        self.stats_user_online = online;
    }

    pub fn set_system_stats_policy(
        &mut self,
        inbound_uplink: Option<bool>,
        inbound_downlink: Option<bool>,
        outbound_uplink: Option<bool>,
        outbound_downlink: Option<bool>,
    ) {
        self.stats_inbound_uplink = inbound_uplink;
        self.stats_inbound_downlink = inbound_downlink;
        self.stats_outbound_uplink = outbound_uplink;
        self.stats_outbound_downlink = outbound_downlink;
    }
}

impl Default for TrafficContext {
    fn default() -> Self {
        Self {
            protocol: "unknown",
            identity: None,
            access_context: None,
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
}

#[derive(Debug, Clone, Default)]
pub struct TrafficSnapshot {
    pub total: TransferTotals,
    pub per_protocol: HashMap<String, TransferTotals>,
    pub per_identity: HashMap<(String, String), TransferTotals>,
    pub per_inbound: HashMap<String, TransferTotals>,
    pub per_outbound: HashMap<String, TransferTotals>,
    pub per_inbound_user: HashMap<(String, String), TransferTotals>,
}

#[derive(Debug, Default)]
struct StatsInner {
    total: TransferTotals,
    per_protocol: HashMap<String, TransferTotals>,
    per_identity: HashMap<(String, String), TransferTotals>,
    per_inbound: HashMap<String, TransferTotals>,
    per_outbound: HashMap<String, TransferTotals>,
    per_inbound_user: HashMap<(String, String), TransferTotals>,
}

impl StatsInner {
    fn record(&mut self, context: TrafficContext, upload: u64, download: u64) {
        self.total.accumulate(upload, download);

        let identity = context.identity.clone();
        let inbound_tag = context.inbound_tag.clone();
        let outbound_tag = context.outbound_tag.clone();
        let record_user_uplink = context.stats_user_uplink.unwrap_or(true);
        let record_user_downlink = context.stats_user_downlink.unwrap_or(true);
        let user_upload = if record_user_uplink { upload } else { 0 };
        let user_download = if record_user_downlink { download } else { 0 };
        let record_user = record_user_uplink || record_user_downlink;
        let record_inbound_uplink = context.stats_inbound_uplink.unwrap_or(true);
        let record_inbound_downlink = context.stats_inbound_downlink.unwrap_or(true);
        let inbound_upload = if record_inbound_uplink { upload } else { 0 };
        let inbound_download = if record_inbound_downlink { download } else { 0 };
        let record_inbound = record_inbound_uplink || record_inbound_downlink;
        let record_outbound_uplink = context.stats_outbound_uplink.unwrap_or(true);
        let record_outbound_downlink =
            context.stats_outbound_downlink.unwrap_or(true);
        let outbound_upload = if record_outbound_uplink { upload } else { 0 };
        let outbound_download = if record_outbound_downlink {
            download
        } else {
            0
        };
        let record_outbound = record_outbound_uplink || record_outbound_downlink;

        let protocol_entry = self
            .per_protocol
            .entry(context.protocol.to_string())
            .or_default();
        protocol_entry.accumulate(upload, download);

        if record_user && let Some(identity) = identity.clone() {
            let key = (context.protocol.to_string(), identity);
            let entry = self.per_identity.entry(key).or_default();
            entry.accumulate(user_upload, user_download);
        }

        if let Some(tag) = inbound_tag {
            if record_inbound {
                let inbound_entry = self.per_inbound.entry(tag.clone()).or_default();
                inbound_entry.accumulate(inbound_upload, inbound_download);
            }

            if record_user && let Some(identity) = identity {
                let key = (tag, identity);
                let entry = self.per_inbound_user.entry(key).or_default();
                entry.accumulate(user_upload, user_download);
            }
        }

        if record_outbound && let Some(tag) = outbound_tag {
            let outbound_entry = self.per_outbound.entry(tag).or_default();
            outbound_entry.accumulate(outbound_upload, outbound_download);
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

impl ActiveConnection {
    fn from_context(context: &TrafficContext) -> Self {
        let identity = if context.stats_user_online.unwrap_or(true) {
            context.identity.clone()
        } else {
            None
        };
        Self {
            inbound_tag: context.inbound_tag.clone(),
            identity,
            client_ip: context.client_ip,
            started_at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Default)]
struct ActiveConnectionsInner {
    connections: HashMap<u64, ActiveConnection>,
}

#[derive(Debug, Default)]
struct ActiveConnections {
    next_id: AtomicU64,
    inner: RwLock<ActiveConnectionsInner>,
}

impl ActiveConnections {
    fn global() -> &'static ActiveConnections {
        static INSTANCE: OnceLock<ActiveConnections> = OnceLock::new();
        INSTANCE.get_or_init(ActiveConnections::default)
    }

    fn insert(&self, entry: ActiveConnection) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner
            .write()
            .expect("active connections poisoned")
            .connections
            .insert(id, entry);
        id
    }

    fn remove(&self, id: u64) {
        self.inner
            .write()
            .expect("active connections poisoned")
            .connections
            .remove(&id);
    }

    fn snapshot(&self) -> Vec<ActiveConnectionSnapshot> {
        self.inner
            .read()
            .expect("active connections poisoned")
            .connections
            .values()
            .map(|entry| ActiveConnectionSnapshot {
                inbound_tag: entry.inbound_tag.clone(),
                identity: entry.identity.clone(),
                client_ip: entry.client_ip,
                started_at: entry.started_at,
            })
            .collect()
    }

    fn count(&self) -> usize {
        self.inner
            .read()
            .expect("active connections poisoned")
            .connections
            .len()
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

    let entry = ActiveConnection::from_context(context);

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
    use std::net::{IpAddr, Ipv4Addr};

    use super::{ActiveConnection, StatsInner, TrafficContext};

    #[test]
    fn user_stats_policy_filters_only_user_dimensions() {
        let mut stats = StatsInner::default();
        let mut context = TrafficContext::new("vless")
            .with_identity("alice")
            .with_inbound_tag("edge");
        context.set_user_stats_policy(Some(false), Some(true), None);

        stats.record(context, 100, 200);

        assert_eq!(stats.total.upload_bytes, 100);
        assert_eq!(stats.total.download_bytes, 200);
        assert_eq!(stats.per_protocol["vless"].upload_bytes, 100);
        assert_eq!(stats.per_protocol["vless"].download_bytes, 200);
        assert_eq!(stats.per_inbound["edge"].upload_bytes, 100);
        assert_eq!(stats.per_inbound["edge"].download_bytes, 200);

        let identity = stats
            .per_identity
            .get(&("vless".to_string(), "alice".to_string()))
            .expect("user protocol stats should exist");
        assert_eq!(identity.upload_bytes, 0);
        assert_eq!(identity.download_bytes, 200);
        let inbound_user = stats
            .per_inbound_user
            .get(&("edge".to_string(), "alice".to_string()))
            .expect("inbound user stats should exist");
        assert_eq!(inbound_user.upload_bytes, 0);
        assert_eq!(inbound_user.download_bytes, 200);
    }

    #[test]
    fn disabling_both_user_directions_omits_user_entries() {
        let mut stats = StatsInner::default();
        let mut context = TrafficContext::new("vmess")
            .with_identity("bob")
            .with_inbound_tag("edge");
        context.set_user_stats_policy(Some(false), Some(false), None);

        stats.record(context, 100, 200);

        assert!(stats.per_identity.is_empty());
        assert!(stats.per_inbound_user.is_empty());
        assert_eq!(stats.per_protocol["vmess"].upload_bytes, 100);
        assert_eq!(stats.per_inbound["edge"].download_bytes, 200);
    }

    #[test]
    fn online_stats_policy_hides_identity_but_preserves_connection_metadata() {
        let mut context = TrafficContext::new("vless")
            .with_identity("alice")
            .with_inbound_tag("edge")
            .with_client_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        context.set_user_stats_policy(None, None, Some(false));

        let hidden = ActiveConnection::from_context(&context);
        assert_eq!(hidden.inbound_tag.as_deref(), Some("edge"));
        assert_eq!(hidden.identity, None);
        assert_eq!(
            hidden.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );

        context.set_user_stats_policy(None, None, Some(true));
        let visible = ActiveConnection::from_context(&context);
        assert_eq!(visible.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn system_stats_policy_filters_inbound_and_outbound_directions() {
        let mut stats = StatsInner::default();
        let mut context = TrafficContext::new("trojan")
            .with_identity("carol")
            .with_inbound_tag("edge")
            .with_outbound_tag("direct");
        context.set_system_stats_policy(
            Some(false),
            Some(true),
            Some(true),
            Some(false),
        );

        stats.record(context, 100, 200);

        let inbound = stats
            .per_inbound
            .get("edge")
            .expect("inbound stats should exist");
        assert_eq!(inbound.upload_bytes, 0);
        assert_eq!(inbound.download_bytes, 200);
        let outbound = stats
            .per_outbound
            .get("direct")
            .expect("outbound stats should exist");
        assert_eq!(outbound.upload_bytes, 100);
        assert_eq!(outbound.download_bytes, 0);
        assert_eq!(stats.per_protocol["trojan"].upload_bytes, 100);
        assert_eq!(stats.per_protocol["trojan"].download_bytes, 200);
    }
}
