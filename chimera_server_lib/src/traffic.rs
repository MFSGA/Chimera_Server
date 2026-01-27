#[cfg(feature = "traffic")]
#[path = "traffic_impl.rs"]
mod traffic_impl;

#[cfg(feature = "traffic")]
pub use traffic_impl::*;

/// No-op implementations when the "traffic" feature is disabled.
#[cfg(not(feature = "traffic"))]
mod traffic_noop {
    use std::{collections::HashMap, net::IpAddr, time::SystemTime};

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

    #[derive(Debug, Clone, Default)]
    pub struct TrafficSnapshot {
        pub total: TransferTotals,
        pub per_protocol: HashMap<String, TransferTotals>,
        pub per_identity: HashMap<(String, String), TransferTotals>,
        pub per_inbound: HashMap<String, TransferTotals>,
        pub per_inbound_user: HashMap<(String, String), TransferTotals>,
    }

    #[derive(Debug, Clone)]
    pub struct ActiveConnectionSnapshot {
        pub inbound_tag: Option<String>,
        pub identity: Option<String>,
        pub client_ip: Option<IpAddr>,
        pub started_at: SystemTime,
    }

    #[derive(Debug)]
    pub struct ConnectionGuard;

    impl ConnectionGuard {
        fn new() -> Self {
            Self
        }
    }

    pub fn record_transfer(_: Option<TrafficContext>, _: u64, _: u64) {
        tracing::warn!(
            "Traffic recording is disabled because the 'traffic' feature is not enabled."
        );
    }

    pub fn snapshot() -> TrafficSnapshot {
        TrafficSnapshot::default()
    }

    pub fn register_connection(_: Option<&TrafficContext>) -> ConnectionGuard {
        ConnectionGuard::new()
    }

    pub fn active_connections() -> Vec<ActiveConnectionSnapshot> {
        Vec::new()
    }

    pub fn active_connection_count() -> usize {
        0
    }
}

#[cfg(not(feature = "traffic"))]
pub use traffic_noop::{
    active_connection_count, active_connections, record_transfer, register_connection, snapshot,
    ActiveConnectionSnapshot, ConnectionGuard, TrafficContext, TrafficSnapshot, TransferTotals,
};
