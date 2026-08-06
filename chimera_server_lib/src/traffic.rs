#[cfg(feature = "traffic")]
#[path = "traffic_impl.rs"]
mod traffic_impl;

#[cfg(feature = "traffic")]
pub use traffic_impl::*;

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream, RawTcpRelayState};

/// Identity metadata used by per-user access policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessIdentity {
    UserUuid(String),
    Protocol(String),
}

/// Transport carrying the policy-controlled connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessTransport {
    Tcp,
    Udp,
    Quic,
    #[default]
    Unknown,
}

/// Shared access-control metadata assembled by inbound handlers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessContext {
    pub identity: Option<AccessIdentity>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub source_port: Option<u16>,
    pub sni: Option<String>,
    pub tls_ech: bool,
    pub http_host: Option<String>,
    pub transport: AccessTransport,
}

#[derive(Clone, Copy)]
pub enum TrafficDirection {
    Upload,
    Download,
}

pub struct MeteredStream<S> {
    inner: S,
    context: Option<TrafficContext>,
    direction: TrafficDirection,
}

impl<S> MeteredStream<S> {
    pub fn new(
        inner: S,
        context: Option<TrafficContext>,
        direction: TrafficDirection,
    ) -> Self {
        Self {
            inner,
            context,
            direction,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let bytes = buf.filled().len().saturating_sub(before) as u64;
            if bytes != 0 {
                let (upload, download) = match self.direction {
                    TrafficDirection::Upload => (bytes, 0),
                    TrafficDirection::Download => (0, bytes),
                };
                record_transfer(self.context.clone(), upload, download);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for MeteredStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncStream for MeteredStream<S> {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        self.inner.raw_tcp_relay_state()
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<std::os::fd::RawFd> {
        self.inner.raw_tcp_fd()
    }
}

/// No-op implementations when the "traffic" feature is disabled.
#[cfg(not(feature = "traffic"))]
mod traffic_noop {
    use std::{collections::HashMap, net::IpAddr, sync::Arc, time::SystemTime};

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

    #[derive(Debug, Clone, Default)]
    pub struct TrafficSnapshot {
        pub total: TransferTotals,
        pub per_protocol: HashMap<String, TransferTotals>,
        pub per_identity: HashMap<(String, String), TransferTotals>,
        pub per_inbound: HashMap<String, TransferTotals>,
        pub per_outbound: HashMap<String, TransferTotals>,
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
    ActiveConnectionSnapshot, ConnectionGuard, TrafficContext, TrafficSnapshot,
    TransferTotals, active_connection_count, active_connections, record_transfer,
    register_connection, snapshot,
};

#[cfg(all(test, feature = "traffic"))]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn routing_identity_prefers_stable_backend_uuid() {
        let context = TrafficContext::new("test")
            .with_identity("protocol-user")
            .with_protocol_identity("protocol-credential");
        assert_eq!(context.routing_identity(), Some("protocol-user"));

        let context = context.with_user_uuid("11111111-1111-4111-8111-111111111111");
        assert_eq!(
            context.routing_identity(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(context.identity.as_deref(), Some("protocol-user"));
    }

    #[tokio::test]
    async fn metered_stream_records_bytes_before_stream_closes() {
        let tag = "metered-stream-live";
        let context = TrafficContext::new("test")
            .with_inbound_tag(tag)
            .with_outbound_tag(tag)
            .with_identity(tag);
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader =
            MeteredStream::new(reader, Some(context), TrafficDirection::Upload);

        writer.write_all(b"live").await.unwrap();
        let mut bytes = [0; 4];
        reader.read_exact(&mut bytes).await.unwrap();

        let totals = snapshot().per_outbound.remove(tag).unwrap();
        assert_eq!(totals.upload_bytes, 4);
        assert_eq!(totals.download_bytes, 0);
    }
}
