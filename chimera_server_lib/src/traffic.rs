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

use crate::async_stream::{AsyncPing, AsyncStream};

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

impl<S: AsyncStream> AsyncStream for MeteredStream<S> {}

/// No-op implementations when the "traffic" feature is disabled.
#[cfg(not(feature = "traffic"))]
mod traffic_noop {
    use std::{collections::HashMap, net::IpAddr, time::SystemTime};

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
