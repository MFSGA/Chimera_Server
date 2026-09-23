use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional, duplex},
    sync::mpsc,
};
use tokio_util::sync::PollSender;

use crate::{
    address::NetLocation,
    async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage,
        AsyncShutdownMessage, AsyncStream, AsyncTargetedMessageStream,
        AsyncWriteSourcedMessage, RawTcpRelayState,
    },
    beginning::udp::run_multi_directional_udp,
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    runtime::DataPlaneRuntime,
    session::sniff::{build_sniffed_route_plan, sniff_stream_protocol},
    traffic::{
        ConnectionGuard, MeteredStream, TrafficContext, TrafficDirection,
        record_transfer_ref, register_connection,
    },
};

use super::{
    bridge_worker::{
        BridgeDispatchContext, BridgeTcpDispatcher, BridgeUdpRequest,
        BridgeUdpResponse, BridgeUdpSession,
    },
    session_stream::ReverseSessionStream,
};

const UDP_CHANNEL_CAPACITY: usize = 16;
const SNIFFING_RELAY_CAPACITY: usize = 16 * 1024;

struct BridgeTrafficStream {
    inner: Box<dyn AsyncStream>,
    context: TrafficContext,
    _connection_guard: ConnectionGuard,
}

impl BridgeTrafficStream {
    fn new(inner: Box<dyn AsyncStream>, context: TrafficContext) -> Self {
        let connection_guard = register_connection(Some(&context));
        Self {
            inner,
            context,
            _connection_guard: connection_guard,
        }
    }
}

impl AsyncRead for BridgeTrafficStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = &result {
            let size = buffer.filled().len().saturating_sub(before) as u64;
            if size != 0 {
                record_transfer_ref(Some(&self.context), 0, size);
            }
        }
        result
    }
}

impl AsyncWrite for BridgeTrafficStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, buffer);
        if let Poll::Ready(Ok(size)) = result {
            if size != 0 {
                record_transfer_ref(Some(&self.context), size as u64, 0);
            }
            Poll::Ready(Ok(size))
        } else {
            result
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for BridgeTrafficStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Pin::new(&mut *self.inner).poll_write_ping(cx)
    }
}

impl AsyncStream for BridgeTrafficStream {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        self.inner.raw_tcp_relay_state()
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<std::os::fd::RawFd> {
        self.inner.raw_tcp_fd()
    }
}

fn reverse_traffic_context(
    runtime: &DataPlaneRuntime,
    reverse_tag: &str,
    source: Option<SocketAddr>,
    context: &BridgeDispatchContext,
) -> TrafficContext {
    let mut traffic_context = TrafficContext::new("vless-reverse")
        .with_inbound_tag(reverse_tag)
        .with_user_level(context.user_level);
    if !context.routing_user.is_empty() {
        traffic_context =
            traffic_context.with_identity(context.routing_user.clone());
    }
    if !context.policy_identity.is_empty() {
        traffic_context =
            traffic_context.with_policy_identity(context.policy_identity.clone());
    }
    if let Some(source) = source {
        traffic_context = traffic_context.with_client_ip(source.ip());
    }
    runtime.apply_traffic_stats_policy(&mut traffic_context);
    traffic_context
}

fn reverse_routing_metadata(
    local: Option<SocketAddr>,
    context: &BridgeDispatchContext,
) -> InboundRoutingMetadata {
    InboundRoutingMetadata {
        local_addr: local,
        policy_identities: if context.policy_identity.is_empty() {
            Vec::new()
        } else {
            vec![context.policy_identity.clone()]
        },
        inbound_protocol: Some("vless-reverse".to_string()),
        ..InboundRoutingMetadata::default()
    }
}

struct BridgeTargetedUdpStream {
    requests: mpsc::Receiver<BridgeUdpRequest>,
    responses: PollSender<BridgeUdpResponse>,
    write_shutdown: bool,
}

impl AsyncPing for BridgeTargetedUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncReadTargetedMessage for BridgeTargetedUdpStream {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<NetLocation>> {
        match Pin::new(&mut self.requests).poll_recv(cx) {
            Poll::Ready(Some(request)) => {
                if request.payload.len() > buffer.remaining() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Reverse Bridge UDP packet exceeds receive buffer",
                    )));
                }
                buffer.put_slice(&request.payload);
                Poll::Ready(Ok(request.target))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Reverse Bridge UDP logical session closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteSourcedMessage for BridgeTargetedUdpStream {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
        source: &SocketAddr,
    ) -> Poll<io::Result<()>> {
        if self.write_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Reverse Bridge UDP response side is closed",
            )));
        }
        match self.responses.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                self.responses
                    .send_item(BridgeUdpResponse {
                        payload: Bytes::copy_from_slice(payload),
                        source: *source,
                    })
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "Reverse Bridge UDP logical session closed",
                        )
                    })?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Reverse Bridge UDP logical session closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for BridgeTargetedUdpStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for BridgeTargetedUdpStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.write_shutdown {
            self.write_shutdown = true;
            self.responses.close();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncTargetedMessageStream for BridgeTargetedUdpStream {}

#[async_trait]
impl BridgeTcpDispatcher for DataPlaneRuntime {
    async fn open_tcp(
        &self,
        reverse_tag: &str,
        target: NetLocation,
        source: Option<SocketAddr>,
        local: Option<SocketAddr>,
        context: BridgeDispatchContext,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let routing_source =
            source.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let resolver = self.resolver();
        let traffic_context =
            reverse_traffic_context(self, reverse_tag, source, &context);

        let Some(sniffing) = context.sniffing.clone() else {
            let metadata = reverse_routing_metadata(local, &context);
            let connection = connect_tcp_outbound_with_routing_metadata(
                &resolver,
                &target,
                self,
                reverse_tag,
                &context.routing_user,
                routing_source,
                metadata,
            )
            .await?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("routing rejected VLESS Reverse Bridge target {target}"),
                )
            })?;

            let traffic_context = connection
                .outbound_tag
                .as_ref()
                .map_or(traffic_context.clone(), |tag| {
                    traffic_context.clone().with_outbound_tag(tag.clone())
                });
            return Ok(Box::new(BridgeTrafficStream::new(
                connection.stream,
                traffic_context,
            )));
        };

        let (mux_side, route_side) = duplex(SNIFFING_RELAY_CAPACITY);
        let runtime = self.clone();
        let reverse_tag = reverse_tag.to_string();
        let original_target = target.clone();
        if !self.spawn_inbound_connection(async move {
            let logical_stream: Box<dyn AsyncStream> =
                Box::new(ReverseSessionStream::new(route_side));
            let result = async {
                let (sniffed_stream, sniffed_metadata) =
                    sniff_stream_protocol(logical_stream, Some(&sniffing)).await?;
                let mut route_plan = build_sniffed_route_plan(
                    Some(&sniffing),
                    sniffed_metadata,
                    &original_target,
                    local,
                );
                let base_metadata = reverse_routing_metadata(local, &context);
                route_plan.routing_metadata.inbound_protocol =
                    base_metadata.inbound_protocol;
                route_plan.routing_metadata.policy_identities =
                    base_metadata.policy_identities;

                let connection = connect_tcp_outbound_with_routing_metadata(
                    &resolver,
                    &route_plan.outbound_target,
                    &runtime,
                    &reverse_tag,
                    &context.routing_user,
                    routing_source,
                    route_plan.routing_metadata,
                )
                .await?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!(
                            "routing rejected sniffed VLESS Reverse Bridge target {}",
                            route_plan.outbound_target
                        ),
                    )
                })?;
                let traffic_context = connection
                    .outbound_tag
                    .as_ref()
                    .map_or(traffic_context.clone(), |tag| {
                        traffic_context.clone().with_outbound_tag(tag.clone())
                    });
                let _connection_guard =
                    register_connection(Some(&traffic_context));
                let mut sniffed_stream = MeteredStream::new(
                    sniffed_stream,
                    Some(traffic_context.clone()),
                    TrafficDirection::Upload,
                );
                let mut remote = MeteredStream::new(
                    connection.stream,
                    Some(traffic_context),
                    TrafficDirection::Download,
                );
                copy_bidirectional(&mut sniffed_stream, &mut remote).await?;
                Ok::<(), std::io::Error>(())
            }
            .await;

            if let Err(error) = result {
                tracing::debug!(
                    reverse_tag = %reverse_tag,
                    target = %original_target,
                    %error,
                    "VLESS Reverse Bridge sniffed TCP relay ended with error"
                );
            }
        }) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "server is shutting down",
            ));
        }

        Ok(Box::new(ReverseSessionStream::new(mux_side)))
    }

    async fn open_udp(
        &self,
        reverse_tag: &str,
        source: Option<SocketAddr>,
        local: Option<SocketAddr>,
        context: BridgeDispatchContext,
    ) -> std::io::Result<BridgeUdpSession> {
        let peer =
            source.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let (request_sender, request_receiver) = mpsc::channel(UDP_CHANNEL_CAPACITY);
        let (response_sender, response_receiver) =
            mpsc::channel(UDP_CHANNEL_CAPACITY);
        let stream = BridgeTargetedUdpStream {
            requests: request_receiver,
            responses: PollSender::new(response_sender),
            write_shutdown: false,
        };
        let resolver = self.resolver();
        let runtime = self.clone();
        let traffic_context =
            reverse_traffic_context(self, reverse_tag, source, &context);
        if !self.spawn_inbound_connection(async move {
            let _ = run_multi_directional_udp(
                Box::new(stream),
                resolver,
                runtime,
                peer,
                local,
                Some(traffic_context),
            )
            .await;
        }) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "server is shutting down",
            ));
        }

        Ok(BridgeUdpSession {
            requests: request_sender,
            responses: response_receiver,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::def::OutboundItem,
        outbound::compile_static_outbound,
        runtime::RuntimeState,
        traffic::{active_connections, snapshot},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    #[test]
    fn reverse_traffic_context_preserves_xray_user_and_policy_identity() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new()).data_plane();
        let source: SocketAddr = "192.0.2.44:51000".parse().unwrap();
        let bridge = BridgeDispatchContext {
            sniffing: None,
            routing_user: "bridge@example.test".to_string(),
            policy_identity: "3ac9b383-75a1-431c-8184-106c80eb2273".to_string(),
            user_level: 7,
        };

        let context =
            reverse_traffic_context(&runtime, "bridge-in", Some(source), &bridge);

        assert_eq!(context.protocol, "vless-reverse");
        assert_eq!(context.identity.as_deref(), Some("bridge@example.test"));
        assert_eq!(
            context.policy_identities,
            vec!["3ac9b383-75a1-431c-8184-106c80eb2273".to_string()]
        );
        assert_eq!(context.inbound_tag.as_deref(), Some("bridge-in"));
        assert_eq!(context.client_ip, Some(source.ip()));
        assert_eq!(context.user_level, 7);
    }

    #[tokio::test]
    async fn reverse_source_reaches_freedom_proxy_protocol_consumer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind PROXY protocol sink");
        let target_addr = listener.local_addr().expect("read sink address");
        let item: OutboundItem = serde_json::from_value(serde_json::json!({
            "protocol": "freedom",
            "tag": "direct",
            "settings": {"proxyProtocol": 1}
        }))
        .expect("parse freedom proxyProtocol outbound");
        let outbound = compile_static_outbound(&item)
            .expect("compile freedom proxyProtocol outbound");
        let runtime = RuntimeState::new(Vec::new(), vec![outbound]).data_plane();
        let source: SocketAddr = "192.0.2.44:51000".parse().unwrap();
        let local: SocketAddr = "203.0.113.9:8443".parse().unwrap();

        let mut stream = runtime
            .open_tcp(
                "bridge-in",
                NetLocation::from_ip_addr(target_addr.ip(), target_addr.port()),
                Some(source),
                Some(local),
                BridgeDispatchContext::default(),
            )
            .await
            .expect("open Reverse Bridge TCP through freedom");
        stream
            .write_all(b"payload")
            .await
            .expect("write Reverse payload");

        let (mut accepted, _) =
            listener.accept().await.expect("accept freedom dial");
        let expected = format!(
            "PROXY TCP4 {} {} {} {}\r\npayload",
            source.ip(),
            target_addr.ip(),
            source.port(),
            target_addr.port()
        );
        let mut received = vec![0u8; expected.len()];
        accepted
            .read_exact(&mut received)
            .await
            .expect("read PROXY header and payload");
        assert_eq!(received, expected.as_bytes());
        assert!(
            !String::from_utf8_lossy(&received).contains(&local.ip().to_string()),
            "Xray freedom proxyProtocol uses inbound Source, not Reverse Local"
        );
    }

    #[cfg(feature = "traffic")]
    #[tokio::test]
    async fn bridge_traffic_stream_records_bytes_and_active_lifecycle() {
        let inbound_tag = "reverse-bridge-traffic-wrapper-test";
        let identity = "reverse-bridge-traffic@example.test";
        let before = snapshot()
            .per_inbound
            .get(inbound_tag)
            .cloned()
            .unwrap_or_default();

        let (inner, mut peer) = duplex(128);
        let context = TrafficContext::new("vless-reverse")
            .with_identity(identity)
            .with_inbound_tag(inbound_tag)
            .with_outbound_tag("direct")
            .with_client_ip("192.0.2.45".parse().unwrap());
        let mut stream = BridgeTrafficStream::new(
            Box::new(ReverseSessionStream::new(inner)),
            context,
        );

        assert!(active_connections().iter().any(|entry| {
            entry.inbound_tag.as_deref() == Some(inbound_tag)
                && entry.identity.as_deref() == Some(identity)
                && entry.client_ip == Some("192.0.2.45".parse().unwrap())
        }));

        stream.write_all(b"upload").await.unwrap();
        let mut upload = [0u8; 6];
        peer.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"upload");

        peer.write_all(b"download").await.unwrap();
        let mut download = [0u8; 8];
        stream.read_exact(&mut download).await.unwrap();
        assert_eq!(&download, b"download");

        drop(stream);
        assert!(
            !active_connections()
                .iter()
                .any(|entry| entry.inbound_tag.as_deref() == Some(inbound_tag))
        );

        let after = snapshot()
            .per_inbound
            .get(inbound_tag)
            .cloned()
            .unwrap_or_default();
        assert_eq!(after.upload_bytes.saturating_sub(before.upload_bytes), 6);
        assert_eq!(
            after.download_bytes.saturating_sub(before.download_bytes),
            8
        );
    }
}
