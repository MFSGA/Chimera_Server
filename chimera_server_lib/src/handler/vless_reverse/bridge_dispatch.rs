use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{ReadBuf, copy_bidirectional, duplex},
    sync::mpsc,
};
use tokio_util::sync::PollSender;

use crate::{
    address::NetLocation,
    async_stream::{
        AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage,
        AsyncShutdownMessage, AsyncStream, AsyncTargetedMessageStream,
        AsyncWriteSourcedMessage,
    },
    beginning::udp::run_multi_directional_udp,
    config::server_config::InboundSniffingConfig,
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    runtime::DataPlaneRuntime,
    session::sniff::{build_sniffed_route_plan, sniff_stream_protocol},
    traffic::TrafficContext,
};

use super::{
    bridge_worker::{
        BridgeTcpDispatcher, BridgeUdpRequest, BridgeUdpResponse, BridgeUdpSession,
    },
    session_stream::ReverseSessionStream,
};

const UDP_CHANNEL_CAPACITY: usize = 16;
const SNIFFING_RELAY_CAPACITY: usize = 16 * 1024;

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
        sniffing: Option<InboundSniffingConfig>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let source =
            source.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let resolver = self.resolver();

        let Some(sniffing) = sniffing else {
            let metadata = InboundRoutingMetadata {
                local_addr: local,
                inbound_protocol: Some("vless-reverse".to_string()),
                ..InboundRoutingMetadata::default()
            };
            let connection = connect_tcp_outbound_with_routing_metadata(
                &resolver,
                &target,
                self,
                reverse_tag,
                "",
                source,
                metadata,
            )
            .await?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("routing rejected VLESS Reverse Bridge target {target}"),
                )
            })?;

            return Ok(connection.stream);
        };

        let (mux_side, route_side) = duplex(SNIFFING_RELAY_CAPACITY);
        let runtime = self.clone();
        let reverse_tag = reverse_tag.to_string();
        let original_target = target.clone();
        if !self.spawn_inbound_connection(async move {
            let logical_stream: Box<dyn AsyncStream> =
                Box::new(ReverseSessionStream::new(route_side));
            let result = async {
                let (mut sniffed_stream, sniffed_metadata) =
                    sniff_stream_protocol(logical_stream, Some(&sniffing)).await?;
                let mut route_plan = build_sniffed_route_plan(
                    Some(&sniffing),
                    sniffed_metadata,
                    &original_target,
                    local,
                );
                route_plan.routing_metadata.inbound_protocol =
                    Some("vless-reverse".to_string());

                let connection = connect_tcp_outbound_with_routing_metadata(
                    &resolver,
                    &route_plan.outbound_target,
                    &runtime,
                    &reverse_tag,
                    "",
                    source,
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
                let mut remote = connection.stream;
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
            TrafficContext::new("vless-reverse").with_inbound_tag(reverse_tag);
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
