use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream, RawTcpRelayState},
    config::server_config::InboundSniffingConfig,
    handler::{
        http::relay_plain_http_response,
        socks::run_udp_relay_with_expected_client,
        tcp::tcp_handler::{
            TcpServerConnectionContext, TcpServerHandler, TcpServerSetupOutcome,
            TcpServerSetupResult,
        },
    },
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    session::{
        policy_stream::copy_bidirectional_with_timeouts_and_accounting,
        sniff::{SniffedRoutePlan, build_sniffed_route_plan, sniff_stream_protocol},
        tcp_relay::{self, RelayTrafficAccounting},
        udp::{
            run_bidirectional_udp, run_multi_directional_udp, run_session_based_udp,
        },
    },
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, record_transfer,
        register_connection,
    },
    transport::tcp::build_proxy_protocol_header,
    util::prefixed_stream::PrefixedStream,
};

use tracing::{info, warn};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum TcpRelayShutdownPolicy {
    #[default]
    Propagate,
    PreserveDestinationWriteAfterUplinkEof,
}

#[derive(Default)]
pub(crate) struct TcpRelayOptions {
    pub(crate) sniffing: Option<InboundSniffingConfig>,
    pub(crate) shutdown_policy: TcpRelayShutdownPolicy,
}

// Xray's stream-one TCP relay keeps reading the destination after its request
// body ends, and does not send that EOF as a TCP FIN to the destination.
// The final dispatcher shutdown flips `force_shutdown` so every exit still
// closes the actual outbound stream. This wrapper also disables raw relay
// paths, which would bypass the deferred shutdown behavior.
struct XrayStreamOneTarget {
    inner: Box<dyn AsyncStream>,
    force_shutdown: Arc<AtomicBool>,
    deferred_shutdown: bool,
}

impl XrayStreamOneTarget {
    fn new(inner: Box<dyn AsyncStream>, force_shutdown: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            force_shutdown,
            deferred_shutdown: false,
        }
    }
}

impl AsyncRead for XrayStreamOneTarget {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for XrayStreamOneTarget {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.force_shutdown.load(Ordering::Acquire) && !self.deferred_shutdown {
            self.deferred_shutdown = true;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for XrayStreamOneTarget {
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

impl AsyncStream for XrayStreamOneTarget {
    fn raw_tcp_relay_state(&self) -> RawTcpRelayState {
        RawTcpRelayState::Unavailable
    }

    #[cfg(unix)]
    fn raw_tcp_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

fn normalize_tcp_fallback(
    setup_outcome: TcpServerSetupOutcome,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> std::io::Result<TcpServerSetupOutcome> {
    match setup_outcome {
        TcpServerSetupOutcome::TcpFallback {
            remote_location,
            stream,
            proxy_protocol_version,
            traffic_context,
        } => {
            let prefix = build_proxy_protocol_header(
                proxy_protocol_version,
                peer_addr,
                local_addr,
            )?;
            Ok(TcpServerSetupOutcome::TcpForward {
                remote_location,
                stream: Box::new(PrefixedStream::new(prefix, stream)),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            })
        }
        outcome => Ok(outcome),
    }
}

pub(crate) fn normalize_setup_result(
    setup_result: TcpServerSetupResult,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> std::io::Result<(SocketAddr, TcpServerSetupOutcome)> {
    let normalized = setup_result.into_normalized();
    let peer_addr = normalized.peer_addr_override.unwrap_or(peer_addr);
    normalize_tcp_fallback(normalized.outcome, peer_addr, local_addr)
        .map(|setup_outcome| (peer_addr, setup_outcome))
}

pub(crate) fn routing_identity(
    traffic_context: Option<&TrafficContext>,
) -> (&str, &str) {
    let inbound_tag = traffic_context
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default();
    let user = traffic_context
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default();
    (inbound_tag, user)
}

pub(crate) fn stream_connection_context(
    runtime: &DataPlaneRuntime,
    local_addr: Option<SocketAddr>,
) -> TcpServerConnectionContext {
    TcpServerConnectionContext {
        local_addr,
        handshake_runtime: Some(runtime.inbound_handshake_runtime()),
        ..TcpServerConnectionContext::default()
    }
}

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    connection_context: TcpServerConnectionContext,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    server_handler
        .setup_server_stream_with_context(Box::new(stream), connection_context)
        .await
}

async fn setup_routed_client_stream(
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    user: &str,
    peer_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<(Box<dyn AsyncStream>, Option<String>)>> {
    connect_tcp_outbound_with_routing_metadata(
        &resolver,
        &remote_location,
        runtime,
        inbound_tag,
        user,
        peer_addr,
        routing_metadata,
    )
    .await
    .map(|connection| {
        connection.map(|connection| {
            (
                Box::new(connection.stream) as Box<dyn AsyncStream>,
                connection.outbound_tag,
            )
        })
    })
}

pub(crate) async fn process_stream_with_sniffing_and_local_addr<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    runtime: DataPlaneRuntime,
    sniffing: Option<InboundSniffingConfig>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let connection_context = stream_connection_context(&runtime, local_addr);
    process_stream_with_context(
        stream,
        server_handler,
        resolver,
        peer_addr,
        runtime,
        connection_context,
        sniffing,
    )
    .await
}

pub(crate) async fn process_stream_with_context<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
    connection_context: TcpServerConnectionContext,
    sniffing: Option<InboundSniffingConfig>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    process_stream_with_context_and_options(
        stream,
        server_handler,
        resolver,
        peer_addr,
        runtime,
        connection_context,
        TcpRelayOptions {
            sniffing,
            ..TcpRelayOptions::default()
        },
    )
    .await
}

pub(crate) async fn process_stream_with_context_and_options<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
    connection_context: TcpServerConnectionContext,
    options: TcpRelayOptions,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let TcpRelayOptions {
        sniffing,
        shutdown_policy: relay_shutdown_policy,
    } = options;
    let local_addr = connection_context.local_addr;
    let handler_manages_handshake_timeout =
        server_handler.manages_handshake_timeout();
    tracing::info!("prepare to setup server stream");
    let setup_result = if handler_manages_handshake_timeout {
        setup_server_stream(stream, server_handler, connection_context.clone())
            .await
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("failed to setup server stream: {}", e),
                )
            })?
    } else {
        match timeout(
            Duration::from_secs(60),
            setup_server_stream(stream, server_handler, connection_context.clone()),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to setup server stream: {}", e),
                ));
            }
            Err(elapsed) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("server setup timed out: {}", elapsed),
                ));
            }
        }
    };
    let (mut peer_addr, mut setup_outcome) =
        normalize_setup_result(setup_result, peer_addr, local_addr)?;

    while matches!(
        &setup_outcome,
        TcpServerSetupOutcome::HttpPlainForward { .. }
    ) {
        let TcpServerSetupOutcome::HttpPlainForward {
            remote_location,
            stream: mut server_stream,
            request_head,
            request_method,
            keep_alive,
            next_handler,
            traffic_context,
        } = setup_outcome
        else {
            unreachable!("HTTP plain-forward loop only accepts HTTP results");
        };
        let mut traffic_context =
            traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));
        if let Some(context) = traffic_context.as_mut() {
            runtime.apply_traffic_stats_policy(context);
        }
        let (inbound_tag, user) = routing_identity(traffic_context.as_ref());
        let (client_stream, outbound_tag) = match timeout(
            Duration::from_secs(60),
            setup_routed_client_stream(
                resolver.clone(),
                remote_location.clone(),
                &runtime,
                inbound_tag,
                user,
                peer_addr,
                InboundRoutingMetadata {
                    local_addr,
                    inbound_protocol: traffic_context
                        .as_ref()
                        .map(|context| context.protocol.to_string()),
                    policy_identities: traffic_context
                        .as_ref()
                        .map(|context| context.policy_identities.clone())
                        .unwrap_or_default(),
                    ..InboundRoutingMetadata::default()
                },
            ),
        )
        .await
        {
            Ok(Ok(Some(result))) => result,
            Ok(Ok(None)) => {
                let _ = server_stream.shutdown().await;
                return Ok(());
            }
            Ok(Err(error)) => {
                let _ = server_stream.shutdown().await;
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to setup HTTP client stream to {}: {}",
                        remote_location, error
                    ),
                ));
            }
            Err(elapsed) => {
                let _ = server_stream.shutdown().await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "HTTP client setup to {} timed out: {}",
                        remote_location, elapsed
                    ),
                ));
            }
        };
        if let Some(tag) = outbound_tag {
            traffic_context =
                traffic_context.map(|context| context.with_outbound_tag(tag));
        }
        let _connection_guard = register_connection(traffic_context.as_ref());
        let mut client_stream = MeteredStream::new(
            client_stream,
            traffic_context.clone(),
            TrafficDirection::Download,
        );
        client_stream.write_all(&request_head).await?;
        client_stream.flush().await?;
        record_transfer(traffic_context, request_head.len() as u64, 0);

        let response_reusable = relay_plain_http_response(
            &mut client_stream,
            &mut server_stream,
            &request_method,
        )
        .await?;
        let _ = client_stream.shutdown().await;
        if !keep_alive || !response_reusable {
            let _ = server_stream.shutdown().await;
            return Ok(());
        }

        let next_result = if next_handler.manages_handshake_timeout() {
            match next_handler
                .setup_server_stream_with_context(
                    server_stream,
                    connection_context.clone(),
                )
                .await
            {
                Ok(result) => result,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        } else {
            match timeout(
                Duration::from_secs(60),
                next_handler.setup_server_stream_with_context(
                    server_stream,
                    connection_context.clone(),
                ),
            )
            .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return Ok(());
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Ok(()),
            }
        };
        (peer_addr, setup_outcome) =
            normalize_setup_result(next_result, peer_addr, local_addr)?;
    }

    match setup_outcome {
        TcpServerSetupOutcome::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: _need_initial_flush,
            connection_success_response,
            traffic_context,
        } => {
            let mut traffic_context = traffic_context
                .map(|context| context.with_client_ip(peer_addr.ip()));
            if let Some(context) = traffic_context.as_mut() {
                runtime.apply_traffic_stats_policy(context);
            }
            let (sniffed_stream, sniffed_metadata) =
                sniff_stream_protocol(server_stream, sniffing.as_ref()).await?;
            server_stream = sniffed_stream;
            let SniffedRoutePlan {
                outbound_target: outbound_remote_location,
                routing_metadata,
            } = build_sniffed_route_plan(
                sniffing.as_ref(),
                sniffed_metadata,
                &remote_location,
                local_addr,
            );
            let (inbound_tag, user) = routing_identity(traffic_context.as_ref());

            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_routed_client_stream(
                    resolver,
                    outbound_remote_location.clone(),
                    &runtime,
                    inbound_tag,
                    user,
                    peer_addr,
                    {
                        let mut routing_metadata = routing_metadata;
                        routing_metadata.inbound_protocol = traffic_context
                            .as_ref()
                            .map(|context| context.protocol.to_string());
                        routing_metadata.policy_identities = traffic_context
                            .as_ref()
                            .map(|context| context.policy_identities.clone())
                            .unwrap_or_default();
                        routing_metadata
                    },
                ),
            );

            let (mut client_stream, outbound_tag) =
                match setup_client_stream_future.await {
                    Ok(Ok(Some(result))) => result,
                    Ok(Ok(None)) => {
                        let _ = server_stream.shutdown().await;
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        let _ = server_stream.shutdown().await;
                        return Err(std::io::Error::new(
                            e.kind(),
                            format!(
                                "failed to setup client stream to {}: {}",
                                outbound_remote_location, e
                            ),
                        ));
                    }
                    Err(elapsed) => {
                        let _ = server_stream.shutdown().await;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "client setup to {} timed out: {}",
                                outbound_remote_location, elapsed
                            ),
                        ));
                    }
                };
            let force_target_shutdown = match relay_shutdown_policy {
                TcpRelayShutdownPolicy::Propagate => None,
                TcpRelayShutdownPolicy::PreserveDestinationWriteAfterUplinkEof => {
                    let force_shutdown = Arc::new(AtomicBool::new(false));
                    client_stream = Box::new(XrayStreamOneTarget::new(
                        client_stream,
                        force_shutdown.clone(),
                    ));
                    Some(force_shutdown)
                }
            };
            if let Some(tag) = outbound_tag {
                traffic_context =
                    traffic_context.map(|context| context.with_outbound_tag(tag));
            }
            let user_level = traffic_context
                .as_ref()
                .map_or(0, |context| context.user_level);
            let _connection_guard = register_connection(traffic_context.as_ref());
            let relay_accounting =
                RelayTrafficAccounting::new(traffic_context.clone());
            let mut server_stream = MeteredStream::new(
                server_stream,
                traffic_context.clone(),
                TrafficDirection::Upload,
            );
            let mut client_stream = MeteredStream::new(
                client_stream,
                traffic_context,
                TrafficDirection::Download,
            );

            if let Some(data) = connection_success_response {
                server_stream.write_all(&data).await?;
            }

            let relay_timeouts = runtime.policy_relay_timeouts(user_level);
            let copy_result = if relay_timeouts.is_empty() {
                tcp_relay::copy_bidirectional_with_accounting(
                    &mut server_stream,
                    &mut client_stream,
                    relay_accounting.clone(),
                )
                .await
            } else {
                copy_bidirectional_with_timeouts_and_accounting(
                    &mut server_stream,
                    &mut client_stream,
                    relay_timeouts,
                    relay_accounting.clone(),
                )
                .await
            };

            if let Some(force_shutdown) = force_target_shutdown {
                force_shutdown.store(true, Ordering::Release);
            }
            let (_, _) =
                futures::join!(server_stream.shutdown(), client_stream.shutdown());
            let copy_result = match copy_result {
                Ok(result) => result,
                Err(error) => {
                    if let Some(partial) =
                        tcp_relay::partial_result_from_error(&error)
                    {
                        warn!(
                            relay_backend = partial.configured_backend(),
                            relay_path = partial.effective_path(),
                            relay_fallback = partial
                                .fallback_reason()
                                .unwrap_or("none"),
                            bypassed_upload = partial.bypassed_left_to_right,
                            bypassed_download = partial.bypassed_right_to_left,
                            %error,
                            "tcp forward stopped after relay error: client->remote {} bytes, remote->client {} bytes",
                            partial.left_to_right,
                            partial.right_to_left,
                        );
                    }
                    return Err(error);
                }
            };

            info!(
                relay_backend = copy_result.configured_backend(),
                relay_path = copy_result.effective_path(),
                relay_fallback = copy_result.fallback_reason().unwrap_or("none"),
                bypassed_upload = copy_result.bypassed_left_to_right,
                bypassed_download = copy_result.bypassed_right_to_left,
                "tcp forward to {} completed: client->remote {} bytes, remote->client {} bytes",
                outbound_remote_location,
                copy_result.left_to_right,
                copy_result.right_to_left,
            );
            Ok(())
        }
        TcpServerSetupOutcome::HttpPlainForward { .. } => {
            unreachable!(
                "HTTP plain-forward results must be handled before generic forwarding"
            )
        }
        TcpServerSetupOutcome::TcpFallback { .. } => {
            unreachable!("fallback result must be normalized before forwarding")
        }
        TcpServerSetupOutcome::UdpAssociate {
            stream,
            udp_socket,
            expected_client,
            user_level,
            traffic_context,
        } => {
            let mut traffic_context = traffic_context
                .map(|context| context.with_client_ip(peer_addr.ip()));
            if let Some(context) = traffic_context.as_mut() {
                runtime.apply_traffic_stats_policy(context);
            }
            let resolver = runtime.resolver();
            run_udp_relay_with_expected_client(
                udp_socket,
                stream,
                resolver,
                runtime,
                Some(expected_client),
                user_level,
                traffic_context,
            )
            .await
        }
        TcpServerSetupOutcome::BidirectionalUdp {
            remote_location,
            stream,
            mut traffic_context,
        } => {
            if let Some(context) = traffic_context.as_mut() {
                runtime.apply_traffic_stats_policy(context);
            }
            run_bidirectional_udp(
                stream,
                remote_location,
                resolver,
                runtime,
                peer_addr,
                local_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupOutcome::MultiDirectionalUdp {
            stream,
            mut traffic_context,
        } => {
            if let Some(context) = traffic_context.as_mut() {
                runtime.apply_traffic_stats_policy(context);
            }
            run_multi_directional_udp(
                stream,
                resolver,
                runtime,
                peer_addr,
                local_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupOutcome::SessionBasedUdp {
            stream,
            mut traffic_context,
        } => {
            if let Some(context) = traffic_context.as_mut() {
                runtime.apply_traffic_stats_policy(context);
            }
            run_session_based_udp(
                stream,
                runtime,
                peer_addr,
                local_addr,
                traffic_context,
            )
            .await
        }
        #[cfg(feature = "vless-reverse")]
        TcpServerSetupOutcome::ReversePortal {
            reverse_tag,
            mut stream,
            connection_success_response,
            mut traffic_context,
        } => {
            if let Some(context) = traffic_context.as_mut() {
                context.client_ip = Some(peer_addr.ip());
                runtime.apply_traffic_stats_policy(context);
            }
            runtime.ensure_reverse_portal(&reverse_tag)?;
            let _connection_guard = register_connection(traffic_context.as_ref());
            if let Some(data) = connection_success_response {
                stream.write_all(&data).await?;
                stream.flush().await?;
            }
            let lease = runtime
                .attach_reverse_portal(&reverse_tag, stream)
                .await
                .map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to register VLESS Reverse portal {reverse_tag}: {error}"
                        ),
                    )
                })?;
            info!(
                reverse_tag = %reverse_tag,
                worker_id = lease.worker_id(),
                "registered VLESS Reverse Portal worker"
            );
            lease.run().await
        }
        TcpServerSetupOutcome::Completed => Ok(()),
    }
}

#[cfg(test)]
mod xray_stream_one_target_tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::timeout;

    use super::XrayStreamOneTarget;

    #[tokio::test]
    async fn defers_uplink_shutdown_and_forces_close_at_session_end() {
        let (inner, mut peer) = duplex(64);
        let force_shutdown = Arc::new(AtomicBool::new(false));
        let mut target =
            XrayStreamOneTarget::new(Box::new(inner), force_shutdown.clone());

        target.write_all(b"request").await.expect("write request");
        let mut request = [0_u8; 7];
        peer.read_exact(&mut request).await.expect("read request");
        assert_eq!(&request, b"request");

        target.shutdown().await.expect("defer request EOF");
        let mut byte = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(20), peer.read(&mut byte))
                .await
                .is_err(),
            "deferred request EOF must keep destination readable"
        );

        peer.write_all(b"response")
            .await
            .expect("write response after request EOF");
        let mut response = [0_u8; 8];
        target
            .read_exact(&mut response)
            .await
            .expect("read response after request EOF");
        assert_eq!(&response, b"response");

        force_shutdown.store(true, Ordering::Release);
        target.shutdown().await.expect("force final shutdown");
        assert_eq!(peer.read(&mut byte).await.expect("read final EOF"), 0);
    }
}
