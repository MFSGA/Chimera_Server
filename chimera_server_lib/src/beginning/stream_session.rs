use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
    beginning::{
        build_proxy_protocol_header, policy_stream, tcp_relay,
        udp::{
            run_bidirectional_udp, run_multi_directional_udp, run_session_based_udp,
        },
    },
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
    resolver::{NativeResolver, Resolver, resolve_single_address},
    runtime::DataPlaneRuntime,
    tls_client_hello::{ClientHelloInspection, inspect_client_hello},
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, record_transfer,
        register_connection,
    },
    util::{prefixed_stream::PrefixedStream, socket::new_tcp_socket},
};

use tracing::{error, info};

const SNIFFING_MAX_BYTES: usize = 32_767;
const SNIFFING_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SniffedRoutingMetadata {
    pub(super) protocol: Option<String>,
    pub(super) domain: Option<String>,
    pub(super) attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SniffInspection {
    NeedMore,
    Complete(SniffedRoutingMetadata),
    NoClue,
}

const XRAY_HTTP_METHODS: &[&[u8]] = &[
    b"get", b"post", b"head", b"put", b"delete", b"options", b"connect",
];

fn ascii_prefix_eq_ignore_case(input: &[u8], expected: &[u8]) -> bool {
    input
        .iter()
        .zip(expected)
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn inspect_http_routing_metadata(input: &[u8]) -> SniffInspection {
    let method_matches = XRAY_HTTP_METHODS.iter().any(|method| {
        input.len() >= method.len()
            && ascii_prefix_eq_ignore_case(&input[..method.len()], method)
    });
    if !method_matches {
        let method_may_match = XRAY_HTTP_METHODS.iter().any(|method| {
            input.len() < method.len()
                && ascii_prefix_eq_ignore_case(input, &method[..input.len()])
        });
        return if method_may_match {
            SniffInspection::NeedMore
        } else {
            SniffInspection::NoClue
        };
    }

    let Some(header_end) = input.windows(4).position(|window| window == b"\r\n\r\n")
    else {
        return SniffInspection::NeedMore;
    };
    let header_block = &input[..header_end + 2];
    let mut lines = header_block.split(|byte| *byte == b'\n');
    let Some(request_line) = lines.next() else {
        return SniffInspection::NoClue;
    };
    let request_line = request_line.strip_suffix(b"\r").unwrap_or(request_line);
    let request_line = String::from_utf8_lossy(request_line);
    let request_parts = request_line.split(' ').collect::<Vec<_>>();

    let mut attributes = HashMap::new();
    let mut domain = None;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let key = String::from_utf8_lossy(&line[..separator]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(&line[separator + 1..])
            .trim()
            .to_string();
        if key == "host" && !value.is_empty() {
            domain = sniffed_http_domain(&value);
        }
        attributes.insert(key, value);
    }
    if request_parts.len() == 3 {
        attributes.insert(":method".into(), request_parts[0].to_string());
        attributes.insert(":path".into(), request_parts[1].to_string());
    }

    SniffInspection::Complete(SniffedRoutingMetadata {
        protocol: domain.as_ref().map(|_| "http1".to_string()),
        domain,
        attributes,
    })
}

fn sniffed_http_domain(host: &str) -> Option<String> {
    let host = host.trim().to_ascii_lowercase();
    let host = if let Some(host) = host.strip_prefix('[') {
        let (host, remainder) = host.split_once(']')?;
        if !remainder.is_empty()
            && !remainder
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return None;
        }
        host
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if !name.contains(':') && port.parse::<u16>().is_ok() {
            name
        } else {
            host.as_str()
        }
    } else {
        host.as_str()
    };
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host.to_string())
    }
}

pub(super) fn inspect_sniffed_routing_metadata(input: &[u8]) -> SniffInspection {
    let tls_inspection = inspect_client_hello(input);
    match tls_inspection {
        ClientHelloInspection::ServerName(server_name) => {
            return SniffInspection::Complete(SniffedRoutingMetadata {
                protocol: Some("tls".into()),
                domain: Some(server_name.to_ascii_lowercase()),
                attributes: HashMap::new(),
            });
        }
        ClientHelloInspection::EncryptedClientHello
        | ClientHelloInspection::NoServerName => {
            return SniffInspection::Complete(SniffedRoutingMetadata {
                protocol: Some("tls".into()),
                domain: None,
                attributes: HashMap::new(),
            });
        }
        ClientHelloInspection::Incomplete
        | ClientHelloInspection::NotTls
        | ClientHelloInspection::Malformed => {}
    }

    match inspect_http_routing_metadata(input) {
        SniffInspection::NoClue
            if tls_inspection == ClientHelloInspection::Incomplete =>
        {
            SniffInspection::NeedMore
        }
        inspection => inspection,
    }
}

fn sniffed_override_domain(
    sniffing: Option<&InboundSniffingConfig>,
    metadata: &SniffedRoutingMetadata,
    remote_location: &NetLocation,
) -> Option<String> {
    let config = sniffing.filter(|config| config.enabled)?;
    let protocol = metadata.protocol.as_deref()?;
    if !config.overrides_protocol(protocol) {
        return None;
    }
    let domain = metadata.domain.as_deref()?;
    if config.excludes_domain(domain) {
        return None;
    }
    let excluded_ip = match remote_location.address() {
        Address::Ipv4(ip) => config.excludes_ip((*ip).into()),
        Address::Ipv6(ip) => config.excludes_ip((*ip).into()),
        Address::Hostname(_) => false,
    };
    (!excluded_ip).then(|| domain.to_string())
}

pub(super) fn route_only_sniffed_domain(
    sniffing: Option<&InboundSniffingConfig>,
    metadata: &SniffedRoutingMetadata,
    remote_location: &NetLocation,
) -> Option<String> {
    sniffing
        .filter(|config| config.route_only)
        .and_then(|config| {
            sniffed_override_domain(Some(config), metadata, remote_location)
        })
}

pub(super) fn sniffed_outbound_target(
    sniffing: Option<&InboundSniffingConfig>,
    metadata: &SniffedRoutingMetadata,
    remote_location: &NetLocation,
) -> NetLocation {
    if sniffing.is_some_and(|config| config.route_only) {
        return remote_location.clone();
    }
    match sniffed_override_domain(sniffing, metadata, remote_location) {
        Some(domain) => {
            NetLocation::new(Address::Hostname(domain), remote_location.port())
        }
        None => remote_location.clone(),
    }
}

pub(super) struct SniffedRoutePlan {
    pub(super) outbound_target: NetLocation,
    pub(super) routing_metadata: InboundRoutingMetadata,
}

pub(super) fn build_sniffed_route_plan(
    sniffing: Option<&InboundSniffingConfig>,
    sniffed: SniffedRoutingMetadata,
    remote_location: &NetLocation,
    local_addr: Option<SocketAddr>,
) -> SniffedRoutePlan {
    let outbound_target =
        sniffed_outbound_target(sniffing, &sniffed, remote_location);
    let route_target_domain =
        route_only_sniffed_domain(sniffing, &sniffed, remote_location);
    SniffedRoutePlan {
        outbound_target,
        routing_metadata: InboundRoutingMetadata {
            local_addr,
            vless_route: 0,
            sniffed_protocol: sniffed.protocol,
            route_target_domain,
            attributes: sniffed.attributes,
        },
    }
}

pub(super) async fn sniff_stream_protocol(
    mut stream: Box<dyn AsyncStream>,
    sniffing: Option<&InboundSniffingConfig>,
) -> std::io::Result<(Box<dyn AsyncStream>, SniffedRoutingMetadata)> {
    if !sniffing.is_some_and(|config| config.enabled) {
        return Ok((stream, SniffedRoutingMetadata::default()));
    }

    let mut captured = Vec::new();
    let sniffed = timeout(SNIFFING_TIMEOUT, async {
        loop {
            match inspect_sniffed_routing_metadata(&captured) {
                SniffInspection::Complete(metadata) => {
                    return Ok::<_, std::io::Error>(metadata);
                }
                SniffInspection::NoClue => {
                    return Ok(SniffedRoutingMetadata::default());
                }
                SniffInspection::NeedMore => {}
            }
            if captured.len() >= SNIFFING_MAX_BYTES {
                return Ok(SniffedRoutingMetadata::default());
            }
            let mut buffer = [0u8; 4096];
            let read_limit = buffer
                .len()
                .min(SNIFFING_MAX_BYTES.saturating_sub(captured.len()));
            let read = stream.read(&mut buffer[..read_limit]).await?;
            if read == 0 {
                return Ok(SniffedRoutingMetadata::default());
            }
            captured.extend_from_slice(&buffer[..read]);
        }
    })
    .await
    .unwrap_or(Ok(SniffedRoutingMetadata::default()))?;

    if captured.is_empty() {
        Ok((stream, sniffed))
    } else {
        Ok((Box::new(PrefixedStream::new(captured, stream)), sniffed))
    }
}

pub(super) async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    process_stream_with_local_addr(
        stream,
        server_handler,
        resolver,
        peer_addr,
        None,
        runtime,
    )
    .await
}

pub(super) async fn process_stream_with_local_addr<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    process_stream_with_sniffing_and_local_addr(
        stream,
        server_handler,
        resolver,
        peer_addr,
        local_addr,
        runtime,
        None,
    )
    .await
}

pub(super) async fn process_stream_with_sniffing_and_local_addr<AS>(
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

pub(super) fn stream_connection_context(
    runtime: &DataPlaneRuntime,
    local_addr: Option<SocketAddr>,
) -> TcpServerConnectionContext {
    TcpServerConnectionContext {
        local_addr,
        runtime: Some(runtime.clone()),
        ..TcpServerConnectionContext::default()
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

pub(super) fn normalize_setup_result(
    setup_result: TcpServerSetupResult,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> std::io::Result<(SocketAddr, TcpServerSetupOutcome)> {
    let normalized = setup_result.into_normalized();
    let peer_addr = normalized.peer_addr_override.unwrap_or(peer_addr);
    normalize_tcp_fallback(normalized.outcome, peer_addr, local_addr)
        .map(|setup_outcome| (peer_addr, setup_outcome))
}

pub(super) fn routing_identity(
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

pub(super) async fn process_stream_with_context<AS>(
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
                    routing_metadata,
                ),
            );

            let (client_stream, outbound_tag) =
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
            if let Some(tag) = outbound_tag {
                traffic_context =
                    traffic_context.map(|context| context.with_outbound_tag(tag));
            }
            let user_level = traffic_context
                .as_ref()
                .map_or(0, |context| context.user_level);
            let _connection_guard = register_connection(traffic_context.as_ref());
            let relay_traffic_context = traffic_context.clone();
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
                tcp_relay::copy_bidirectional(&mut server_stream, &mut client_stream)
                    .await
            } else {
                policy_stream::copy_bidirectional_with_timeouts(
                    &mut server_stream,
                    &mut client_stream,
                    relay_timeouts,
                )
                .await
            };

            let (_, _) =
                futures::join!(server_stream.shutdown(), client_stream.shutdown());
            let copy_result = copy_result?;
            record_transfer(
                relay_traffic_context,
                copy_result.bypassed_left_to_right,
                copy_result.bypassed_right_to_left,
            );

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
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
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
        TcpServerSetupOutcome::AlreadyHandled => Ok(()),
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
    let server_stream = Box::new(stream);
    server_handler
        .setup_server_stream_with_context(server_stream, connection_context)
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

async fn connect_tcp_target(
    target_addr: SocketAddr,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let client_stream = tcp_socket.connect(target_addr).await?;

    if let Err(e) = client_stream.set_nodelay(true) {
        error!("Failed to set TCP no-delay on client socket: {}", e);
    }

    Ok(Box::new(client_stream))
}

pub async fn setup_client_stream(
    _server_stream: &mut Box<dyn AsyncStream>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let target_addr = resolve_single_address(&resolver, &remote_location).await?;
    connect_tcp_target(target_addr).await.map(Some)
}
