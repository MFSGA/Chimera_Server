use std::{net::SocketAddr, sync::Arc, time::Duration};

use quic::start_quic_server;
#[cfg(target_os = "linux")]
use socket2::SockRef;
#[cfg(feature = "user_domain_access")]
use tokio::{io::AsyncReadExt, time::Instant};
use tokio::{io::AsyncWriteExt, task::JoinHandle, time::timeout};
use udp::{
    run_bidirectional_udp, run_multi_directional_udp, run_session_based_udp,
    start_udp_server,
};

use crate::{
    address::{BindLocation, NetLocation},
    async_stream::AsyncStream,
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig},
    },
    handler::{
        socks::run_udp_relay,
        tcp::{
            tcp_handler::{
                TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
            },
            tcp_handler_util::create_tcp_server_handler,
        },
    },
    outbound::connect_tcp_outbound,
    resolver::{Resolver, resolve_single_address},
    runtime::RuntimeState,
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, record_transfer,
        register_connection,
    },
    util::{prefixed_stream::PrefixedStream, socket::new_tcp_socket},
};

#[cfg(feature = "user_domain_access")]
use crate::{
    address::Address,
    runtime::UserDomainAccessTlsProbeOutcome,
    tls_client_hello::{ClientHelloInspection, inspect_client_hello},
    user_domain_access::{AccessAction, AccessTarget, EnforcementMode, UserId},
};

use tracing::{error, info};

#[cfg(feature = "grpc_transport")]
mod grpc_transport;
#[cfg(feature = "grpc_transport")]
pub(crate) use grpc_transport::GrpcClientConfig;
mod policy_stream;
mod quic;
mod tcp_relay;
pub(crate) mod udp;
mod xhttp;

pub async fn start_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    if is_xhttp_server_protocol(&config.protocol) {
        return xhttp::start_xhttp_server(config, runtime).await;
    }
    #[cfg(feature = "grpc_transport")]
    if is_grpc_server_protocol(&config.protocol) {
        return grpc_transport::start_grpc_server(config, runtime).await;
    }

    let mut join_handles = Vec::with_capacity(3);

    match config.transport {
        Transport::Tcp => {
            match start_tcp_server_with_runtime(config.clone(), runtime).await {
                Ok(Some(handle)) => {
                    join_handles.push(handle);
                }
                Ok(None) => (),
                Err(e) => {
                    for join_handle in join_handles {
                        join_handle.abort();
                    }
                    return Err(e);
                }
            }
        }
        Transport::TcpAndUdp => {
            match start_tcp_server_with_runtime(config.clone(), runtime.clone())
                .await
            {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            match start_udp_server(config.clone(), runtime).await {
                Ok(Some(handle)) => join_handles.push(handle),
                Ok(None) => {}
                Err(error) => {
                    for join_handle in join_handles {
                        join_handle.abort();
                    }
                    return Err(error);
                }
            }
        }
        Transport::Quic => match start_quic_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        // UDP listeners need runtime state for routing/outbound selection.
        Transport::Udp => match start_udp_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles)
}

#[cfg(feature = "grpc_transport")]
fn is_grpc_server_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Grpc(_) => true,
        ServerProxyConfig::ProxyProtocol { inner }
        | ServerProxyConfig::TcpKeepAlive { inner, .. }
        | ServerProxyConfig::TcpUserTimeout { inner, .. }
        | ServerProxyConfig::TcpCongestion { inner, .. }
        | ServerProxyConfig::TcpWindowClamp { inner, .. } => {
            is_grpc_server_protocol(inner)
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            matches!(tls_config.inner.as_ref(), ServerProxyConfig::Grpc(_))
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            matches!(reality_config.inner.as_ref(), ServerProxyConfig::Grpc(_))
        }
        _ => false,
    }
}

fn is_xhttp_server_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Xhttp { .. } => true,
        ServerProxyConfig::ProxyProtocol { inner }
        | ServerProxyConfig::TcpKeepAlive { inner, .. }
        | ServerProxyConfig::TcpUserTimeout { inner, .. }
        | ServerProxyConfig::TcpCongestion { inner, .. }
        | ServerProxyConfig::TcpWindowClamp { inner, .. } => {
            is_xhttp_server_protocol(inner)
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => {
            matches!(tls_config.inner.as_ref(), ServerProxyConfig::Xhttp { .. })
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(reality_config) => {
            matches!(
                reality_config.inner.as_ref(),
                ServerProxyConfig::Xhttp { .. }
            )
        }
        _ => false,
    }
}

pub async fn start_tcp_server(
    config: ServerConfig,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let runtime = RuntimeState::new(vec![config.clone()], Vec::new());
    start_tcp_server_with_runtime(config, runtime).await
}

async fn start_tcp_server_with_runtime(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,

        protocol,
        ..
    } = config;

    tracing::info!("Starting {} TCP server at {}", &protocol, &bind_location);

    let mut rules_stack = vec![];

    let tcp_handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(create_tcp_server_handler(protocol, &tag, &mut rules_stack)?);
    tracing::debug!("TCP handler: {:?}", tcp_handler);

    let listener = match bind_location {
        BindLocation::Address(a) => {
            let socket_addr = a.to_socket_addr()?;
            tokio::net::TcpListener::bind(socket_addr).await?
        }
    };

    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_tcp_server(listener, tcp_handler, runtime).await {
            error!("TCP server stopped with error: {}", err);
        }
    })))
}

async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let resolver = runtime.resolver();

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {}", e);
                continue;
            }
        };
        if let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {}", e);
        }
        let cloned_cache = resolver.clone();
        let cloned_handler = server_handler.clone();
        let runtime = runtime.clone();

        tokio::spawn(async move {
            let connection_context = match tcp_server_connection_context(
                &stream,
                cloned_handler.as_ref().as_ref(),
            ) {
                Ok(context) => context,
                Err(error) => {
                    error!(
                        "{}:{} failed to read original destination: {}",
                        addr.ip(),
                        addr.port(),
                        error
                    );
                    return;
                }
            };
            if let Err(e) = process_stream_with_context(
                stream,
                cloned_handler,
                cloned_cache,
                addr,
                runtime,
                connection_context,
            )
            .await
            {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                tracing::debug!(
                    "{}:{} finished successfully",
                    addr.ip(),
                    addr.port()
                );
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn tcp_server_connection_context(
    stream: &tokio::net::TcpStream,
    server_handler: &dyn TcpServerHandler,
) -> std::io::Result<TcpServerConnectionContext> {
    let local_addr = stream.local_addr()?;
    if !server_handler.requires_original_destination() {
        return Ok(TcpServerConnectionContext {
            original_destination: None,
            local_addr: Some(local_addr),
            ..TcpServerConnectionContext::default()
        });
    }

    let socket = SockRef::from(stream);
    let original_destination = if stream.local_addr()?.is_ipv6() {
        socket.original_dst_v6()?
    } else {
        socket.original_dst_v4()?
    };
    let original_destination =
        original_destination.as_socket().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SO_ORIGINAL_DST returned a non-IP socket address",
            )
        })?;

    Ok(TcpServerConnectionContext {
        original_destination: Some(NetLocation::from_ip_addr(
            original_destination.ip(),
            original_destination.port(),
        )),
        local_addr: Some(local_addr),
        ..TcpServerConnectionContext::default()
    })
}

#[cfg(not(target_os = "linux"))]
fn tcp_server_connection_context(
    stream: &tokio::net::TcpStream,
    server_handler: &dyn TcpServerHandler,
) -> std::io::Result<TcpServerConnectionContext> {
    if server_handler.requires_original_destination() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dokodemo-door followRedirect is supported only on Linux",
        ));
    }

    Ok(TcpServerConnectionContext {
        original_destination: None,
        local_addr: Some(stream.local_addr()?),
        ..TcpServerConnectionContext::default()
    })
}

fn build_proxy_protocol_header(
    version: u8,
    source: SocketAddr,
    destination: Option<SocketAddr>,
) -> std::io::Result<Vec<u8>> {
    match version {
        1 => {
            let Some(destination) = destination else {
                return Ok(b"PROXY UNKNOWN\r\n".to_vec());
            };
            let family = match (source.ip(), destination.ip()) {
                (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => "TCP4",
                (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_)) => "TCP6",
                _ => return Ok(b"PROXY UNKNOWN\r\n".to_vec()),
            };
            Ok(format!(
                "PROXY {family} {} {} {} {}\r\n",
                source.ip(),
                destination.ip(),
                source.port(),
                destination.port()
            )
            .into_bytes())
        }
        2 => {
            let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            let Some(destination) = destination else {
                header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                return Ok(header);
            };
            match (source.ip(), destination.ip()) {
                (std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(dest_ip)) => {
                    header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&dest_ip.octets());
                }
                (std::net::IpAddr::V6(source_ip), std::net::IpAddr::V6(dest_ip)) => {
                    header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
                    header.extend_from_slice(&source_ip.octets());
                    header.extend_from_slice(&dest_ip.octets());
                }
                _ => {
                    header.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                    return Ok(header);
                }
            }
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
            Ok(header)
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported PROXY protocol version {other}"),
        )),
    }
}

#[cfg(feature = "user_domain_access")]
async fn enrich_tls_access_metadata(
    mut stream: Box<dyn AsyncStream>,
    traffic_context: &mut Option<TrafficContext>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
) -> std::io::Result<Box<dyn AsyncStream>> {
    let Some(policy) = runtime.user_domain_access() else {
        return Ok(stream);
    };
    if policy.enforcement_mode() == EnforcementMode::Disabled {
        return Ok(stream);
    }
    let Some(context) = traffic_context.as_ref() else {
        return Ok(stream);
    };
    if matches!(
        classify_access_target(context, remote_location)?.0,
        AccessTarget::Domain(_)
    ) {
        return Ok(stream);
    }

    let probe_config = runtime.user_domain_access_tls_probe_config();
    let deadline = Instant::now() + probe_config.timeout;
    let mut captured = Vec::new();
    let mut timed_out = false;
    let inspection = loop {
        match inspect_client_hello(&captured) {
            ClientHelloInspection::Incomplete
                if captured.len() < probe_config.max_bytes =>
            {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    timed_out = true;
                    break ClientHelloInspection::Incomplete;
                }
                let mut buffer = [0u8; 4096];
                let read_limit =
                    buffer.len().min(probe_config.max_bytes - captured.len());
                match timeout(remaining, stream.read(&mut buffer[..read_limit]))
                    .await
                {
                    Ok(Ok(0)) => break ClientHelloInspection::Incomplete,
                    Ok(Ok(length)) => captured.extend_from_slice(&buffer[..length]),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => {
                        timed_out = true;
                        break ClientHelloInspection::Incomplete;
                    }
                }
            }
            inspection => break inspection,
        }
    };

    let probe_outcome = match &inspection {
        ClientHelloInspection::ServerName(_) => {
            UserDomainAccessTlsProbeOutcome::ServerName
        }
        ClientHelloInspection::EncryptedClientHello => {
            UserDomainAccessTlsProbeOutcome::EncryptedClientHello
        }
        ClientHelloInspection::NotTls => UserDomainAccessTlsProbeOutcome::NotTls,
        ClientHelloInspection::Incomplete => {
            UserDomainAccessTlsProbeOutcome::Incomplete
        }
        ClientHelloInspection::Malformed => {
            UserDomainAccessTlsProbeOutcome::Malformed
        }
        ClientHelloInspection::NoServerName => {
            UserDomainAccessTlsProbeOutcome::NoServerName
        }
    };
    runtime.record_user_domain_access_tls_probe(
        probe_outcome,
        captured.len(),
        timed_out,
    );

    if let Some(context) = traffic_context.as_mut() {
        match inspection {
            ClientHelloInspection::ServerName(server_name) => {
                context.set_access_sni(server_name);
            }
            ClientHelloInspection::EncryptedClientHello => context.mark_tls_ech(),
            ClientHelloInspection::Incomplete
            | ClientHelloInspection::NotTls
            | ClientHelloInspection::Malformed
            | ClientHelloInspection::NoServerName => {}
        }
    }

    if captured.is_empty() {
        Ok(stream)
    } else {
        Ok(Box::new(PrefixedStream::new(captured, stream)))
    }
}

#[cfg(feature = "user_domain_access")]
fn classify_access_target(
    context: &TrafficContext,
    remote_location: &NetLocation,
) -> std::io::Result<(AccessTarget, &'static str)> {
    let metadata = context.access_context();
    let protocol_target = metadata
        .and_then(|metadata| metadata.target_host.as_deref())
        .map(|value| AccessTarget::classify(Some(value)))
        .transpose()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid protocol access-policy target: {error}"),
            )
        })?;

    if let Some(AccessTarget::Domain(domain)) = protocol_target.as_ref() {
        return Ok((AccessTarget::Domain(domain.clone()), "protocol-target"));
    }

    for (candidate, source) in [
        (
            metadata.and_then(|metadata| metadata.sni.as_deref()),
            "tls-sni",
        ),
        (
            metadata.and_then(|metadata| metadata.http_host.as_deref()),
            "http-host",
        ),
    ] {
        let Some(candidate) = candidate else {
            continue;
        };
        let target = AccessTarget::classify(Some(candidate)).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid {source} access-policy target: {error}"),
            )
        })?;
        if matches!(target, AccessTarget::Domain(_)) {
            return Ok((target, source));
        }
    }

    if metadata.is_some_and(|metadata| metadata.tls_ech) {
        return Ok((protocol_target.unwrap_or(AccessTarget::Unknown), "tls-ech"));
    }

    if let Some(target) = protocol_target {
        return Ok((target, "protocol-target"));
    }

    let target = match remote_location.address() {
        Address::Hostname(domain) => {
            AccessTarget::classify(Some(domain)).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid access-policy target domain: {error}"),
                )
            })?
        }
        Address::Ipv4(address) => {
            AccessTarget::IpAddress(std::net::IpAddr::V4(*address))
        }
        Address::Ipv6(address) => {
            AccessTarget::IpAddress(std::net::IpAddr::V6(*address))
        }
    };
    Ok((target, "forward-target"))
}

#[cfg(feature = "user_domain_access")]
pub(crate) fn enforce_user_domain_access(
    runtime: &RuntimeState,
    traffic_context: Option<&TrafficContext>,
    remote_location: &NetLocation,
) -> std::io::Result<Option<UserId>> {
    let Some(policy) = runtime.user_domain_access() else {
        return Ok(None);
    };
    let Some(context) = traffic_context else {
        return Ok(None);
    };
    let user_uuid = if let Some(user_uuid) = context.user_uuid() {
        Some(user_uuid.parse::<UserId>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid access-policy user UUID: {error}"),
            )
        })?)
    } else if context.protocol == "vless" {
        let Some(identity) = context.protocol_identity() else {
            return Ok(None);
        };
        Some(policy.resolve_vless_identity(identity).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid VLESS access-policy identity: {error}"),
            )
        })?)
    } else if context.protocol == "vmess" {
        let Some(identity) = context.protocol_identity() else {
            return Ok(None);
        };
        Some(policy.resolve_vmess_identity(identity).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid VMess access-policy identity: {error}"),
            )
        })?)
    } else if context.protocol == "tuic" {
        let Some(identity) = context.protocol_identity() else {
            return Ok(None);
        };
        Some(policy.resolve_tuic_identity(identity).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid TUIC access-policy identity: {error}"),
            )
        })?)
    } else if context.protocol == "hysteria2" {
        context
            .protocol_identity()
            .and_then(|identity| policy.resolve_hysteria2_identity(identity))
    } else if context.protocol == "trojan" {
        context
            .protocol_identity()
            .and_then(|identity| policy.resolve_trojan_identity(identity.as_bytes()))
    } else if context.protocol == "http" {
        context
            .protocol_identity()
            .and_then(|identity| policy.resolve_http_identity(identity))
    } else if context.protocol == "socks" {
        context
            .protocol_identity()
            .and_then(|identity| policy.resolve_socks_identity(identity))
    } else {
        return Ok(None);
    };
    let enforcement_mode = policy.enforcement_mode();
    if enforcement_mode == EnforcementMode::Disabled {
        runtime.record_user_domain_access_disabled_bypass();
        return Ok(user_uuid);
    }

    let (target, target_source) = classify_access_target(context, remote_location)?;
    let decision = policy.decide_optional(user_uuid, &target);
    runtime.record_user_domain_access_decision(&decision, enforcement_mode);
    if decision.action == AccessAction::Allow {
        return Ok(user_uuid);
    }

    let decision_user_uuid = decision
        .user_uuid
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unmapped".into());
    if enforcement_mode == EnforcementMode::Shadow {
        tracing::info!(
            user_uuid = %decision_user_uuid,
            target = %remote_location,
            target_class = ?decision.target_class,
            target_source,
            reason = ?decision.reason,
            matched_rule_id = decision.matched_rule_id.as_deref().unwrap_or("none"),
            "user-domain access shadow policy would reject outbound target"
        );
        return Ok(user_uuid);
    }

    tracing::warn!(
        user_uuid = %decision_user_uuid,
        target = %remote_location,
        target_class = ?decision.target_class,
        target_source,
        reason = ?decision.reason,
        matched_rule_id = decision.matched_rule_id.as_deref().unwrap_or("none"),
        "user-domain access policy rejected outbound target"
    );
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "user-domain access policy rejected target {remote_location}: {:?}",
            decision.reason
        ),
    ))
}

pub(super) async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    process_stream_with_context(
        stream,
        server_handler,
        resolver,
        peer_addr,
        runtime,
        TcpServerConnectionContext::default(),
    )
    .await
}

async fn process_stream_with_context<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
    mut connection_context: TcpServerConnectionContext,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    if connection_context.resolver.is_none() {
        connection_context.resolver = Some(resolver.clone());
    }
    let local_addr = connection_context.local_addr;
    let setup_server_stream_future = timeout(
        runtime.policy_handshake_timeout(0),
        setup_server_stream(stream, server_handler, connection_context),
    );
    tracing::info!("prepare to setup server stream");
    let setup_result = match setup_server_stream_future.await {
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
    };
    let peer_addr = setup_result.client_addr().unwrap_or(peer_addr);
    let setup_result = match setup_result {
        TcpServerSetupResult::TcpFallback {
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
            TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(PrefixedStream::new(prefix, stream)),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            }
        }
        other => other,
    };

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: _need_initial_flush,
            connection_success_response,
            traffic_context,
        } => {
            let mut traffic_context =
                traffic_context.map(|context| context.with_client_addr(peer_addr));
            let inbound_tag = traffic_context
                .as_ref()
                .and_then(|context| context.inbound_tag.as_deref())
                .unwrap_or_default()
                .to_string();
            #[cfg(feature = "user_domain_access")]
            {
                server_stream = enrich_tls_access_metadata(
                    server_stream,
                    &mut traffic_context,
                    &remote_location,
                    &runtime,
                )
                .await?;
            }
            #[cfg(feature = "user_domain_access")]
            match enforce_user_domain_access(
                &runtime,
                traffic_context.as_ref(),
                &remote_location,
            ) {
                Ok(Some(user_uuid)) => {
                    if let Some(context) = traffic_context.as_mut() {
                        context.set_user_uuid(user_uuid.to_string());
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = server_stream.shutdown().await;
                    return Err(error);
                }
            }

            let user_level = traffic_context
                .as_ref()
                .map_or(0, |context| context.user_level);
            let user_stats = runtime.policy_user_stats(user_level);
            let system_stats = runtime.policy_system_stats();
            if let Some(context) = traffic_context.as_mut() {
                context.set_user_stats_policy(
                    user_stats.uplink,
                    user_stats.downlink,
                    user_stats.online,
                );
                context.set_system_stats_policy(
                    system_stats.inbound_uplink,
                    system_stats.inbound_downlink,
                    system_stats.outbound_uplink,
                    system_stats.outbound_downlink,
                );
            }
            let user = traffic_context
                .as_ref()
                .and_then(TrafficContext::routing_identity)
                .unwrap_or_default()
                .to_string();

            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_routed_client_stream(
                    resolver,
                    remote_location.clone(),
                    &runtime,
                    &inbound_tag,
                    &user,
                    peer_addr,
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
                                remote_location, e
                            ),
                        ));
                    }
                    Err(elapsed) => {
                        let _ = server_stream.shutdown().await;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "client setup to {} timed out: {}",
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
                remote_location,
                copy_result.left_to_right,
                copy_result.right_to_left,
            );
            Ok(())
        }
        TcpServerSetupResult::TcpFallback { .. } => {
            unreachable!("fallback result must be normalized before forwarding")
        }
        TcpServerSetupResult::UdpAssociate {
            stream,
            socket,
            client_udp_port_hint,
            traffic_context,
        } => {
            let traffic_context =
                traffic_context.map(|context| context.with_client_addr(peer_addr));
            run_udp_relay(
                socket,
                stream,
                resolver,
                runtime,
                peer_addr,
                client_udp_port_hint,
                traffic_context,
            )
            .await
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream,
            traffic_context,
        } => {
            run_bidirectional_udp(
                stream,
                remote_location,
                resolver,
                runtime,
                peer_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream,
            traffic_context,
        } => {
            run_multi_directional_udp(
                stream,
                resolver,
                runtime,
                peer_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream,
            traffic_context,
        } => {
            run_session_based_udp(
                stream,
                resolver,
                runtime,
                peer_addr,
                traffic_context,
            )
            .await
        }
        TcpServerSetupResult::AlreadyHandled => Ok(()),
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
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    peer_addr: SocketAddr,
) -> std::io::Result<Option<(Box<dyn AsyncStream>, Option<String>)>> {
    connect_tcp_outbound(
        &resolver,
        &remote_location,
        runtime,
        inbound_tag,
        user,
        peer_addr,
    )
    .await
    .map(|connection| {
        connection.map(|connection| (connection.stream, connection.outbound_tag))
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    #[cfg(feature = "user_domain_access")]
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    #[cfg(feature = "user_domain_access")]
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    };
    #[cfg(target_os = "linux")]
    use tokio::net::{TcpListener, TcpStream};

    #[cfg(any(target_os = "linux", feature = "user_domain_access"))]
    use crate::address::{Address, NetLocation};
    #[cfg(feature = "user_domain_access")]
    use crate::{
        async_stream::{AsyncPing, AsyncStream},
        traffic::{AccessTransport, TrafficContext},
        user_domain_access::{UserDomainAccessConfig, UserDomainAccessPolicy},
    };
    #[cfg(target_os = "linux")]
    use crate::{
        config::server_config::DokodemoDoorConfig,
        handler::dokodemo::DokodemoDoorTcpHandler,
    };

    use super::*;

    #[cfg(feature = "user_domain_access")]
    struct AccessTestStream(DuplexStream);

    #[cfg(feature = "user_domain_access")]
    impl AsyncRead for AccessTestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    #[cfg(feature = "user_domain_access")]
    impl AsyncWrite for AccessTestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "user_domain_access")]
    impl AsyncPing for AccessTestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    #[cfg(feature = "user_domain_access")]
    impl AsyncStream for AccessTestStream {}

    #[cfg(feature = "user_domain_access")]
    fn tls_client_hello(server_name: &str) -> Vec<u8> {
        let name = server_name.as_bytes();
        let mut server_name_extension = Vec::new();
        server_name_extension
            .extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
        server_name_extension.push(0);
        server_name_extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
        server_name_extension.extend_from_slice(name);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions
            .extend_from_slice(&(server_name_extension.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name_extension);

        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = vec![
            22,
            3,
            1,
            ((handshake.len() >> 8) & 0xff) as u8,
            (handshake.len() & 0xff) as u8,
        ];
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn proxy_protocol_v1_encodes_ipv4_addresses_and_ports() {
        let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let header = build_proxy_protocol_header(1, source, Some(destination))
            .expect("build PROXY v1 header");
        assert_eq!(header, b"PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n");
    }

    #[test]
    fn proxy_protocol_v2_encodes_ipv4_addresses_and_ports() {
        let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let destination: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let header = build_proxy_protocol_header(2, source, Some(destination))
            .expect("build PROXY v2 header");
        let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        expected.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        expected.extend_from_slice(&[192, 0, 2, 10]);
        expected.extend_from_slice(&[198, 51, 100, 20]);
        expected.extend_from_slice(&12345u16.to_be_bytes());
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(header, expected);
    }

    #[test]
    fn proxy_protocol_uses_unknown_or_local_for_mixed_families() {
        let source = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let destination = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
        assert_eq!(
            build_proxy_protocol_header(1, source, Some(destination)).unwrap(),
            b"PROXY UNKNOWN\r\n"
        );
        let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        expected.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(
            build_proxy_protocol_header(2, source, Some(destination)).unwrap(),
            expected
        );
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn user_domain_access_is_enforced_before_outbound_connect() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "defaultAction": "allow",
                "users": [{
                    "userUuid": "11111111-1111-4111-8111-111111111111",
                    "protocolIdentity": {
                        "vlessUuid": "22222222-2222-4222-8222-222222222222",
                        "httpUsername": "alice"
                    },
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "id": "allow-example",
                        "domain": "example.com",
                        "match": "suffix",
                        "action": "allow"
                    }]
                }]
            }))
            .expect("policy config should parse");
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime.replace_user_domain_access(Some(
            UserDomainAccessPolicy::compile(config).expect("policy should compile"),
        ));
        let context = TrafficContext::new("vless")
            .with_protocol_identity("22222222-2222-4222-8222-222222222222");

        let allowed =
            NetLocation::new(Address::Hostname("api.example.com".into()), 443);
        let resolved_user =
            enforce_user_domain_access(&runtime, Some(&context), &allowed)
                .expect("suffix should allow the target")
                .expect("VLESS identity should resolve");
        assert_eq!(
            resolved_user.to_string(),
            "11111111-1111-4111-8111-111111111111"
        );

        let rejected =
            NetLocation::new(Address::Hostname("blocked.example.net".into()), 443);
        let error = enforce_user_domain_access(&runtime, Some(&context), &rejected)
            .expect_err("allowlist miss should reject before connect");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let direct_ip =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let error = enforce_user_domain_access(&runtime, Some(&context), &direct_ip)
            .expect_err("unknown IP target should use unknownTargetAction");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let http_context = TrafficContext::new("http")
            .with_protocol_identity("alice")
            .with_access_target("192.0.2.1", 80, AccessTransport::Tcp)
            .with_access_http_host("api.example.com");
        let resolved_user =
            enforce_user_domain_access(&runtime, Some(&http_context), &direct_ip)
                .expect("HTTP Host should be evaluated before the IP fallback")
                .expect("HTTP username should resolve");
        assert_eq!(
            resolved_user.to_string(),
            "11111111-1111-4111-8111-111111111111"
        );
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn shadow_and_disabled_modes_do_not_reject_data_path() {
        fn runtime(mode: &str) -> RuntimeState {
            let config = serde_json::from_value::<UserDomainAccessConfig>(
                serde_json::json!({
                    "enforcementMode": mode,
                    "defaultAction": "reject",
                    "users": [{
                        "userUuid": "11111111-1111-4111-8111-111111111111",
                        "protocolIdentity": {
                            "vlessUuid": "22222222-2222-4222-8222-222222222222"
                        },
                        "mode": "allowlist",
                        "unknownTargetAction": "reject",
                        "rules": [{
                            "domain": "allowed.example",
                            "match": "exact",
                            "action": "allow"
                        }]
                    }]
                }),
            )
            .expect("policy config should parse");
            let runtime = RuntimeState::new(Vec::new(), Vec::new());
            runtime.replace_user_domain_access(Some(
                UserDomainAccessPolicy::compile(config)
                    .expect("policy should compile"),
            ));
            runtime
        }

        let context = TrafficContext::new("vless")
            .with_protocol_identity("22222222-2222-4222-8222-222222222222");
        let blocked =
            NetLocation::new(Address::Hostname("blocked.example".into()), 443);

        let shadow = runtime("shadow");
        enforce_user_domain_access(&shadow, Some(&context), &blocked)
            .expect("shadow mode must not reject the data path");
        let shadow_stats = shadow.user_domain_access_stats();
        assert_eq!(shadow_stats.evaluations, 1);
        assert_eq!(shadow_stats.rejected, 1);
        assert_eq!(shadow_stats.shadow_rejections, 1);
        assert_eq!(shadow_stats.enforced_rejections, 0);

        let disabled = runtime("disabled");
        enforce_user_domain_access(&disabled, Some(&context), &blocked)
            .expect("disabled mode must bypass policy evaluation");
        let disabled_stats = disabled.user_domain_access_stats();
        assert_eq!(disabled_stats.evaluations, 0);
        assert_eq!(disabled_stats.disabled_bypasses, 1);
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn access_target_prefers_domain_then_sni_then_http_host() {
        let remote =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);

        let protocol_domain = TrafficContext::new("vless")
            .with_access_target("api.example.com", 443, AccessTransport::Tcp)
            .with_access_sni("sni.example.net");
        let (target, source) =
            classify_access_target(&protocol_domain, &remote).unwrap();
        assert_eq!(source, "protocol-target");
        let AccessTarget::Domain(domain) = target else {
            panic!("protocol domain should be selected");
        };
        assert_eq!(domain.as_str(), "api.example.com");

        let sni = TrafficContext::new("vless")
            .with_access_target("192.0.2.1", 443, AccessTransport::Tcp)
            .with_access_sni("sni.example.net")
            .with_access_http_host("host.example.org");
        let (target, source) = classify_access_target(&sni, &remote).unwrap();
        assert_eq!(source, "tls-sni");
        let AccessTarget::Domain(domain) = target else {
            panic!("SNI should be selected for an IP protocol target");
        };
        assert_eq!(domain.as_str(), "sni.example.net");

        let http_host = TrafficContext::new("http")
            .with_access_target("192.0.2.1", 80, AccessTransport::Tcp)
            .with_access_http_host("host.example.org");
        let (target, source) = classify_access_target(&http_host, &remote).unwrap();
        assert_eq!(source, "http-host");
        let AccessTarget::Domain(domain) = target else {
            panic!("HTTP Host should be selected after an IP target");
        };
        assert_eq!(domain.as_str(), "host.example.org");
    }

    #[cfg(feature = "user_domain_access")]
    #[tokio::test]
    async fn tls_sni_probe_replays_consumed_bytes_before_policy_decision() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "defaultAction": "reject",
                "users": [{
                    "userUuid": "11111111-1111-4111-8111-111111111111",
                    "protocolIdentity": {
                        "vlessUuid": "22222222-2222-4222-8222-222222222222"
                    },
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": "sni.example.com",
                        "match": "exact",
                        "action": "allow"
                    }]
                }]
            }))
            .expect("policy config should parse");
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime.replace_user_domain_access(Some(
            UserDomainAccessPolicy::compile(config).expect("policy should compile"),
        ));

        let remote =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let mut context = Some(
            TrafficContext::new("vless")
                .with_protocol_identity("22222222-2222-4222-8222-222222222222")
                .with_access_target("192.0.2.1", 443, AccessTransport::Tcp),
        );
        let hello = tls_client_hello("sni.example.com");
        let mut expected = hello.clone();
        expected.extend_from_slice(b"application-data");
        let (mut client, server) = duplex(4096);
        client
            .write_all(&expected)
            .await
            .expect("write ClientHello and payload");

        let mut stream = enrich_tls_access_metadata(
            Box::new(AccessTestStream(server)),
            &mut context,
            &remote,
            &runtime,
        )
        .await
        .expect("SNI probe should succeed");
        assert_eq!(
            context
                .as_ref()
                .and_then(TrafficContext::access_context)
                .and_then(|access| access.sni.as_deref()),
            Some("sni.example.com")
        );
        enforce_user_domain_access(&runtime, context.as_ref(), &remote)
            .expect("extracted SNI should allow the IP target");

        let mut replayed = vec![0u8; expected.len()];
        stream
            .read_exact(&mut replayed)
            .await
            .expect("read replayed ClientHello and payload");
        assert_eq!(replayed, expected);
        let stats = runtime.user_domain_access_stats();
        assert_eq!(stats.tls_probe_attempts, 1);
        assert_eq!(stats.tls_sni_found, 1);
        assert_eq!(stats.tls_captured_bytes, expected.len() as u64);
    }

    #[cfg(feature = "user_domain_access")]
    #[tokio::test]
    async fn tls_probe_capture_limit_is_strict_and_all_bytes_are_replayed() {
        let config =
            serde_json::from_value::<UserDomainAccessConfig>(serde_json::json!({
                "defaultAction": "allow",
                "users": []
            }))
            .expect("policy config should parse");
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime
            .configure_user_domain_access_tls_probe(Some(50), Some(1_024))
            .expect("TLS probe config should install");
        runtime.replace_user_domain_access(Some(
            UserDomainAccessPolicy::compile(config).expect("policy should compile"),
        ));

        let remote =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let mut context = Some(TrafficContext::new("vless").with_access_target(
            "192.0.2.1",
            443,
            AccessTransport::Tcp,
        ));
        let mut expected = vec![0x16, 0x03, 0x03, 0xff, 0xff];
        expected.resize(2_048, 0);
        let (mut client, server) = duplex(4_096);
        client
            .write_all(&expected)
            .await
            .expect("write incomplete oversized ClientHello record");

        let mut stream = enrich_tls_access_metadata(
            Box::new(AccessTestStream(server)),
            &mut context,
            &remote,
            &runtime,
        )
        .await
        .expect("bounded TLS probe should return a replay stream");
        let mut replayed = vec![0u8; expected.len()];
        stream
            .read_exact(&mut replayed)
            .await
            .expect("read captured and unread TLS bytes");
        assert_eq!(replayed, expected);

        let stats = runtime.user_domain_access_stats();
        assert_eq!(stats.tls_probe_attempts, 1);
        assert_eq!(
            stats.tls_sni_found
                + stats.tls_ech_detected
                + stats.tls_not_tls
                + stats.tls_incomplete
                + stats.tls_malformed
                + stats.tls_no_server_name,
            1
        );
        assert_eq!(stats.tls_captured_bytes, 1_024);
        assert_eq!(stats.tls_timeouts, 0);
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn ech_is_classified_as_non_domain_even_with_outer_sni() {
        let remote =
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let mut context = TrafficContext::new("vless")
            .with_access_target("192.0.2.1", 443, AccessTransport::Tcp)
            .with_access_sni("public.example.com");
        context.mark_tls_ech();

        let (target, source) = classify_access_target(&context, &remote).unwrap();
        assert_eq!(source, "tls-ech");
        assert_eq!(
            target,
            AccessTarget::IpAddress(Ipv4Addr::new(192, 0, 2, 1).into())
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn original_destination_matches_tcp_listener() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind original-destination listener");
        let listener_addr = listener.local_addr().expect("listener address");
        let connect_task = tokio::spawn(async move {
            TcpStream::connect(listener_addr)
                .await
                .expect("connect original-destination listener")
        });
        let (server_stream, _) = listener
            .accept()
            .await
            .expect("accept original-destination connection");
        let _client_stream = connect_task.await.expect("connect task finished");
        let handler = DokodemoDoorTcpHandler::new(
            DokodemoDoorConfig {
                target: NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 1),
                follow_redirect: true,
                user_level: 0,
            },
            "dokodemo-original-destination",
        );

        let context = tcp_server_connection_context(&server_stream, &handler)
            .expect("read SO_ORIGINAL_DST from accepted TCP connection");
        assert_eq!(
            context.original_destination,
            Some(NetLocation::from_ip_addr(
                listener_addr.ip(),
                listener_addr.port(),
            ))
        );
    }
}
