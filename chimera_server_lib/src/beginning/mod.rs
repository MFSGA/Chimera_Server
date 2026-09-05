use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use quic::start_quic_server;
#[cfg(target_os = "linux")]
use socket2::SockRef;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};
use udp::{
    run_bidirectional_udp, run_multi_directional_udp, run_session_based_udp,
    start_udp_server,
};

use crate::{
    address::{Address, BindLocation, NetLocation},
    async_stream::AsyncStream,
    config::{
        Transport,
        server_config::{InboundSniffingConfig, ServerConfig, ServerProxyConfig},
    },
    handler::{
        http::relay_plain_http_response,
        socks::run_udp_relay_with_expected_client,
        tcp::{
            tcp_handler::{
                TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
            },
            tcp_handler_util::create_tcp_server_handler,
        },
    },
    outbound::{InboundRoutingMetadata, connect_tcp_outbound_with_routing_metadata},
    resolver::{NativeResolver, Resolver, resolve_single_address},
    runtime::RuntimeState,
    tls_client_hello::{ClientHelloInspection, inspect_client_hello},
    traffic::{
        MeteredStream, TrafficContext, TrafficDirection, record_transfer,
        register_connection, register_identity,
    },
    util::{prefixed_stream::PrefixedStream, socket::new_tcp_socket},
};

use tracing::{error, info};

const SNIFFING_MAX_BYTES: usize = 32_767;
const SNIFFING_TIMEOUT: Duration = Duration::from_millis(200);

#[cfg(feature = "grpc_transport")]
mod grpc_transport;
mod quic;
mod tcp_relay;
pub(crate) mod udp;
mod xhttp;

pub async fn start_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    register_configured_identities(&config.protocol);

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

fn register_configured_identities(protocol: &ServerProxyConfig) {
    match protocol {
        #[cfg(feature = "http")]
        ServerProxyConfig::Http { accounts, .. } => {
            for account in accounts {
                register_identity(account.username.clone());
            }
        }
        #[cfg(feature = "mixed")]
        ServerProxyConfig::Mixed { accounts, .. } => {
            for account in accounts.snapshot() {
                register_identity(account.username);
            }
        }
        ServerProxyConfig::Socks { accounts, .. } => {
            for account in accounts.snapshot() {
                register_identity(account.username);
            }
        }
        #[cfg(feature = "vless")]
        ServerProxyConfig::Vless { users, .. } => {
            for user in users {
                if !user.user_label.is_empty() {
                    register_identity(user.user_label.clone());
                }
            }
        }
        #[cfg(feature = "vmess")]
        ServerProxyConfig::Vmess { users } => {
            for user in users {
                if !user.user_label.is_empty() {
                    register_identity(user.user_label.clone());
                }
            }
        }
        #[cfg(feature = "trojan")]
        ServerProxyConfig::Trojan { users, .. } => {
            for user in users {
                if let Some(email) = user.email.as_deref() {
                    register_identity(email.to_string());
                }
            }
        }
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, .. } => {
            for user in users {
                if !user.email.is_empty() {
                    register_identity(user.email.clone());
                }
            }
        }
        #[cfg(feature = "hysteria")]
        ServerProxyConfig::Hysteria2 { config } => {
            for user in &config.clients {
                if let Some(email) = user.email.as_deref() {
                    register_identity(email.to_string());
                }
            }
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            register_configured_identities(inner);
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            register_configured_identities(config.inner.as_ref());
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(_) => {}
        _ => {}
    }
}

#[cfg(feature = "grpc_transport")]
fn is_grpc_server_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Grpc(_) => true,
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
        sniffing,
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
        if let Err(err) =
            run_tcp_server(listener, tcp_handler, runtime, sniffing).await
        {
            error!("TCP server stopped with error: {}", err);
        }
    })))
}

async fn run_tcp_server(
    listener: tokio::net::TcpListener,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    runtime: RuntimeState,
    sniffing: Option<InboundSniffingConfig>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let listener_addr = listener.local_addr()?;

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
        let sniffing = sniffing.clone();

        tokio::spawn(async move {
            let connection_context = match tcp_server_connection_context(
                &stream,
                cloned_handler.as_ref().as_ref(),
            ) {
                Ok(mut context) => {
                    context.peer_addr = Some(addr);
                    context.listener_addr = Some(listener_addr);
                    context.runtime = Some(runtime.clone());
                    context
                }
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
                sniffing,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SniffedRoutingMetadata {
    protocol: Option<String>,
    domain: Option<String>,
    attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SniffInspection {
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

fn inspect_sniffed_routing_metadata(input: &[u8]) -> SniffInspection {
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

fn route_only_sniffed_domain(
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

fn sniffed_outbound_target(
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

struct SniffedRoutePlan {
    outbound_target: NetLocation,
    routing_metadata: InboundRoutingMetadata,
}

fn build_sniffed_route_plan(
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

async fn sniff_stream_protocol(
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
    runtime: RuntimeState,
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
    runtime: RuntimeState,
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
    runtime: RuntimeState,
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

fn stream_connection_context(
    runtime: &RuntimeState,
    local_addr: Option<SocketAddr>,
) -> TcpServerConnectionContext {
    TcpServerConnectionContext {
        local_addr,
        runtime: Some(runtime.clone()),
        ..TcpServerConnectionContext::default()
    }
}

fn peel_peer_addr_overrides(
    mut setup_result: TcpServerSetupResult,
    mut peer_addr: SocketAddr,
) -> (SocketAddr, TcpServerSetupResult) {
    loop {
        match setup_result {
            TcpServerSetupResult::PeerAddrOverride {
                peer_addr: overridden,
                inner,
            } => {
                peer_addr = overridden;
                setup_result = *inner;
            }
            result => return (peer_addr, result),
        }
    }
}

fn normalize_tcp_fallback(
    setup_result: TcpServerSetupResult,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> std::io::Result<TcpServerSetupResult> {
    match setup_result {
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
            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(PrefixedStream::new(prefix, stream)),
                need_initial_flush: false,
                connection_success_response: None,
                traffic_context,
            })
        }
        result => Ok(result),
    }
}

fn normalize_setup_result(
    setup_result: TcpServerSetupResult,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> std::io::Result<(SocketAddr, TcpServerSetupResult)> {
    let (peer_addr, setup_result) =
        peel_peer_addr_overrides(setup_result, peer_addr);
    normalize_tcp_fallback(setup_result, peer_addr, local_addr)
        .map(|setup_result| (peer_addr, setup_result))
}

fn routing_identity(traffic_context: Option<&TrafficContext>) -> (&str, &str) {
    let inbound_tag = traffic_context
        .and_then(|context| context.inbound_tag.as_deref())
        .unwrap_or_default();
    let user = traffic_context
        .and_then(|context| context.identity.as_deref())
        .unwrap_or_default();
    (inbound_tag, user)
}

async fn process_stream_with_context<AS>(
    stream: AS,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    peer_addr: SocketAddr,
    runtime: RuntimeState,
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
    let (peer_addr, mut setup_result) =
        normalize_setup_result(setup_result, peer_addr, local_addr)?;

    while matches!(&setup_result, TcpServerSetupResult::HttpPlainForward { .. }) {
        let TcpServerSetupResult::HttpPlainForward {
            remote_location,
            stream: mut server_stream,
            request_head,
            request_method,
            keep_alive,
            next_handler,
            traffic_context,
        } = setup_result
        else {
            unreachable!("HTTP plain-forward loop only accepts HTTP results");
        };
        let mut traffic_context =
            traffic_context.map(|context| context.with_client_ip(peer_addr.ip()));
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

        setup_result = if next_handler.manages_handshake_timeout() {
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
    }

    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: _need_initial_flush,
            connection_success_response,
            traffic_context,
        } => {
            let mut traffic_context = traffic_context
                .map(|context| context.with_client_ip(peer_addr.ip()));
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

            let copy_result = tcp_relay::copy_bidirectional(
                &mut server_stream,
                &mut client_stream,
            )
            .await;

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
        TcpServerSetupResult::HttpPlainForward { .. } => {
            unreachable!(
                "HTTP plain-forward results must be handled before generic forwarding"
            )
        }
        TcpServerSetupResult::PeerAddrOverride { .. } => {
            unreachable!(
                "peer address override must be normalized before forwarding"
            )
        }
        TcpServerSetupResult::TcpFallback { .. } => {
            unreachable!("fallback result must be normalized before forwarding")
        }
        TcpServerSetupResult::UdpAssociate {
            stream,
            udp_socket,
            expected_client,
            user_level,
            traffic_context,
        } => {
            let traffic_context = traffic_context
                .map(|context| context.with_client_ip(peer_addr.ip()));
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
            run_session_based_udp(stream, runtime, peer_addr, traffic_context).await
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[cfg(target_os = "linux")]
    use tokio::net::{TcpListener, TcpStream};

    #[cfg(target_os = "linux")]
    use crate::{
        address::{Address, NetLocation},
        config::server_config::DokodemoDoorConfig,
        handler::dokodemo::DokodemoDoorTcpHandler,
    };

    use super::*;

    #[test]
    fn sniffed_http_metadata_drives_xray_override_and_exclusions() {
        let SniffInspection::Complete(metadata) = inspect_sniffed_routing_metadata(
            b"GET /private?q=1 HTTP/1.1\r\nHost: Api.Example.COM:443\r\nX-Test: ok\r\n\r\n",
        ) else {
            panic!("HTTP request should be sniffed");
        };
        assert_eq!(metadata.protocol.as_deref(), Some("http1"));
        assert_eq!(metadata.domain.as_deref(), Some("api.example.com"));
        assert_eq!(
            metadata.attributes.get(":method").map(String::as_str),
            Some("GET")
        );
        assert_eq!(
            metadata.attributes.get(":path").map(String::as_str),
            Some("/private?q=1")
        );
        assert_eq!(
            metadata.attributes.get("x-test").map(String::as_str),
            Some("ok")
        );

        let original =
            NetLocation::new(Address::Ipv4("192.0.2.7".parse().unwrap()), 8443);
        let replace = InboundSniffingConfig {
            enabled: true,
            dest_override_http: true,
            ..InboundSniffingConfig::default()
        };
        assert_eq!(
            sniffed_outbound_target(Some(&replace), &metadata, &original),
            NetLocation::new(Address::Hostname("api.example.com".into()), 8443)
        );

        let route_only = InboundSniffingConfig {
            route_only: true,
            ..replace.clone()
        };
        assert_eq!(
            sniffed_outbound_target(Some(&route_only), &metadata, &original),
            original
        );
        assert_eq!(
            route_only_sniffed_domain(Some(&route_only), &metadata, &original)
                .as_deref(),
            Some("api.example.com")
        );
        let local_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let plan = build_sniffed_route_plan(
            Some(&route_only),
            metadata.clone(),
            &original,
            Some(local_addr),
        );
        assert_eq!(plan.outbound_target, original);
        assert_eq!(plan.routing_metadata.local_addr, Some(local_addr));
        assert_eq!(
            plan.routing_metadata.sniffed_protocol.as_deref(),
            Some("http1")
        );
        assert_eq!(
            plan.routing_metadata.route_target_domain.as_deref(),
            Some("api.example.com")
        );

        let exclusions = crate::routing_state::SniffExclusionMatcher::compile(
            vec!["domain:example.com".into()],
            vec!["192.0.2.0/24".into()],
        )
        .expect("sniff exclusions should compile");
        let excluded = InboundSniffingConfig {
            exclusions: Arc::new(exclusions),
            ..replace
        };
        assert_eq!(
            sniffed_outbound_target(Some(&excluded), &metadata, &original),
            original
        );
        assert_eq!(
            route_only_sniffed_domain(Some(&excluded), &metadata, &original),
            None
        );
    }

    #[tokio::test]
    async fn sniff_stream_replays_consumed_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().unwrap();
        let connect = tokio::net::TcpStream::connect(addr);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        let mut client = client.expect("connect loopback client");
        let (server, _) = accepted.expect("accept loopback client");

        let payload = b"GET / HTTP/1.1\r\nHost: replay.example\r\n\r\nbody";
        client.write_all(payload).await.unwrap();
        let config = InboundSniffingConfig {
            enabled: true,
            dest_override_http: true,
            ..InboundSniffingConfig::default()
        };
        let (mut stream, metadata) =
            sniff_stream_protocol(Box::new(server), Some(&config))
                .await
                .expect("sniff stream");
        assert_eq!(metadata.domain.as_deref(), Some("replay.example"));
        let mut replayed = vec![0; payload.len()];
        stream.read_exact(&mut replayed).await.unwrap();
        assert_eq!(replayed, payload);
    }

    #[test]
    fn logical_stream_context_preserves_local_addr() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let local_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let context = stream_connection_context(&runtime, Some(local_addr));

        assert_eq!(context.local_addr, Some(local_addr));
        assert!(context.runtime.is_some());
    }

    #[test]
    fn routing_identity_projects_only_routing_fields() {
        assert_eq!(routing_identity(None), ("", ""));

        let context = TrafficContext::new("test")
            .with_inbound_tag("inbound-a")
            .with_identity("user-a");
        assert_eq!(routing_identity(Some(&context)), ("inbound-a", "user-a"));
    }

    #[test]
    fn setup_result_normalization_uses_innermost_peer_override() {
        let original: SocketAddr = "192.0.2.1:1000".parse().unwrap();
        let outer: SocketAddr = "192.0.2.2:2000".parse().unwrap();
        let inner: SocketAddr = "192.0.2.3:3000".parse().unwrap();
        let result = TcpServerSetupResult::PeerAddrOverride {
            peer_addr: outer,
            inner: Box::new(TcpServerSetupResult::PeerAddrOverride {
                peer_addr: inner,
                inner: Box::new(TcpServerSetupResult::AlreadyHandled),
            }),
        };

        let (peer_addr, normalized) =
            normalize_setup_result(result, original, None).unwrap();
        assert_eq!(peer_addr, inner);
        assert!(matches!(normalized, TcpServerSetupResult::AlreadyHandled));
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
