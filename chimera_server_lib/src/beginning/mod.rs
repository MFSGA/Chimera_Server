use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use quic::start_quic_server;
#[cfg(target_os = "linux")]
use socket2::SockRef;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
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
        server_config::{
            InboundSniffingConfig, ServerConfig, ServerProxyConfig, TcpSocketPolicy,
        },
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
const ACCEPT_ERROR_UNHEALTHY_AFTER: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_MIN_FAILURES: u32 = 8;
const ACCEPT_ERROR_INITIAL_BACKOFF: Duration = Duration::from_millis(25);
const ACCEPT_ERROR_MAX_BACKOFF: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptErrorDisposition {
    Retry(Duration),
    Fatal,
}

#[derive(Debug)]
pub(super) struct TcpAcceptHealth {
    first_failure: Option<Instant>,
    retry_backoff: Duration,
    consecutive_failures: u32,
}

impl Default for TcpAcceptHealth {
    fn default() -> Self {
        Self {
            first_failure: None,
            retry_backoff: ACCEPT_ERROR_INITIAL_BACKOFF,
            consecutive_failures: 0,
        }
    }
}

impl TcpAcceptHealth {
    fn reset(&mut self) {
        self.first_failure = None;
        self.retry_backoff = ACCEPT_ERROR_INITIAL_BACKOFF;
        self.consecutive_failures = 0;
    }

    fn record_success(&mut self) {
        self.reset();
    }

    fn classify_error(&mut self, error: &std::io::Error) -> AcceptErrorDisposition {
        self.classify_error_at(error, Instant::now())
    }

    fn classify_error_at(
        &mut self,
        error: &std::io::Error,
        now: Instant,
    ) -> AcceptErrorDisposition {
        use std::io::ErrorKind;

        match error.kind() {
            // These can describe one failed connection attempt rather than a
            // broken listening socket. Do not let a client-side abort poison
            // listener health.
            ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted => {
                self.reset();
                return AcceptErrorDisposition::Retry(Duration::ZERO);
            }
            ErrorKind::WouldBlock => {
                self.reset();
                return AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF);
            }
            // A listening socket returning these states cannot meaningfully
            // recover by spinning in accept(). Normal shutdown aborts the task
            // before this path, so these indicate an unexpected listener fault.
            ErrorKind::BrokenPipe
            | ErrorKind::InvalidInput
            | ErrorKind::NotConnected
            | ErrorKind::Unsupported => {
                self.consecutive_failures =
                    self.consecutive_failures.saturating_add(1);
                return AcceptErrorDisposition::Fatal;
            }
            _ => {}
        }

        let first_failure = *self.first_failure.get_or_insert(now);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= ACCEPT_ERROR_MIN_FAILURES
            && now.saturating_duration_since(first_failure)
                >= ACCEPT_ERROR_UNHEALTHY_AFTER
        {
            return AcceptErrorDisposition::Fatal;
        }

        let backoff = self.retry_backoff;
        self.retry_backoff = self
            .retry_backoff
            .saturating_mul(2)
            .min(ACCEPT_ERROR_MAX_BACKOFF);
        AcceptErrorDisposition::Retry(backoff)
    }
}

pub(super) async fn accept_tcp_with_health(
    listener: &tokio::net::TcpListener,
    health: &mut TcpAcceptHealth,
    listener_kind: &'static str,
) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    loop {
        match listener.accept().await {
            Ok(accepted) => {
                health.record_success();
                return Ok(accepted);
            }
            Err(error) => match health.classify_error(&error) {
                AcceptErrorDisposition::Retry(backoff) => {
                    error!(
                        listener_kind,
                        consecutive_failures = health.consecutive_failures,
                        retry_after_ms = backoff.as_millis(),
                        %error,
                        "listener accept failed; retrying"
                    );
                    if !backoff.is_zero() {
                        tokio::time::sleep(backoff).await;
                    }
                }
                AcceptErrorDisposition::Fatal => {
                    error!(
                        listener_kind,
                        consecutive_failures = health.consecutive_failures,
                        %error,
                        "listener accept remained unhealthy; stopping listener task"
                    );
                    return Err(error);
                }
            },
        }
    }
}

/// Wait for the next QUIC connection attempt and surface endpoint-driver loss as
/// a listener failure. Quinn 0.11 reports UDP socket I/O failure by terminating
/// its internal endpoint driver; `Endpoint::accept()` then yields `None`, the
/// same value used for an explicitly closed endpoint. Chimera does not close
/// these endpoints directly during normal inbound stop (the owning listener
/// task is aborted instead), so a naturally completed accept is unexpected and
/// must terminate the listener task for generation-aware health propagation.
pub(crate) async fn accept_quic_with_health(
    endpoint: &quinn::Endpoint,
    listener_kind: &'static str,
) -> std::io::Result<quinn::Incoming> {
    match endpoint.accept().await {
        Some(incoming) => Ok(incoming),
        None => {
            let error = std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("{listener_kind} QUIC endpoint stopped accepting"),
            );
            error!(
                listener_kind,
                %error,
                "QUIC endpoint stopped unexpectedly; stopping listener task"
            );
            Err(error)
        }
    }
}

#[cfg(feature = "grpc_transport")]
pub(crate) mod grpc_transport;
mod policy_stream;
mod quic;
mod tcp_relay;
mod transport_plan;
pub(crate) mod udp;
mod xhttp;

struct StartingTasks {
    handles: Vec<JoinHandle<()>>,
}

impl StartingTasks {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            handles: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, handle: JoinHandle<()>) {
        self.handles.push(handle);
    }

    fn commit(mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.handles)
    }

    fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

impl Drop for StartingTasks {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

/// Listener tasks produced only after every required socket bind/listen step
/// for one inbound has succeeded. Dropping the value before adoption aborts
/// the listeners, so lifecycle code cannot accidentally detach a ready-but-
/// unpublished instance.
pub(crate) struct BoundInboundTasks {
    handles: Option<Vec<JoinHandle<()>>>,
}

impl BoundInboundTasks {
    fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            handles: Some(handles),
        }
    }

    pub(crate) fn into_handles(mut self) -> Vec<JoinHandle<()>> {
        self.handles.take().unwrap_or_default()
    }
}

impl Drop for BoundInboundTasks {
    fn drop(&mut self) {
        if let Some(handles) = self.handles.take() {
            for handle in handles {
                handle.abort();
            }
        }
    }
}

pub(crate) async fn start_bound_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<BoundInboundTasks> {
    start_server_tasks(config, runtime)
        .await
        .map(BoundInboundTasks::new)
}

pub async fn start_servers(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    Ok(start_bound_servers(config, runtime).await?.into_handles())
}

async fn start_server_tasks(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    register_configured_identities(&config.protocol, &runtime);

    match transport_plan::compile_listener_plan(&config.protocol) {
        transport_plan::InboundListenerPlan::Xhttp(plan) => {
            return xhttp::start_xhttp_server(config, runtime, *plan).await;
        }
        #[cfg(feature = "grpc_transport")]
        transport_plan::InboundListenerPlan::Grpc(plan) => {
            return grpc_transport::start_grpc_server(config, runtime, *plan).await;
        }
        transport_plan::InboundListenerPlan::Stream => {}
    }

    let mut join_handles = StartingTasks::with_capacity(3);

    match config.transport {
        Transport::Tcp => {
            match start_tcp_server_with_runtime(config.clone(), runtime).await {
                Ok(Some(handle)) => {
                    join_handles.push(handle);
                }
                Ok(None) => (),
                Err(e) => return Err(e),
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
                Err(error) => return Err(error),
            }
        }
        Transport::Quic => match start_quic_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => return Err(e),
        },
        // UDP listeners need runtime state for routing/outbound selection.
        Transport::Udp => match start_udp_server(config.clone(), runtime).await {
            Ok(Some(handle)) => {
                join_handles.push(handle);
            }
            Ok(None) => (),
            Err(e) => return Err(e),
        },
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles.commit())
}

fn register_stats_identity(runtime: &RuntimeState, level: u32, identity: String) {
    if identity.is_empty() {
        return;
    }
    let policy = runtime.policy_user_stats(level);
    if policy.uplink || policy.downlink {
        register_identity(identity);
    }
}

fn register_configured_identities(
    protocol: &ServerProxyConfig,
    runtime: &RuntimeState,
) {
    match protocol {
        #[cfg(feature = "http")]
        ServerProxyConfig::Http {
            accounts,
            user_level,
            ..
        } => {
            for account in accounts {
                register_stats_identity(
                    runtime,
                    *user_level,
                    account.username.clone(),
                );
            }
        }
        #[cfg(feature = "mixed")]
        ServerProxyConfig::Mixed { accounts, .. } => {
            for account in accounts.snapshot() {
                register_stats_identity(runtime, 0, account.username);
            }
        }
        ServerProxyConfig::Socks {
            accounts,
            user_level,
            ..
        } => {
            for account in accounts.snapshot() {
                register_stats_identity(runtime, *user_level, account.username);
            }
        }
        #[cfg(feature = "vless")]
        ServerProxyConfig::Vless { users, .. } => {
            for user in users {
                register_stats_identity(
                    runtime,
                    user.user_level,
                    user.user_label.clone(),
                );
            }
        }
        #[cfg(feature = "vmess")]
        ServerProxyConfig::Vmess { users } => {
            for user in users {
                register_stats_identity(
                    runtime,
                    user.user_level,
                    user.user_label.clone(),
                );
            }
        }
        #[cfg(feature = "trojan")]
        ServerProxyConfig::Trojan { users, .. } => {
            for user in users {
                let identity = user
                    .email
                    .clone()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| user.password.clone());
                register_stats_identity(runtime, user.user_level, identity);
            }
        }
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, .. } => {
            for user in users {
                register_stats_identity(
                    runtime,
                    user.user_level,
                    user.email.clone(),
                );
            }
        }
        #[cfg(feature = "hysteria")]
        ServerProxyConfig::Hysteria2 { config } => {
            for user in &config.clients {
                let identity = user
                    .email
                    .clone()
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| user.password.clone());
                register_stats_identity(runtime, user.level, identity);
            }
        }
        #[cfg(feature = "tuic")]
        ServerProxyConfig::TuicV5 { config } => {
            register_stats_identity(runtime, 0, config.uuid.clone());
        }
        ServerProxyConfig::Xhttp { inner, .. } => {
            register_configured_identities(inner, runtime);
        }
        #[cfg(feature = "httpupgrade")]
        ServerProxyConfig::HttpUpgrade(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        #[cfg(feature = "grpc_transport")]
        ServerProxyConfig::Grpc(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        #[cfg(feature = "reality")]
        ServerProxyConfig::Reality(config) => {
            register_configured_identities(config.inner.as_ref(), runtime);
        }
        _ => {}
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
        tcp_socket_policy,
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
            create_tcp_listener(socket_addr, tcp_socket_policy.as_ref()).await?
        }
    };

    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_tcp_server(
            listener,
            tcp_handler,
            runtime,
            sniffing,
            tcp_socket_policy,
        )
        .await
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
    tcp_socket_policy: Option<TcpSocketPolicy>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let listener_addr = listener.local_addr()?;

    let mut accept_health = TcpAcceptHealth::default();
    loop {
        let (stream, addr) =
            accept_tcp_with_health(&listener, &mut accept_health, "tcp").await?;
        if let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay: {}", e);
        }
        if let Some(policy) = tcp_socket_policy.as_ref()
            && let Err(error) =
                apply_tcp_socket_policy(&stream, listener_addr, addr, policy)
        {
            error!(
                peer = %addr,
                listener = %listener_addr,
                congestion = %policy.congestion,
                %error,
                "failed to apply inbound TCP socket policy"
            );
            continue;
        }
        let cloned_cache = resolver.clone();
        let cloned_handler = server_handler.clone();
        let connection_runtime = runtime.clone();
        let sniffing = sniffing.clone();

        runtime.spawn_inbound_connection(async move {
            let connection_context = match tcp_server_connection_context(
                &stream,
                cloned_handler.as_ref().as_ref(),
            ) {
                Ok(mut context) => {
                    context.peer_addr = Some(addr);
                    context.listener_addr = Some(listener_addr);
                    context.runtime = Some(connection_runtime.clone());
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
                connection_runtime,
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

async fn create_tcp_listener(
    bind_addr: SocketAddr,
    policy: Option<&TcpSocketPolicy>,
) -> std::io::Result<tokio::net::TcpListener> {
    let bind_interface = policy.and_then(|policy| policy.bind_interface.clone());
    let multipath = policy.is_some_and(|policy| policy.multipath);
    let socket = crate::util::socket::new_xray_tcp_listener_socket(
        bind_interface,
        bind_addr.is_ipv6(),
        multipath,
    )?;

    #[cfg(target_os = "linux")]
    if let Some(policy) = policy {
        let fd = socket.as_raw_fd();
        if policy.ipv6_only {
            if !bind_addr.is_ipv6() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "sockopt.v6only requires an IPv6 listener",
                ));
            }
            crate::util::socket::configure_ipv6_only(fd)?;
        }
        if let Some(mark) = policy.mark {
            crate::util::socket::configure_socket_mark(fd, mark)?;
        }
        if policy.transparent {
            crate::util::socket::configure_ip_transparent(fd)?;
        }
        if let Some(value) = policy.fast_open {
            crate::util::socket::configure_tcp_fast_open(fd, value)?;
        }
        if let Some(value) = policy.max_seg {
            crate::util::socket::configure_tcp_max_seg(fd, value)?;
        }
        crate::util::socket::configure_custom_sockopt(
            fd,
            if bind_addr.is_ipv6() { "tcp6" } else { "tcp4" },
            &policy.custom_sockopt,
        )?;
    }

    #[cfg(not(target_os = "linux"))]
    if policy.is_some_and(|policy| {
        policy.ipv6_only
            || policy.mark.is_some()
            || policy.transparent
            || policy.fast_open.is_some()
            || policy.max_seg.is_some()
            || !policy.custom_sockopt.is_empty()
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "configured inbound TCP listener socket options are unsupported on this platform",
        ));
    }

    socket.bind(bind_addr)?;
    socket.listen(1024)
}

#[cfg(target_os = "linux")]
fn apply_tcp_socket_policy(
    stream: &tokio::net::TcpStream,
    listener_addr: SocketAddr,
    peer_addr: SocketAddr,
    policy: &TcpSocketPolicy,
) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    if !policy.congestion.is_empty() {
        crate::util::socket::set_tcp_congestion(fd, &policy.congestion)?;
    }
    if policy.keep_alive_idle != 0 || policy.keep_alive_interval != 0 {
        crate::util::socket::configure_tcp_keepalive(
            fd,
            policy.keep_alive_idle,
            policy.keep_alive_interval,
        )?;
    }
    if let Some(timeout_ms) = policy.user_timeout_ms {
        crate::util::socket::configure_tcp_user_timeout(fd, timeout_ms)?;
    }
    if let Some(value) = policy.window_clamp {
        crate::util::socket::configure_tcp_window_clamp(fd, value)?;
    }
    if let Some(brutal) = policy.brutal.as_ref() {
        let group_id =
            crate::util::socket::tcp_brutal_group_id(listener_addr, peer_addr);
        crate::util::socket::set_tcp_brutal_params(
            fd,
            brutal.rate_bytes_per_sec,
            brutal.cwnd_gain,
            group_id,
        )?;
        tracing::debug!(
            peer = %peer_addr,
            listener = %listener_addr,
            rate_bytes_per_sec = brutal.rate_bytes_per_sec,
            cwnd_gain = brutal.cwnd_gain,
            group_id,
            "configured TCP Brutal v2 inbound socket"
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_tcp_socket_policy(
    _stream: &tokio::net::TcpStream,
    _listener_addr: SocketAddr,
    _peer_addr: SocketAddr,
    policy: &TcpSocketPolicy,
) -> std::io::Result<()> {
    if policy.has_connection_options() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "configured inbound TCP connection socket options are unsupported on this platform",
        ))
    } else {
        Ok(())
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
        TcpServerSetupResult::BidirectionalUdp {
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
        TcpServerSetupResult::MultiDirectionalUdp {
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
        TcpServerSetupResult::SessionBasedUdp {
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
    use std::{
        io::IoSliceMut,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use quinn::{
        AsyncUdpSocket, UdpPoller,
        udp::{RecvMeta, Transmit},
    };
    #[cfg(target_os = "linux")]
    use tokio::net::{TcpListener, TcpStream};

    #[cfg(target_os = "linux")]
    use crate::{
        address::{Address, NetLocation},
        config::server_config::DokodemoDoorConfig,
        handler::dokodemo::DokodemoDoorTcpHandler,
    };

    use super::*;

    #[derive(Debug)]
    struct AlwaysWritableUdpPoller;

    impl UdpPoller for AlwaysWritableUdpPoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct FailingQuicUdpSocket {
        local_addr: SocketAddr,
    }

    impl AsyncUdpSocket for FailingQuicUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(AlwaysWritableUdpPoller)
        }

        fn try_send(&self, _transmit: &Transmit) -> std::io::Result<()> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            _bufs: &mut [IoSliceMut<'_>],
            _meta: &mut [RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::other(
                "simulated QUIC UDP receive failure",
            )))
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }
    }

    #[tokio::test]
    async fn quic_endpoint_driver_loss_reaches_inbound_health() {
        let config = ServerConfig {
            tag: "quic-driver-loss".to_string(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                10002,
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: crate::config::server_config::SocksUserStore::new(
                    Vec::new(),
                ),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            },
            transport: Transport::Quic,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        };
        let runtime = RuntimeState::new(vec![config], Vec::new());
        assert!(runtime.mark_running());

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(FailingQuicUdpSocket {
                local_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 10002)),
            }),
            Arc::new(quinn::TokioRuntime),
        )
        .expect("construct endpoint with controlled failing socket");
        let task = tokio::spawn(async move {
            let error = accept_quic_with_health(&endpoint, "test-quic")
                .await
                .expect_err("driver loss must end QUIC accept");
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        });
        runtime.register_inbound_tasks("quic-driver-loss", vec![task]);

        let failure = tokio::time::timeout(
            Duration::from_secs(1),
            runtime.wait_for_inbound_failure(),
        )
        .await
        .expect("QUIC listener failure should reach runtime health");
        assert_eq!(failure.tag, "quic-driver-loss");
        assert!(!runtime.is_ready());
    }

    #[test]
    fn tcp_accept_health_fails_only_after_sustained_listener_errors() {
        let mut health = TcpAcceptHealth::default();
        let error = std::io::Error::other("simulated listener resource failure");
        let started = Instant::now();

        for attempt in 0..(ACCEPT_ERROR_MIN_FAILURES - 1) {
            let disposition = health.classify_error_at(
                &error,
                started + Duration::from_millis(u64::from(attempt) * 100),
            );
            assert!(matches!(disposition, AcceptErrorDisposition::Retry(_)));
        }
        assert_eq!(
            health.classify_error_at(
                &error,
                started + ACCEPT_ERROR_UNHEALTHY_AFTER - Duration::from_millis(1),
            ),
            AcceptErrorDisposition::Retry(ACCEPT_ERROR_MAX_BACKOFF)
        );
        assert_eq!(
            health
                .classify_error_at(&error, started + ACCEPT_ERROR_UNHEALTHY_AFTER,),
            AcceptErrorDisposition::Fatal
        );
    }

    #[test]
    fn tcp_accept_health_resets_on_success_or_connection_scoped_error() {
        let mut health = TcpAcceptHealth::default();
        let listener_error =
            std::io::Error::other("simulated listener resource failure");
        let aborted = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
        let started = Instant::now();

        assert_eq!(
            health.classify_error_at(&listener_error, started),
            AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
        );
        assert_eq!(
            health.classify_error_at(&aborted, started + Duration::from_secs(4)),
            AcceptErrorDisposition::Retry(Duration::ZERO)
        );
        assert_eq!(
            health.classify_error_at(
                &listener_error,
                started + Duration::from_secs(10)
            ),
            AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
        );

        health.record_success();
        assert_eq!(
            health.classify_error_at(
                &listener_error,
                started + Duration::from_secs(20)
            ),
            AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
        );
    }

    #[test]
    fn tcp_accept_health_bounds_backoff_and_fails_terminal_states_immediately() {
        let mut health = TcpAcceptHealth::default();
        let error = std::io::Error::other("simulated listener resource failure");
        let started = Instant::now();
        let mut last_retry = Duration::ZERO;
        for attempt in 0..6 {
            let disposition = health.classify_error_at(
                &error,
                started + Duration::from_millis(attempt * 100),
            );
            let AcceptErrorDisposition::Retry(backoff) = disposition else {
                panic!("short error streak should remain retryable");
            };
            last_retry = backoff;
        }
        assert_eq!(last_retry, ACCEPT_ERROR_MAX_BACKOFF);

        let would_block = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        assert_eq!(
            health.classify_error_at(&would_block, started + Duration::from_secs(1)),
            AcceptErrorDisposition::Retry(ACCEPT_ERROR_INITIAL_BACKOFF)
        );

        let terminal = std::io::Error::from(std::io::ErrorKind::NotConnected);
        assert_eq!(
            health.classify_error_at(&terminal, started + Duration::from_secs(1)),
            AcceptErrorDisposition::Fatal
        );
    }

    #[tokio::test]
    async fn bound_inbound_tasks_drop_releases_ready_listener() {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral port");
        let address = probe.local_addr().expect("read ephemeral address");
        drop(probe);

        let config = ServerConfig {
            tag: "bound-ready".to_string(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                address.ip(),
                address.port(),
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: crate::config::server_config::SocksUserStore::new(
                    Vec::new(),
                ),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        };
        let runtime = RuntimeState::new(vec![config.clone()], Vec::new());
        let bound = start_bound_servers(config, runtime)
            .await
            .expect("bind inbound before returning readiness token");

        assert!(
            tokio::net::TcpListener::bind(address).await.is_err(),
            "bound result must represent an already-owned listener"
        );
        drop(bound);

        for _ in 0..50 {
            if let Ok(listener) = tokio::net::TcpListener::bind(address).await {
                drop(listener);
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("dropping an unadopted bound result must release its listener");
    }

    #[test]
    fn configured_identity_registration_respects_user_stats_policy() {
        let disabled_identity = "stats-policy-disabled-identity";
        let disabled_runtime = RuntimeState::new(Vec::new(), Vec::new());
        register_stats_identity(&disabled_runtime, 7, disabled_identity.to_string());
        assert!(
            !crate::traffic::snapshot()
                .known_identities
                .contains(disabled_identity)
        );

        let enabled_identity = "stats-policy-enabled-identity";
        let enabled_runtime = RuntimeState::new(Vec::new(), Vec::new());
        let mut levels = std::collections::HashMap::new();
        levels.insert(
            7,
            Some(crate::config::def::PolicyLevelConfig {
                stats_user_uplink: true,
                ..crate::config::def::PolicyLevelConfig::default()
            }),
        );
        enabled_runtime.replace_policy(Some(&crate::config::def::PolicyConfig {
            levels,
            ..crate::config::def::PolicyConfig::default()
        }));
        register_stats_identity(&enabled_runtime, 7, enabled_identity.to_string());
        assert!(
            crate::traffic::snapshot()
                .known_identities
                .contains(enabled_identity)
        );
    }

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
