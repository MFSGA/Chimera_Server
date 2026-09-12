use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use quic::start_quic_server;
#[cfg(target_os = "linux")]
use socket2::SockRef;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use tokio::task::JoinHandle;
use udp::start_udp_server;

use crate::{
    address::{BindLocation, NetLocation},
    config::{
        Transport,
        server_config::{
            InboundSniffingConfig, ServerConfig, ServerProxyConfig, TcpSocketPolicy,
        },
    },
    handler::tcp::{
        tcp_handler::{TcpServerConnectionContext, TcpServerHandler},
        tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::RuntimeState,
    traffic::register_identity,
};

use tracing::error;

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
        let connection_runtime = runtime.data_plane();
        let sniffing = sniffing.clone();

        runtime.spawn_inbound_connection(async move {
            let connection_context = match tcp_server_connection_context(
                &stream,
                cloned_handler.as_ref().as_ref(),
            ) {
                Ok(mut context) => {
                    context.peer_addr = Some(addr);
                    context.listener_addr = Some(listener_addr);
                    context.handshake_runtime =
                        Some(connection_runtime.inbound_handshake_runtime());
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

mod stream_session;
use stream_session::*;

#[cfg(test)]
mod tests;
