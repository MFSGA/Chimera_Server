// TODO: remove this once WIP modules stabilize and dead code is pruned
#![allow(dead_code)]

pub use beginning::start_tcp_server;
pub use config::{
    def::LiteralConfig,
    server_config::{ServerConfig, ServerProxyConfig},
};
use config::{
    def::{ApiConfig, DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS},
    rule::RoutingConfig,
};
pub use config_loader::{ConfigFormat, resolve_config_source};
pub use runtime::{OutboundSummary, RuntimeState};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::task::{JoinError, JoinHandle};
use tokio_rustls::rustls;

mod address;

mod async_stream;

mod beginning;

mod config;

mod config_loader;

mod geodata;

#[cfg(feature = "api")]
mod grpc;

mod mcp;

mod outbound;

mod runtime;

#[cfg(feature = "reality")]
pub mod reality;

mod log;

mod handler;

mod inbound;

mod resolver;

mod routing_observer;
mod routing_process;
mod routing_state;
mod routing_webhook;
mod session_tasks;
mod tls_client_hello;

pub mod traffic;

mod util;

mod xudp_registry;

mod user_domain;

#[allow(clippy::large_enum_variant)]
pub enum ConfigType {
    File(String),

    Str(String),
}

impl ConfigType {
    pub fn try_parse(
        self,
        format: Option<ConfigFormat>,
    ) -> Result<LiteralConfig, Error> {
        match self {
            ConfigType::File(file) => {
                config_loader::parse_config_source(&file, format)
            }

            _ => {
                todo!()
            }
        }
    }
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

pub struct Options {
    pub config: ConfigType,
    pub config_format: Option<ConfigFormat>,

    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

pub struct ServerRuntime {
    pub inbounds: Vec<ServerConfig>,
    pub runtime_state: RuntimeState,
}

#[derive(Debug)]
struct ServerShutdownReport {
    stopped_inbounds: usize,
    drained_connections: bool,
    cancelled_connections: usize,
    stopped_global_xudp_workers: usize,
}

enum ServerExit {
    Signal(&'static str),
    SignalError(std::io::Error),
    ServiceTask(Result<(), JoinError>),
    InboundFailure(crate::inbound::InboundFailure),
}

async fn wait_for_shutdown_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                Ok("SIGINT")
            }
            signal = terminate.recv() => {
                signal.ok_or_else(|| std::io::Error::other("SIGTERM listener closed"))?;
                Ok("SIGTERM")
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("CTRL_C")
    }
}

async fn wait_for_service_task(
    handles: &mut [JoinHandle<()>],
) -> Result<(), JoinError> {
    if handles.is_empty() {
        return std::future::pending().await;
    }
    futures::future::select_all(handles.iter_mut()).await.0
}

async fn shutdown_server_runtime(
    runtime_state: &RuntimeState,
    service_tasks: Vec<JoinHandle<()>>,
    connection_grace_period: Duration,
    failed: bool,
) -> ServerShutdownReport {
    runtime_state.begin_draining();

    // Close connection registration first so an accept racing with listener
    // teardown cannot escape the server-level owner.
    runtime_state.close_inbound_connection_tasks();

    // Stop every non-inbound service promptly before waiting for data-plane
    // listener cleanup. InboundManager aborts all listeners before awaiting any
    // one handle, so the process stops accepting across the whole server first.
    for task in &service_tasks {
        task.abort();
    }
    let stopped_inbounds = runtime_state.inbound_manager().stop_all_tasks().await;
    for task in service_tasks {
        let _ = task.await;
    }

    let connection_shutdown = runtime_state
        .drain_inbound_connection_tasks(connection_grace_period)
        .await;
    let stopped_global_xudp_workers =
        beginning::udp::shutdown_global_xudp_workers().await;
    runtime_state.finish_shutdown(failed);

    ServerShutdownReport {
        stopped_inbounds,
        drained_connections: connection_shutdown.drained,
        cancelled_connections: connection_shutdown.cancelled_tasks,
        stopped_global_xudp_workers,
    }
}

fn install_configured_user_domain_policy(
    runtime_state: &RuntimeState,
    policy: Option<&serde_json::Value>,
) -> Result<(), Error> {
    let Some(policy) = policy else {
        return Ok(());
    };

    let json_config = serde_json::to_string(policy).map_err(|error| {
        Error::InvalidConfig(format!(
            "could not serialize userDomainAccess configuration: {error}"
        ))
    })?;
    runtime_state
        .apply_user_domain_policy(&json_config)
        .map(|_| ())
        .map_err(|failure| {
            Error::InvalidConfig(format!(
                "invalid userDomainAccess configuration: {}",
                failure.message
            ))
        })
}

pub fn prepare_server_runtime(
    config: LiteralConfig,
    cwd: Option<&str>,
    log_file: Option<&str>,
) -> Result<ServerRuntime, Error> {
    let policy_config = config.policy.clone();
    let user_domain_access = config.user_domain_access.clone();
    let inbounds = prepare_server_inbounds(config, cwd, log_file)?;
    let runtime_state = RuntimeState::new(inbounds.clone(), Vec::new());
    runtime_state.replace_policy(policy_config.as_ref());
    install_configured_user_domain_policy(
        &runtime_state,
        user_domain_access.as_ref(),
    )?;

    Ok(ServerRuntime {
        inbounds,
        runtime_state,
    })
}

pub fn prepare_server_inbounds(
    config: LiteralConfig,
    cwd: Option<&str>,
    log_file: Option<&str>,
) -> Result<Vec<ServerConfig>, Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    log::init(config.log.as_ref(), cwd, log_file)?;

    config
        .inbounds
        .into_iter()
        .map(ServerConfig::try_from)
        .collect::<Result<Vec<_>, _>>()
}

pub fn is_tcp_reality_server(config: &ServerConfig) -> bool {
    #[cfg(feature = "reality")]
    {
        matches!(config.transport, crate::config::Transport::Tcp)
            && matches!(config.protocol, ServerProxyConfig::Reality(_))
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = config;
        false
    }
}

#[derive(Default)]
struct ResolvedApiConfig<'a> {
    listen_addr: Option<SocketAddr>,
    inbound: Option<&'a ServerConfig>,
}

fn resolve_api_config<'a>(
    api_config: Option<&ApiConfig>,
    routing_config: Option<&RoutingConfig>,
    all_inbounds: &'a [ServerConfig],
) -> Result<ResolvedApiConfig<'a>, Error> {
    let Some(api) = api_config else {
        return Ok(ResolvedApiConfig::default());
    };

    if let Some(listen) = api.listen.as_ref() {
        let listen_addr = listen.parse::<SocketAddr>().map_err(|err| {
            Error::InvalidConfig(format!("invalid api.listen {}: {}", listen, err))
        })?;
        return Ok(ResolvedApiConfig {
            listen_addr: Some(listen_addr),
            inbound: None,
        });
    }

    let Some(api_tag) = api.tag.as_deref() else {
        return Ok(ResolvedApiConfig::default());
    };
    let Some(routing) = routing_config else {
        return Ok(ResolvedApiConfig::default());
    };

    let mut matched_api_rule = false;
    for rule in &routing.rules {
        if rule.outbound_tag.as_deref() != Some(api_tag) {
            continue;
        }
        matched_api_rule = true;

        for inbound_tag in &rule.inbound_tag {
            let Some(inbound) = all_inbounds
                .iter()
                .find(|config| config.tag == *inbound_tag)
            else {
                continue;
            };

            ensure_api_inbound_protocol(inbound)?;
            return Ok(ResolvedApiConfig {
                listen_addr: Some(api_inbound_listen_addr(inbound)?),
                inbound: Some(inbound),
            });
        }
    }

    if matched_api_rule {
        return Err(Error::InvalidConfig(format!(
            "api routing for outbound {} does not reference an existing inbound",
            api_tag
        )));
    }

    Ok(ResolvedApiConfig::default())
}

fn api_inbound_listen_addr(inbound: &ServerConfig) -> Result<SocketAddr, Error> {
    match &inbound.bind_location {
        crate::address::BindLocation::Address(addr) => Ok(addr.to_socket_addr()?),
    }
}

fn ensure_api_inbound_protocol(inbound: &ServerConfig) -> Result<(), Error> {
    if is_api_inbound_protocol(&inbound.protocol) {
        return Ok(());
    }

    Err(Error::InvalidConfig(format!(
        "api inbound {} must use dokodemo-door semantics",
        inbound.tag
    )))
}

fn is_api_inbound_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::DokodemoDoor { .. } => true,
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => matches!(
            tls_config.inner.as_ref(),
            ServerProxyConfig::DokodemoDoor { .. }
        ),
        _ => false,
    }
}

fn api_inbound_uses_tls(_protocol: &ServerProxyConfig) -> bool {
    #[cfg(feature = "tls")]
    if matches!(_protocol, ServerProxyConfig::Tls(_)) {
        return true;
    }

    false
}

pub fn start(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let Options {
        config,
        config_format,
        cwd,
        rt,
        log_file,
    } = opts;
    let config = config.try_parse(config_format)?;

    let rt = match rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };

    rt.block_on(async {
        match start_async(config, cwd.as_deref(), log_file.as_deref()).await {
            Err(e) => {
                eprintln!("start error: {}", e);
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

fn compile_configured_outbounds(
    outbounds: &[config::def::OutboundItem],
) -> Result<Vec<OutboundSummary>, Error> {
    outbounds
        .iter()
        .map(outbound::compile_static_outbound)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::InvalidConfig)
}

pub fn validate(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 1. config parse
    let config = opts.config.try_parse(opts.config_format)?;
    let _ = compile_configured_outbounds(&config.outbounds)?;

    let validation_runtime = RuntimeState::new(Vec::new(), Vec::new());
    install_configured_user_domain_policy(
        &validation_runtime,
        config.user_domain_access.as_ref(),
    )?;

    // 2. api/mcp config validation
    let api_config = config.api.clone();
    let mcp_config = config.mcp.clone();
    let routing_config = config.routing.clone();
    routing_observer::validate_observatory_config(
        config.observatory.as_ref(),
        config.burst_observatory.as_ref(),
    )
    .map_err(Error::InvalidConfig)?;

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(ServerConfig::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    routing_state::RoutingState::from_config(config.routing.as_ref())
        .map_err(Error::InvalidConfig)?;

    let resolved_api = resolve_api_config(
        api_config.as_ref(),
        routing_config.as_ref(),
        &all_inbounds,
    )?;
    let api_addr = resolved_api.listen_addr;

    if let Some(mcp) = mcp_config.as_ref()
        && let Some(listen) = mcp.listen.as_ref()
    {
        let _ = listen.parse::<std::net::SocketAddr>().map_err(|err| {
            Error::InvalidConfig(format!("invalid mcp.listen {}: {}", listen, err))
        })?;
        let _ = mcp.update_interval_ms.max(100);
    }

    let mut any_server = !all_inbounds.is_empty();
    if let Some(api) = api_config.as_ref()
        && api_addr.is_some()
        && !api.services.is_empty()
    {
        any_server = true;
    }
    if let Some(mcp) = mcp_config.as_ref()
        && mcp.listen.as_ref().is_some()
    {
        any_server = true;
    }

    if !any_server {
        return Err(Error::InvalidConfig(
            "no servers started; check inbounds/api configuration".into(),
        ));
    }

    Ok(())
}

async fn start_async(
    config: LiteralConfig,
    cwd: Option<&str>,
    log_file: Option<&str>,
) -> Result<(), Error> {
    let connection_drain_timeout = Duration::from_secs(
        config
            .shutdown
            .as_ref()
            .map(|shutdown| shutdown.grace_period_seconds)
            .unwrap_or(DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS),
    );

    //  todo: log mod
    log::init(config.log.as_ref(), cwd, log_file)?;
    // 2. api config
    let api_config = config.api.clone();
    let mcp_config = config.mcp.clone();
    let routing_config = config.routing.clone();
    let policy_config = config.policy.clone();
    let user_domain_access = config.user_domain_access.clone();
    let observatory_config = config.observatory.clone();
    let burst_observatory_config = config.burst_observatory.clone();
    routing_observer::validate_observatory_config(
        observatory_config.as_ref(),
        burst_observatory_config.as_ref(),
    )
    .map_err(Error::InvalidConfig)?;
    let outbounds = compile_configured_outbounds(&config.outbounds)?;

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(ServerConfig::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let runtime_state = RuntimeState::new(all_inbounds.clone(), outbounds);
    runtime_state.replace_policy(policy_config.as_ref());
    install_configured_user_domain_policy(
        &runtime_state,
        user_domain_access.as_ref(),
    )?;
    runtime_state.replace_routing(
        routing_state::RoutingState::from_config(config.routing.as_ref())
            .map_err(Error::InvalidConfig)?,
    );

    let resolved_api = resolve_api_config(
        api_config.as_ref(),
        routing_config.as_ref(),
        &all_inbounds,
    )?;
    let api_addr = resolved_api.listen_addr;
    let skip_inbound_tag = resolved_api.inbound.map(|inbound| inbound.tag.clone());
    if api_config.is_some() {
        if let Some(inbound) = resolved_api.inbound
            && api_inbound_uses_tls(&inbound.protocol)
        {
            tracing::warn!(
                "api inbound {} uses tls settings, but local grpc currently listens without tls",
                inbound.tag
            );
        }
        if api_addr.is_none() {
            tracing::warn!("api is configured but no listen address was resolved");
        }
    }

    let mut join_handles = Vec::with_capacity(4);
    let mut has_started_server = false;
    if let Some(mcp) = mcp_config.as_ref() {
        if let Some(listen) = mcp.listen.as_ref() {
            let listen = listen.parse::<std::net::SocketAddr>().map_err(|err| {
                Error::InvalidConfig(format!(
                    "invalid mcp.listen {}: {}",
                    listen, err
                ))
            })?;
            let interval_ms = mcp.update_interval_ms.max(100);
            let mcp_handle = mcp::start_mcp_server(mcp::McpServerConfig {
                listen,
                path: mcp.path.clone(),
                update_interval: Duration::from_millis(interval_ms),
            })
            .await?;
            join_handles.push(mcp_handle);
            has_started_server = true;
        } else {
            tracing::warn!("mcp is configured but no listen address was resolved");
        }
    }

    // Bind every configured data-plane listener before advertising the control
    // plane. rnode uses GetSysStats as its readiness probe, so starting gRPC
    // first would allow a process with a failed inbound bind to look healthy.
    if let Some(tag) = skip_inbound_tag.as_deref() {
        tracing::info!("skip api inbound {} to avoid grpc port conflict", tag);
    }
    let started_inbounds = runtime_state
        .inbound_manager()
        .start_configured_inbounds(
            runtime_state.clone(),
            skip_inbound_tag.as_deref(),
        )
        .await?;
    has_started_server |= started_inbounds > 0;

    if let Some(observer) = routing_observer::start_observer(
        runtime_state.clone(),
        observatory_config,
        burst_observatory_config,
    )
    .map_err(Error::InvalidConfig)?
    {
        join_handles.push(observer);
        has_started_server = true;
    }
    #[cfg(feature = "api")]
    if let Some(api) = api_config.as_ref()
        && let Some(listen) = api_addr
    {
        if !api.services.is_empty() {
            let grpc_handle = grpc::start_grpc_server(
                grpc::GrpcServerConfig {
                    listen,
                    services: api.services.clone(),
                },
                runtime_state.clone(),
            )
            .await?;
            join_handles.push(grpc_handle);
            has_started_server = true;
        } else {
            tracing::warn!("api is configured but no services are enabled");
        }
    }

    #[cfg(not(feature = "api"))]
    if let Some(api) = api_config.as_ref()
        && !api.services.is_empty()
    {
        tracing::warn!(
            "api services configured but the \"api\" feature is disabled; grpc support is unavailable"
        );
    }

    if !has_started_server {
        return Err(Error::InvalidConfig(
            "no servers started; check inbounds/api configuration".into(),
        ));
    }
    if !runtime_state.mark_running() {
        return Err(Error::Io(std::io::Error::other(
            "runtime lifecycle left starting state before startup completed",
        )));
    }

    let exit = {
        let shutdown_signal = wait_for_shutdown_signal();
        let service_task = wait_for_service_task(&mut join_handles);
        let inbound_failure = runtime_state.wait_for_inbound_failure();
        tokio::pin!(shutdown_signal);
        tokio::pin!(service_task);
        tokio::pin!(inbound_failure);
        tokio::select! {
            result = &mut shutdown_signal => match result {
                Ok(signal) => ServerExit::Signal(signal),
                Err(error) => ServerExit::SignalError(error),
            },
            result = &mut service_task => ServerExit::ServiceTask(result),
            failure = &mut inbound_failure => ServerExit::InboundFailure(failure),
        }
    };

    match &exit {
        ServerExit::Signal(signal) => {
            tracing::info!(
                %signal,
                grace_period_seconds = connection_drain_timeout.as_secs(),
                "shutdown requested; stopping listeners"
            );
        }
        ServerExit::InboundFailure(failure) => {
            tracing::error!(
                inbound_tag = %failure.tag,
                generation = failure.generation,
                "inbound listener exited unexpectedly; shutting down server"
            );
        }
        ServerExit::SignalError(_) | ServerExit::ServiceTask(_) => {}
    }

    let failed = !matches!(&exit, ServerExit::Signal(_));
    let shutdown = shutdown_server_runtime(
        &runtime_state,
        join_handles,
        connection_drain_timeout,
        failed,
    )
    .await;
    tracing::info!(
        stopped_inbounds = shutdown.stopped_inbounds,
        drained_connections = shutdown.drained_connections,
        cancelled_connections = shutdown.cancelled_connections,
        stopped_global_xudp_workers = shutdown.stopped_global_xudp_workers,
        lifecycle = runtime_state.lifecycle_state().as_str(),
        "server shutdown complete"
    );

    match exit {
        ServerExit::Signal(_) => Ok(()),
        ServerExit::SignalError(error) => {
            tracing::error!(%error, "shutdown signal listener failed");
            Err(Error::Io(error))
        }
        ServerExit::ServiceTask(Ok(())) => Err(Error::Io(std::io::Error::other(
            "server task finished unexpectedly",
        ))),
        ServerExit::ServiceTask(Err(error)) => {
            tracing::error!(%error, "runtime task failed; server shut down");
            Err(Error::Io(std::io::Error::other(error)))
        }
        ServerExit::InboundFailure(failure) => {
            Err(Error::Io(std::io::Error::other(format!(
                "inbound {} generation {} listener exited unexpectedly",
                failure.tag, failure.generation
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        compile_configured_outbounds, prepare_server_runtime, resolve_api_config,
    };
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            def::ApiConfig,
            rule::{RoutingConfig, RuleConfig},
            server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
        },
    };

    #[test]
    fn check_compiles_outbounds_like_startup() {
        let config: crate::config::def::LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [],
                "outbounds": [
                    {"tag": "broken", "protocol": "vless"}
                ]
            }"#,
        )
        .expect("parse outbound validation config");

        let error = compile_configured_outbounds(&config.outbounds)
            .expect_err("VLESS outbound without settings must fail validation");
        assert!(matches!(
            error,
            crate::Error::InvalidConfig(message)
                if message == "vless outbound broken requires settings"
        ));
    }

    #[test]
    fn prepare_server_runtime_applies_root_xray_policy() {
        let config: crate::config::def::LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [],
                "outbounds": [],
                "policy": {"levels": {"7": {"handshake": 2}}}
            }"#,
        )
        .expect("parse root policy config");
        let prepared = prepare_server_runtime(config, None, None)
            .expect("prepare server runtime");
        assert_eq!(
            prepared.runtime_state.xray_handshake_timeout_for_level(7),
            Duration::from_secs(2)
        );
        assert_eq!(
            prepared.runtime_state.xray_handshake_timeout_for_level(8),
            Duration::from_secs(60)
        );
    }

    fn make_inbound(tag: &str, port: u16) -> ServerConfig {
        ServerConfig {
            tag: tag.to_string(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::from("127.0.0.1").expect("valid ip"),
                port,
            )),
            protocol: ServerProxyConfig::DokodemoDoor {
                config: DokodemoDoorConfig {
                    target: NetLocation::new(
                        Address::from("127.0.0.1").expect("valid ip"),
                        port,
                    ),
                    follow_redirect: false,
                    user_level: 0,
                },
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }
    }

    #[test]
    fn resolve_api_config_prefers_explicit_listen() {
        let api = ApiConfig {
            tag: Some("api".into()),
            services: vec!["StatsService".into()],
            listen: Some("127.0.0.1:7000".into()),
        };
        let routing = RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["api-in".into()],
                outbound_tag: Some("api".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        };
        let inbounds = vec![make_inbound("api-in", 61000)];

        let resolved = resolve_api_config(Some(&api), Some(&routing), &inbounds)
            .expect("api config should resolve");

        assert_eq!(
            resolved.listen_addr.map(|addr| addr.to_string()),
            Some("127.0.0.1:7000".into())
        );
        assert!(resolved.inbound.is_none());
    }

    #[test]
    fn resolve_api_config_uses_routing_rule_for_api_tag() {
        let api = ApiConfig {
            tag: Some("REMNAWAVE_API".into()),
            services: vec!["HandlerService".into()],
            listen: None,
        };
        let routing = RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["REMNAWAVE_API_INBOUND".into()],
                outbound_tag: Some("REMNAWAVE_API".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        };
        let inbounds = vec![make_inbound("REMNAWAVE_API_INBOUND", 61000)];

        let resolved = resolve_api_config(Some(&api), Some(&routing), &inbounds)
            .expect("api inbound should resolve from routing");

        assert_eq!(
            resolved.listen_addr.map(|addr| addr.to_string()),
            Some("127.0.0.1:61000".into())
        );
        assert_eq!(
            resolved.inbound.map(|inbound| inbound.tag.as_str()),
            Some("REMNAWAVE_API_INBOUND")
        );
    }
}
