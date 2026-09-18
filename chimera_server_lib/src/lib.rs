pub use beginning::start_tcp_server;
pub use config::{
    def::LiteralConfig,
    server_config::{ServerConfig, ServerProxyConfig},
};
use config::{
    def::{ApiConfig, DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS, PolicyConfig},
    rule::RoutingConfig,
    server_config::InboundPlan,
};
pub use config_loader::{ConfigFormat, resolve_config_source};
use resolver::{HostRuleValue, NativeResolver, Resolver};
use routing_state::RoutingState;
pub use runtime::{OutboundSummary, RuntimeState};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::task::{JoinError, JoinHandle};
use tokio_rustls::rustls;
use user_domain::{UserDomainAccessPublication, parse_publication};

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
mod session;
mod session_tasks;

mod transport;

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
    policy: Option<&UserDomainAccessPublication>,
) -> Result<(), Error> {
    let Some(policy) = policy else {
        return Ok(());
    };

    runtime_state
        .apply_user_domain_publication(policy.clone())
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
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    log::init(config.log.as_ref(), cwd, log_file)?;

    let plan = ValidatedServerPlan::compile(config)?;
    let runtime_state = RuntimeState::new_with_resolver(
        plan.inbounds.clone(),
        plan.outbounds.clone(),
        plan.resolver.clone(),
    );
    runtime_state.replace_policy(plan.policy.as_ref());
    install_configured_user_domain_policy(
        &runtime_state,
        plan.user_domain_access.as_ref(),
    )?;
    runtime_state.replace_routing(plan.routing);

    Ok(ServerRuntime {
        inbounds: plan.inbounds,
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

    compile_inbounds(config.inbounds)
}

fn compile_inbounds(
    inbounds: Vec<config::def::InboudItem>,
) -> Result<Vec<ServerConfig>, Error> {
    inbounds
        .into_iter()
        .map(|inbound| {
            InboundPlan::from_compiled(ServerConfig::try_from(inbound)?)
                .map(InboundPlan::into_server_config)
        })
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApiListen {
    Tcp(SocketAddr),
    AbstractUnix(String),
}

impl ApiListen {
    fn abstract_unix(value: &str) -> Result<Self, Error> {
        if !cfg!(target_os = "linux") {
            return Err(Error::InvalidConfig(
                "abstract Unix API listeners are supported only on Linux".into(),
            ));
        }

        let Some(name) = value.strip_prefix('@') else {
            return Err(Error::InvalidConfig(
                "abstract Unix API listen name must start with @".into(),
            ));
        };
        if name.is_empty() {
            return Err(Error::InvalidConfig(
                "abstract Unix API listen name must not be empty".into(),
            ));
        }
        if name.as_bytes().contains(&0) {
            return Err(Error::InvalidConfig(
                "abstract Unix API listen name must not contain NUL".into(),
            ));
        }
        if name.len() > 107 {
            return Err(Error::InvalidConfig(
                "abstract Unix API listen name exceeds Linux sun_path capacity"
                    .into(),
            ));
        }
        Ok(Self::AbstractUnix(name.to_string()))
    }
}

#[derive(Default)]
struct ResolvedApiConfig {
    listen: Option<ApiListen>,
    inbound_tag: Option<String>,
    inbound_uses_tls: bool,
}

fn resolve_api_config(
    api_config: Option<&ApiConfig>,
    routing_config: Option<&RoutingConfig>,
    all_inbounds: &[ServerConfig],
) -> Result<ResolvedApiConfig, Error> {
    let Some(api) = api_config else {
        return Ok(ResolvedApiConfig::default());
    };

    if let Some(listen) = api.listen.as_ref() {
        let listen_addr = listen.parse::<SocketAddr>().map_err(|err| {
            Error::InvalidConfig(format!("invalid api.listen {}: {}", listen, err))
        })?;
        return Ok(ResolvedApiConfig {
            listen: Some(ApiListen::Tcp(listen_addr)),
            inbound_tag: None,
            inbound_uses_tls: false,
        });
    }

    let Some(api_tag) = api.tag.as_deref() else {
        return Ok(ResolvedApiConfig::default());
    };
    let Some(routing) = routing_config else {
        return Err(Error::InvalidConfig(format!(
            "api tag {} requires a routing rule to an API inbound",
            api_tag
        )));
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
                listen: Some(api_inbound_listen(inbound)?),
                inbound_tag: Some(inbound.tag.clone()),
                inbound_uses_tls: api_inbound_uses_tls(&inbound.protocol),
            });
        }
    }

    if matched_api_rule {
        return Err(Error::InvalidConfig(format!(
            "api routing for outbound {} does not reference an existing inbound",
            api_tag
        )));
    }

    Err(Error::InvalidConfig(format!(
        "api tag {} is not referenced by any routing rule",
        api_tag
    )))
}

fn api_inbound_listen(inbound: &ServerConfig) -> Result<ApiListen, Error> {
    match &inbound.protocol {
        ServerProxyConfig::Tunnel => match &inbound.bind_location {
            crate::address::BindLocation::Address(addr) => {
                ApiListen::abstract_unix(&addr.address().to_string())
            }
        },
        _ => match &inbound.bind_location {
            crate::address::BindLocation::Address(addr) => {
                Ok(ApiListen::Tcp(addr.to_socket_addr()?))
            }
        },
    }
}

fn ensure_api_inbound_protocol(inbound: &ServerConfig) -> Result<(), Error> {
    if is_api_inbound_protocol(&inbound.protocol) {
        return Ok(());
    }

    Err(Error::InvalidConfig(format!(
        "api inbound {} must use dokodemo-door or tunnel semantics",
        inbound.tag
    )))
}

fn is_api_inbound_protocol(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::DokodemoDoor { .. } | ServerProxyConfig::Tunnel => true,
        #[cfg(feature = "tls")]
        ServerProxyConfig::Tls(tls_config) => matches!(
            tls_config.inner.as_ref(),
            ServerProxyConfig::DokodemoDoor { .. }
        ),
        _ => false,
    }
}

fn ensure_api_tunnels_are_control_only(
    all_inbounds: &[ServerConfig],
    resolved_api: &ResolvedApiConfig,
) -> Result<(), Error> {
    let selected_tunnel_tag = resolved_api.inbound_tag.as_deref().filter(|tag| {
        all_inbounds.iter().any(|inbound| {
            inbound.tag == *tag
                && matches!(inbound.protocol, ServerProxyConfig::Tunnel)
        })
    });

    if let Some(inbound) = all_inbounds.iter().find(|inbound| {
        matches!(inbound.protocol, ServerProxyConfig::Tunnel)
            && Some(inbound.tag.as_str()) != selected_tunnel_tag
    }) {
        return Err(Error::InvalidConfig(format!(
            "tunnel inbound {} is reserved for api.tag routing and cannot run as a proxy inbound",
            inbound.tag
        )));
    }

    Ok(())
}

fn api_inbound_uses_tls(_protocol: &ServerProxyConfig) -> bool {
    #[cfg(feature = "tls")]
    if matches!(_protocol, ServerProxyConfig::Tls(_)) {
        return true;
    }

    false
}

struct ValidatedServerPlan {
    inbounds: Vec<ServerConfig>,
    outbounds: Vec<OutboundSummary>,
    routing: RoutingState,
    resolver: Arc<dyn Resolver>,
    policy: Option<PolicyConfig>,
    user_domain_access: Option<UserDomainAccessPublication>,
    api: Option<ApiConfig>,
    mcp: Option<mcp::McpServerConfig>,
    mcp_configured_without_listen: bool,
    observatory: Option<config::def::ObservatoryConfig>,
    burst_observatory: Option<config::def::BurstObservatoryConfig>,
    resolved_api: ResolvedApiConfig,
    shutdown_grace_period: Duration,
}

impl ValidatedServerPlan {
    fn compile(config: LiteralConfig) -> Result<Self, Error> {
        let LiteralConfig {
            inbounds,
            outbounds,
            api,
            policy,
            routing,
            dns,
            user_domain_access,
            observatory,
            burst_observatory,
            shutdown,
            mcp,
            ..
        } = config;

        #[cfg(not(feature = "api"))]
        if api
            .as_ref()
            .is_some_and(|config| !config.services.is_empty())
        {
            return Err(Error::InvalidConfig(
                "api services configured but the \"api\" feature is disabled".into(),
            ));
        }

        let inbounds = compile_inbounds(inbounds)?;
        let outbounds = compile_configured_outbounds(&outbounds)?;
        let resolver = compile_configured_resolver(dns.as_ref())?;
        let routing_state = RoutingState::from_config(routing.as_ref())
            .map_err(Error::InvalidConfig)?;
        routing_observer::validate_observatory_config(
            observatory.as_ref(),
            burst_observatory.as_ref(),
        )
        .map_err(Error::InvalidConfig)?;

        let user_domain_access = user_domain_access
            .map(|policy| {
                let json_config = serde_json::to_string(&policy).map_err(|error| {
                    Error::InvalidConfig(format!(
                        "could not serialize userDomainAccess configuration: {error}"
                    ))
                })?;
                parse_publication(&json_config).map_err(|failure| {
                    Error::InvalidConfig(format!(
                        "invalid userDomainAccess configuration: {}",
                        failure.message
                    ))
                })
            })
            .transpose()?;

        let resolved_api =
            resolve_api_config(api.as_ref(), routing.as_ref(), &inbounds)?;
        ensure_api_tunnels_are_control_only(&inbounds, &resolved_api)?;

        let mcp_configured_without_listen =
            mcp.as_ref().is_some_and(|config| config.listen.is_none());
        let mcp = match mcp {
            Some(config) => match config.listen {
                Some(listen) => {
                    let listen = listen.parse::<SocketAddr>().map_err(|err| {
                        Error::InvalidConfig(format!(
                            "invalid mcp.listen {}: {}",
                            listen, err
                        ))
                    })?;
                    Some(mcp::McpServerConfig {
                        listen,
                        path: config.path,
                        update_interval: Duration::from_millis(
                            config.update_interval_ms.max(100),
                        ),
                    })
                }
                None => None,
            },
            None => None,
        };

        let shutdown_grace_period = Duration::from_secs(
            shutdown
                .as_ref()
                .map(|config| config.grace_period_seconds)
                .unwrap_or(DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS),
        );

        Ok(Self {
            inbounds,
            outbounds,
            routing: routing_state,
            resolver,
            policy,
            user_domain_access,
            api,
            mcp,
            mcp_configured_without_listen,
            observatory,
            burst_observatory,
            resolved_api,
            shutdown_grace_period,
        })
    }

    fn ensure_server_component(&self) -> Result<(), Error> {
        let api_started = self.api.as_ref().is_some_and(|api| {
            self.resolved_api.listen.is_some() && !api.services.is_empty()
        });
        if self.inbounds.is_empty() && !api_started && self.mcp.is_none() {
            return Err(Error::InvalidConfig(
                "no servers started; check inbounds/api configuration".into(),
            ));
        }
        Ok(())
    }
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

fn compile_configured_resolver(
    config: Option<&config::def::DnsConfig>,
) -> Result<Arc<dyn Resolver>, Error> {
    let query_strategy = config
        .map(config::def::DnsConfig::compile_query_strategy)
        .unwrap_or_default();
    let client_ip = config
        .map(config::def::DnsConfig::compile_client_ip)
        .transpose()
        .map_err(Error::InvalidConfig)?
        .flatten();
    let disable_cache = config.and_then(|dns| dns.disable_cache).unwrap_or(false);
    let enable_parallel_query = config
        .map(config::def::DnsConfig::compile_enable_parallel_query)
        .unwrap_or(false);
    let (disable_fallback, disable_fallback_if_match) = config
        .map(config::def::DnsConfig::compile_fallback_options)
        .unwrap_or_default();
    let servers = config
        .map(config::def::DnsConfig::compile_server_configs)
        .transpose()
        .map_err(Error::InvalidConfig)?
        .unwrap_or_default();
    let hosts = config
        .map(config::def::DnsConfig::compile_hosts)
        .transpose()
        .map_err(Error::InvalidConfig)?
        .unwrap_or_default();
    let rules = hosts
        .into_iter()
        .map(|host| {
            let value = match (host.response_code, host.proxied_domain) {
                (Some(code), _) => HostRuleValue::ResponseCode(code),
                (None, Some(domain)) => HostRuleValue::ProxiedDomain(domain),
                (None, None) => HostRuleValue::Ips(host.addresses),
            };
            (host.rule, value)
        })
        .collect();
    NativeResolver::with_host_rules_and_server_configs_with_query_strategy_and_fallback_options_and_runtime_options(
        rules,
        servers,
        query_strategy,
        disable_fallback,
        disable_fallback_if_match,
        client_ip,
        resolver::NativeResolverOptions {
            disable_cache,
            enable_parallel_query,
        },
    )
    .map(|resolver| Arc::new(resolver) as Arc<dyn Resolver>)
    .map_err(|error| Error::InvalidConfig(format!("invalid dns.hosts: {error}")))
}

pub fn validate(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Parse and compile the same plan that startup consumes. Validation does
    // not construct RuntimeState or start any task/listener.
    let config = opts.config.try_parse(opts.config_format)?;
    ValidatedServerPlan::compile(config)?.ensure_server_component()
}

async fn start_async(
    config: LiteralConfig,
    cwd: Option<&str>,
    log_file: Option<&str>,
) -> Result<(), Error> {
    //  todo: log mod
    log::init(config.log.as_ref(), cwd, log_file)?;
    let plan = ValidatedServerPlan::compile(config)?;
    plan.ensure_server_component()?;
    let connection_drain_timeout = plan.shutdown_grace_period;
    let api_config = plan.api;
    let mcp_configured_without_listen = plan.mcp_configured_without_listen;
    let mcp_config = plan.mcp;
    let observatory_config = plan.observatory;
    let burst_observatory_config = plan.burst_observatory;
    let resolved_api = plan.resolved_api;
    let api_listen = resolved_api.listen.clone();
    let skip_inbound_tag = resolved_api.inbound_tag.clone();

    let runtime_state = RuntimeState::new_with_resolver(
        plan.inbounds,
        plan.outbounds,
        plan.resolver,
    );
    runtime_state.replace_policy(plan.policy.as_ref());
    install_configured_user_domain_policy(
        &runtime_state,
        plan.user_domain_access.as_ref(),
    )?;
    runtime_state.replace_routing(plan.routing);
    if api_config.is_some() {
        if let Some(inbound_tag) = resolved_api.inbound_tag.as_deref()
            && resolved_api.inbound_uses_tls
        {
            tracing::warn!(
                "api inbound {} uses tls settings, but local grpc currently listens without tls",
                inbound_tag
            );
        }
        if api_listen.is_none() {
            tracing::warn!("api is configured but no listen address was resolved");
        }
    }

    let mut join_handles = Vec::with_capacity(4);
    let startup_result: Result<(), Error> = async {
        let mut has_started_server = false;
        if let Some(mcp) = mcp_config {
            let mcp_handle = mcp::start_mcp_server(mcp).await?;
            join_handles.push(mcp_handle);
            has_started_server = true;
        } else if mcp_configured_without_listen {
            tracing::warn!("mcp is configured but no listen address was resolved");
        }

        // Bind every configured data-plane listener before advertising the
        // control plane. rnode uses GetSysStats as its readiness probe, so
        // starting gRPC first would allow a process with a failed inbound
        // bind to look healthy.
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
            runtime_state.data_plane(),
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
            && let Some(listen) = api_listen
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
        Ok(())
    }
    .await;
    if let Err(error) = startup_result {
        let shutdown = shutdown_server_runtime(
            &runtime_state,
            join_handles,
            connection_drain_timeout,
            true,
        )
        .await;
        tracing::error!(
            stopped_inbounds = shutdown.stopped_inbounds,
            cancelled_connections = shutdown.cancelled_connections,
            "server startup failed; startup resources rolled back"
        );
        return Err(error);
    }
    if !runtime_state.mark_running() {
        let shutdown = shutdown_server_runtime(
            &runtime_state,
            join_handles,
            connection_drain_timeout,
            true,
        )
        .await;
        tracing::error!(
            stopped_inbounds = shutdown.stopped_inbounds,
            cancelled_connections = shutdown.cancelled_connections,
            "server startup lifecycle transition failed; startup resources rolled back"
        );
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
        ApiListen, compile_configured_outbounds,
        ensure_api_tunnels_are_control_only, prepare_server_runtime,
        resolve_api_config,
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

    #[tokio::test]
    async fn prepare_server_runtime_uses_configured_dns_hosts() {
        let config: crate::config::def::LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [],
                "outbounds": [],
                "dns": {"hosts": {
                    "domain:example.com": "192.0.2.10",
                    "alias.example": "mapped.example",
                    "mapped.example": "192.0.2.11"
                }}
            }"#,
        )
        .expect("parse dns hosts config");
        let prepared = prepare_server_runtime(config, None, None)
            .expect("prepare server runtime with dns hosts");
        let location = NetLocation::from_str("WWW.EXAMPLE.COM.:8443", None)
            .expect("parse mapped domain");

        assert_eq!(
            prepared
                .runtime_state
                .data_plane()
                .resolver()
                .resolve_location(&location)
                .await
                .expect("resolve configured host"),
            vec!["192.0.2.10:8443".parse().unwrap()]
        );
        let alias = NetLocation::from_str("alias.example:8443", None)
            .expect("parse proxied mapped domain");
        assert_eq!(
            prepared
                .runtime_state
                .data_plane()
                .resolver()
                .resolve_location(&alias)
                .await
                .expect("resolve proxied configured host"),
            vec!["192.0.2.11:8443".parse().unwrap()]
        );
    }

    #[test]
    fn prepare_server_runtime_does_not_bind_inbound_listeners() {
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("allocate an inbound test port");
        let port = probe.local_addr().expect("read test port").port();
        drop(probe);
        let config: crate::config::def::LiteralConfig =
            serde_json::from_str(&format!(
                r#"{{
                    "inbounds": [{{
                        "tag": "prepared-only",
                        "listen": "127.0.0.1",
                        "port": {port},
                        "protocol": "dokodemo-door",
                        "settings": {{"address": "example.com", "port": 80}},
                        "streamSettings": {{"network": "tcp"}}
                    }}],
                    "outbounds": [{{"tag": "direct", "protocol": "freedom"}}]
                }}"#
            ))
            .expect("parse prepared-only config");

        let _prepared = prepare_server_runtime(config, None, None)
            .expect("prepare server runtime without binding");
        std::net::TcpListener::bind(("127.0.0.1", port))
            .expect("preparation must not bind the inbound listener");
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

    fn make_tunnel_inbound(tag: &str, listen: &str) -> ServerConfig {
        ServerConfig {
            tag: tag.to_string(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::from(listen).expect("valid abstract API name"),
                0,
            )),
            protocol: ServerProxyConfig::Tunnel,
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn abstract_api_listen_validates_namespace_name() {
        assert_eq!(
            ApiListen::abstract_unix("@/run/chimera/xtls.sock")
                .expect("slashes are valid bytes in the abstract namespace"),
            ApiListen::AbstractUnix("/run/chimera/xtls.sock".into())
        );
        assert!(ApiListen::abstract_unix("@").is_err());
        assert!(ApiListen::abstract_unix("chimera-api").is_err());
        assert!(ApiListen::abstract_unix(&format!("@{}", "a".repeat(108))).is_err());
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
            resolved.listen,
            Some(ApiListen::Tcp(
                "127.0.0.1:7000".parse().expect("valid API listen")
            ))
        );
        assert!(resolved.inbound_tag.is_none());
    }

    #[test]
    fn resolve_api_config_rejects_api_tag_without_routing() {
        let api = ApiConfig {
            tag: Some("chimera-api".into()),
            services: vec!["StatsService".into()],
            listen: None,
        };

        let error = match resolve_api_config(Some(&api), None, &[]) {
            Ok(_) => panic!("api.tag without routing must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("api tag chimera-api requires a routing rule")
        );
    }

    #[test]
    fn resolve_api_config_rejects_unreferenced_api_tag() {
        let api = ApiConfig {
            tag: Some("chimera-api".into()),
            services: vec!["StatsService".into()],
            listen: None,
        };
        let routing = RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["other-api-in".into()],
                outbound_tag: Some("other-api".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        };

        let error = match resolve_api_config(Some(&api), Some(&routing), &[]) {
            Ok(_) => panic!("unreferenced api.tag must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(
                "api tag chimera-api is not referenced by any routing rule"
            )
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn resolve_api_config_uses_abstract_tunnel_for_api_tag() {
        let api = ApiConfig {
            tag: Some("chimera-api".into()),
            services: vec!["StatsService".into(), "HandlerService".into()],
            listen: None,
        };
        let routing = RoutingConfig {
            rules: vec![RuleConfig {
                inbound_tag: vec!["chimera-api-in".into()],
                outbound_tag: Some("chimera-api".into()),
                ..RuleConfig::default()
            }],
            ..RoutingConfig::default()
        };
        let inbounds = vec![make_tunnel_inbound("chimera-api-in", "@chimera-api")];

        let resolved = resolve_api_config(Some(&api), Some(&routing), &inbounds)
            .expect("abstract API tunnel should resolve from routing");

        assert_eq!(
            resolved.listen,
            Some(ApiListen::AbstractUnix("chimera-api".into()))
        );
        assert_eq!(resolved.inbound_tag.as_deref(), Some("chimera-api-in"));
    }

    #[test]
    fn unclaimed_tunnel_cannot_run_as_proxy_inbound() {
        let inbounds = vec![make_tunnel_inbound("chimera-api-in", "@chimera-api")];
        let resolved = resolve_api_config(None, None, &inbounds)
            .expect("absence of api config should resolve to no API listener");

        let error = ensure_api_tunnels_are_control_only(&inbounds, &resolved)
            .expect_err("unclaimed tunnel must fail closed");
        assert!(error.to_string().contains(
            "tunnel inbound chimera-api-in is reserved for api.tag routing"
        ));
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
            resolved.listen,
            Some(ApiListen::Tcp(
                "127.0.0.1:61000".parse().expect("valid API listen")
            ))
        );
        assert_eq!(
            resolved.inbound_tag.as_deref(),
            Some("REMNAWAVE_API_INBOUND")
        );
    }
}
