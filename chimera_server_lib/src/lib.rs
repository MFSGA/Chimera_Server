// TODO: remove this once WIP modules stabilize and dead code is pruned
#![allow(dead_code)]

use beginning::start_servers;
pub use beginning::start_tcp_server;
use config::{def::ApiConfig, rule::RoutingConfig};
pub use config::{
    def::LiteralConfig,
    server_config::{ServerConfig, ServerProxyConfig},
};
pub use config_loader::{ConfigFormat, resolve_config_source};
pub use runtime::{OutboundSummary, RuntimeState};
#[cfg(feature = "user_domain_access")]
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
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
mod outbound_registry;
mod outbound_transport;
mod socks_outbound;
#[cfg(feature = "trojan")]
mod trojan_outbound;
#[cfg(feature = "vless")]
mod vless_outbound;

mod runtime;
#[cfg(all(test, feature = "user_domain_access"))]
mod runtime_user_domain_access_tests;

#[cfg(feature = "reality")]
pub mod reality;

mod log;

mod handler;
mod http_outbound;

mod resolver;

mod routing_observer;
mod routing_process;
mod routing_state;
mod routing_webhook;

pub mod traffic;

#[cfg(feature = "user_domain_access")]
mod tls_client_hello;
#[cfg(feature = "user_domain_access")]
pub mod user_domain_access;

mod util;

mod xhttp_outbound;
mod xudp_registry;

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
            ConfigType::Str(content) => {
                config_loader::parse_config_content(&content, format)
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

#[cfg(feature = "user_domain_access")]
fn resolve_user_domain_access_store_path(
    store: Option<&config::def::UserDomainAccessStoreConfig>,
    cwd: Option<&str>,
) -> Result<Option<PathBuf>, Error> {
    let Some(store) = store else {
        return Ok(None);
    };
    let value = store.path.trim();
    if value.is_empty() {
        return Err(Error::InvalidConfig(
            "userDomainAccessStore.path must not be empty".into(),
        ));
    }
    if let Some(node_uuid) = store.node_uuid.as_deref() {
        uuid::Uuid::parse_str(node_uuid.trim()).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid userDomainAccessStore.nodeUuid {node_uuid}: {error}"
            ))
        })?;
    }
    let path = PathBuf::from(value);
    Ok(Some(if path.is_absolute() {
        path
    } else if let Some(cwd) = cwd {
        Path::new(cwd).join(path)
    } else {
        path
    }))
}

#[cfg(feature = "user_domain_access")]
fn build_user_domain_access_signature_verifier(
    store: Option<&config::def::UserDomainAccessStoreConfig>,
) -> Result<user_domain_access::UserDomainAccessSignatureVerifier, Error> {
    let require_signature = store.is_some_and(|store| store.require_signature);
    let keys = store
        .into_iter()
        .flat_map(|store| store.trusted_signing_keys.iter())
        .map(|key| (key.key_id.clone(), key.public_key.clone()));
    user_domain_access::UserDomainAccessSignatureVerifier::from_base64_keys(
        require_signature,
        keys,
    )
    .map_err(|error| Error::InvalidConfig(error.to_string()))
}

#[cfg(feature = "user_domain_access")]
fn user_domain_access_tls_probe_settings(
    store: Option<&config::def::UserDomainAccessStoreConfig>,
) -> (Option<u64>, Option<usize>) {
    store
        .map(|store| (store.tls_probe_timeout_millis, store.tls_probe_max_bytes))
        .unwrap_or_default()
}

#[cfg(feature = "user_domain_access")]
#[derive(Debug)]
struct InitialUserDomainAccess {
    config: Option<user_domain_access::UserDomainAccessConfig>,
    highest_seen_version: u64,
    history: Vec<user_domain_access::UserDomainAccessConfig>,
}

#[cfg(feature = "user_domain_access")]
fn select_initial_user_domain_access(
    configured: Option<user_domain_access::UserDomainAccessConfig>,
    store_path: Option<&Path>,
) -> Result<InitialUserDomainAccess, Error> {
    let persisted = store_path
        .map(runtime::load_user_domain_access_store)
        .transpose()
        .map_err(Error::InvalidConfig)?
        .flatten();
    let (persisted_config, persisted_highest, persisted_history) = match persisted {
        Some(stored) => (
            Some(stored.config),
            stored.highest_seen_version,
            stored.history,
        ),
        None => (None, 0, Vec::new()),
    };
    let (selected, history) = match (configured, persisted_config) {
        (None, None) => (None, Vec::new()),
        (Some(config), None) => (Some(config), Vec::new()),
        (None, Some(config)) => (Some(config), persisted_history),
        (Some(configured), Some(persisted)) => {
            if configured.version == persisted.version {
                if configured == persisted {
                    (Some(configured), persisted_history)
                } else {
                    return Err(Error::InvalidConfig(format!(
                        "user-domain access configured and persisted revisions both use version {} but differ",
                        configured.version
                    )));
                }
            } else if configured.version > persisted_highest {
                let mut history =
                    Vec::with_capacity(runtime::user_domain_access_history_limit());
                history.push(persisted);
                for revision in persisted_history {
                    if history.len() == runtime::user_domain_access_history_limit() {
                        break;
                    }
                    if !history
                        .iter()
                        .any(|existing| existing.version == revision.version)
                    {
                        history.push(revision);
                    }
                }
                (Some(configured), history)
            } else {
                (Some(persisted), persisted_history)
            }
        }
    };
    let highest_seen_version = selected
        .as_ref()
        .map(|config| config.version)
        .unwrap_or_default()
        .max(persisted_highest);
    Ok(InitialUserDomainAccess {
        config: selected,
        highest_seen_version,
        history,
    })
}

#[cfg(feature = "user_domain_access")]
fn compile_user_domain_access(
    config: Option<&user_domain_access::UserDomainAccessConfig>,
) -> Result<Option<user_domain_access::UserDomainAccessPolicy>, Error> {
    config
        .cloned()
        .map(user_domain_access::UserDomainAccessPolicy::compile)
        .transpose()
        .map_err(|error| Error::InvalidConfig(error.to_string()))
}

fn compile_outbound_summaries(
    items: &[config::def::OutboundItem],
) -> Result<Vec<OutboundSummary>, Error> {
    let outbounds = items
        .iter()
        .map(|item| OutboundSummary {
            tag: item.tag.clone(),
            protocol: item.protocol.clone(),
            settings: item.settings.clone(),
            stream_settings: item.stream_settings.clone(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        })
        .collect::<Vec<_>>();
    RuntimeState::compile_outbounds(outbounds).map_err(Error::InvalidConfig)
}

pub struct ServerRuntime {
    pub inbounds: Vec<ServerConfig>,
    pub runtime_state: RuntimeState,
}

fn configure_runtime_resolver(
    runtime_state: &RuntimeState,
    dns: Option<&crate::config::def::DnsConfig>,
) -> Result<(), Error> {
    let Some(dns) = dns else {
        return Ok(());
    };
    let dns_servers = dns.compile_servers()?;
    let dns_hosts = dns.compile_hosts()?;
    let mut configured_resolver = runtime_state.resolver();
    let mut resolver_changed = false;
    if !dns_servers.is_empty() {
        let upstreams = dns_servers
            .into_iter()
            .map(|upstream| {
                let resolver: Arc<dyn crate::resolver::Resolver> =
                    Arc::new(crate::resolver::DnsWireResolver::new(upstream));
                Arc::new(crate::resolver::TimeoutResolver::new(
                    resolver,
                    Duration::from_secs(5),
                )) as Arc<dyn crate::resolver::Resolver>
            })
            .collect::<Vec<_>>();
        let composite: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::CompositeResolver::new(upstreams));
        let ordered: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::AddressOrderingResolver::new(
                composite,
                crate::resolver::AddressFamilyPreference::Preserve,
            ));
        configured_resolver =
            Arc::new(crate::resolver::CachedResolver::new(ordered));
        resolver_changed = true;
    }
    if !dns_hosts.is_empty() {
        configured_resolver = Arc::new(crate::resolver::HostsResolver::new(
            dns_hosts,
            configured_resolver,
        ));
        resolver_changed = true;
    }
    if resolver_changed {
        runtime_state.replace_resolver(configured_resolver);
    }
    Ok(())
}

pub fn prepare_server_runtime(
    config: LiteralConfig,
    cwd: Option<&str>,
    log_file: Option<&str>,
) -> Result<ServerRuntime, Error> {
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_node_uuid = config
        .user_domain_access_store
        .as_ref()
        .and_then(|store| store.node_uuid.clone());
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_signature_verifier =
        build_user_domain_access_signature_verifier(
            config.user_domain_access_store.as_ref(),
        )?;
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_tls_probe = user_domain_access_tls_probe_settings(
        config.user_domain_access_store.as_ref(),
    );
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_store = resolve_user_domain_access_store_path(
        config.user_domain_access_store.as_ref(),
        cwd,
    )?;
    #[cfg(feature = "user_domain_access")]
    let user_domain_access = select_initial_user_domain_access(
        config.user_domain_access.clone(),
        user_domain_access_store.as_deref(),
    )?;
    let dns_config = config.dns.clone();
    let policy_config = config.policy.clone();
    let outbounds = compile_outbound_summaries(&config.outbounds)?;
    let inbounds = prepare_server_inbounds(config, cwd, log_file)?;
    let runtime_state = RuntimeState::try_new(inbounds.clone(), outbounds)
        .map_err(Error::InvalidConfig)?;
    configure_runtime_resolver(&runtime_state, dns_config.as_ref())?;
    runtime_state
        .configure_policy(policy_config.as_ref())
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    runtime_state
        .configure_user_domain_access_signature_verifier(
            user_domain_access_signature_verifier,
        )
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    runtime_state
        .configure_user_domain_access_tls_probe(
            user_domain_access_tls_probe.0,
            user_domain_access_tls_probe.1,
        )
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    if let Some(path) = user_domain_access_store {
        runtime_state
            .configure_user_domain_access_store(path)
            .map_err(Error::InvalidConfig)?;
    }
    #[cfg(feature = "user_domain_access")]
    if let Some(node_uuid) = user_domain_access_node_uuid.as_deref() {
        runtime_state
            .configure_user_domain_access_target_node(node_uuid)
            .map_err(Error::InvalidConfig)?;
    }
    #[cfg(feature = "user_domain_access")]
    runtime_state
        .restore_user_domain_access_persisted_state(
            user_domain_access.highest_seen_version,
            user_domain_access.history,
        )
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    if let Some(config) = user_domain_access.config {
        runtime_state
            .install_user_domain_access(config)
            .map_err(Error::InvalidConfig)?;
    }

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

pub fn validate(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 1. config parse
    let config = opts.config.try_parse(opts.config_format)?;

    // 2. api/mcp config validation
    let api_config = config.api.clone();
    let mcp_config = config.mcp.clone();
    let routing_config = config.routing.clone();
    routing_observer::validate_observatory_config(
        config.observatory.as_ref(),
        config.burst_observatory.as_ref(),
    )
    .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    {
        let store_config = config.user_domain_access_store.as_ref();
        let store_path = resolve_user_domain_access_store_path(
            store_config,
            opts.cwd.as_deref(),
        )?;
        let selected = select_initial_user_domain_access(
            config.user_domain_access.clone(),
            store_path.as_deref(),
        )?;
        let validation_state = RuntimeState::new(Vec::new(), Vec::new());
        validation_state
            .configure_user_domain_access_signature_verifier(
                build_user_domain_access_signature_verifier(store_config)?,
            )
            .map_err(Error::InvalidConfig)?;
        let tls_probe = user_domain_access_tls_probe_settings(store_config);
        validation_state
            .configure_user_domain_access_tls_probe(tls_probe.0, tls_probe.1)
            .map_err(Error::InvalidConfig)?;
        if let Some(node_uuid) =
            store_config.and_then(|store| store.node_uuid.as_deref())
        {
            validation_state
                .configure_user_domain_access_target_node(node_uuid)
                .map_err(Error::InvalidConfig)?;
        }
        validation_state
            .restore_user_domain_access_persisted_state(
                selected.highest_seen_version,
                selected.history,
            )
            .map_err(Error::InvalidConfig)?;
        if let Some(config) = selected.config {
            validation_state
                .install_user_domain_access(config)
                .map_err(Error::InvalidConfig)?;
        }
    }

    compile_outbound_summaries(&config.outbounds)?;
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
    //  todo: log mod
    log::init(config.log.as_ref(), cwd, log_file)?;
    // 2. api config
    let api_config = config.api.clone();
    let mcp_config = config.mcp.clone();
    let routing_config = config.routing.clone();
    let observatory_config = config.observatory.clone();
    let burst_observatory_config = config.burst_observatory.clone();
    let dns_config = config.dns.clone();
    let policy_config = config.policy.clone();
    routing_observer::validate_observatory_config(
        observatory_config.as_ref(),
        burst_observatory_config.as_ref(),
    )
    .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_node_uuid = config
        .user_domain_access_store
        .as_ref()
        .and_then(|store| store.node_uuid.clone());
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_signature_verifier =
        build_user_domain_access_signature_verifier(
            config.user_domain_access_store.as_ref(),
        )?;
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_tls_probe = user_domain_access_tls_probe_settings(
        config.user_domain_access_store.as_ref(),
    );
    #[cfg(feature = "user_domain_access")]
    let user_domain_access_store = resolve_user_domain_access_store_path(
        config.user_domain_access_store.as_ref(),
        cwd,
    )?;
    #[cfg(feature = "user_domain_access")]
    let user_domain_access = select_initial_user_domain_access(
        config.user_domain_access.clone(),
        user_domain_access_store.as_deref(),
    )?;
    let outbounds = compile_outbound_summaries(&config.outbounds)?;

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(ServerConfig::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let runtime_state = RuntimeState::try_new(all_inbounds.clone(), outbounds)
        .map_err(Error::InvalidConfig)?;
    configure_runtime_resolver(&runtime_state, dns_config.as_ref())?;
    runtime_state
        .configure_policy(policy_config.as_ref())
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    runtime_state
        .configure_user_domain_access_signature_verifier(
            user_domain_access_signature_verifier,
        )
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    runtime_state
        .configure_user_domain_access_tls_probe(
            user_domain_access_tls_probe.0,
            user_domain_access_tls_probe.1,
        )
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    if let Some(path) = user_domain_access_store {
        runtime_state
            .configure_user_domain_access_store(path)
            .map_err(Error::InvalidConfig)?;
    }
    #[cfg(feature = "user_domain_access")]
    if let Some(node_uuid) = user_domain_access_node_uuid.as_deref() {
        runtime_state
            .configure_user_domain_access_target_node(node_uuid)
            .map_err(Error::InvalidConfig)?;
    }
    #[cfg(feature = "user_domain_access")]
    runtime_state
        .restore_user_domain_access_persisted_state(
            user_domain_access.highest_seen_version,
            user_domain_access.history,
        )
        .map_err(Error::InvalidConfig)?;
    #[cfg(feature = "user_domain_access")]
    if let Some(config) = user_domain_access.config {
        runtime_state
            .install_user_domain_access(config)
            .map_err(Error::InvalidConfig)?;
    }
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

    for config in all_inbounds {
        // Skip the API inbound if it's configured to avoid port conflicts
        if skip_inbound_tag.as_deref() == Some(config.tag.as_str()) {
            tracing::info!(
                "skip api inbound {} to avoid grpc port conflict",
                config.tag
            );
            continue;
        }
        // Runtime state lets UDP listeners evaluate routing and outbound policy.
        let inbound_tag = config.tag.clone();
        let handles = start_servers(config, runtime_state.clone()).await?;
        runtime_state.register_inbound_tasks(&inbound_tag, &handles);
        has_started_server = true;
    }

    if !has_started_server {
        return Err(Error::InvalidConfig(
            "no servers started; check inbounds/api configuration".into(),
        ));
    }

    join_handles.push(tokio::spawn(std::future::pending()));
    let result = futures::future::select_all(join_handles).await.0;
    match result {
        Ok(()) => Err(Error::Io(std::io::Error::other(
            "server task finished unexpectedly",
        ))),
        Err(x) => {
            tracing::error!("runtime error: {}, shutting down", x);
            Err(Error::Io(std::io::Error::other(x)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    #[cfg(feature = "user_domain_access")]
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::net::UdpSocket;

    use super::{
        ConfigType, compile_outbound_summaries, prepare_server_runtime,
        resolve_api_config,
    };
    #[cfg(feature = "user_domain_access")]
    use super::{compile_user_domain_access, select_initial_user_domain_access};
    #[cfg(feature = "user_domain_access")]
    use crate::user_domain_access::{
        UserDomainAccessConfig, user_domain_access_checksum,
    };
    use crate::{
        RuntimeState,
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            def::{ApiConfig, OutboundItem},
            rule::{RoutingConfig, RuleConfig},
            server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
        },
        outbound_registry::OutboundConnectorKind,
    };

    #[test]
    fn string_config_parses_without_exposing_source_on_failure() {
        let parsed =
            ConfigType::Str(r#"{"inbounds":[],"outbounds":[]}"#.to_string())
                .try_parse(Some(crate::ConfigFormat::Json))
                .expect("inline JSON config should parse");
        assert!(parsed.inbounds.is_empty());
        assert!(parsed.outbounds.is_empty());

        let secret = "do-not-log-this-password";
        let error = ConfigType::Str(format!(
            r#"{{"inbounds":[],"outbounds":[],"password":"{secret}""#
        ))
        .try_parse(Some(crate::ConfigFormat::Json))
        .expect_err("invalid inline JSON must fail");
        assert!(!error.to_string().contains(secret));
    }

    #[test]
    fn unsupported_xray_top_level_apps_and_policy_fail_closed() {
        for field in [
            "metrics",
            "reverse",
            "fakeDns",
            "version",
            "geodata",
            "env",
            "transport",
        ] {
            let mut config = serde_json::json!({
                "inbounds": [],
                "outbounds": []
            });
            config[field] = serde_json::json!({});
            let error = ConfigType::Str(config.to_string())
                .try_parse(Some(crate::ConfigFormat::Json))
                .expect_err("unsupported Xray top-level app must fail closed");
            assert!(error.to_string().contains(field));
        }

        let config = ConfigType::Str(
            serde_json::json!({
                "inbounds": [],
                "outbounds": [],
                "policy": {
                    "levels": {
                        "0": {"handshake": 4, "connIdle": 30, "uplinkOnly": 2, "downlinkOnly": 3, "bufferSize": 64},
                        "7": {"connIdle": 9, "statsUserUplink": false, "statsUserDownlink": true, "statsUserOnline": false},
                        "8": {"bufferSize": -1},
                        "9": {"bufferSize": 0}
                    },
                    "system": {
                        "statsInboundUplink": false,
                        "statsInboundDownlink": true,
                        "statsOutboundUplink": true,
                        "statsOutboundDownlink": false
                    }
                }
            })
            .to_string(),
        )
        .try_parse(Some(crate::ConfigFormat::Json))
        .expect("policy.levels.0.handshake should be supported");
        let runtime = prepare_server_runtime(config, None, None)
            .expect("policy runtime should build");
        assert_eq!(
            runtime.runtime_state.policy_handshake_timeout(0),
            std::time::Duration::from_secs(4)
        );
        assert_eq!(
            runtime.runtime_state.policy_handshake_timeout(1),
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            runtime.runtime_state.policy_connection_idle_timeout(0),
            Some(std::time::Duration::from_secs(30))
        );
        assert_eq!(
            runtime.runtime_state.policy_connection_idle_timeout(1),
            None
        );
        let relay_timeouts = runtime.runtime_state.policy_relay_timeouts(0);
        assert_eq!(
            relay_timeouts.uplink_only,
            Some(std::time::Duration::from_secs(2))
        );
        assert_eq!(
            relay_timeouts.downlink_only,
            Some(std::time::Duration::from_secs(3))
        );
        assert_eq!(relay_timeouts.buffer_size, Some(64 * 1024));
        assert_eq!(
            runtime.runtime_state.policy_relay_timeouts(8).buffer_size,
            None
        );
        assert_eq!(
            runtime.runtime_state.policy_relay_timeouts(9).buffer_size,
            Some(1)
        );
        assert_eq!(
            runtime
                .runtime_state
                .policy_relay_timeouts(7)
                .connection_idle,
            Some(std::time::Duration::from_secs(9))
        );
        let user_stats = runtime.runtime_state.policy_user_stats(7);
        assert_eq!(user_stats.uplink, Some(false));
        assert_eq!(user_stats.downlink, Some(true));
        assert_eq!(user_stats.online, Some(false));
        assert_eq!(
            runtime.runtime_state.policy_user_stats(1),
            crate::runtime::PolicyUserStats::default()
        );
        let system_stats = runtime.runtime_state.policy_system_stats();
        assert_eq!(system_stats.inbound_uplink, Some(false));
        assert_eq!(system_stats.inbound_downlink, Some(true));
        assert_eq!(system_stats.outbound_uplink, Some(true));
        assert_eq!(system_stats.outbound_downlink, Some(false));

        let unsupported_policy =
            serde_json::json!({"system": {"statsUnknown": true}});
        let error = ConfigType::Str(
            serde_json::json!({
                "inbounds": [],
                "outbounds": [],
                "policy": unsupported_policy
            })
            .to_string(),
        )
        .try_parse(Some(crate::ConfigFormat::Json))
        .expect_err("unimplemented policy fields must fail closed");
        assert!(error.to_string().contains("unknown field"), "{error}");

        let error = ConfigType::Str(
            serde_json::json!({
                "inbounds": [],
                "outbounds": [],
                "unknownXrayField": true
            })
            .to_string(),
        )
        .try_parse(Some(crate::ConfigFormat::Json))
        .expect_err("unknown top-level field must fail closed");
        assert!(error.to_string().contains("unknownXrayField"));
    }

    fn dns_runtime_test_response(query: &[u8]) -> Vec<u8> {
        const HEADER_LENGTH: usize = 12;
        let query_type =
            u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
        let rdata = match query_type {
            1 => vec![198, 51, 100, 88],
            28 => "2001:db8::88"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            other => panic!("unexpected DNS query type {other}"),
        };
        let mut response = Vec::new();
        response.extend_from_slice(&query[..2]);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[HEADER_LENGTH..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        response
    }

    #[tokio::test]
    async fn dns_servers_install_cached_udp_runtime_resolver() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 512];
            for _ in 0..2 {
                let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
                let response = dns_runtime_test_response(&buffer[..length]);
                server.send_to(&response, peer).await.unwrap();
            }
        });

        let config = ConfigType::Str(
            serde_json::json!({
                "inbounds": [],
                "outbounds": [],
                "dns": {"servers": [server_addr.to_string()]}
            })
            .to_string(),
        )
        .try_parse(Some(crate::ConfigFormat::Json))
        .expect("UDP dns.servers config should parse");
        let runtime = prepare_server_runtime(config, None, None)
            .expect("UDP dns.servers runtime should build")
            .runtime_state;
        let target =
            NetLocation::new(Address::from("runtime-dns.example").unwrap(), 9443);
        let first = tokio::time::timeout(
            Duration::from_secs(2),
            runtime.resolver().resolve_location(&target),
        )
        .await
        .expect("runtime DNS lookup timeout")
        .expect("runtime DNS lookup failed");
        let second = tokio::time::timeout(
            Duration::from_secs(2),
            runtime.resolver().resolve_location(&target),
        )
        .await
        .expect("cached runtime DNS lookup timeout")
        .expect("cached runtime DNS lookup failed");
        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                "198.51.100.88:9443".parse().unwrap(),
                "[2001:db8::88]:9443".parse().unwrap(),
            ]
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn dns_hosts_install_exact_runtime_overrides() {
        let config = ConfigType::Str(
            serde_json::json!({
                "inbounds": [],
                "outbounds": [],
                "dns": {
                    "hosts": {
                        "full:Runtime.Test.Invalid": [
                            "192.0.2.44",
                            "2001:db8::44"
                        ]
                    }
                }
            })
            .to_string(),
        )
        .try_parse(Some(crate::ConfigFormat::Json))
        .expect("exact dns.hosts config should parse");
        let runtime = prepare_server_runtime(config, None, None)
            .expect("dns.hosts runtime should build")
            .runtime_state;
        let addresses = runtime
            .resolver()
            .resolve_location(&NetLocation::new(
                Address::from("runtime.test.invalid").unwrap(),
                8443,
            ))
            .await
            .expect("dns.hosts runtime lookup should succeed");
        assert_eq!(
            addresses,
            vec![
                "192.0.2.44:8443".parse().unwrap(),
                "[2001:db8::44]:8443".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn unsupported_dns_semantics_fail_closed() {
        for (dns, expected_error) in [
            (
                serde_json::json!({
                    "servers": [{
                        "address": "1.1.1.1",
                        "expectIPs": ["geoip:us"]
                    }]
                }),
                "dns.servers advanced objects",
            ),
            (
                serde_json::json!({
                    "servers": ["https://1.1.1.1/dns-query"]
                }),
                "unsupported DNS upstream scheme",
            ),
            (
                serde_json::json!({
                    "hosts": {"domain:example.com": "192.0.2.1"}
                }),
                "dns.hosts pattern",
            ),
            (
                serde_json::json!({
                    "hosts": {"example.com": "alias.example"}
                }),
                "dns.hosts value",
            ),
        ] {
            let error = ConfigType::Str(
                serde_json::json!({
                    "inbounds": [],
                    "outbounds": [],
                    "dns": dns
                })
                .to_string(),
            )
            .try_parse(Some(crate::ConfigFormat::Json))
            .expect_err("unsupported DNS semantics must fail closed");
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn unknown_inbound_and_stream_fields_fail_closed() {
        for (field, value) in [
            ("snifing", serde_json::json!({"enabled": true})),
            ("unexpectedInboundOption", serde_json::json!(true)),
        ] {
            let mut inbound = serde_json::json!({
                "listen": "127.0.0.1",
                "port": 10000,
                "protocol": "dokodemo-door",
                "tag": "strict-inbound",
                "settings": {"address": "127.0.0.1", "port": 53}
            });
            inbound[field] = value;
            let error = ConfigType::Str(
                serde_json::json!({
                    "inbounds": [inbound],
                    "outbounds": []
                })
                .to_string(),
            )
            .try_parse(Some(crate::ConfigFormat::Json))
            .expect_err("unknown inbound field must fail closed");
            assert!(error.to_string().contains(field));
        }

        for field in ["sockopt", "tcpSettings", "unexpectedTransportOption"] {
            let mut stream_settings = serde_json::json!({"network": "tcp"});
            stream_settings[field] = serde_json::json!({});
            let error = ConfigType::Str(
                serde_json::json!({
                    "inbounds": [{
                        "listen": "127.0.0.1",
                        "port": 10000,
                        "protocol": "dokodemo-door",
                        "tag": "strict-stream",
                        "settings": {"address": "127.0.0.1", "port": 53},
                        "streamSettings": stream_settings
                    }],
                    "outbounds": []
                })
                .to_string(),
            )
            .try_parse(Some(crate::ConfigFormat::Json))
            .expect_err("unknown streamSettings field must fail closed");
            assert!(error.to_string().contains(field));
        }
    }

    #[cfg(feature = "user_domain_access")]
    fn test_policy(version: u64, domain: &str) -> UserDomainAccessConfig {
        let mut config: UserDomainAccessConfig =
            serde_json::from_value(serde_json::json!({
                "version": version,
                "defaultAction": "reject",
                "users": [{
                    "userUuid": "11111111-1111-4111-8111-111111111111",
                    "mode": "allowlist",
                    "unknownTargetAction": "reject",
                    "rules": [{
                        "domain": domain,
                        "match": "exact",
                        "action": "allow"
                    }]
                }]
            }))
            .unwrap();
        config.checksum = Some(user_domain_access_checksum(&config).unwrap());
        config
    }

    #[cfg(feature = "user_domain_access")]
    fn temporary_store_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "chimera-startup-policy-{}-{nonce}.json",
            std::process::id()
        ))
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
        }
    }

    #[test]
    fn static_outbounds_are_compiled_before_runtime_installation() {
        let summaries = compile_outbound_summaries(&[
            OutboundItem {
                protocol: " Freedom ".into(),
                tag: " direct ".into(),
                settings: None,
                stream_settings: None,
            },
            OutboundItem {
                protocol: "blackhole".into(),
                tag: "blocked".into(),
                settings: None,
                stream_settings: None,
            },
        ])
        .expect("supported static outbounds should compile");
        let runtime = RuntimeState::try_new(Vec::new(), summaries)
            .expect("compiled outbounds should install");
        assert_eq!(runtime.outbounds()[0].tag, "direct");
        assert_eq!(runtime.outbounds()[0].protocol, "freedom");
        assert!(matches!(
            runtime.outbound_connector("direct").as_deref(),
            Some(OutboundConnectorKind::Freedom)
        ));
        assert!(matches!(
            runtime.outbound_connector("blocked").as_deref(),
            Some(OutboundConnectorKind::Blackhole)
        ));

        let unsupported = compile_outbound_summaries(&[OutboundItem {
            protocol: "vless".into(),
            tag: "proxy".into(),
            settings: None,
            stream_settings: None,
        }])
        .expect_err("unsupported static outbound must fail closed");
        assert!(unsupported.to_string().contains("requires settings"));

        let duplicate = compile_outbound_summaries(&[
            OutboundItem {
                protocol: "freedom".into(),
                tag: "same".into(),
                settings: None,
                stream_settings: None,
            },
            OutboundItem {
                protocol: "blackhole".into(),
                tag: "same".into(),
                settings: None,
                stream_settings: None,
            },
        ])
        .expect_err("duplicate static outbound tags must fail closed");
        assert!(
            duplicate
                .to_string()
                .contains("duplicate outbound tag same")
        );
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

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn compiles_user_domain_access_into_runtime_state() {
        let config = r#"
        {
          "inbounds": [],
          "outbounds": [],
          "userDomainAccess": {
            "defaultAction": "allow",
            "users": [{
              "userUuid": "11111111-1111-4111-8111-111111111111",
              "mode": "allowlist",
              "unknownTargetAction": "reject",
              "rules": [{
                "domain": "example.com",
                "match": "suffix",
                "action": "allow"
              }]
            }]
          }
        }
        "#
        .parse::<crate::LiteralConfig>()
        .expect("literal policy should parse");
        let policy = compile_user_domain_access(config.user_domain_access.as_ref())
            .expect("policy should compile")
            .expect("compiled policy missing");

        let runtime = crate::RuntimeState::new(Vec::new(), Vec::new());
        runtime.replace_user_domain_access(Some(policy));
        let active = runtime
            .user_domain_access()
            .expect("runtime policy missing");
        let user = "11111111-1111-4111-8111-111111111111"
            .parse()
            .expect("valid user UUID");
        assert!(active.contains_user(user));
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn startup_selection_prefers_newer_persisted_revision() {
        let store = temporary_store_path();
        let runtime = crate::RuntimeState::new(Vec::new(), Vec::new());
        runtime
            .configure_user_domain_access_store(store.clone())
            .unwrap();
        runtime
            .install_user_domain_access(test_policy(2, "persisted.example"))
            .unwrap();

        let selected = select_initial_user_domain_access(
            Some(test_policy(1, "configured.example")),
            Some(&store),
        )
        .unwrap();
        let selected_config =
            selected.config.expect("startup policy should be selected");
        assert_eq!(selected.highest_seen_version, 2);
        assert_eq!(selected_config.version, 2);
        assert_eq!(
            selected_config.users[0].rules[0].domain,
            "persisted.example"
        );

        let mut conflicting = test_policy(2, "conflict.example");
        conflicting.checksum =
            Some(user_domain_access_checksum(&conflicting).unwrap());
        let error =
            select_initial_user_domain_access(Some(conflicting), Some(&store))
                .expect_err("same-version divergent startup policies must fail");
        assert!(error.to_string().contains("both use version 2 but differ"));

        fs::remove_file(store).unwrap();
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn startup_selection_keeps_persisted_history_for_a_newer_configured_revision() {
        let store = temporary_store_path();
        let runtime = crate::RuntimeState::new(Vec::new(), Vec::new());
        runtime
            .configure_user_domain_access_store(store.clone())
            .unwrap();
        runtime
            .install_user_domain_access(test_policy(1, "one.example"))
            .unwrap();
        runtime
            .install_user_domain_access(test_policy(2, "two.example"))
            .unwrap();
        runtime.rollback_user_domain_access(1).unwrap();

        let selected = select_initial_user_domain_access(
            Some(test_policy(3, "three.example")),
            Some(&store),
        )
        .expect("new configured policy should be selected");
        assert_eq!(selected.highest_seen_version, 3);
        assert_eq!(
            selected
                .config
                .as_ref()
                .expect("selected policy missing")
                .version,
            3
        );
        assert_eq!(
            selected
                .history
                .iter()
                .map(|config| config.version)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        let restarted = crate::RuntimeState::new(Vec::new(), Vec::new());
        restarted
            .restore_user_domain_access_persisted_state(
                selected.highest_seen_version,
                selected.history,
            )
            .expect("persisted history should restore");
        restarted
            .install_user_domain_access(
                selected.config.expect("selected policy missing"),
            )
            .expect("new configured policy should install");
        assert_eq!(
            restarted
                .rollback_user_domain_access(2)
                .expect("persisted version 2 should remain retained")
                .version,
            2
        );
        assert_eq!(
            restarted
                .rollback_user_domain_access(1)
                .expect("persisted version 1 should remain retained")
                .version,
            1
        );

        fs::remove_file(store).unwrap();
    }

    #[cfg(feature = "user_domain_access")]
    #[test]
    fn rejects_invalid_user_domain_access_before_runtime_installation() {
        let config = r#"
        {
          "inbounds": [],
          "outbounds": [],
          "userDomainAccess": {
            "users": [{
              "userUuid": "11111111-1111-4111-8111-111111111111",
              "mode": "allowlist",
              "unknownTargetAction": "reject",
              "rules": []
            }]
          }
        }
        "#
        .parse::<crate::LiteralConfig>()
        .expect("literal policy should parse");

        let error = compile_user_domain_access(config.user_domain_access.as_ref())
            .expect_err("empty allowlist should fail");
        assert!(error.to_string().contains("allowlist"));
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
