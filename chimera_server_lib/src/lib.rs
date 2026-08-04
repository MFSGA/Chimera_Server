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
use std::net::SocketAddr;
#[cfg(feature = "user_domain_access")]
use std::path::{Path, PathBuf};
use std::time::Duration;
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

mod runtime;
#[cfg(all(test, feature = "user_domain_access"))]
mod runtime_user_domain_access_tests;

#[cfg(feature = "reality")]
pub mod reality;

mod log;

mod handler;

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

pub struct ServerRuntime {
    pub inbounds: Vec<ServerConfig>,
    pub runtime_state: RuntimeState,
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
    let inbounds = prepare_server_inbounds(config, cwd, log_file)?;
    let runtime_state = RuntimeState::new(inbounds.clone(), Vec::new());
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
    let outbounds = config
        .outbounds
        .iter()
        .map(|item| OutboundSummary {
            tag: item.tag.clone(),
            protocol: item.protocol.clone(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        })
        .collect::<Vec<_>>();

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(ServerConfig::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let runtime_state = RuntimeState::new(all_inbounds.clone(), outbounds);
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
    #[cfg(feature = "user_domain_access")]
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::resolve_api_config;
    #[cfg(feature = "user_domain_access")]
    use super::{compile_user_domain_access, select_initial_user_domain_access};
    #[cfg(feature = "user_domain_access")]
    use crate::user_domain_access::{
        UserDomainAccessConfig, user_domain_access_checksum,
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
                },
            },
            transport: Transport::Tcp,
            quic_settings: None,
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
