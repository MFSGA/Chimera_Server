use beginning::start_servers;
use config::{
    def::{ApiConfig, LiteralConfig},
    rule::RoutingConfig,
    server_config::{ServerConfig, ServerProxyConfig},
};
pub use config_loader::{ConfigFormat, resolve_config_source};
use runtime::{OutboundSummary, RuntimeState};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio_rustls::rustls;

mod address;

mod async_stream;

mod beginning;

mod config;

mod config_loader;

#[cfg(feature = "api")]
mod grpc;

mod mcp;

mod runtime;

#[cfg(feature = "reality")]
pub mod reality;

mod log;

mod handler;

mod resolver;

mod routing_state;

pub mod traffic;

mod util;

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

fn api_inbound_uses_tls(protocol: &ServerProxyConfig) -> bool {
    #[cfg(feature = "tls")]
    if matches!(protocol, ServerProxyConfig::Tls(_)) {
        return true;
    }

    false
}

pub fn start(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };

    rt.block_on(async {
        match start_async(opts).await {
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

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(ServerConfig::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    routing_state::RoutingState::from_config(config.routing.as_ref())
        .map_err(Error::InvalidConfig)?;

    let api_addr = resolve_api_config(
        api_config.as_ref(),
        routing_config.as_ref(),
        &all_inbounds,
    )?
    .listen_addr;

    if let Some(mcp) = mcp_config.as_ref() {
        if let Some(listen) = mcp.listen.as_ref() {
            let _ = listen.parse::<std::net::SocketAddr>().map_err(|err| {
                Error::InvalidConfig(format!(
                    "invalid mcp.listen {}: {}",
                    listen, err
                ))
            })?;
            let _ = mcp.update_interval_ms.max(100);
        }
    }

    let mut any_server = !all_inbounds.is_empty();
    if let Some(api) = api_config.as_ref() {
        if api_addr.is_some() && !api.services.is_empty() {
            any_server = true;
        }
    }
    if let Some(mcp) = mcp_config.as_ref() {
        if mcp.listen.as_ref().is_some() {
            any_server = true;
        }
    }

    if !any_server {
        return Err(Error::InvalidConfig(
            "no servers started; check inbounds/api configuration".into(),
        ));
    }

    Ok(())
}

async fn start_async(opts: Options) -> Result<(), Error> {
    // 1. config parse
    let config = opts.config.try_parse(opts.config_format)?;
    //  todo: log mod
    log::init(
        config.log.as_ref(),
        opts.cwd.as_deref(),
        opts.log_file.as_deref(),
    )?;
    // 2. api config
    let api_config = config.api.clone();
    let mcp_config = config.mcp.clone();
    let routing_config = config.routing.clone();
    let outbounds = config
        .outbounds
        .iter()
        .map(|item| OutboundSummary {
            tag: item.tag.clone(),
            protocol: item.protocol.clone(),
        })
        .collect::<Vec<_>>();

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(|inbound| ServerConfig::try_from(inbound).unwrap())
        .collect::<Vec<_>>();

    let runtime_state = RuntimeState::new(all_inbounds.clone(), outbounds);
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
        if let Some(inbound) = resolved_api.inbound {
            if api_inbound_uses_tls(&inbound.protocol) {
                tracing::warn!(
                    "api inbound {} uses tls settings, but local grpc currently listens without tls",
                    inbound.tag
                );
            }
        }
        if api_addr.is_none() {
            tracing::warn!("api is configured but no listen address was resolved");
        }
    }

    let mut join_handles = Vec::with_capacity(all_inbounds.len() * 2 + 1);
    #[cfg(feature = "api")]
    if let Some(api) = api_config.as_ref() {
        if let Some(listen) = api_addr {
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
            } else {
                tracing::warn!("api is configured but no services are enabled");
            }
        }
    }

    #[cfg(not(feature = "api"))]
    if let Some(api) = api_config.as_ref() {
        if !api.services.is_empty() {
            tracing::warn!(
                "api services configured but the \"api\" feature is disabled; grpc support is unavailable"
            );
        }
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
        let mut handles = start_servers(config).await?;
        join_handles.append(&mut handles);
    }

    if join_handles.is_empty() {
        return Err(Error::InvalidConfig(
            "no servers started; check inbounds/api configuration".into(),
        ));
    }

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
    use super::resolve_api_config;
    use crate::{
        address::{Address, BindLocation, NetLocation},
        config::{
            Transport,
            def::ApiConfig,
            rule::{RoutingConfig, RuleConfig},
            server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
        },
    };

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
