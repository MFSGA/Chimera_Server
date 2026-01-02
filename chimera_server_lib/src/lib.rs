use beginning::start_servers;
use config::{
    def::{self, LiteralConfig},
    server_config::ServerConfig,
};
use runtime::{OutboundSummary, RuntimeState};
use thiserror::Error;
use tokio_rustls::rustls;

mod address;

mod async_stream;

mod beginning;

mod config;

mod grpc;

mod runtime;

pub mod reality;

mod log;

mod handler;

mod resolver;

pub mod traffic;

mod util;

#[allow(clippy::large_enum_variant)]
pub enum Config {
    File(String),

    Str(String),
}

impl Config {
    pub fn try_parse(self) -> Result<LiteralConfig, Error> {
        match self {
            Config::File(file) => {
                TryInto::<def::LiteralConfig>::try_into(std::path::PathBuf::from(file))
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
    pub config: Config,

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

async fn start_async(opts: Options) -> Result<(), Error> {
    let config = opts.config.try_parse()?;
    log::init(
        config.log.as_ref(),
        opts.cwd.as_deref(),
        opts.log_file.as_deref(),
    )?;

    let api_config = config.api.clone();
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

    let mut api_addr = None;
    let mut skip_inbound_tag = None;
    if let Some(api) = api_config.as_ref() {
        if let Some(listen) = api.listen.as_ref() {
            api_addr = Some(listen.parse::<std::net::SocketAddr>().map_err(|err| {
                Error::InvalidConfig(format!("invalid api.listen {}: {}", listen, err))
            })?);
        }

        if api_addr.is_none() {
            if let Some(tag) = api.tag.as_ref() {
                if let Some(inbound) = all_inbounds.iter().find(|cfg| cfg.tag == *tag) {
                    if let crate::address::BindLocation::Address(addr) = &inbound.bind_location {
                        api_addr = Some(addr.to_socket_addr()?);
                        skip_inbound_tag = Some(tag.clone());
                    }
                }
            }
        }
        if api_addr.is_none() {
            tracing::warn!("api is configured but no listen address was resolved");
        }
    }

    let mut join_handles = Vec::with_capacity(all_inbounds.len() * 2 + 1);
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

    for config in all_inbounds {
        if skip_inbound_tag.as_deref() == Some(config.tag.as_str()) {
            tracing::info!("skip api inbound {} to avoid grpc port conflict", config.tag);
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
