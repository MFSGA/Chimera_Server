use beginning::start_servers;
use config::{
    def::{self, LiteralConfig},
    internal::InternalConfig,
    server_config::ServerConfig,
};
use thiserror::Error;
use tokio_rustls::rustls;

mod address;

mod async_stream;

mod beginning;

mod config;

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

    let all_inbounds = config
        .inbounds
        .into_iter()
        .map(|inbound| ServerConfig::try_from(inbound).unwrap())
        .collect::<Vec<_>>();

    let mut join_handles = Vec::with_capacity(all_inbounds.len() * 2);
    for config in all_inbounds {
        join_handles.append(&mut start_servers(config).await.unwrap());
    }

    futures::future::select_all(join_handles)
        .await
        .0
        .map_err(|x| {
            tracing::error!("runtime error: {}, shutting down", x);
            Error::Io(std::io::Error::other(x))
        })
}
