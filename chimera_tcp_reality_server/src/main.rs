use std::{ffi::OsString, path::PathBuf, process::exit};

use chimera_server_lib::{
    ConfigFormat, ConfigType, Error, ServerConfig, is_tcp_reality_server,
    prepare_server_inbounds, resolve_config_source, start_tcp_server,
};
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "chimera-tcp-reality-server",
    about = "Run the Chimera TCP+REALITY / TCP+REALITY+Vision server entrypoint backed by chimera_server_lib::start_tcp_server"
)]
struct Cli {
    directory: Option<PathBuf>,

    #[clap(
        short,
        long,
        value_parser,
        value_name = "SOURCE",
        default_value = "config.json5",
        help = "Specify configuration file or external config source"
    )]
    config: String,

    #[arg(long, value_enum)]
    format: Option<CliConfigFormat>,

    #[arg(long, default_value_t = false)]
    check: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliConfigFormat {
    Json,
    Json5,
}

impl From<CliConfigFormat> for ConfigFormat {
    fn from(value: CliConfigFormat) -> Self {
        match value {
            CliConfigFormat::Json => ConfigFormat::Json,
            CliConfigFormat::Json5 => ConfigFormat::Json5,
        }
    }
}

fn main() {
    let cli = Cli::parse_from(normalized_args());
    let base_dir = cli
        .directory
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    let config_source =
        match resolve_config_source(&cli.config, Some(base_dir.as_path())) {
            Ok(source) => source,
            Err(err) => {
                eprintln!("invalid config source: {err}");
                exit(1);
            }
        };
    let config_format = cli.format.map(Into::into);
    let cwd = cli
        .directory
        .as_ref()
        .map(|path| path.to_string_lossy().to_string());

    let result = run(cli.check, config_source, config_format, cwd.as_deref());

    if let Err(err) = result {
        eprintln!(
            "{} error: {err}",
            if cli.check { "config" } else { "start" }
        );
        exit(1);
    }
}

fn run(
    check: bool,
    config_source: String,
    config_format: Option<ConfigFormat>,
    cwd: Option<&str>,
) -> Result<(), Error> {
    let config = ConfigType::File(config_source).try_parse(config_format)?;
    let inbounds = prepare_server_inbounds(config, cwd, None)?;
    ensure_supported_tcp_reality_only(&inbounds)?;

    if check {
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(start_tcp_reality_servers(inbounds))
}

fn ensure_supported_tcp_reality_only(
    inbounds: &[ServerConfig],
) -> Result<(), Error> {
    if inbounds.is_empty() {
        return Err(Error::InvalidConfig(
            "tcp+reality server requires at least one tcp+reality or tcp+reality+vision inbound".into(),
        ));
    }

    for inbound in inbounds {
        if !is_tcp_reality_server(inbound) {
            return Err(Error::InvalidConfig(format!(
                "inbound {} is not a tcp+reality or tcp+reality+vision server",
                inbound.tag
            )));
        }
    }

    Ok(())
}

async fn start_tcp_reality_servers(
    inbounds: Vec<ServerConfig>,
) -> Result<(), Error> {
    let mut join_handles = Vec::with_capacity(inbounds.len());

    for inbound in inbounds {
        if let Some(handle) = start_tcp_server(inbound).await? {
            join_handles.push(handle);
        }
    }

    if join_handles.is_empty() {
        return Err(Error::InvalidConfig(
            "no tcp+reality or tcp+reality+vision servers started".into(),
        ));
    }

    match futures::future::select_all(join_handles).await.0 {
        Ok(()) => Err(Error::Io(std::io::Error::other(
            "tcp+reality or tcp+reality+vision server task finished unexpectedly",
        ))),
        Err(err) => Err(Error::Io(std::io::Error::other(err))),
    }
}

fn normalized_args() -> Vec<OsString> {
    std::env::args_os()
        .map(|arg| {
            let Some(raw) = arg.to_str() else {
                return arg;
            };

            normalize_legacy_flag(raw)
                .map(OsString::from)
                .unwrap_or(arg)
        })
        .collect()
}

fn normalize_legacy_flag(arg: &str) -> Option<String> {
    for name in ["config", "format", "check"] {
        let long = format!("--{name}");
        let legacy = format!("-{name}");
        if arg == legacy {
            return Some(long);
        }
        if let Some(value) = arg.strip_prefix(&format!("{legacy}=")) {
            return Some(format!("{long}={value}"));
        }
    }

    None
}
