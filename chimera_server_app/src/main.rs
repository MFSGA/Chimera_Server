use std::{ffi::OsString, path::PathBuf, process::exit};

use chimera::ConfigFormat;
use chimera::TokioRuntime;
use clap::{Parser, ValueEnum};

extern crate chimera_server_lib as chimera;

#[derive(Parser)]
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
    let config_source = match chimera::resolve_config_source(
        &cli.config,
        Some(base_dir.as_path()),
    ) {
        Ok(source) => source,
        Err(err) => {
            eprintln!("invalid config source: {err}");
            exit(1);
        }
    };
    let config_format = cli.format.map(Into::into);

    if cli.check {
        match chimera::validate(chimera::Options {
            config: chimera::ConfigType::File(config_source),
            config_format,
            cwd: cli.directory.map(|x| x.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
        }) {
            Ok(_) => exit(0),
            Err(e) => {
                eprintln!("config invalid: {e}");
                exit(1);
            }
        }
    }

    match chimera::start(chimera::Options {
        config: chimera::ConfigType::File(config_source),
        config_format,
        cwd: cli.directory.map(|x| x.to_string_lossy().to_string()),
        rt: Some(TokioRuntime::MultiThread),
        log_file: None,
    }) {
        Ok(_) => {}
        Err(_) => {
            exit(1);
        }
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
