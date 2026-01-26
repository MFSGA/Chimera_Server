use std::{
    path::{Path, PathBuf},
    process::exit,
};

use chimera::TokioRuntime;
use clap::Parser;

extern crate chimera_server_lib as chimera;

#[derive(Parser)]
struct Cli {
    directory: Option<PathBuf>,
    #[clap(default_value = "config.json5", value_name = "FILE", value_parser)]
    config: PathBuf,

    #[arg(long, default_value_t = false)]
    check: bool,
}

fn main() {
    let cli = Cli::parse();
    let file = cli
        .directory
        .as_ref()
        .unwrap_or(&std::env::current_dir().unwrap())
        .join(cli.config)
        .to_string_lossy()
        .to_string();

    if !Path::new(&file).exists() {
        panic!("config file not found: {}", file);
    }

    if cli.check {
        match chimera::validate(chimera::Options {
            config: chimera::ConfigType::File(file),
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
        config: chimera::ConfigType::File(file),
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
