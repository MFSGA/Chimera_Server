use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use chimera_perf::tls;
use clap::Parser;
use tokio::{io::AsyncReadExt, net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Parser)]
#[command(about = "Stable local TLS 1.3 decoy for REALITY benchmarks")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:52081")]
    listen: SocketAddr,

    #[arg(long)]
    cert: PathBuf,

    #[arg(long)]
    key: PathBuf,

    #[arg(long, default_value_t = 1)]
    worker_threads: usize,

    #[arg(long, default_value_t = 4096)]
    max_connections: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.worker_threads == 0 {
        bail!("--worker-threads must be greater than zero");
    }
    if args.max_connections == 0 {
        bail!("--max-connections must be greater than zero");
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.worker_threads)
        .enable_all()
        .build()?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let acceptor =
        TlsAcceptor::from(Arc::new(tls::server_config(&args.cert, &args.key)?));
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind REALITY decoy on {}", args.listen))?;
    let local_addr = listener.local_addr()?;
    eprintln!("chimera-perf decoy listening on {local_addr}");
    let semaphore = Arc::new(Semaphore::new(args.max_connections));

    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = semaphore.clone().acquire_owned().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match acceptor.accept(stream).await {
                Ok(mut tls) => {
                    let mut byte = [0_u8; 1];
                    let _ = tls.read(&mut byte).await;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(error) => {
                    eprintln!(
                        "decoy {local_addr} connection {peer} ended during TLS: {error}"
                    );
                }
            }
        });
    }
}
