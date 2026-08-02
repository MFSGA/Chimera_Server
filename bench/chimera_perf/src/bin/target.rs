use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use chimera_perf::{
    pattern::PatternStream,
    protocol::{ACK_LEN, Ack, DOWNLOAD_READY, READY_LEN, REQUEST_LEN, Request},
    tls::{self, BenchIo, BoxedBenchIo},
};
use clap::Parser;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

#[derive(Debug, Parser)]
#[command(about = "Streaming target for Chimera throughput benchmarks")]
struct Args {
    #[arg(long, default_value = "payload")]
    name: String,

    #[arg(long, default_value = "127.0.0.1:52080")]
    listen: SocketAddr,

    #[arg(long, default_value_t = 64 * 1024)]
    buffer_size: usize,

    #[arg(long, default_value_t = 4096)]
    max_connections: usize,

    #[arg(long, default_value_t = 1)]
    worker_threads: usize,

    #[arg(long)]
    tcp_nodelay: bool,

    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.buffer_size == 0 {
        bail!("--buffer-size must be greater than zero");
    }
    if args.max_connections == 0 {
        bail!("--max-connections must be greater than zero");
    }
    if args.worker_threads == 0 {
        bail!("--worker-threads must be greater than zero");
    }

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.worker_threads)
        .enable_all()
        .build()?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let tls_config = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(Arc::new(tls::server_config(cert, key)?)),
        (None, None) => None,
        _ => unreachable!("clap enforces paired TLS certificate and key"),
    };
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind benchmark target on {}", args.listen))?;
    let local_addr = listener.local_addr()?;
    eprintln!(
        "chimera-perf target {} listening on {local_addr}",
        args.name,
    );

    let semaphore = Arc::new(Semaphore::new(args.max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = semaphore.clone().acquire_owned().await?;
        let name = args.name.clone();
        let buffer_size = args.buffer_size;
        let tcp_nodelay = args.tcp_nodelay;
        let tls_config = tls_config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                handle_connection(stream, buffer_size, tcp_nodelay, tls_config).await
            {
                eprintln!(
                    "target {name} {local_addr} connection {peer} failed: {error:#}"
                );
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    buffer_size: usize,
    tcp_nodelay: bool,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    stream.set_nodelay(tcp_nodelay)?;
    let mut stream: BoxedBenchIo = match tls_config {
        Some(config) => tls::accept(stream, config).await?,
        None => tls::plain(stream),
    };

    let mut request_bytes = [0_u8; REQUEST_LEN];
    stream.read_exact(&mut request_bytes).await?;
    let request = Request::decode(&request_bytes)?;

    receive_upload(&mut stream, request, buffer_size).await?;
    let ack = Ack::OK.encode();
    debug_assert_eq!(ack.len(), ACK_LEN);
    stream.write_all(&ack).await?;
    stream.flush().await?;

    let mut ready = [0_u8; READY_LEN];
    stream.read_exact(&mut ready).await?;
    if ready != DOWNLOAD_READY {
        bail!("invalid download-ready barrier");
    }

    send_download(&mut stream, request, buffer_size).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn receive_upload(
    stream: &mut dyn BenchIo,
    request: Request,
    buffer_size: usize,
) -> Result<()> {
    let mut remaining = request.upload_len;
    let mut buffer = vec![0_u8; buffer_size];
    let mut verifier = request
        .full_verify()
        .then(|| (PatternStream::new(request.seed), vec![0_u8; buffer_size]));

    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer_size as u64))?;
        stream.read_exact(&mut buffer[..count]).await?;
        if let Some((pattern, expected)) = verifier.as_mut()
            && !pattern.matches(&buffer[..count], &mut expected[..count])
        {
            bail!("upload pattern verification failed");
        }
        remaining -= count as u64;
    }
    Ok(())
}

async fn send_download(
    stream: &mut dyn BenchIo,
    request: Request,
    buffer_size: usize,
) -> Result<()> {
    let mut remaining = request.download_len;
    let mut buffer = vec![0_u8; buffer_size];
    let mut pattern = PatternStream::new(request.seed ^ u64::MAX);
    if !request.full_verify() {
        pattern.fill(&mut buffer);
    }

    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer_size as u64))?;
        if request.full_verify() {
            pattern.fill(&mut buffer[..count]);
        }
        stream.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    stream.flush().await?;
    Ok(())
}
