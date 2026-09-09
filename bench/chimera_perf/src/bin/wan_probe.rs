use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use chimera_perf::{
    pattern::PatternStream,
    socks::connect_via_socks5,
    stats::{coefficient_of_variation, median, percentile},
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Barrier,
    task::JoinSet,
    time::{Instant, timeout},
};

const MAGIC: &[u8; 8] = b"CHMWAN01";
const HEADER_LEN: usize = 32;
const ROUNDTRIP_SYNC: u8 = 0xAC;
const DUPLEX_READY: u8 = 0xAD;
const DUPLEX_DONE: u8 = 0xAE;
const DEFAULT_CHUNK_BYTES: usize = 128 * 1024;
const DEFAULT_MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const STABILITY_CV_LIMIT: f64 = 0.03;

#[derive(Debug, Parser)]
#[command(about = "Cross-host proxy/WAN performance probe for Chimera_Server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the deterministic high-throughput target on a separate host.
    Server(ServerArgs),
    /// Benchmark one or more direct/SOCKS5 paths to the target.
    Client(ClientArgs),
}

#[derive(Debug, Args)]
struct ServerArgs {
    /// Listen address. Bind 0.0.0.0 only on a controlled benchmark host/firewall.
    #[arg(long, default_value = "127.0.0.1:20000")]
    bind: SocketAddr,

    /// Reject a single-flow payload larger than this value.
    #[arg(long, default_value_t = DEFAULT_MAX_PAYLOAD_BYTES)]
    max_payload_bytes: u64,

    /// Per-read/write scratch size.
    #[arg(long, default_value_t = DEFAULT_CHUNK_BYTES)]
    chunk_bytes: usize,

    /// Log accepted connections and failures to stderr.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum TransferMode {
    /// Upload the full payload, receive a sync byte, then download the payload.
    Roundtrip,
    /// Upload and download simultaneously, then wait for server verification.
    Duplex,
}

impl TransferMode {
    fn wire(self) -> u8 {
        match self {
            Self::Roundtrip => 0,
            Self::Duplex => 1,
        }
    }

    fn from_wire(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Roundtrip),
            1 => Ok(Self::Duplex),
            other => bail!("unsupported transfer mode {other}"),
        }
    }
}

#[derive(Debug, Clone)]
struct EndpointSpec {
    label: String,
    proxy: Option<SocketAddr>,
}

impl FromStr for EndpointSpec {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (label, path) = value
            .split_once('=')
            .context("endpoint must be LABEL=direct or LABEL=HOST:PORT")?;
        let label = label.trim();
        let path = path.trim();
        ensure!(!label.is_empty(), "endpoint label must not be empty");
        ensure!(!path.is_empty(), "endpoint path must not be empty");
        let proxy =
            if path.eq_ignore_ascii_case("direct") {
                None
            } else {
                Some(path.parse::<SocketAddr>().with_context(|| {
                    format!("invalid SOCKS5 proxy address {path:?}")
                })?)
            };
        Ok(Self {
            label: label.to_owned(),
            proxy,
        })
    }
}

#[derive(Debug, Args)]
struct ClientArgs {
    /// Target host running `wan_probe server`.
    #[arg(long)]
    target_host: String,

    /// Target port running `wan_probe server`.
    #[arg(long, default_value_t = 20_000)]
    target_port: u16,

    /// Test path. Repeat for A/B, e.g. raw=direct, xray=127.0.0.1:1081.
    #[arg(long = "endpoint", required = true)]
    endpoints: Vec<EndpointSpec>,

    /// Concurrent flows. Comma-separated and/or repeated.
    #[arg(long, value_delimiter = ',', default_value = "1,16,64")]
    concurrency: Vec<usize>,

    /// Bytes transferred in each direction by every flow.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    payload_bytes: u64,

    /// Transfer shape.
    #[arg(long, value_enum, default_value_t = TransferMode::Roundtrip)]
    mode: TransferMode,

    /// Warmup samples per endpoint/concurrency pair.
    #[arg(long, default_value_t = 3)]
    warmup: usize,

    /// Formal samples per endpoint/concurrency pair.
    #[arg(long, default_value_t = 10)]
    runs: usize,

    /// Timeout for connection setup and each data-flow sample.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,

    /// Per-read/write scratch size.
    #[arg(long, default_value_t = DEFAULT_CHUNK_BYTES)]
    chunk_bytes: usize,

    /// Deterministic seed for payloads and A/B ordering.
    #[arg(long, default_value_t = 0x4348_494d_4552_4101)]
    seed: u64,

    /// Write the complete JSON report to this path instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Print warmup progress as well as formal run progress.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug)]
struct RequestHeader {
    mode: TransferMode,
    payload_bytes: u64,
    seed: u64,
}

#[derive(Debug)]
struct PreparedFlow {
    stream: TcpStream,
    setup_ms: f64,
    seed: u64,
}

#[derive(Debug, Serialize)]
struct FlowReport {
    setup_ms: f64,
    upload_mbps: Option<f64>,
    download_mbps: Option<f64>,
    duplex_mbps: Option<f64>,
    upload_end_seconds: Option<f64>,
    download_start_seconds: Option<f64>,
    download_end_seconds: Option<f64>,
    duplex_end_seconds: Option<f64>,
}

#[derive(Debug, Serialize)]
struct RunReport {
    endpoint: String,
    proxy: Option<String>,
    concurrency: usize,
    warmup: bool,
    run_index: usize,
    valid: bool,
    connection_successes: usize,
    connection_failures: usize,
    flow_successes: usize,
    flow_failures: usize,
    setup_p50_ms: Option<f64>,
    setup_p99_ms: Option<f64>,
    aggregate_upload_mbps: Option<f64>,
    aggregate_download_mbps: Option<f64>,
    aggregate_duplex_mbps: Option<f64>,
    flow_upload_p50_mbps: Option<f64>,
    flow_upload_p99_mbps: Option<f64>,
    flow_download_p50_mbps: Option<f64>,
    flow_download_p99_mbps: Option<f64>,
    flow_duplex_p50_mbps: Option<f64>,
    flow_duplex_p99_mbps: Option<f64>,
    errors: Vec<String>,
    flows: Vec<FlowReport>,
}

#[derive(Debug, Serialize)]
struct EndpointSummary {
    endpoint: String,
    proxy: Option<String>,
    concurrency: usize,
    valid_runs: usize,
    invalid_runs: usize,
    connection_success_rate: f64,
    flow_success_rate: f64,
    aggregate_upload_mbps_median: Option<f64>,
    aggregate_upload_cv: Option<f64>,
    aggregate_download_mbps_median: Option<f64>,
    aggregate_download_cv: Option<f64>,
    aggregate_duplex_mbps_median: Option<f64>,
    aggregate_duplex_cv: Option<f64>,
    setup_p50_ms_median: Option<f64>,
    setup_p99_ms_median: Option<f64>,
    stable_at_3pct_cv: bool,
}

#[derive(Debug, Serialize)]
struct ClientReport {
    schema_version: u32,
    target_host: String,
    target_port: u16,
    mode: TransferMode,
    payload_bytes_per_direction_per_flow: u64,
    warmup_runs: usize,
    formal_runs: usize,
    stability_cv_limit: f64,
    endpoints: Vec<String>,
    concurrency: Vec<usize>,
    summaries: Vec<EndpointSummary>,
    runs: Vec<RunReport>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Server(args) => run_server(args).await,
        Command::Client(args) => run_client(args).await,
    }
}

async fn run_server(args: ServerArgs) -> Result<()> {
    ensure!(
        args.max_payload_bytes > 0,
        "--max-payload-bytes must be > 0"
    );
    ensure!(args.chunk_bytes > 0, "--chunk-bytes must be > 0");

    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("bind WAN probe server at {}", args.bind))?;
    eprintln!("wan_probe server listening on {}", args.bind);

    loop {
        let (stream, peer) =
            listener.accept().await.context("accept WAN probe client")?;
        stream.set_nodelay(true)?;
        let max_payload_bytes = args.max_payload_bytes;
        let chunk_bytes = args.chunk_bytes;
        let verbose = args.verbose;
        tokio::spawn(async move {
            if verbose {
                eprintln!("wan_probe accepted {peer}");
            }
            if let Err(error) =
                handle_server_connection(stream, max_payload_bytes, chunk_bytes)
                    .await
            {
                eprintln!("wan_probe connection {peer} failed: {error:#}");
            }
        });
    }
}

async fn handle_server_connection(
    mut stream: TcpStream,
    max_payload_bytes: u64,
    chunk_bytes: usize,
) -> Result<()> {
    let header = read_header(&mut stream).await?;
    ensure!(
        header.payload_bytes <= max_payload_bytes,
        "requested payload {} exceeds server limit {}",
        header.payload_bytes,
        max_payload_bytes
    );

    match header.mode {
        TransferMode::Roundtrip => {
            verify_pattern(
                &mut stream,
                header.payload_bytes,
                header.seed,
                chunk_bytes,
            )
            .await?;
            stream.write_all(&[ROUNDTRIP_SYNC]).await?;
            send_pattern(
                &mut stream,
                header.payload_bytes,
                header.seed,
                chunk_bytes,
            )
            .await?;
            stream.shutdown().await?;
        }
        TransferMode::Duplex => {
            stream.write_all(&[DUPLEX_READY]).await?;
            let (mut reader, mut writer) = stream.into_split();
            tokio::try_join!(
                verify_pattern(
                    &mut reader,
                    header.payload_bytes,
                    header.seed,
                    chunk_bytes,
                ),
                send_pattern(
                    &mut writer,
                    header.payload_bytes,
                    header.seed,
                    chunk_bytes,
                )
            )?;
            writer.write_all(&[DUPLEX_DONE]).await?;
            writer.shutdown().await?;
        }
    }
    Ok(())
}

async fn run_client(args: ClientArgs) -> Result<()> {
    validate_client_args(&args)?;

    let timeout_duration = Duration::from_secs(args.timeout_secs);
    let mut all_runs = Vec::new();

    for &concurrency in &args.concurrency {
        for warmup_index in 0..args.warmup {
            for endpoint_index in endpoint_order(
                args.endpoints.len(),
                args.seed,
                concurrency,
                true,
                warmup_index,
            ) {
                let endpoint = &args.endpoints[endpoint_index];
                if args.verbose {
                    eprintln!(
                        "[warmup] endpoint={} c={} run={}/{}",
                        endpoint.label,
                        concurrency,
                        warmup_index + 1,
                        args.warmup
                    );
                }
                let report = run_endpoint_sample(
                    endpoint,
                    &args,
                    concurrency,
                    true,
                    warmup_index,
                    timeout_duration,
                )
                .await;
                all_runs.push(report);
            }
        }

        for run_index in 0..args.runs {
            for endpoint_index in endpoint_order(
                args.endpoints.len(),
                args.seed,
                concurrency,
                false,
                run_index,
            ) {
                let endpoint = &args.endpoints[endpoint_index];
                let report = run_endpoint_sample(
                    endpoint,
                    &args,
                    concurrency,
                    false,
                    run_index,
                    timeout_duration,
                )
                .await;
                print_run_progress(&report, args.mode, args.runs);
                all_runs.push(report);
            }
        }
    }

    let summaries = build_summaries(&args, &all_runs);
    let report = ClientReport {
        schema_version: 1,
        target_host: args.target_host.clone(),
        target_port: args.target_port,
        mode: args.mode,
        payload_bytes_per_direction_per_flow: args.payload_bytes,
        warmup_runs: args.warmup,
        formal_runs: args.runs,
        stability_cv_limit: STABILITY_CV_LIMIT,
        endpoints: args
            .endpoints
            .iter()
            .map(|endpoint| endpoint.label.clone())
            .collect(),
        concurrency: args.concurrency.clone(),
        summaries,
        runs: all_runs,
    };

    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &args.output {
        fs::write(path, format!("{json}\n"))
            .with_context(|| format!("write WAN report to {}", path.display()))?;
        eprintln!("WAN report written to {}", path.display());
    } else {
        println!("{json}");
    }
    Ok(())
}

fn validate_client_args(args: &ClientArgs) -> Result<()> {
    ensure!(
        !args.target_host.trim().is_empty(),
        "--target-host must not be empty"
    );
    ensure!(args.payload_bytes > 0, "--payload-bytes must be > 0");
    ensure!(args.runs > 0, "--runs must be > 0");
    ensure!(args.timeout_secs > 0, "--timeout-secs must be > 0");
    ensure!(args.chunk_bytes > 0, "--chunk-bytes must be > 0");
    ensure!(
        !args.concurrency.is_empty(),
        "at least one concurrency is required"
    );
    ensure!(
        args.concurrency.iter().all(|value| *value > 0),
        "all concurrency values must be > 0"
    );

    let mut labels = BTreeSet::new();
    for endpoint in &args.endpoints {
        ensure!(
            labels.insert(endpoint.label.clone()),
            "duplicate endpoint label {:?}",
            endpoint.label
        );
    }
    Ok(())
}

async fn run_endpoint_sample(
    endpoint: &EndpointSpec,
    args: &ClientArgs,
    concurrency: usize,
    warmup: bool,
    run_index: usize,
    timeout_duration: Duration,
) -> RunReport {
    let mut prepared = Vec::with_capacity(concurrency);
    let mut errors = Vec::new();
    let mut setup_set = JoinSet::new();

    for flow_index in 0..concurrency {
        let endpoint = endpoint.clone();
        let target_host = args.target_host.clone();
        let target_port = args.target_port;
        let mode = args.mode;
        let payload_bytes = args.payload_bytes;
        let seed = flow_seed(args.seed, concurrency, warmup, run_index, flow_index);
        setup_set.spawn(async move {
            timeout(
                timeout_duration,
                prepare_flow(
                    &endpoint,
                    &target_host,
                    target_port,
                    mode,
                    payload_bytes,
                    seed,
                ),
            )
            .await
            .context("connection setup timed out")?
        });
    }

    while let Some(joined) = setup_set.join_next().await {
        match joined {
            Ok(Ok(flow)) => prepared.push(flow),
            Ok(Err(error)) => push_error(&mut errors, format!("setup: {error:#}")),
            Err(error) => push_error(&mut errors, format!("setup task: {error}")),
        }
    }

    let connection_successes = prepared.len();
    let connection_failures = concurrency.saturating_sub(connection_successes);
    let setup_values = prepared
        .iter()
        .map(|flow| flow.setup_ms)
        .collect::<Vec<_>>();

    if connection_failures > 0 {
        return RunReport {
            endpoint: endpoint.label.clone(),
            proxy: endpoint.proxy.map(|proxy| proxy.to_string()),
            concurrency,
            warmup,
            run_index,
            valid: false,
            connection_successes,
            connection_failures,
            flow_successes: 0,
            flow_failures: connection_successes,
            setup_p50_ms: metric_percentile(&setup_values, 50.0),
            setup_p99_ms: metric_percentile(&setup_values, 99.0),
            aggregate_upload_mbps: None,
            aggregate_download_mbps: None,
            aggregate_duplex_mbps: None,
            flow_upload_p50_mbps: None,
            flow_upload_p99_mbps: None,
            flow_download_p50_mbps: None,
            flow_download_p99_mbps: None,
            flow_duplex_p50_mbps: None,
            flow_duplex_p99_mbps: None,
            errors,
            flows: Vec::new(),
        };
    }

    let barrier = Arc::new(Barrier::new(concurrency));
    let common_start = Arc::new(OnceLock::<Instant>::new());
    let mut flow_set = JoinSet::new();

    for flow in prepared {
        let barrier = Arc::clone(&barrier);
        let common_start = Arc::clone(&common_start);
        let chunk_bytes = args.chunk_bytes;
        let payload_bytes = args.payload_bytes;
        let mode = args.mode;
        flow_set.spawn(async move {
            timeout(
                timeout_duration,
                run_flow(
                    flow,
                    payload_bytes,
                    mode,
                    chunk_bytes,
                    barrier,
                    common_start,
                ),
            )
            .await
            .context("data flow timed out")?
        });
    }

    let mut flows = Vec::with_capacity(concurrency);
    while let Some(joined) = flow_set.join_next().await {
        match joined {
            Ok(Ok(flow)) => flows.push(flow),
            Ok(Err(error)) => push_error(&mut errors, format!("flow: {error:#}")),
            Err(error) => push_error(&mut errors, format!("flow task: {error}")),
        }
    }

    let flow_successes = flows.len();
    let flow_failures = concurrency.saturating_sub(flow_successes);
    let valid = flow_failures == 0;

    let upload_values = optional_values(&flows, |flow| flow.upload_mbps);
    let download_values = optional_values(&flows, |flow| flow.download_mbps);
    let duplex_values = optional_values(&flows, |flow| flow.duplex_mbps);

    let aggregate_upload_mbps = if valid && args.mode == TransferMode::Roundtrip {
        flows
            .iter()
            .filter_map(|flow| flow.upload_end_seconds)
            .reduce(f64::max)
            .map(|seconds| mbps(args.payload_bytes * concurrency as u64, seconds))
    } else {
        None
    };
    let aggregate_download_mbps = if valid && args.mode == TransferMode::Roundtrip {
        let start = flows
            .iter()
            .filter_map(|flow| flow.download_start_seconds)
            .reduce(f64::min);
        let end = flows
            .iter()
            .filter_map(|flow| flow.download_end_seconds)
            .reduce(f64::max);
        match (start, end) {
            (Some(start), Some(end)) if end > start => {
                Some(mbps(args.payload_bytes * concurrency as u64, end - start))
            }
            _ => None,
        }
    } else {
        None
    };
    let aggregate_duplex_mbps = if valid && args.mode == TransferMode::Duplex {
        flows
            .iter()
            .filter_map(|flow| flow.duplex_end_seconds)
            .reduce(f64::max)
            .map(|seconds| {
                mbps(args.payload_bytes * concurrency as u64 * 2, seconds)
            })
    } else {
        None
    };

    RunReport {
        endpoint: endpoint.label.clone(),
        proxy: endpoint.proxy.map(|proxy| proxy.to_string()),
        concurrency,
        warmup,
        run_index,
        valid,
        connection_successes,
        connection_failures,
        flow_successes,
        flow_failures,
        setup_p50_ms: metric_percentile(&setup_values, 50.0),
        setup_p99_ms: metric_percentile(&setup_values, 99.0),
        aggregate_upload_mbps: aggregate_upload_mbps.map(round_metric),
        aggregate_download_mbps: aggregate_download_mbps.map(round_metric),
        aggregate_duplex_mbps: aggregate_duplex_mbps.map(round_metric),
        flow_upload_p50_mbps: metric_percentile(&upload_values, 50.0),
        flow_upload_p99_mbps: metric_percentile(&upload_values, 99.0),
        flow_download_p50_mbps: metric_percentile(&download_values, 50.0),
        flow_download_p99_mbps: metric_percentile(&download_values, 99.0),
        flow_duplex_p50_mbps: metric_percentile(&duplex_values, 50.0),
        flow_duplex_p99_mbps: metric_percentile(&duplex_values, 99.0),
        errors,
        flows,
    }
}

async fn prepare_flow(
    endpoint: &EndpointSpec,
    target_host: &str,
    target_port: u16,
    mode: TransferMode,
    payload_bytes: u64,
    seed: u64,
) -> Result<PreparedFlow> {
    let started = Instant::now();
    let mut stream = if let Some(proxy) = endpoint.proxy {
        connect_via_socks5(proxy, target_host, target_port, true).await?
    } else {
        let stream = TcpStream::connect((target_host, target_port))
            .await
            .with_context(|| {
                format!("connect target {target_host}:{target_port}")
            })?;
        stream.set_nodelay(true)?;
        stream
    };

    write_header(&mut stream, mode, payload_bytes, seed).await?;
    if mode == TransferMode::Duplex {
        let mut ready = [0_u8; 1];
        stream.read_exact(&mut ready).await?;
        ensure!(
            ready[0] == DUPLEX_READY,
            "server returned invalid duplex-ready byte 0x{:02x}",
            ready[0]
        );
    }

    Ok(PreparedFlow {
        stream,
        setup_ms: started.elapsed().as_secs_f64() * 1000.0,
        seed,
    })
}

async fn run_flow(
    flow: PreparedFlow,
    payload_bytes: u64,
    mode: TransferMode,
    chunk_bytes: usize,
    barrier: Arc<Barrier>,
    common_start: Arc<OnceLock<Instant>>,
) -> Result<FlowReport> {
    match mode {
        TransferMode::Roundtrip => {
            run_roundtrip_flow(
                flow,
                payload_bytes,
                chunk_bytes,
                barrier,
                common_start,
            )
            .await
        }
        TransferMode::Duplex => {
            run_duplex_flow(flow, payload_bytes, chunk_bytes, barrier, common_start)
                .await
        }
    }
}

async fn run_roundtrip_flow(
    mut flow: PreparedFlow,
    payload_bytes: u64,
    chunk_bytes: usize,
    barrier: Arc<Barrier>,
    common_start: Arc<OnceLock<Instant>>,
) -> Result<FlowReport> {
    barrier.wait().await;
    let global_start = *common_start.get_or_init(Instant::now);
    let upload_started = Instant::now();
    send_pattern(&mut flow.stream, payload_bytes, flow.seed, chunk_bytes).await?;
    let mut sync = [0_u8; 1];
    flow.stream.read_exact(&mut sync).await?;
    ensure!(
        sync[0] == ROUNDTRIP_SYNC,
        "server returned invalid roundtrip sync byte 0x{:02x}",
        sync[0]
    );
    let upload_seconds = upload_started.elapsed().as_secs_f64();
    let upload_end_seconds = global_start.elapsed().as_secs_f64();

    let download_start_seconds = global_start.elapsed().as_secs_f64();
    let download_started = Instant::now();
    verify_pattern(&mut flow.stream, payload_bytes, flow.seed, chunk_bytes).await?;
    let download_seconds = download_started.elapsed().as_secs_f64();
    let download_end_seconds = global_start.elapsed().as_secs_f64();

    Ok(FlowReport {
        setup_ms: round_metric(flow.setup_ms),
        upload_mbps: Some(round_metric(mbps(payload_bytes, upload_seconds))),
        download_mbps: Some(round_metric(mbps(payload_bytes, download_seconds))),
        duplex_mbps: None,
        upload_end_seconds: Some(upload_end_seconds),
        download_start_seconds: Some(download_start_seconds),
        download_end_seconds: Some(download_end_seconds),
        duplex_end_seconds: None,
    })
}

async fn run_duplex_flow(
    flow: PreparedFlow,
    payload_bytes: u64,
    chunk_bytes: usize,
    barrier: Arc<Barrier>,
    common_start: Arc<OnceLock<Instant>>,
) -> Result<FlowReport> {
    barrier.wait().await;
    let global_start = *common_start.get_or_init(Instant::now);
    let duplex_started = Instant::now();
    let (mut reader, mut writer) = flow.stream.into_split();

    let upload = async {
        send_pattern(&mut writer, payload_bytes, flow.seed, chunk_bytes).await?;
        writer.shutdown().await?;
        Result::<()>::Ok(())
    };
    let download = async {
        verify_pattern(&mut reader, payload_bytes, flow.seed, chunk_bytes).await?;
        let mut done = [0_u8; 1];
        reader.read_exact(&mut done).await?;
        ensure!(
            done[0] == DUPLEX_DONE,
            "server returned invalid duplex-done byte 0x{:02x}",
            done[0]
        );
        Result::<()>::Ok(())
    };
    tokio::try_join!(upload, download)?;

    let duplex_seconds = duplex_started.elapsed().as_secs_f64();
    let duplex_end_seconds = global_start.elapsed().as_secs_f64();
    Ok(FlowReport {
        setup_ms: round_metric(flow.setup_ms),
        upload_mbps: None,
        download_mbps: None,
        duplex_mbps: Some(round_metric(mbps(payload_bytes * 2, duplex_seconds))),
        upload_end_seconds: None,
        download_start_seconds: None,
        download_end_seconds: None,
        duplex_end_seconds: Some(duplex_end_seconds),
    })
}

async fn send_pattern<W>(
    writer: &mut W,
    payload_bytes: u64,
    seed: u64,
    chunk_bytes: usize,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut pattern = PatternStream::new(seed);
    let mut buffer = vec![0_u8; chunk_bytes];
    let mut remaining = payload_bytes;
    while remaining > 0 {
        let count = remaining.min(chunk_bytes as u64) as usize;
        pattern.fill(&mut buffer[..count]);
        writer.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    Ok(())
}

async fn verify_pattern<R>(
    reader: &mut R,
    payload_bytes: u64,
    seed: u64,
    chunk_bytes: usize,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut pattern = PatternStream::new(seed);
    let mut buffer = vec![0_u8; chunk_bytes];
    let mut expected = vec![0_u8; chunk_bytes];
    let mut remaining = payload_bytes;
    let mut offset = 0_u64;

    while remaining > 0 {
        let count = remaining.min(chunk_bytes as u64) as usize;
        reader.read_exact(&mut buffer[..count]).await?;
        if !pattern.matches(&buffer[..count], &mut expected[..count]) {
            bail!("payload mismatch at or after byte offset {offset}");
        }
        remaining -= count as u64;
        offset += count as u64;
    }
    Ok(())
}

async fn write_header(
    writer: &mut TcpStream,
    mode: TransferMode,
    payload_bytes: u64,
    seed: u64,
) -> Result<()> {
    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8] = mode.wire();
    header[16..24].copy_from_slice(&payload_bytes.to_be_bytes());
    header[24..32].copy_from_slice(&seed.to_be_bytes());
    writer.write_all(&header).await?;
    Ok(())
}

async fn read_header(reader: &mut TcpStream) -> Result<RequestHeader> {
    let mut header = [0_u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    ensure!(&header[..8] == MAGIC, "invalid WAN probe magic");
    ensure!(
        header[9..16].iter().all(|byte| *byte == 0),
        "non-zero reserved WAN probe header bytes"
    );
    let mode = TransferMode::from_wire(header[8])?;
    let payload_bytes = u64::from_be_bytes(header[16..24].try_into().unwrap());
    let seed = u64::from_be_bytes(header[24..32].try_into().unwrap());
    ensure!(payload_bytes > 0, "payload size must be > 0");
    Ok(RequestHeader {
        mode,
        payload_bytes,
        seed,
    })
}

fn build_summaries(args: &ClientArgs, runs: &[RunReport]) -> Vec<EndpointSummary> {
    let mut grouped: BTreeMap<(String, usize), Vec<&RunReport>> = BTreeMap::new();
    for run in runs.iter().filter(|run| !run.warmup) {
        grouped
            .entry((run.endpoint.clone(), run.concurrency))
            .or_default()
            .push(run);
    }

    let mut summaries = Vec::new();
    for endpoint in &args.endpoints {
        for &concurrency in &args.concurrency {
            let key = (endpoint.label.clone(), concurrency);
            let group = grouped.get(&key).cloned().unwrap_or_default();
            let valid = group
                .iter()
                .copied()
                .filter(|run| run.valid)
                .collect::<Vec<_>>();
            let invalid_runs = group.len().saturating_sub(valid.len());
            let attempted_connections = group.len() * concurrency;
            let connection_successes = group
                .iter()
                .map(|run| run.connection_successes)
                .sum::<usize>();
            let flow_successes =
                group.iter().map(|run| run.flow_successes).sum::<usize>();

            let upload = valid
                .iter()
                .filter_map(|run| run.aggregate_upload_mbps)
                .collect::<Vec<_>>();
            let download = valid
                .iter()
                .filter_map(|run| run.aggregate_download_mbps)
                .collect::<Vec<_>>();
            let duplex = valid
                .iter()
                .filter_map(|run| run.aggregate_duplex_mbps)
                .collect::<Vec<_>>();
            let setup_p50 = valid
                .iter()
                .filter_map(|run| run.setup_p50_ms)
                .collect::<Vec<_>>();
            let setup_p99 = valid
                .iter()
                .filter_map(|run| run.setup_p99_ms)
                .collect::<Vec<_>>();

            let upload_cv = metric_cv(&upload);
            let download_cv = metric_cv(&download);
            let duplex_cv = metric_cv(&duplex);
            let stable = invalid_runs == 0
                && valid.len() == args.runs
                && match args.mode {
                    TransferMode::Roundtrip => {
                        upload_cv.is_some_and(|value| value <= STABILITY_CV_LIMIT)
                            && download_cv
                                .is_some_and(|value| value <= STABILITY_CV_LIMIT)
                    }
                    TransferMode::Duplex => {
                        duplex_cv.is_some_and(|value| value <= STABILITY_CV_LIMIT)
                    }
                };

            summaries.push(EndpointSummary {
                endpoint: endpoint.label.clone(),
                proxy: endpoint.proxy.map(|proxy| proxy.to_string()),
                concurrency,
                valid_runs: valid.len(),
                invalid_runs,
                connection_success_rate: ratio(
                    connection_successes,
                    attempted_connections,
                ),
                flow_success_rate: ratio(flow_successes, attempted_connections),
                aggregate_upload_mbps_median: metric_median(&upload),
                aggregate_upload_cv: upload_cv,
                aggregate_download_mbps_median: metric_median(&download),
                aggregate_download_cv: download_cv,
                aggregate_duplex_mbps_median: metric_median(&duplex),
                aggregate_duplex_cv: duplex_cv,
                setup_p50_ms_median: metric_median(&setup_p50),
                setup_p99_ms_median: metric_median(&setup_p99),
                stable_at_3pct_cv: stable,
            });
        }
    }
    summaries
}

fn print_run_progress(report: &RunReport, mode: TransferMode, runs: usize) {
    if !report.valid {
        eprintln!(
            "[run] endpoint={} c={} run={}/{} INVALID setup_fail={} flow_fail={} {}",
            report.endpoint,
            report.concurrency,
            report.run_index + 1,
            runs,
            report.connection_failures,
            report.flow_failures,
            report.errors.first().map(String::as_str).unwrap_or("")
        );
        return;
    }

    match mode {
        TransferMode::Roundtrip => eprintln!(
            "[run] endpoint={} c={} run={}/{} up={:.2} Mbps down={:.2} Mbps setup_p99={:.2} ms",
            report.endpoint,
            report.concurrency,
            report.run_index + 1,
            runs,
            report.aggregate_upload_mbps.unwrap_or_default(),
            report.aggregate_download_mbps.unwrap_or_default(),
            report.setup_p99_ms.unwrap_or_default(),
        ),
        TransferMode::Duplex => eprintln!(
            "[run] endpoint={} c={} run={}/{} duplex={:.2} Mbps setup_p99={:.2} ms",
            report.endpoint,
            report.concurrency,
            report.run_index + 1,
            runs,
            report.aggregate_duplex_mbps.unwrap_or_default(),
            report.setup_p99_ms.unwrap_or_default(),
        ),
    }
}

fn endpoint_order(
    endpoint_count: usize,
    seed: u64,
    concurrency: usize,
    warmup: bool,
    run_index: usize,
) -> Vec<usize> {
    let mut order = (0..endpoint_count).collect::<Vec<_>>();
    order.sort_by_key(|index| {
        splitmix64(
            seed ^ ((concurrency as u64) << 32)
                ^ ((run_index as u64) << 8)
                ^ ((*index as u64) << 1)
                ^ u64::from(warmup),
        )
    });
    order
}

fn flow_seed(
    seed: u64,
    concurrency: usize,
    warmup: bool,
    run_index: usize,
    flow_index: usize,
) -> u64 {
    splitmix64(
        seed ^ ((concurrency as u64) << 40)
            ^ ((run_index as u64) << 16)
            ^ ((flow_index as u64) << 1)
            ^ u64::from(warmup),
    )
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn optional_values<F>(flows: &[FlowReport], select: F) -> Vec<f64>
where
    F: Fn(&FlowReport) -> Option<f64>,
{
    flows.iter().filter_map(select).collect()
}

fn metric_percentile(values: &[f64], p: f64) -> Option<f64> {
    (!values.is_empty()).then(|| round_metric(percentile(values, p)))
}

fn metric_median(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| round_metric(median(values)))
}

fn metric_cv(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| round_metric(coefficient_of_variation(values)))
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    round_metric(numerator as f64 / denominator as f64)
}

fn mbps(bytes: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    bytes as f64 * 8.0 / seconds / 1_000_000.0
}

fn round_metric(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn push_error(errors: &mut Vec<String>, error: String) {
    const MAX_ERRORS: usize = 8;
    if errors.len() < MAX_ERRORS {
        errors.push(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_supports_direct_and_socks() {
        let direct: EndpointSpec = "raw=direct".parse().unwrap();
        assert_eq!(direct.label, "raw");
        assert!(direct.proxy.is_none());

        let socks: EndpointSpec = "chimera=127.0.0.1:1080".parse().unwrap();
        assert_eq!(socks.label, "chimera");
        assert_eq!(socks.proxy.unwrap(), "127.0.0.1:1080".parse().unwrap());
    }

    #[test]
    fn endpoint_order_is_a_permutation() {
        let mut order = endpoint_order(5, 7, 64, false, 3);
        order.sort_unstable();
        assert_eq!(order, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn stability_requires_all_formal_runs() {
        let args = ClientArgs {
            target_host: "example.invalid".into(),
            target_port: 20000,
            endpoints: vec!["raw=direct".parse().unwrap()],
            concurrency: vec![1],
            payload_bytes: 1024,
            mode: TransferMode::Roundtrip,
            warmup: 0,
            runs: 2,
            timeout_secs: 1,
            chunk_bytes: 1024,
            seed: 1,
            output: None,
            verbose: false,
        };
        let run = |index| RunReport {
            endpoint: "raw".into(),
            proxy: None,
            concurrency: 1,
            warmup: false,
            run_index: index,
            valid: true,
            connection_successes: 1,
            connection_failures: 0,
            flow_successes: 1,
            flow_failures: 0,
            setup_p50_ms: Some(1.0),
            setup_p99_ms: Some(1.0),
            aggregate_upload_mbps: Some(100.0),
            aggregate_download_mbps: Some(100.0),
            aggregate_duplex_mbps: None,
            flow_upload_p50_mbps: Some(100.0),
            flow_upload_p99_mbps: Some(100.0),
            flow_download_p50_mbps: Some(100.0),
            flow_download_p99_mbps: Some(100.0),
            flow_duplex_p50_mbps: None,
            flow_duplex_p99_mbps: None,
            errors: Vec::new(),
            flows: Vec::new(),
        };
        let summaries = build_summaries(&args, &[run(0), run(1)]);
        assert!(summaries[0].stable_at_3pct_cv);
    }
}
