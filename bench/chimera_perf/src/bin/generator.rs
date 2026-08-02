use std::{
    fs,
    io::{BufWriter, Write},
    net::SocketAddr,
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use chimera_perf::{
    pattern::PatternStream,
    protocol::{
        ACK_LEN, Ack, DOWNLOAD_READY, FLAG_FULL_VERIFY, REQUEST_LEN, Request,
    },
    socks::connect_via_socks5,
    stats::{coefficient_of_variation, median, percentile},
};
use clap::Parser;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Barrier,
    task::JoinSet,
    time::timeout,
};

#[derive(Debug, Parser)]
#[command(about = "Native streaming generator for Chimera throughput benchmarks")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:52080")]
    target: String,

    #[arg(long)]
    socks5: Option<SocketAddr>,

    #[arg(long, default_value = "raw-tcp")]
    label: String,

    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    upload_bytes: u64,

    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    download_bytes: u64,

    #[arg(long, default_value_t = 1)]
    concurrency: usize,

    #[arg(long, default_value_t = 3)]
    warmup: usize,

    #[arg(long, default_value_t = 10)]
    runs: usize,

    #[arg(long, default_value_t = 64 * 1024)]
    buffer_size: usize,

    #[arg(long)]
    full_verify: bool,

    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,

    #[arg(long, default_value_t = 1)]
    worker_threads: usize,

    #[arg(long)]
    max_cv: Option<f64>,

    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value = ".")]
    repository: PathBuf,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionResult {
    upload_seconds: f64,
    download_seconds: f64,
}

#[derive(Debug, Serialize)]
struct HostMetadata {
    hostname: String,
    kernel: String,
    cpu_model: String,
    logical_cpus: usize,
    cpu_affinity: String,
    git_commit: String,
    git_dirty: bool,
    binary_blake3: String,
    build_profile: &'static str,
}

#[derive(Debug, Serialize)]
struct RunResult<'a> {
    schema_version: u32,
    record_type: &'static str,
    unix_time_seconds: u64,
    label: &'a str,
    transport: &'static str,
    target: &'a str,
    socks5: Option<String>,
    run_index: usize,
    warmup: bool,
    concurrency: usize,
    upload_bytes_per_connection: u64,
    download_bytes_per_connection: u64,
    buffer_size: usize,
    full_verify: bool,
    upload_mbps: f64,
    download_mbps: f64,
    upload_connection_p50_mbps: f64,
    upload_connection_p99_mbps: f64,
    download_connection_p50_mbps: f64,
    download_connection_p99_mbps: f64,
    host: &'a HostMetadata,
}

#[derive(Debug, Serialize)]
struct Summary<'a> {
    schema_version: u32,
    record_type: &'static str,
    unix_time_seconds: u64,
    label: &'a str,
    transport: &'static str,
    target: &'a str,
    socks5: Option<String>,
    runs: usize,
    warmup_runs: usize,
    concurrency: usize,
    upload_bytes_per_connection: u64,
    download_bytes_per_connection: u64,
    buffer_size: usize,
    full_verify: bool,
    upload_median_mbps: f64,
    upload_p99_mbps: f64,
    upload_cv: f64,
    download_median_mbps: f64,
    download_p99_mbps: f64,
    download_cv: f64,
    host: &'a HostMetadata,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_args(&args)?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.worker_threads)
        .enable_all()
        .build()?
        .block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let (target_host, target_port) = split_host_port(&args.target)?;
    let host = collect_host_metadata(&args.repository)?;

    let mut output = match &args.output {
        Some(path) => Some(BufWriter::new(
            fs::File::create(path)
                .with_context(|| format!("create output file {}", path.display()))?,
        )),
        None => None,
    };

    for warmup_index in 0..args.warmup {
        let results =
            run_once(&args, &target_host, target_port, warmup_index).await?;
        let record = build_run_result(&args, &host, warmup_index, true, &results);
        emit_json(&record, &mut output)?;
    }

    let mut upload_runs = Vec::with_capacity(args.runs);
    let mut download_runs = Vec::with_capacity(args.runs);
    for run_index in 0..args.runs {
        let results = run_once(&args, &target_host, target_port, run_index).await?;
        let record = build_run_result(&args, &host, run_index, false, &results);
        upload_runs.push(record.upload_mbps);
        download_runs.push(record.download_mbps);
        emit_json(&record, &mut output)?;
    }

    let summary = Summary {
        schema_version: 1,
        record_type: "summary",
        unix_time_seconds: unix_time_seconds(),
        label: &args.label,
        transport: if args.socks5.is_some() {
            "socks5"
        } else {
            "direct"
        },
        target: &args.target,
        socks5: args.socks5.map(|address| address.to_string()),
        runs: args.runs,
        warmup_runs: args.warmup,
        concurrency: args.concurrency,
        upload_bytes_per_connection: args.upload_bytes,
        download_bytes_per_connection: args.download_bytes,
        buffer_size: args.buffer_size,
        full_verify: args.full_verify,
        upload_median_mbps: round(median(&upload_runs)),
        upload_p99_mbps: round(percentile(&upload_runs, 99.0)),
        upload_cv: round(coefficient_of_variation(&upload_runs)),
        download_median_mbps: round(median(&download_runs)),
        download_p99_mbps: round(percentile(&download_runs, 99.0)),
        download_cv: round(coefficient_of_variation(&download_runs)),
        host: &host,
    };
    emit_json(&summary, &mut output)?;
    if let Some(writer) = output.as_mut() {
        writer.flush()?;
    }
    if let Some(max_cv) = args.max_cv
        && (summary.upload_cv > max_cv || summary.download_cv > max_cv)
    {
        bail!(
            "benchmark is unstable: upload CV {:.4}, download CV {:.4}, limit {:.4}",
            summary.upload_cv,
            summary.download_cv,
            max_cv,
        );
    }
    Ok(())
}

fn validate_args(args: &Args) -> Result<()> {
    if args.concurrency == 0 {
        bail!("--concurrency must be greater than zero");
    }
    if args.runs == 0 {
        bail!("--runs must be greater than zero");
    }
    if args.buffer_size == 0 {
        bail!("--buffer-size must be greater than zero");
    }
    if args.worker_threads == 0 {
        bail!("--worker-threads must be greater than zero");
    }
    if args
        .max_cv
        .is_some_and(|value| !(0.0..=1.0).contains(&value))
    {
        bail!("--max-cv must be between 0 and 1");
    }
    if args.upload_bytes == 0 && args.download_bytes == 0 {
        bail!("at least one transfer direction must be non-zero");
    }
    Ok(())
}

async fn run_once(
    args: &Args,
    target_host: &str,
    target_port: u16,
    run_index: usize,
) -> Result<Vec<ConnectionResult>> {
    let upload_barrier = Arc::new(Barrier::new(args.concurrency + 1));
    let download_barrier = Arc::new(Barrier::new(args.concurrency + 1));
    let mut tasks = JoinSet::new();

    for connection_index in 0..args.concurrency {
        let target = args.target.clone();
        let target_host = target_host.to_owned();
        let socks5 = args.socks5;
        let upload_barrier = upload_barrier.clone();
        let download_barrier = download_barrier.clone();
        let upload_len = args.upload_bytes;
        let download_len = args.download_bytes;
        let buffer_size = args.buffer_size;
        let full_verify = args.full_verify;
        let timeout_duration = Duration::from_secs(args.timeout_secs);
        let seed = 0x4348_494d_4552_4100_u64
            ^ ((run_index as u64) << 32)
            ^ connection_index as u64;

        tasks.spawn(async move {
            timeout(
                timeout_duration,
                run_connection(
                    &target,
                    &target_host,
                    target_port,
                    socks5,
                    upload_len,
                    download_len,
                    buffer_size,
                    full_verify,
                    seed,
                    upload_barrier,
                    download_barrier,
                ),
            )
            .await
            .context("benchmark connection timed out")?
        });
    }

    upload_barrier.wait().await;
    download_barrier.wait().await;

    let mut results = Vec::with_capacity(args.concurrency);
    while let Some(result) = tasks.join_next().await {
        results.push(result.context("benchmark task panicked")??);
    }
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    target: &str,
    target_host: &str,
    target_port: u16,
    socks5: Option<SocketAddr>,
    upload_len: u64,
    download_len: u64,
    buffer_size: usize,
    full_verify: bool,
    seed: u64,
    upload_barrier: Arc<Barrier>,
    download_barrier: Arc<Barrier>,
) -> Result<ConnectionResult> {
    let mut stream = match socks5 {
        Some(proxy) => connect_via_socks5(proxy, target_host, target_port).await?,
        None => TcpStream::connect(target)
            .await
            .with_context(|| format!("connect benchmark target {target}"))?,
    };
    stream.set_nodelay(true)?;

    let request = Request {
        flags: if full_verify { FLAG_FULL_VERIFY } else { 0 },
        upload_len,
        download_len,
        seed,
    };
    let request_bytes = request.encode();
    debug_assert_eq!(request_bytes.len(), REQUEST_LEN);
    stream.write_all(&request_bytes).await?;

    upload_barrier.wait().await;
    let upload_started = Instant::now();
    send_pattern(&mut stream, upload_len, seed, buffer_size, full_verify).await?;
    stream.flush().await?;
    let mut ack_bytes = [0_u8; ACK_LEN];
    stream.read_exact(&mut ack_bytes).await?;
    let ack = Ack::decode(&ack_bytes)?;
    if ack.status != 0 {
        bail!(
            "benchmark target rejected upload with status {}",
            ack.status
        );
    }
    let upload_seconds = upload_started.elapsed().as_secs_f64();

    download_barrier.wait().await;
    let download_started = Instant::now();
    stream.write_all(&DOWNLOAD_READY).await?;
    stream.flush().await?;
    receive_pattern(
        &mut stream,
        download_len,
        seed ^ u64::MAX,
        buffer_size,
        full_verify,
    )
    .await?;
    let download_seconds = download_started.elapsed().as_secs_f64();

    Ok(ConnectionResult {
        upload_seconds,
        download_seconds,
    })
}

async fn send_pattern(
    stream: &mut TcpStream,
    length: u64,
    seed: u64,
    buffer_size: usize,
    full_verify: bool,
) -> Result<()> {
    let mut remaining = length;
    let mut buffer = vec![0_u8; buffer_size];
    let mut pattern = PatternStream::new(seed);
    if !full_verify {
        pattern.fill(&mut buffer);
    }
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer_size as u64))?;
        if full_verify {
            pattern.fill(&mut buffer[..count]);
        }
        stream.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    Ok(())
}

async fn receive_pattern(
    stream: &mut TcpStream,
    length: u64,
    seed: u64,
    buffer_size: usize,
    full_verify: bool,
) -> Result<()> {
    let mut remaining = length;
    let mut buffer = vec![0_u8; buffer_size];
    let mut verifier =
        full_verify.then(|| (PatternStream::new(seed), vec![0_u8; buffer_size]));
    while remaining > 0 {
        let count = usize::try_from(remaining.min(buffer_size as u64))?;
        stream.read_exact(&mut buffer[..count]).await?;
        if let Some((pattern, expected)) = verifier.as_mut()
            && !pattern.matches(&buffer[..count], &mut expected[..count])
        {
            bail!("download pattern verification failed");
        }
        remaining -= count as u64;
    }
    Ok(())
}

fn build_run_result<'a>(
    args: &'a Args,
    host: &'a HostMetadata,
    run_index: usize,
    warmup: bool,
    results: &[ConnectionResult],
) -> RunResult<'a> {
    let upload_seconds = results
        .iter()
        .map(|result| result.upload_seconds)
        .fold(0.0_f64, f64::max);
    let download_seconds = results
        .iter()
        .map(|result| result.download_seconds)
        .fold(0.0_f64, f64::max);
    let upload_connection_mbps: Vec<_> = results
        .iter()
        .map(|result| mbps(args.upload_bytes, result.upload_seconds))
        .collect();
    let download_connection_mbps: Vec<_> = results
        .iter()
        .map(|result| mbps(args.download_bytes, result.download_seconds))
        .collect();

    RunResult {
        schema_version: 1,
        record_type: "run",
        unix_time_seconds: unix_time_seconds(),
        label: &args.label,
        transport: if args.socks5.is_some() {
            "socks5"
        } else {
            "direct"
        },
        target: &args.target,
        socks5: args.socks5.map(|address| address.to_string()),
        run_index,
        warmup,
        concurrency: args.concurrency,
        upload_bytes_per_connection: args.upload_bytes,
        download_bytes_per_connection: args.download_bytes,
        buffer_size: args.buffer_size,
        full_verify: args.full_verify,
        upload_mbps: round(mbps(
            args.upload_bytes.saturating_mul(args.concurrency as u64),
            upload_seconds,
        )),
        download_mbps: round(mbps(
            args.download_bytes.saturating_mul(args.concurrency as u64),
            download_seconds,
        )),
        upload_connection_p50_mbps: round(median(&upload_connection_mbps)),
        upload_connection_p99_mbps: round(percentile(&upload_connection_mbps, 99.0)),
        download_connection_p50_mbps: round(median(&download_connection_mbps)),
        download_connection_p99_mbps: round(percentile(
            &download_connection_mbps,
            99.0,
        )),
        host,
    }
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .context("IPv6 target must use [address]:port")?;
        return Ok((host.to_owned(), port.parse()?));
    }
    let (host, port) = value
        .rsplit_once(':')
        .context("target must use host:port")?;
    if host.is_empty() {
        bail!("target host cannot be empty");
    }
    Ok((host.to_owned(), port.parse()?))
}

fn collect_host_metadata(repository: &PathBuf) -> Result<HostMetadata> {
    let hostname =
        command_output("hostname", &[]).unwrap_or_else(|| "unknown".to_owned());
    let kernel =
        command_output("uname", &["-srvm"]).unwrap_or_else(|| "unknown".to_owned());
    let cpu_model = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.strip_prefix("model name\t:")
                    .or_else(|| line.strip_prefix("Hardware\t:"))
                    .map(str::trim)
                    .map(ToOwned::to_owned)
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let logical_cpus = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(0);
    let cpu_affinity = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.strip_prefix("Cpus_allowed_list:")
                    .map(str::trim)
                    .map(ToOwned::to_owned)
            })
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let git_commit = git_output(repository, &["rev-parse", "HEAD"])
        .unwrap_or_else(|| "unknown".to_owned());
    let git_dirty = git_output(repository, &["status", "--porcelain"])
        .is_some_and(|output| !output.is_empty());
    let binary_blake3 = fs::read(std::env::current_exe()?)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .unwrap_or_else(|_| "unknown".to_owned());

    Ok(HostMetadata {
        hostname,
        kernel,
        cpu_model,
        logical_cpus,
        cpu_affinity,
        git_commit,
        git_dirty,
        binary_blake3,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    })
}

fn git_output(repository: &PathBuf, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn emit_json<T: Serialize>(
    record: &T,
    output: &mut Option<BufWriter<fs::File>>,
) -> Result<()> {
    let line = serde_json::to_string(record)?;
    println!("{line}");
    if let Some(writer) = output.as_mut() {
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn mbps(bytes: u64, seconds: f64) -> f64 {
    if bytes == 0 {
        return 0.0;
    }
    let seconds = seconds.max(f64::EPSILON);
    bytes as f64 * 8.0 / seconds / 1_000_000.0
}

fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_domain_targets() {
        assert_eq!(
            split_host_port("127.0.0.1:443").unwrap(),
            ("127.0.0.1".to_owned(), 443)
        );
        assert_eq!(
            split_host_port("example.com:8443").unwrap(),
            ("example.com".to_owned(), 8443)
        );
    }

    #[test]
    fn parses_bracketed_ipv6_target() {
        assert_eq!(
            split_host_port("[::1]:443").unwrap(),
            ("::1".to_owned(), 443)
        );
    }
}
