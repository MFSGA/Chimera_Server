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
    tls::{self, BenchIo, BoxedBenchIo},
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

    /// Continue measured runs until both --runs and this duration are satisfied.
    #[arg(long)]
    duration_secs: Option<u64>,

    /// Sample fd/RSS/thread counters from this process after every measured run.
    #[arg(long)]
    monitor_pid: Option<u32>,

    /// Wait before the final monitored-process snapshot to let connections and allocators settle.
    #[arg(long, default_value_t = 0)]
    cooldown_secs: u64,

    /// Fail when the monitored process ends with more than this many additional fds.
    #[arg(long)]
    max_fd_delta: Option<usize>,

    /// Fail when final monitored-process RSS grows by more than this many KiB.
    #[arg(long)]
    max_rss_delta_kib: Option<u64>,

    /// Emit one measured run record every N runs; the final run is always emitted.
    #[arg(long, default_value_t = 1)]
    emit_every_runs: usize,

    #[arg(long, default_value_t = 64 * 1024)]
    buffer_size: usize,

    #[arg(long)]
    full_verify: bool,

    #[arg(long)]
    inner_tls: bool,

    #[arg(long)]
    tcp_nodelay: bool,

    #[arg(long, default_value = "benchmark.local")]
    tls_server_name: String,

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

#[derive(Debug, Clone, Serialize)]
struct ProcessSnapshot {
    pid: u32,
    fd_count: usize,
    vm_rss_kib: Option<u64>,
    vm_hwm_kib: Option<u64>,
    threads: Option<u64>,
}

#[derive(Debug)]
struct ProcessMonitorAccumulator {
    start: ProcessSnapshot,
    end: ProcessSnapshot,
    samples: usize,
    max_fd_count: usize,
    max_vm_rss_kib: Option<u64>,
    max_vm_hwm_kib: Option<u64>,
    max_threads: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ProcessMonitorSummary {
    pid: u32,
    samples: usize,
    start_fd_count: usize,
    end_fd_count: usize,
    max_fd_count: usize,
    fd_delta: i64,
    start_vm_rss_kib: Option<u64>,
    end_vm_rss_kib: Option<u64>,
    max_vm_rss_kib: Option<u64>,
    vm_rss_delta_kib: Option<i64>,
    max_vm_hwm_kib: Option<u64>,
    max_threads: Option<u64>,
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
    inner_tls: bool,
    tcp_nodelay: bool,
    upload_mbps: f64,
    download_mbps: f64,
    upload_connection_p50_mbps: f64,
    upload_connection_p99_mbps: f64,
    download_connection_p50_mbps: f64,
    download_connection_p99_mbps: f64,
    soak_elapsed_seconds: Option<f64>,
    monitored_process: Option<ProcessSnapshot>,
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
    requested_duration_seconds: Option<u64>,
    cooldown_seconds: u64,
    max_fd_delta_allowed: Option<usize>,
    max_rss_delta_kib_allowed: Option<u64>,
    measured_elapsed_seconds: f64,
    completed_connections: usize,
    total_upload_bytes: u64,
    total_download_bytes: u64,
    concurrency: usize,
    upload_bytes_per_connection: u64,
    download_bytes_per_connection: u64,
    buffer_size: usize,
    full_verify: bool,
    inner_tls: bool,
    tcp_nodelay: bool,
    upload_median_mbps: f64,
    upload_p99_mbps: f64,
    upload_cv: f64,
    download_median_mbps: f64,
    download_p99_mbps: f64,
    download_cv: f64,
    monitored_process: Option<ProcessMonitorSummary>,
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
        let record =
            build_run_result(&args, &host, warmup_index, true, &results, None, None);
        emit_json(&record, &mut output)?;
    }

    let measured_started = Instant::now();
    let mut process_monitor = match args.monitor_pid {
        Some(pid) => {
            Some(ProcessMonitorAccumulator::new(read_process_snapshot(pid)?))
        }
        None => None,
    };

    let mut upload_runs = Vec::with_capacity(args.runs);
    let mut download_runs = Vec::with_capacity(args.runs);
    let mut run_index = 0_usize;
    while should_continue_measurement(
        run_index,
        args.runs,
        measured_started.elapsed(),
        args.duration_secs,
    ) {
        let results = run_once(&args, &target_host, target_port, run_index).await?;
        let monitored_process = match args.monitor_pid {
            Some(pid) => {
                let snapshot = read_process_snapshot(pid)?;
                if let Some(monitor) = process_monitor.as_mut() {
                    monitor.observe(&snapshot);
                }
                Some(snapshot)
            }
            None => None,
        };
        let record = build_run_result(
            &args,
            &host,
            run_index,
            false,
            &results,
            Some(round(measured_started.elapsed().as_secs_f64())),
            monitored_process,
        );
        upload_runs.push(record.upload_mbps);
        download_runs.push(record.download_mbps);
        let completed_runs = run_index.saturating_add(1);
        let final_run = !should_continue_measurement(
            completed_runs,
            args.runs,
            measured_started.elapsed(),
            args.duration_secs,
        );
        if run_index.is_multiple_of(args.emit_every_runs) || final_run {
            emit_json(&record, &mut output)?;
        }
        run_index = completed_runs;
    }

    let measured_elapsed_seconds = measured_started.elapsed().as_secs_f64();
    if args.cooldown_secs > 0 {
        tokio::time::sleep(Duration::from_secs(args.cooldown_secs)).await;
        if let (Some(pid), Some(monitor)) =
            (args.monitor_pid, process_monitor.as_mut())
        {
            monitor.observe(&read_process_snapshot(pid)?);
        }
    }
    let completed_connections = run_index.saturating_mul(args.concurrency);
    let completed_connections_u64 =
        u64::try_from(completed_connections).unwrap_or(u64::MAX);
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
        runs: run_index,
        warmup_runs: args.warmup,
        requested_duration_seconds: args.duration_secs,
        cooldown_seconds: args.cooldown_secs,
        max_fd_delta_allowed: args.max_fd_delta,
        max_rss_delta_kib_allowed: args.max_rss_delta_kib,
        measured_elapsed_seconds: round(measured_elapsed_seconds),
        completed_connections,
        total_upload_bytes: args
            .upload_bytes
            .saturating_mul(completed_connections_u64),
        total_download_bytes: args
            .download_bytes
            .saturating_mul(completed_connections_u64),
        concurrency: args.concurrency,
        upload_bytes_per_connection: args.upload_bytes,
        download_bytes_per_connection: args.download_bytes,
        buffer_size: args.buffer_size,
        full_verify: args.full_verify,
        inner_tls: args.inner_tls,
        tcp_nodelay: args.tcp_nodelay,
        upload_median_mbps: round(median(&upload_runs)),
        upload_p99_mbps: round(percentile(&upload_runs, 99.0)),
        upload_cv: round(coefficient_of_variation(&upload_runs)),
        download_median_mbps: round(median(&download_runs)),
        download_p99_mbps: round(percentile(&download_runs, 99.0)),
        download_cv: round(coefficient_of_variation(&download_runs)),
        monitored_process: process_monitor
            .as_ref()
            .map(ProcessMonitorAccumulator::summary),
        host: &host,
    };
    emit_json(&summary, &mut output)?;
    if let Some(writer) = output.as_mut() {
        writer.flush()?;
    }
    enforce_process_growth_limits(
        summary.monitored_process.as_ref(),
        args.max_fd_delta,
        args.max_rss_delta_kib,
    )?;
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
    if args.duration_secs == Some(0) {
        bail!("--duration-secs must be greater than zero");
    }
    if args.emit_every_runs == 0 {
        bail!("--emit-every-runs must be greater than zero");
    }
    if args.monitor_pid.is_none()
        && (args.cooldown_secs > 0
            || args.max_fd_delta.is_some()
            || args.max_rss_delta_kib.is_some())
    {
        bail!("--cooldown-secs and process growth limits require --monitor-pid");
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
        let inner_tls = args.inner_tls;
        let tcp_nodelay = args.tcp_nodelay;
        let tls_server_name = args.tls_server_name.clone();
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
                    inner_tls,
                    tcp_nodelay,
                    &tls_server_name,
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
    inner_tls: bool,
    tcp_nodelay: bool,
    tls_server_name: &str,
    seed: u64,
    upload_barrier: Arc<Barrier>,
    download_barrier: Arc<Barrier>,
) -> Result<ConnectionResult> {
    let setup = setup_connection(
        target,
        target_host,
        target_port,
        socks5,
        inner_tls,
        tcp_nodelay,
        tls_server_name,
    )
    .await;

    upload_barrier.wait().await;
    let mut stream = match setup {
        Ok(stream) => stream,
        Err(error) => {
            download_barrier.wait().await;
            return Err(error);
        }
    };

    let upload_result = async {
        let request = Request {
            flags: if full_verify { FLAG_FULL_VERIFY } else { 0 },
            upload_len,
            download_len,
            seed,
        };
        let request_bytes = request.encode();
        debug_assert_eq!(request_bytes.len(), REQUEST_LEN);
        stream.write_all(&request_bytes).await?;

        let upload_started = Instant::now();
        send_pattern(&mut *stream, upload_len, seed, buffer_size, full_verify)
            .await?;
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
        Ok::<_, anyhow::Error>(upload_started.elapsed().as_secs_f64())
    }
    .await;

    download_barrier.wait().await;
    let upload_seconds = upload_result?;

    let download_started = Instant::now();
    stream.write_all(&DOWNLOAD_READY).await?;
    stream.flush().await?;
    receive_pattern(
        &mut *stream,
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

async fn setup_connection(
    target: &str,
    target_host: &str,
    target_port: u16,
    socks5: Option<SocketAddr>,
    inner_tls: bool,
    tcp_nodelay: bool,
    tls_server_name: &str,
) -> Result<BoxedBenchIo> {
    let stream = match socks5 {
        Some(proxy) => {
            connect_via_socks5(proxy, target_host, target_port, tcp_nodelay).await?
        }
        None => TcpStream::connect(target)
            .await
            .with_context(|| format!("connect benchmark target {target}"))?,
    };
    stream.set_nodelay(tcp_nodelay)?;
    if inner_tls {
        tls::connect(stream, tls_server_name).await
    } else {
        Ok(tls::plain(stream))
    }
}

async fn send_pattern(
    stream: &mut dyn BenchIo,
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
    stream: &mut dyn BenchIo,
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
    soak_elapsed_seconds: Option<f64>,
    monitored_process: Option<ProcessSnapshot>,
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
        inner_tls: args.inner_tls,
        tcp_nodelay: args.tcp_nodelay,
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
        soak_elapsed_seconds,
        monitored_process,
        host,
    }
}

fn should_continue_measurement(
    completed_runs: usize,
    minimum_runs: usize,
    elapsed: Duration,
    duration_secs: Option<u64>,
) -> bool {
    completed_runs < minimum_runs
        || duration_secs
            .is_some_and(|seconds| elapsed < Duration::from_secs(seconds))
}

fn read_process_snapshot(pid: u32) -> Result<ProcessSnapshot> {
    let fd_path = format!("/proc/{pid}/fd");
    let fd_count = fs::read_dir(&fd_path)
        .with_context(|| format!("read monitored process fd directory {fd_path}"))?
        .try_fold(0_usize, |count, entry| {
            entry.map(|_| count.saturating_add(1))
        })?;
    let status_path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(&status_path)
        .with_context(|| format!("read monitored process status {status_path}"))?;

    Ok(ProcessSnapshot {
        pid,
        fd_count,
        vm_rss_kib: parse_status_number(&status, "VmRSS:"),
        vm_hwm_kib: parse_status_number(&status, "VmHWM:"),
        threads: parse_status_number(&status, "Threads:"),
    })
}

fn parse_status_number(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        line.strip_prefix(key)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

impl ProcessMonitorAccumulator {
    fn new(snapshot: ProcessSnapshot) -> Self {
        Self {
            start: snapshot.clone(),
            end: snapshot.clone(),
            samples: 1,
            max_fd_count: snapshot.fd_count,
            max_vm_rss_kib: snapshot.vm_rss_kib,
            max_vm_hwm_kib: snapshot.vm_hwm_kib,
            max_threads: snapshot.threads,
        }
    }

    fn observe(&mut self, snapshot: &ProcessSnapshot) {
        debug_assert_eq!(snapshot.pid, self.start.pid);
        self.end = snapshot.clone();
        self.samples = self.samples.saturating_add(1);
        self.max_fd_count = self.max_fd_count.max(snapshot.fd_count);
        self.max_vm_rss_kib = max_optional(self.max_vm_rss_kib, snapshot.vm_rss_kib);
        self.max_vm_hwm_kib = max_optional(self.max_vm_hwm_kib, snapshot.vm_hwm_kib);
        self.max_threads = max_optional(self.max_threads, snapshot.threads);
    }

    fn summary(&self) -> ProcessMonitorSummary {
        ProcessMonitorSummary {
            pid: self.start.pid,
            samples: self.samples,
            start_fd_count: self.start.fd_count,
            end_fd_count: self.end.fd_count,
            max_fd_count: self.max_fd_count,
            fd_delta: signed_usize_delta(self.end.fd_count, self.start.fd_count),
            start_vm_rss_kib: self.start.vm_rss_kib,
            end_vm_rss_kib: self.end.vm_rss_kib,
            max_vm_rss_kib: self.max_vm_rss_kib,
            vm_rss_delta_kib: signed_optional_delta(
                self.end.vm_rss_kib,
                self.start.vm_rss_kib,
            ),
            max_vm_hwm_kib: self.max_vm_hwm_kib,
            max_threads: self.max_threads,
        }
    }
}

fn max_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn signed_usize_delta(end: usize, start: usize) -> i64 {
    let end = i64::try_from(end).unwrap_or(i64::MAX);
    let start = i64::try_from(start).unwrap_or(i64::MAX);
    end.saturating_sub(start)
}

fn signed_optional_delta(end: Option<u64>, start: Option<u64>) -> Option<i64> {
    let (end, start) = (end?, start?);
    let end = i64::try_from(end).unwrap_or(i64::MAX);
    let start = i64::try_from(start).unwrap_or(i64::MAX);
    Some(end.saturating_sub(start))
}

fn enforce_process_growth_limits(
    monitor: Option<&ProcessMonitorSummary>,
    max_fd_delta: Option<usize>,
    max_rss_delta_kib: Option<u64>,
) -> Result<()> {
    let Some(monitor) = monitor else {
        return Ok(());
    };
    if let Some(limit) = max_fd_delta {
        let growth = usize::try_from(monitor.fd_delta.max(0)).unwrap_or(usize::MAX);
        if growth > limit {
            bail!("monitored process fd growth {growth} exceeds limit {limit}");
        }
    }
    if let Some(limit) = max_rss_delta_kib {
        let growth = monitor
            .vm_rss_delta_kib
            .and_then(|delta| u64::try_from(delta.max(0)).ok())
            .unwrap_or(0);
        if growth > limit {
            bail!(
                "monitored process RSS growth {growth} KiB exceeds limit {limit} KiB"
            );
        }
    }
    Ok(())
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
        writer.flush()?;
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

    #[test]
    fn duration_is_a_lower_bound_after_minimum_runs() {
        assert!(should_continue_measurement(
            0,
            2,
            Duration::from_secs(100),
            Some(10),
        ));
        assert!(should_continue_measurement(
            2,
            2,
            Duration::from_secs(9),
            Some(10),
        ));
        assert!(!should_continue_measurement(
            2,
            2,
            Duration::from_secs(10),
            Some(10),
        ));
        assert!(!should_continue_measurement(2, 2, Duration::ZERO, None,));
    }

    #[test]
    fn parses_linux_process_status_numbers() {
        let status =
            "Name:\ttest\nVmHWM:\t  4096 kB\nVmRSS:\t  3072 kB\nThreads:\t7\n";
        assert_eq!(parse_status_number(status, "VmHWM:"), Some(4096));
        assert_eq!(parse_status_number(status, "VmRSS:"), Some(3072));
        assert_eq!(parse_status_number(status, "Threads:"), Some(7));
        assert_eq!(parse_status_number(status, "Missing:"), None);
    }

    #[test]
    fn summarizes_process_growth_and_peaks() {
        let samples = [
            ProcessSnapshot {
                pid: 42,
                fd_count: 10,
                vm_rss_kib: Some(1000),
                vm_hwm_kib: Some(1200),
                threads: Some(2),
            },
            ProcessSnapshot {
                pid: 42,
                fd_count: 14,
                vm_rss_kib: Some(1600),
                vm_hwm_kib: Some(1700),
                threads: Some(4),
            },
            ProcessSnapshot {
                pid: 42,
                fd_count: 11,
                vm_rss_kib: Some(1100),
                vm_hwm_kib: Some(1700),
                threads: Some(3),
            },
        ];
        let mut monitor = ProcessMonitorAccumulator::new(samples[0].clone());
        monitor.observe(&samples[1]);
        monitor.observe(&samples[2]);
        let summary = monitor.summary();
        assert_eq!(summary.pid, 42);
        assert_eq!(summary.samples, 3);
        assert_eq!(summary.max_fd_count, 14);
        assert_eq!(summary.fd_delta, 1);
        assert_eq!(summary.max_vm_rss_kib, Some(1600));
        assert_eq!(summary.vm_rss_delta_kib, Some(100));
        assert_eq!(summary.max_vm_hwm_kib, Some(1700));
        assert_eq!(summary.max_threads, Some(4));
    }

    #[test]
    fn process_growth_limits_are_enforced_after_cooldown() {
        let mut summary = ProcessMonitorSummary {
            pid: 42,
            samples: 3,
            start_fd_count: 10,
            end_fd_count: 10,
            max_fd_count: 14,
            fd_delta: 0,
            start_vm_rss_kib: Some(1000),
            end_vm_rss_kib: Some(1100),
            max_vm_rss_kib: Some(1600),
            vm_rss_delta_kib: Some(100),
            max_vm_hwm_kib: Some(1700),
            max_threads: Some(4),
        };
        enforce_process_growth_limits(Some(&summary), Some(0), Some(100)).unwrap();

        summary.fd_delta = 2;
        assert!(
            enforce_process_growth_limits(Some(&summary), Some(1), None).is_err()
        );
        summary.fd_delta = -1;
        summary.vm_rss_delta_kib = Some(101);
        assert!(
            enforce_process_growth_limits(Some(&summary), None, Some(100)).is_err()
        );
        assert!(enforce_process_growth_limits(None, Some(0), Some(0)).is_ok());
    }

    #[test]
    fn reads_current_process_snapshot() {
        let snapshot = read_process_snapshot(std::process::id()).unwrap();
        assert_eq!(snapshot.pid, std::process::id());
        assert!(snapshot.fd_count > 0);
        assert!(snapshot.threads.is_some_and(|threads| threads > 0));
    }
}
