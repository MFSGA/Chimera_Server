#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp_asyncfd_pacing_probe requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io,
        net::{TcpListener, TcpStream},
        os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        sync::Arc,
        time::Instant,
    };

    use anyhow::{Result, bail};
    use chimera_perf::stats::{coefficient_of_variation, median};
    use clap::{Parser, ValueEnum};
    use serde::Serialize;
    use tokio::{
        io::unix::AsyncFd,
        io::{AsyncReadExt, AsyncWriteExt, Interest},
        sync::Barrier,
    };

    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const PATTERN_BYTE: u8 = 0x5a;

    #[derive(Debug, Parser)]
    #[command(about = "Concurrent AsyncFd TCP pacing probe for Brutal2 design work")]
    struct Args {
        #[arg(long, default_value_t = 1)]
        connections: usize,

        #[arg(long, default_value_t = 4)]
        worker_threads: usize,

        #[arg(long, default_value_t = 16 * 1024 * 1024_u64)]
        bytes_per_connection: u64,

        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,

        #[arg(long, default_value_t = 32 * 1024 * 1024_u64)]
        rate_bytes_per_sec: u64,

        #[arg(long)]
        unpaced: bool,

        #[arg(long)]
        second_rate_bytes_per_sec: Option<u64>,

        #[arg(long, value_delimiter = ',')]
        rate_updates_bytes_per_sec: Vec<u64>,

        #[arg(long)]
        notsent_lowat_bytes: Option<u32>,

        #[arg(long)]
        notsent_lowat_ms: Option<u32>,

        #[arg(long)]
        notsent_lowat_min_bytes: Option<u32>,

        #[arg(long)]
        notsent_lowat_max_bytes: Option<u32>,

        #[arg(long, default_value_t = 0.0)]
        notsent_lowat_update_threshold_percent: f64,

        #[arg(long)]
        notsent_lowat_gate_decreases_only: bool,

        #[arg(long)]
        adaptive_notsent_lowat_bytes: Option<u32>,

        #[arg(long, default_value_t = 128 * 1024)]
        pipe_size: usize,

        #[arg(long, value_enum, default_value_t = DestinationDrainMode::Single)]
        destination_drain_mode: DestinationDrainMode,

        #[arg(long, value_enum, default_value_t = SourceReadinessMode::Guarded)]
        source_readiness_mode: SourceReadinessMode,

        #[arg(long, default_value_t = 1)]
        warmup: usize,

        #[arg(long, default_value_t = 5)]
        runs: usize,

        #[arg(long)]
        sample_tcp_info: bool,

        #[arg(long)]
        sample_rate_decrease_recovery: bool,

        #[arg(long)]
        sample_rate_decrease_flight: bool,

        #[arg(long, default_value_t = 0)]
        sample_partial_notsent_every: u64,

        #[arg(long, default_value_t = 0)]
        sample_writable_wake_every: u64,

        #[arg(long)]
        verify: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    enum DestinationDrainMode {
        Single,
        TwoSplices,
        UntilWouldBlock,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    enum SourceReadinessMode {
        Guarded,
        TryFirst,
    }

    impl SourceReadinessMode {
        fn as_str(self) -> &'static str {
            match self {
                Self::Guarded => "guarded",
                Self::TryFirst => "try-first",
            }
        }
    }

    impl DestinationDrainMode {
        fn as_str(self) -> &'static str {
            match self {
                Self::Single => "single",
                Self::TwoSplices => "two-splices",
                Self::UntilWouldBlock => "until-would-block",
            }
        }

        fn max_splice_attempts(self) -> Option<usize> {
            match self {
                Self::Single => Some(1),
                Self::TwoSplices => Some(2),
                Self::UntilWouldBlock => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct Usage {
        cpu_seconds: f64,
        voluntary_context_switches: i64,
        involuntary_context_switches: i64,
    }

    #[derive(Debug, Clone, Copy)]
    struct TcpInfoSample {
        rtt_us: u32,
        unacked_bytes: u64,
        snd_cwnd_bytes: u64,
    }

    #[derive(Debug, Clone, Copy)]
    struct RateUpdate {
        after_bytes: u64,
        rate: u64,
        notsent_lowat: Option<u32>,
    }

    #[derive(Debug, Clone)]
    struct RelayOptions {
        requested_pipe_size: usize,
        destination_drain_mode: DestinationDrainMode,
        source_readiness_mode: SourceReadinessMode,
        initial_rate: u64,
        initial_notsent_lowat: Option<u32>,
        rate_updates: Arc<[RateUpdate]>,
        notsent_lowat_update_threshold_percent: f64,
        notsent_lowat_gate_decreases_only: bool,
        adaptive_notsent_lowat: Option<u32>,
        sample_tcp_info: bool,
        sample_rate_decrease_recovery: bool,
        sample_rate_decrease_flight: bool,
        sample_partial_notsent_every: u64,
        sample_writable_wake_every: u64,
    }

    #[derive(Debug, Clone, Copy)]
    struct RateDecreaseRecovery {
        elapsed_us: f64,
        forwarded_bytes: u64,
        would_blocks: u64,
        start_notsent_bytes: u32,
        target_notsent_bytes: u32,
    }

    #[derive(Debug, Clone, Copy)]
    struct RateDecreaseFlightSample {
        unsent_bytes: u32,
        unacked_bytes: u64,
        snd_cwnd_bytes: u64,
        new_rate_bdp_bytes: u64,
    }

    #[derive(Debug)]
    struct PendingRateDecreaseRecovery {
        started: Instant,
        transferred_at_start: u64,
        would_blocks: u64,
        start_notsent_bytes: u32,
        target_notsent_bytes: u32,
    }

    #[derive(Debug)]
    struct RelayStats {
        bytes: u64,
        elapsed_us: f64,
        pipe_capacity: usize,
        destination_ready_acquisitions: u64,
        destination_would_blocks: u64,
        source_ready_acquisitions: u64,
        source_try_first_successes: u64,
        source_would_blocks: u64,
        source_splice_successes: u64,
        source_splice_bytes: u64,
        source_partial_splices: u64,
        destination_splice_successes: u64,
        destination_splice_bytes: u64,
        destination_partial_splices: u64,
        destination_partial_notsent_samples: u64,
        destination_partial_notsent_bytes: u64,
        destination_partial_notsent_min: Option<u32>,
        destination_partial_notsent_max: Option<u32>,
        writable_wake_samples: u64,
        writable_wake_at_or_below_lowat: u64,
        writable_wake_notsent_bytes: u64,
        writable_wake_unacked_bytes: u64,
        writable_wake_cwnd_bytes: u64,
        notsent_bytes_at_rate_update: Option<u32>,
        tcp_info_at_rate_update: Option<TcpInfoSample>,
        notsent_bytes_at_lowat_restore: Option<u32>,
        adaptive_lowat_applied: bool,
        adaptive_lowat_restores: u64,
        pacing_updates: u64,
        notsent_lowat_updates: u64,
        rate_decrease_recoveries: Vec<RateDecreaseRecovery>,
        rate_decrease_flight_samples: Vec<RateDecreaseFlightSample>,
        incomplete_rate_decrease_recoveries: u64,
    }

    #[derive(Debug, Serialize)]
    struct RunRecord {
        schema_version: u32,
        record_type: &'static str,
        run_index: usize,
        warmup: bool,
        connections: usize,
        worker_threads: usize,
        bytes_per_connection: u64,
        total_bytes: u64,
        chunk_size: usize,
        pipe_size: usize,
        actual_pipe_capacity_min: usize,
        actual_pipe_capacity_max: usize,
        pipe_capacity_shortfall_connections: u64,
        unpaced: bool,
        destination_drain_mode: &'static str,
        source_readiness_mode: &'static str,
        requested_rate_bytes_per_sec: Option<u64>,
        second_rate_bytes_per_sec: Option<u64>,
        rate_updates_bytes_per_sec: Vec<u64>,
        requested_notsent_lowat_bytes: Option<u32>,
        requested_notsent_lowat_ms: Option<u32>,
        requested_notsent_lowat_min_bytes: Option<u32>,
        requested_notsent_lowat_max_bytes: Option<u32>,
        notsent_lowat_update_threshold_percent: f64,
        notsent_lowat_gate_decreases_only: bool,
        effective_initial_notsent_lowat_bytes: Option<u32>,
        effective_second_notsent_lowat_bytes: Option<u32>,
        adaptive_notsent_lowat_bytes: Option<u32>,
        sample_tcp_info: bool,
        sample_rate_decrease_recovery: bool,
        sample_rate_decrease_flight: bool,
        sample_partial_notsent_every: u64,
        sample_writable_wake_every: u64,
        destination_ready_acquisitions_total: u64,
        destination_ready_acquisitions_per_connection: f64,
        relay_elapsed_us_median: f64,
        relay_elapsed_us_max: f64,
        relay_elapsed_max_to_median_ratio: f64,
        destination_would_blocks_total: u64,
        destination_would_blocks_per_connection: f64,
        source_ready_acquisitions_total: u64,
        source_ready_acquisitions_per_connection: f64,
        source_try_first_successes_total: u64,
        source_try_first_successes_per_connection: f64,
        source_would_blocks_total: u64,
        source_splice_successes_total: u64,
        source_splice_bytes_per_success: f64,
        source_partial_splices_total: u64,
        destination_splice_successes_total: u64,
        destination_splice_bytes_per_success: f64,
        destination_partial_splices_total: u64,
        destination_partial_notsent_samples_total: u64,
        destination_partial_notsent_bytes_mean: Option<f64>,
        destination_partial_notsent_min: Option<u32>,
        destination_partial_notsent_max: Option<u32>,
        writable_wake_samples_total: u64,
        writable_wake_at_or_below_lowat_ratio: Option<f64>,
        writable_wake_notsent_bytes_mean: Option<f64>,
        writable_wake_unacked_bytes_mean: Option<f64>,
        writable_wake_cwnd_bytes_mean: Option<f64>,
        writer_elapsed_us_median: f64,
        writer_elapsed_us_max: f64,
        writer_elapsed_max_to_median_ratio: f64,
        sink_elapsed_us_median: f64,
        sink_elapsed_us_max: f64,
        sink_elapsed_max_to_median_ratio: f64,
        notsent_bytes_at_rate_update_median: Option<f64>,
        tcp_rtt_us_at_rate_update_median: Option<f64>,
        tcp_unacked_bytes_at_rate_update_median: Option<f64>,
        tcp_snd_cwnd_bytes_at_rate_update_median: Option<f64>,
        notsent_bytes_at_lowat_restore_median: Option<f64>,
        adaptive_lowat_applied_total: u64,
        adaptive_lowat_restores_total: u64,
        pacing_updates_total: u64,
        notsent_lowat_updates_total: u64,
        rate_decrease_recoveries_total: u64,
        rate_decrease_flight_samples_total: u64,
        rate_decrease_flight_unsent_bytes_median: Option<f64>,
        rate_decrease_flight_unacked_bytes_median: Option<f64>,
        rate_decrease_flight_cwnd_bytes_median: Option<f64>,
        rate_decrease_flight_bdp_bytes_median: Option<f64>,
        rate_decrease_flight_admitted_to_bdp_ratio_median: Option<f64>,
        rate_decrease_flight_unacked_to_bdp_ratio_median: Option<f64>,
        incomplete_rate_decrease_recoveries_total: u64,
        rate_decrease_recovery_elapsed_us_median: Option<f64>,
        rate_decrease_recovery_forwarded_bytes_median: Option<f64>,
        rate_decrease_recovery_would_blocks_median: Option<f64>,
        rate_decrease_recovery_start_notsent_bytes_median: Option<f64>,
        rate_decrease_recovery_target_notsent_bytes_median: Option<f64>,
        elapsed_seconds: f64,
        aggregate_throughput_gbps: f64,
        per_connection_rate_ratio: Option<f64>,
        cpu_seconds: f64,
        cpu_seconds_per_gib: f64,
        voluntary_context_switches: i64,
        involuntary_context_switches: i64,
    }

    #[derive(Debug, Serialize)]
    struct Summary {
        schema_version: u32,
        record_type: &'static str,
        connections: usize,
        worker_threads: usize,
        runs: usize,
        warmup_runs: usize,
        bytes_per_connection: u64,
        chunk_size: usize,
        pipe_size: usize,
        actual_pipe_capacity_min: usize,
        actual_pipe_capacity_max: usize,
        pipe_capacity_shortfall_connections_median: f64,
        unpaced: bool,
        destination_drain_mode: &'static str,
        source_readiness_mode: &'static str,
        requested_rate_bytes_per_sec: Option<u64>,
        second_rate_bytes_per_sec: Option<u64>,
        rate_updates_bytes_per_sec: Vec<u64>,
        requested_notsent_lowat_bytes: Option<u32>,
        requested_notsent_lowat_ms: Option<u32>,
        requested_notsent_lowat_min_bytes: Option<u32>,
        requested_notsent_lowat_max_bytes: Option<u32>,
        notsent_lowat_update_threshold_percent: f64,
        notsent_lowat_gate_decreases_only: bool,
        effective_initial_notsent_lowat_bytes: Option<u32>,
        effective_second_notsent_lowat_bytes: Option<u32>,
        adaptive_notsent_lowat_bytes: Option<u32>,
        sample_tcp_info: bool,
        sample_rate_decrease_recovery: bool,
        sample_rate_decrease_flight: bool,
        sample_partial_notsent_every: u64,
        sample_writable_wake_every: u64,
        aggregate_throughput_median_gbps: f64,
        throughput_cv: f64,
        per_connection_rate_ratio_median: Option<f64>,
        cpu_seconds_per_gib_median: f64,
        context_switches_median: f64,
        destination_ready_acquisitions_per_connection_median: f64,
        destination_would_blocks_per_connection_median: f64,
        source_ready_acquisitions_per_connection_median: f64,
        source_try_first_successes_per_connection_median: f64,
        relay_elapsed_us_median: f64,
        relay_elapsed_us_max_median: f64,
        relay_elapsed_max_to_median_ratio_median: f64,
        writer_elapsed_us_median: f64,
        writer_elapsed_us_max_median: f64,
        writer_elapsed_max_to_median_ratio_median: f64,
        sink_elapsed_us_median: f64,
        sink_elapsed_us_max_median: f64,
        sink_elapsed_max_to_median_ratio_median: f64,
        notsent_bytes_at_rate_update_median: Option<f64>,
        tcp_rtt_us_at_rate_update_median: Option<f64>,
        tcp_unacked_bytes_at_rate_update_median: Option<f64>,
        tcp_snd_cwnd_bytes_at_rate_update_median: Option<f64>,
        notsent_bytes_at_lowat_restore_median: Option<f64>,
        adaptive_lowat_applied_per_connection_median: f64,
        adaptive_lowat_restores_per_connection_median: f64,
        pacing_updates_per_connection_median: f64,
        notsent_lowat_updates_per_connection_median: f64,
        rate_decrease_recoveries_per_connection_median: f64,
        rate_decrease_flight_samples_per_connection_median: f64,
        rate_decrease_flight_unsent_bytes_median: Option<f64>,
        rate_decrease_flight_unacked_bytes_median: Option<f64>,
        rate_decrease_flight_cwnd_bytes_median: Option<f64>,
        rate_decrease_flight_bdp_bytes_median: Option<f64>,
        rate_decrease_flight_admitted_to_bdp_ratio_median: Option<f64>,
        rate_decrease_flight_unacked_to_bdp_ratio_median: Option<f64>,
        incomplete_rate_decrease_recoveries_per_connection_median: f64,
        rate_decrease_recovery_elapsed_us_median: Option<f64>,
        rate_decrease_recovery_forwarded_bytes_median: Option<f64>,
        rate_decrease_recovery_would_blocks_median: Option<f64>,
        rate_decrease_recovery_start_notsent_bytes_median: Option<f64>,
        rate_decrease_recovery_target_notsent_bytes_median: Option<f64>,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        let (initial_notsent_lowat, second_notsent_lowat) =
            resolved_static_lowats(&args)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.worker_threads)
            .enable_io()
            .build()?;

        for run_index in 0..args.warmup {
            let record = runtime.block_on(run_once(&args, run_index, true))?;
            println!("{}", serde_json::to_string(&record)?);
        }

        let mut throughput = Vec::with_capacity(args.runs);
        let mut ratios = Vec::with_capacity(args.runs);
        let mut actual_pipe_capacity_min = Vec::with_capacity(args.runs);
        let mut actual_pipe_capacity_max = Vec::with_capacity(args.runs);
        let mut pipe_capacity_shortfalls = Vec::with_capacity(args.runs);
        let mut cpu_per_gib = Vec::with_capacity(args.runs);
        let mut context_switches = Vec::with_capacity(args.runs);
        let mut destination_ready_acquisitions = Vec::with_capacity(args.runs);
        let mut destination_blocks = Vec::with_capacity(args.runs);
        let mut source_ready_acquisitions = Vec::with_capacity(args.runs);
        let mut source_try_first_successes = Vec::with_capacity(args.runs);
        let mut relay_elapsed_us = Vec::with_capacity(args.runs);
        let mut relay_elapsed_us_max = Vec::with_capacity(args.runs);
        let mut relay_elapsed_ratios = Vec::with_capacity(args.runs);
        let mut writer_elapsed_us = Vec::with_capacity(args.runs);
        let mut writer_elapsed_us_max = Vec::with_capacity(args.runs);
        let mut writer_elapsed_ratios = Vec::with_capacity(args.runs);
        let mut sink_elapsed_us = Vec::with_capacity(args.runs);
        let mut sink_elapsed_us_max = Vec::with_capacity(args.runs);
        let mut sink_elapsed_ratios = Vec::with_capacity(args.runs);
        let mut notsent = Vec::new();
        let mut tcp_rtt = Vec::new();
        let mut tcp_unacked = Vec::new();
        let mut tcp_cwnd = Vec::new();
        let mut restore_notsent = Vec::new();
        let mut adaptive_applied = Vec::with_capacity(args.runs);
        let mut adaptive_restores = Vec::with_capacity(args.runs);
        let mut pacing_updates = Vec::with_capacity(args.runs);
        let mut notsent_lowat_updates = Vec::with_capacity(args.runs);
        let mut rate_decrease_recoveries = Vec::with_capacity(args.runs);
        let mut rate_decrease_flight_samples = Vec::with_capacity(args.runs);
        let mut rate_decrease_flight_unsent = Vec::new();
        let mut rate_decrease_flight_unacked = Vec::new();
        let mut rate_decrease_flight_cwnd = Vec::new();
        let mut rate_decrease_flight_bdp = Vec::new();
        let mut rate_decrease_flight_admitted_ratio = Vec::new();
        let mut rate_decrease_flight_unacked_ratio = Vec::new();
        let mut incomplete_rate_decrease_recoveries = Vec::with_capacity(args.runs);
        let mut recovery_elapsed_us = Vec::new();
        let mut recovery_forwarded_bytes = Vec::new();
        let mut recovery_would_blocks = Vec::new();
        let mut recovery_start_notsent = Vec::new();
        let mut recovery_target_notsent = Vec::new();
        for run_index in 0..args.runs {
            let record = runtime.block_on(run_once(&args, run_index, false))?;
            throughput.push(record.aggregate_throughput_gbps);
            if let Some(ratio) = record.per_connection_rate_ratio {
                ratios.push(ratio);
            }
            actual_pipe_capacity_min.push(record.actual_pipe_capacity_min);
            actual_pipe_capacity_max.push(record.actual_pipe_capacity_max);
            pipe_capacity_shortfalls
                .push(record.pipe_capacity_shortfall_connections as f64);
            cpu_per_gib.push(record.cpu_seconds_per_gib);
            context_switches.push(
                (record.voluntary_context_switches
                    + record.involuntary_context_switches) as f64,
            );
            destination_ready_acquisitions
                .push(record.destination_ready_acquisitions_per_connection);
            destination_blocks.push(record.destination_would_blocks_per_connection);
            source_ready_acquisitions
                .push(record.source_ready_acquisitions_per_connection);
            source_try_first_successes
                .push(record.source_try_first_successes_per_connection);
            relay_elapsed_us.push(record.relay_elapsed_us_median);
            relay_elapsed_us_max.push(record.relay_elapsed_us_max);
            relay_elapsed_ratios.push(record.relay_elapsed_max_to_median_ratio);
            writer_elapsed_us.push(record.writer_elapsed_us_median);
            writer_elapsed_us_max.push(record.writer_elapsed_us_max);
            writer_elapsed_ratios.push(record.writer_elapsed_max_to_median_ratio);
            sink_elapsed_us.push(record.sink_elapsed_us_median);
            sink_elapsed_us_max.push(record.sink_elapsed_us_max);
            sink_elapsed_ratios.push(record.sink_elapsed_max_to_median_ratio);
            if let Some(bytes) = record.notsent_bytes_at_rate_update_median {
                notsent.push(bytes);
            }
            if let Some(rtt_us) = record.tcp_rtt_us_at_rate_update_median {
                tcp_rtt.push(rtt_us);
            }
            if let Some(bytes) = record.tcp_unacked_bytes_at_rate_update_median {
                tcp_unacked.push(bytes);
            }
            if let Some(bytes) = record.tcp_snd_cwnd_bytes_at_rate_update_median {
                tcp_cwnd.push(bytes);
            }
            if let Some(bytes) = record.notsent_bytes_at_lowat_restore_median {
                restore_notsent.push(bytes);
            }
            adaptive_applied.push(
                record.adaptive_lowat_applied_total as f64 / args.connections as f64,
            );
            adaptive_restores.push(
                record.adaptive_lowat_restores_total as f64
                    / args.connections as f64,
            );
            pacing_updates
                .push(record.pacing_updates_total as f64 / args.connections as f64);
            notsent_lowat_updates.push(
                record.notsent_lowat_updates_total as f64 / args.connections as f64,
            );
            rate_decrease_recoveries.push(
                record.rate_decrease_recoveries_total as f64
                    / args.connections as f64,
            );
            rate_decrease_flight_samples.push(
                record.rate_decrease_flight_samples_total as f64
                    / args.connections as f64,
            );
            if let Some(value) = record.rate_decrease_flight_unsent_bytes_median {
                rate_decrease_flight_unsent.push(value);
            }
            if let Some(value) = record.rate_decrease_flight_unacked_bytes_median {
                rate_decrease_flight_unacked.push(value);
            }
            if let Some(value) = record.rate_decrease_flight_cwnd_bytes_median {
                rate_decrease_flight_cwnd.push(value);
            }
            if let Some(value) = record.rate_decrease_flight_bdp_bytes_median {
                rate_decrease_flight_bdp.push(value);
            }
            if let Some(value) =
                record.rate_decrease_flight_admitted_to_bdp_ratio_median
            {
                rate_decrease_flight_admitted_ratio.push(value);
            }
            if let Some(value) =
                record.rate_decrease_flight_unacked_to_bdp_ratio_median
            {
                rate_decrease_flight_unacked_ratio.push(value);
            }
            incomplete_rate_decrease_recoveries.push(
                record.incomplete_rate_decrease_recoveries_total as f64
                    / args.connections as f64,
            );
            if let Some(value) = record.rate_decrease_recovery_elapsed_us_median {
                recovery_elapsed_us.push(value);
            }
            if let Some(value) = record.rate_decrease_recovery_forwarded_bytes_median
            {
                recovery_forwarded_bytes.push(value);
            }
            if let Some(value) = record.rate_decrease_recovery_would_blocks_median {
                recovery_would_blocks.push(value);
            }
            if let Some(value) =
                record.rate_decrease_recovery_start_notsent_bytes_median
            {
                recovery_start_notsent.push(value);
            }
            if let Some(value) =
                record.rate_decrease_recovery_target_notsent_bytes_median
            {
                recovery_target_notsent.push(value);
            }
            println!("{}", serde_json::to_string(&record)?);
        }

        println!(
            "{}",
            serde_json::to_string(&Summary {
                schema_version: 1,
                record_type: "summary",
                connections: args.connections,
                worker_threads: args.worker_threads,
                runs: args.runs,
                warmup_runs: args.warmup,
                bytes_per_connection: args.bytes_per_connection,
                chunk_size: args.chunk_size,
                pipe_size: args.pipe_size,
                actual_pipe_capacity_min: *actual_pipe_capacity_min
                    .iter()
                    .min()
                    .expect("at least one measured run"),
                actual_pipe_capacity_max: *actual_pipe_capacity_max
                    .iter()
                    .max()
                    .expect("at least one measured run"),
                pipe_capacity_shortfall_connections_median: round(median(
                    &pipe_capacity_shortfalls,
                )),
                unpaced: args.unpaced,
                destination_drain_mode: args.destination_drain_mode.as_str(),
                source_readiness_mode: args.source_readiness_mode.as_str(),
                requested_rate_bytes_per_sec: (!args.unpaced)
                    .then_some(args.rate_bytes_per_sec),
                second_rate_bytes_per_sec: args.second_rate_bytes_per_sec,
                rate_updates_bytes_per_sec: args.rate_updates_bytes_per_sec.clone(),
                requested_notsent_lowat_bytes: args.notsent_lowat_bytes,
                requested_notsent_lowat_ms: args.notsent_lowat_ms,
                requested_notsent_lowat_min_bytes: args.notsent_lowat_min_bytes,
                requested_notsent_lowat_max_bytes: args.notsent_lowat_max_bytes,
                notsent_lowat_update_threshold_percent: args
                    .notsent_lowat_update_threshold_percent,
                notsent_lowat_gate_decreases_only: args
                    .notsent_lowat_gate_decreases_only,
                effective_initial_notsent_lowat_bytes: initial_notsent_lowat,
                effective_second_notsent_lowat_bytes: second_notsent_lowat,
                adaptive_notsent_lowat_bytes: args.adaptive_notsent_lowat_bytes,
                sample_tcp_info: args.sample_tcp_info,
                sample_rate_decrease_recovery: args.sample_rate_decrease_recovery,
                sample_rate_decrease_flight: args.sample_rate_decrease_flight,
                sample_partial_notsent_every: args.sample_partial_notsent_every,
                sample_writable_wake_every: args.sample_writable_wake_every,
                aggregate_throughput_median_gbps: round(median(&throughput)),
                throughput_cv: round(coefficient_of_variation(&throughput)),
                per_connection_rate_ratio_median: (!ratios.is_empty())
                    .then(|| round(median(&ratios))),
                cpu_seconds_per_gib_median: round(median(&cpu_per_gib)),
                context_switches_median: round(median(&context_switches)),
                destination_ready_acquisitions_per_connection_median: round(median(
                    &destination_ready_acquisitions,
                )),
                destination_would_blocks_per_connection_median: round(median(
                    &destination_blocks
                )),
                source_ready_acquisitions_per_connection_median: round(median(
                    &source_ready_acquisitions,
                )),
                source_try_first_successes_per_connection_median: round(median(
                    &source_try_first_successes,
                )),
                relay_elapsed_us_median: round(median(&relay_elapsed_us)),
                relay_elapsed_us_max_median: round(median(&relay_elapsed_us_max)),
                relay_elapsed_max_to_median_ratio_median: round(median(
                    &relay_elapsed_ratios,
                )),
                writer_elapsed_us_median: round(median(&writer_elapsed_us)),
                writer_elapsed_us_max_median: round(median(&writer_elapsed_us_max)),
                writer_elapsed_max_to_median_ratio_median: round(median(
                    &writer_elapsed_ratios,
                )),
                sink_elapsed_us_median: round(median(&sink_elapsed_us)),
                sink_elapsed_us_max_median: round(median(&sink_elapsed_us_max)),
                sink_elapsed_max_to_median_ratio_median: round(median(
                    &sink_elapsed_ratios,
                )),
                notsent_bytes_at_rate_update_median: (!notsent.is_empty())
                    .then(|| round(median(&notsent))),
                tcp_rtt_us_at_rate_update_median: (!tcp_rtt.is_empty())
                    .then(|| round(median(&tcp_rtt))),
                tcp_unacked_bytes_at_rate_update_median: (!tcp_unacked.is_empty())
                    .then(|| round(median(&tcp_unacked))),
                tcp_snd_cwnd_bytes_at_rate_update_median: (!tcp_cwnd.is_empty())
                    .then(|| round(median(&tcp_cwnd))),
                notsent_bytes_at_lowat_restore_median: (!restore_notsent.is_empty())
                    .then(|| round(median(&restore_notsent))),
                adaptive_lowat_applied_per_connection_median: round(median(
                    &adaptive_applied,
                )),
                adaptive_lowat_restores_per_connection_median: round(median(
                    &adaptive_restores,
                )),
                pacing_updates_per_connection_median: round(
                    median(&pacing_updates,)
                ),
                notsent_lowat_updates_per_connection_median: round(median(
                    &notsent_lowat_updates,
                )),
                rate_decrease_recoveries_per_connection_median: round(median(
                    &rate_decrease_recoveries,
                )),
                rate_decrease_flight_samples_per_connection_median: round(median(
                    &rate_decrease_flight_samples,
                )),
                rate_decrease_flight_unsent_bytes_median:
                    (!rate_decrease_flight_unsent.is_empty())
                        .then(|| round(median(&rate_decrease_flight_unsent))),
                rate_decrease_flight_unacked_bytes_median:
                    (!rate_decrease_flight_unacked.is_empty())
                        .then(|| round(median(&rate_decrease_flight_unacked))),
                rate_decrease_flight_cwnd_bytes_median: (!rate_decrease_flight_cwnd
                    .is_empty())
                .then(|| round(median(&rate_decrease_flight_cwnd))),
                rate_decrease_flight_bdp_bytes_median: (!rate_decrease_flight_bdp
                    .is_empty())
                .then(|| round(median(&rate_decrease_flight_bdp))),
                rate_decrease_flight_admitted_to_bdp_ratio_median:
                    (!rate_decrease_flight_admitted_ratio.is_empty())
                        .then(|| round(median(&rate_decrease_flight_admitted_ratio))),
                rate_decrease_flight_unacked_to_bdp_ratio_median:
                    (!rate_decrease_flight_unacked_ratio.is_empty())
                        .then(|| round(median(&rate_decrease_flight_unacked_ratio))),
                incomplete_rate_decrease_recoveries_per_connection_median: round(
                    median(&incomplete_rate_decrease_recoveries,)
                ),
                rate_decrease_recovery_elapsed_us_median: (!recovery_elapsed_us
                    .is_empty())
                .then(|| round(median(&recovery_elapsed_us))),
                rate_decrease_recovery_forwarded_bytes_median:
                    (!recovery_forwarded_bytes.is_empty())
                        .then(|| round(median(&recovery_forwarded_bytes))),
                rate_decrease_recovery_would_blocks_median: (!recovery_would_blocks
                    .is_empty())
                .then(|| round(median(&recovery_would_blocks))),
                rate_decrease_recovery_start_notsent_bytes_median:
                    (!recovery_start_notsent.is_empty())
                        .then(|| round(median(&recovery_start_notsent))),
                rate_decrease_recovery_target_notsent_bytes_median:
                    (!recovery_target_notsent.is_empty())
                        .then(|| round(median(&recovery_target_notsent))),
            })?
        );
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        if args.connections == 0 {
            bail!("--connections must be greater than zero");
        }
        if args.worker_threads == 0 {
            bail!("--worker-threads must be greater than zero");
        }
        if args.bytes_per_connection == 0 {
            bail!("--bytes-per-connection must be greater than zero");
        }
        if args.chunk_size == 0 {
            bail!("--chunk-size must be greater than zero");
        }
        if args.pipe_size == 0 || args.pipe_size > i32::MAX as usize {
            bail!("--pipe-size must be between 1 and i32::MAX");
        }
        if args.rate_bytes_per_sec == 0
            || args.second_rate_bytes_per_sec == Some(0)
            || args.rate_updates_bytes_per_sec.contains(&0)
        {
            bail!("pacing rates must be greater than zero");
        }
        if args.destination_drain_mode != DestinationDrainMode::Single
            && (args.second_rate_bytes_per_sec.is_some()
                || !args.rate_updates_bytes_per_sec.is_empty()
                || args.notsent_lowat_update_threshold_percent != 0.0
                || args.notsent_lowat_gate_decreases_only
                || args.adaptive_notsent_lowat_bytes.is_some()
                || args.sample_tcp_info
                || args.sample_rate_decrease_recovery
                || args.sample_rate_decrease_flight)
        {
            bail!(
                "non-single --destination-drain-mode supports only steady pacing with optional static TCP_NOTSENT_LOWAT, or --unpaced"
            );
        }
        if args.unpaced
            && (args.second_rate_bytes_per_sec.is_some()
                || !args.rate_updates_bytes_per_sec.is_empty()
                || args.notsent_lowat_bytes.is_some()
                || args.notsent_lowat_ms.is_some()
                || args.notsent_lowat_min_bytes.is_some()
                || args.notsent_lowat_max_bytes.is_some()
                || args.notsent_lowat_update_threshold_percent != 0.0
                || args.notsent_lowat_gate_decreases_only
                || args.adaptive_notsent_lowat_bytes.is_some()
                || args.sample_tcp_info
                || args.sample_rate_decrease_recovery
                || args.sample_rate_decrease_flight)
        {
            bail!(
                "--unpaced cannot be combined with pacing, low-water, or rate-update options"
            );
        }
        if args.second_rate_bytes_per_sec.is_some()
            && !args.rate_updates_bytes_per_sec.is_empty()
        {
            bail!(
                "--second-rate-bytes-per-sec and --rate-updates-bytes-per-sec are mutually exclusive"
            );
        }
        if args.rate_updates_bytes_per_sec.len() > 64 {
            bail!("--rate-updates-bytes-per-sec supports at most 64 updates");
        }
        let lowat_modes = usize::from(args.notsent_lowat_bytes.is_some())
            + usize::from(args.notsent_lowat_ms.is_some())
            + usize::from(args.adaptive_notsent_lowat_bytes.is_some());
        if lowat_modes > 1 {
            bail!(
                "--notsent-lowat-bytes, --notsent-lowat-ms, and --adaptive-notsent-lowat-bytes are mutually exclusive"
            );
        }
        if args.notsent_lowat_ms == Some(0) {
            bail!("--notsent-lowat-ms must be greater than zero");
        }
        if !args.notsent_lowat_update_threshold_percent.is_finite()
            || !(0.0..=100.0).contains(&args.notsent_lowat_update_threshold_percent)
        {
            bail!(
                "--notsent-lowat-update-threshold-percent must be between 0 and 100"
            );
        }
        if (args.notsent_lowat_update_threshold_percent > 0.0
            || args.notsent_lowat_gate_decreases_only)
            && args.notsent_lowat_ms.is_none()
        {
            bail!("low-water publication gating requires --notsent-lowat-ms");
        }
        if (args.notsent_lowat_min_bytes.is_some()
            || args.notsent_lowat_max_bytes.is_some())
            && args.notsent_lowat_ms.is_none()
        {
            bail!(
                "--notsent-lowat-min-bytes and --notsent-lowat-max-bytes require --notsent-lowat-ms"
            );
        }
        if args.sample_rate_decrease_recovery && args.notsent_lowat_ms.is_none() {
            bail!("--sample-rate-decrease-recovery requires --notsent-lowat-ms");
        }
        if args.sample_rate_decrease_flight {
            let mut previous = args.rate_bytes_per_sec;
            let has_decrease =
                requested_rate_updates(args).into_iter().any(|rate| {
                    let decreased = rate < previous;
                    previous = rate;
                    decreased
                });
            if !has_decrease {
                bail!(
                    "--sample-rate-decrease-flight requires at least one pacing-rate decrease"
                );
            }
        }
        if args.sample_partial_notsent_every > 0
            && (args.unpaced
                || args.destination_drain_mode != DestinationDrainMode::Single
                || (args.notsent_lowat_bytes.is_none()
                    && args.notsent_lowat_ms.is_none()))
        {
            bail!(
                "--sample-partial-notsent-every requires paced single-drain mode with static TCP_NOTSENT_LOWAT"
            );
        }
        if args.sample_writable_wake_every > 0
            && (args.unpaced
                || args.destination_drain_mode != DestinationDrainMode::Single
                || (args.notsent_lowat_bytes.is_none()
                    && args.notsent_lowat_ms.is_none()))
        {
            bail!(
                "--sample-writable-wake-every requires paced single-drain mode with static TCP_NOTSENT_LOWAT"
            );
        }
        if args.notsent_lowat_min_bytes == Some(0)
            || args.notsent_lowat_max_bytes == Some(0)
        {
            bail!("bounded TCP_NOTSENT_LOWAT values must be greater than zero");
        }
        if let (Some(minimum), Some(maximum)) =
            (args.notsent_lowat_min_bytes, args.notsent_lowat_max_bytes)
            && minimum > maximum
        {
            bail!(
                "--notsent-lowat-min-bytes cannot exceed --notsent-lowat-max-bytes"
            );
        }
        let _ = resolved_static_lowats(args)?;
        if args.adaptive_notsent_lowat_bytes.is_some() {
            if !args.rate_updates_bytes_per_sec.is_empty() {
                bail!(
                    "--adaptive-notsent-lowat-bytes does not support --rate-updates-bytes-per-sec"
                );
            }
            let Some(second_rate) = args.second_rate_bytes_per_sec else {
                bail!(
                    "--adaptive-notsent-lowat-bytes requires --second-rate-bytes-per-sec"
                );
            };
            if second_rate >= args.rate_bytes_per_sec {
                bail!(
                    "--adaptive-notsent-lowat-bytes requires the second pacing rate to be lower"
                );
            }
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        Ok(())
    }

    fn resolved_static_lowats(args: &Args) -> Result<(Option<u32>, Option<u32>)> {
        if let Some(bytes) = args.notsent_lowat_bytes {
            return Ok((Some(bytes), args.second_rate_bytes_per_sec.map(|_| bytes)));
        }
        let Some(milliseconds) = args.notsent_lowat_ms else {
            return Ok((None, None));
        };
        let initial = queue_time_lowat_bytes(
            args.rate_bytes_per_sec,
            milliseconds,
            args.notsent_lowat_min_bytes,
            args.notsent_lowat_max_bytes,
        )?;
        let second = args
            .second_rate_bytes_per_sec
            .map(|rate| {
                queue_time_lowat_bytes(
                    rate,
                    milliseconds,
                    args.notsent_lowat_min_bytes,
                    args.notsent_lowat_max_bytes,
                )
            })
            .transpose()?;
        Ok((Some(initial), second))
    }

    fn queue_time_lowat_bytes(
        rate_bytes_per_sec: u64,
        milliseconds: u32,
        minimum: Option<u32>,
        maximum: Option<u32>,
    ) -> Result<u32> {
        let mut bytes = (u128::from(rate_bytes_per_sec) * u128::from(milliseconds)
            / 1_000)
            .max(1);
        if let Some(minimum) = minimum {
            bytes = bytes.max(u128::from(minimum));
        }
        if let Some(maximum) = maximum {
            bytes = bytes.min(u128::from(maximum));
        }
        u32::try_from(bytes).map_err(|_| {
            anyhow::anyhow!(
                "rate {rate_bytes_per_sec} B/s with {milliseconds} ms queue time exceeds TCP_NOTSENT_LOWAT u32 range"
            )
        })
    }

    fn requested_rate_updates(args: &Args) -> Vec<u64> {
        if let Some(second) = args.second_rate_bytes_per_sec {
            vec![second]
        } else {
            args.rate_updates_bytes_per_sec.clone()
        }
    }

    fn build_rate_updates(args: &Args) -> Result<Vec<RateUpdate>> {
        let rates = requested_rate_updates(args);
        if rates.is_empty() {
            return Ok(Vec::new());
        }
        let phases = rates.len() as u64 + 1;
        let mut updates = Vec::with_capacity(rates.len());
        for (index, rate) in rates.into_iter().enumerate() {
            let after_bytes =
                args.bytes_per_connection.saturating_mul(index as u64 + 1) / phases;
            let notsent_lowat = match args.notsent_lowat_ms {
                Some(milliseconds) => Some(queue_time_lowat_bytes(
                    rate,
                    milliseconds,
                    args.notsent_lowat_min_bytes,
                    args.notsent_lowat_max_bytes,
                )?),
                None => None,
            };
            updates.push(RateUpdate {
                after_bytes,
                rate,
                notsent_lowat,
            });
        }
        Ok(updates)
    }

    fn should_publish_lowat(
        last_published: u32,
        candidate: u32,
        threshold_percent: f64,
        gate_decreases_only: bool,
    ) -> bool {
        if candidate == last_published {
            return false;
        }
        if gate_decreases_only && candidate > last_published {
            return true;
        }
        let delta = last_published.abs_diff(candidate) as f64;
        delta * 100.0 / last_published as f64 >= threshold_percent
    }

    async fn run_once(
        args: &Args,
        run_index: usize,
        warmup: bool,
    ) -> Result<RunRecord> {
        let (initial_notsent_lowat, second_notsent_lowat) =
            resolved_static_lowats(args)?;
        let rate_updates: Arc<[RateUpdate]> = build_rate_updates(args)?.into();
        let barrier = Arc::new(Barrier::new(args.connections * 3 + 1));
        let mut writers = Vec::with_capacity(args.connections);
        let mut relays = Vec::with_capacity(args.connections);
        let mut sinks = Vec::with_capacity(args.connections);

        for _ in 0..args.connections {
            let (writer, relay_source) = tcp_pair()?;
            let (relay_destination, sink) = tcp_pair()?;
            for stream in [&writer, &relay_source, &relay_destination, &sink] {
                stream.set_nodelay(true)?;
                stream.set_nonblocking(true)?;
            }

            let source =
                Arc::new(AsyncFd::new(duplicate_fd(relay_source.as_raw_fd())?)?);
            let destination = Arc::new(AsyncFd::new(duplicate_fd(
                relay_destination.as_raw_fd(),
            )?)?);
            if !args.unpaced {
                set_max_pacing_rate(
                    destination.get_ref().as_raw_fd(),
                    args.rate_bytes_per_sec,
                )?;
            }
            if let Some(lowat) = initial_notsent_lowat {
                set_tcp_notsent_lowat(destination.get_ref().as_raw_fd(), lowat)?;
            }
            drop(relay_source);
            drop(relay_destination);

            let writer = tokio::net::TcpStream::from_std(writer)?;
            let sink = tokio::net::TcpStream::from_std(sink)?;
            let writer_barrier = Arc::clone(&barrier);
            let sink_barrier = Arc::clone(&barrier);
            let relay_barrier = Arc::clone(&barrier);
            let bytes = args.bytes_per_connection;
            let chunk_size = args.chunk_size;
            let verify = args.verify;
            let relay_options = RelayOptions {
                requested_pipe_size: args.pipe_size,
                destination_drain_mode: args.destination_drain_mode,
                source_readiness_mode: args.source_readiness_mode,
                initial_rate: args.rate_bytes_per_sec,
                initial_notsent_lowat,
                rate_updates: Arc::clone(&rate_updates),
                notsent_lowat_update_threshold_percent: args
                    .notsent_lowat_update_threshold_percent,
                notsent_lowat_gate_decreases_only: args
                    .notsent_lowat_gate_decreases_only,
                adaptive_notsent_lowat: args.adaptive_notsent_lowat_bytes,
                sample_tcp_info: args.sample_tcp_info,
                sample_rate_decrease_recovery: args.sample_rate_decrease_recovery,
                sample_rate_decrease_flight: args.sample_rate_decrease_flight,
                sample_partial_notsent_every: args.sample_partial_notsent_every,
                sample_writable_wake_every: args.sample_writable_wake_every,
            };

            writers.push(tokio::spawn(async move {
                write_payload(writer, writer_barrier, bytes, chunk_size).await
            }));
            sinks.push(tokio::spawn(async move {
                read_payload(sink, sink_barrier, bytes, chunk_size, verify).await
            }));
            relays.push(tokio::spawn(async move {
                splice_relay(source, destination, relay_barrier, relay_options).await
            }));
        }

        let usage_before = usage()?;
        let started = Instant::now();
        barrier.wait().await;

        let mut writer_elapsed_us = Vec::with_capacity(args.connections);
        for writer in writers {
            writer_elapsed_us.push(
                writer
                    .await
                    .map_err(|_| anyhow::anyhow!("writer task panicked"))??,
            );
        }

        let mut relay_stats = Vec::with_capacity(args.connections);
        for relay in relays {
            relay_stats.push(
                relay
                    .await
                    .map_err(|_| anyhow::anyhow!("relay task panicked"))??,
            );
        }
        let mut sink_elapsed_us = Vec::with_capacity(args.connections);
        for sink in sinks {
            sink_elapsed_us.push(
                sink.await
                    .map_err(|_| anyhow::anyhow!("sink task panicked"))??,
            );
        }
        let elapsed = started.elapsed().as_secs_f64();
        let usage_after = usage()?;

        let total_bytes = args
            .bytes_per_connection
            .checked_mul(args.connections as u64)
            .ok_or_else(|| {
                anyhow::anyhow!("total benchmark bytes overflowed u64")
            })?;
        if relay_stats
            .iter()
            .any(|stats| stats.bytes != args.bytes_per_connection)
        {
            bail!("one or more relays transferred an unexpected byte count");
        }
        let actual_pipe_capacity_min = relay_stats
            .iter()
            .map(|stats| stats.pipe_capacity)
            .min()
            .expect("at least one relay");
        let actual_pipe_capacity_max = relay_stats
            .iter()
            .map(|stats| stats.pipe_capacity)
            .max()
            .expect("at least one relay");
        let pipe_capacity_shortfall_connections = relay_stats
            .iter()
            .filter(|stats| stats.pipe_capacity < args.pipe_size)
            .count() as u64;
        let destination_ready_acquisitions_total = relay_stats
            .iter()
            .map(|stats| stats.destination_ready_acquisitions)
            .sum::<u64>();
        let destination_would_blocks_total = relay_stats
            .iter()
            .map(|stats| stats.destination_would_blocks)
            .sum::<u64>();
        let source_ready_acquisitions_total = relay_stats
            .iter()
            .map(|stats| stats.source_ready_acquisitions)
            .sum::<u64>();
        let source_try_first_successes_total = relay_stats
            .iter()
            .map(|stats| stats.source_try_first_successes)
            .sum::<u64>();
        let relay_elapsed_us = relay_stats
            .iter()
            .map(|stats| stats.elapsed_us)
            .collect::<Vec<_>>();
        let relay_elapsed_us_median = median(&relay_elapsed_us);
        let relay_elapsed_us_max = relay_elapsed_us
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let writer_elapsed_us_median = median(&writer_elapsed_us);
        let writer_elapsed_us_max = writer_elapsed_us
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let sink_elapsed_us_median = median(&sink_elapsed_us);
        let sink_elapsed_us_max = sink_elapsed_us
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let source_would_blocks_total = relay_stats
            .iter()
            .map(|stats| stats.source_would_blocks)
            .sum::<u64>();
        let source_splice_successes_total = relay_stats
            .iter()
            .map(|stats| stats.source_splice_successes)
            .sum::<u64>();
        let source_splice_bytes_total = relay_stats
            .iter()
            .map(|stats| stats.source_splice_bytes)
            .sum::<u64>();
        let source_partial_splices_total = relay_stats
            .iter()
            .map(|stats| stats.source_partial_splices)
            .sum::<u64>();
        let destination_splice_successes_total = relay_stats
            .iter()
            .map(|stats| stats.destination_splice_successes)
            .sum::<u64>();
        let destination_splice_bytes_total = relay_stats
            .iter()
            .map(|stats| stats.destination_splice_bytes)
            .sum::<u64>();
        let destination_partial_splices_total = relay_stats
            .iter()
            .map(|stats| stats.destination_partial_splices)
            .sum::<u64>();
        let destination_partial_notsent_samples_total = relay_stats
            .iter()
            .map(|stats| stats.destination_partial_notsent_samples)
            .sum::<u64>();
        let destination_partial_notsent_bytes_total = relay_stats
            .iter()
            .map(|stats| stats.destination_partial_notsent_bytes)
            .sum::<u64>();
        let destination_partial_notsent_min = relay_stats
            .iter()
            .filter_map(|stats| stats.destination_partial_notsent_min)
            .min();
        let destination_partial_notsent_max = relay_stats
            .iter()
            .filter_map(|stats| stats.destination_partial_notsent_max)
            .max();
        let writable_wake_samples_total = relay_stats
            .iter()
            .map(|stats| stats.writable_wake_samples)
            .sum::<u64>();
        let writable_wake_at_or_below_lowat_total = relay_stats
            .iter()
            .map(|stats| stats.writable_wake_at_or_below_lowat)
            .sum::<u64>();
        let writable_wake_notsent_bytes_total = relay_stats
            .iter()
            .map(|stats| stats.writable_wake_notsent_bytes)
            .sum::<u64>();
        let writable_wake_unacked_bytes_total = relay_stats
            .iter()
            .map(|stats| stats.writable_wake_unacked_bytes)
            .sum::<u64>();
        let writable_wake_cwnd_bytes_total = relay_stats
            .iter()
            .map(|stats| stats.writable_wake_cwnd_bytes)
            .sum::<u64>();
        let notsent = relay_stats
            .iter()
            .filter_map(|stats| stats.notsent_bytes_at_rate_update.map(f64::from))
            .collect::<Vec<_>>();
        let tcp_rtt = relay_stats
            .iter()
            .filter_map(|stats| {
                stats.tcp_info_at_rate_update.map(|info| info.rtt_us as f64)
            })
            .collect::<Vec<_>>();
        let tcp_unacked = relay_stats
            .iter()
            .filter_map(|stats| {
                stats
                    .tcp_info_at_rate_update
                    .map(|info| info.unacked_bytes as f64)
            })
            .collect::<Vec<_>>();
        let tcp_cwnd = relay_stats
            .iter()
            .filter_map(|stats| {
                stats
                    .tcp_info_at_rate_update
                    .map(|info| info.snd_cwnd_bytes as f64)
            })
            .collect::<Vec<_>>();
        let restore_notsent = relay_stats
            .iter()
            .filter_map(|stats| stats.notsent_bytes_at_lowat_restore.map(f64::from))
            .collect::<Vec<_>>();
        let adaptive_lowat_applied_total = relay_stats
            .iter()
            .filter(|stats| stats.adaptive_lowat_applied)
            .count() as u64;
        let adaptive_lowat_restores_total = relay_stats
            .iter()
            .map(|stats| stats.adaptive_lowat_restores)
            .sum::<u64>();
        let pacing_updates_total = relay_stats
            .iter()
            .map(|stats| stats.pacing_updates)
            .sum::<u64>();
        let notsent_lowat_updates_total = relay_stats
            .iter()
            .map(|stats| stats.notsent_lowat_updates)
            .sum::<u64>();
        let rate_decrease_recoveries_total = relay_stats
            .iter()
            .map(|stats| stats.rate_decrease_recoveries.len() as u64)
            .sum::<u64>();
        let incomplete_rate_decrease_recoveries_total = relay_stats
            .iter()
            .map(|stats| stats.incomplete_rate_decrease_recoveries)
            .sum::<u64>();
        let rate_decrease_recoveries = relay_stats
            .iter()
            .flat_map(|stats| stats.rate_decrease_recoveries.iter().copied())
            .collect::<Vec<_>>();
        let rate_decrease_flight_samples = relay_stats
            .iter()
            .flat_map(|stats| stats.rate_decrease_flight_samples.iter().copied())
            .collect::<Vec<_>>();
        let flight_unsent = rate_decrease_flight_samples
            .iter()
            .map(|sample| f64::from(sample.unsent_bytes))
            .collect::<Vec<_>>();
        let flight_unacked = rate_decrease_flight_samples
            .iter()
            .map(|sample| sample.unacked_bytes as f64)
            .collect::<Vec<_>>();
        let flight_cwnd = rate_decrease_flight_samples
            .iter()
            .map(|sample| sample.snd_cwnd_bytes as f64)
            .collect::<Vec<_>>();
        let flight_bdp = rate_decrease_flight_samples
            .iter()
            .map(|sample| sample.new_rate_bdp_bytes as f64)
            .collect::<Vec<_>>();
        let flight_admitted_ratio = rate_decrease_flight_samples
            .iter()
            .map(|sample| {
                (u64::from(sample.unsent_bytes) + sample.unacked_bytes) as f64
                    / sample.new_rate_bdp_bytes as f64
            })
            .collect::<Vec<_>>();
        let flight_unacked_ratio = rate_decrease_flight_samples
            .iter()
            .map(|sample| {
                sample.unacked_bytes as f64 / sample.new_rate_bdp_bytes as f64
            })
            .collect::<Vec<_>>();
        let recovery_elapsed_us = rate_decrease_recoveries
            .iter()
            .map(|sample| sample.elapsed_us)
            .collect::<Vec<_>>();
        let recovery_forwarded_bytes = rate_decrease_recoveries
            .iter()
            .map(|sample| sample.forwarded_bytes as f64)
            .collect::<Vec<_>>();
        let recovery_would_blocks = rate_decrease_recoveries
            .iter()
            .map(|sample| sample.would_blocks as f64)
            .collect::<Vec<_>>();
        let recovery_start_notsent = rate_decrease_recoveries
            .iter()
            .map(|sample| sample.start_notsent_bytes as f64)
            .collect::<Vec<_>>();
        let recovery_target_notsent = rate_decrease_recoveries
            .iter()
            .map(|sample| sample.target_notsent_bytes as f64)
            .collect::<Vec<_>>();
        let expected_rate = (!args.unpaced).then(|| effective_requested_rate(args));
        let per_connection_observed_rate =
            args.bytes_per_connection as f64 / elapsed;
        let cpu_seconds = usage_after.cpu_seconds - usage_before.cpu_seconds;

        Ok(RunRecord {
            schema_version: 1,
            record_type: "run",
            run_index,
            warmup,
            connections: args.connections,
            worker_threads: args.worker_threads,
            bytes_per_connection: args.bytes_per_connection,
            total_bytes,
            chunk_size: args.chunk_size,
            pipe_size: args.pipe_size,
            actual_pipe_capacity_min,
            actual_pipe_capacity_max,
            pipe_capacity_shortfall_connections,
            unpaced: args.unpaced,
            destination_drain_mode: args.destination_drain_mode.as_str(),
            source_readiness_mode: args.source_readiness_mode.as_str(),
            requested_rate_bytes_per_sec: (!args.unpaced)
                .then_some(args.rate_bytes_per_sec),
            second_rate_bytes_per_sec: args.second_rate_bytes_per_sec,
            rate_updates_bytes_per_sec: args.rate_updates_bytes_per_sec.clone(),
            requested_notsent_lowat_bytes: args.notsent_lowat_bytes,
            requested_notsent_lowat_ms: args.notsent_lowat_ms,
            requested_notsent_lowat_min_bytes: args.notsent_lowat_min_bytes,
            requested_notsent_lowat_max_bytes: args.notsent_lowat_max_bytes,
            notsent_lowat_update_threshold_percent: args
                .notsent_lowat_update_threshold_percent,
            notsent_lowat_gate_decreases_only: args
                .notsent_lowat_gate_decreases_only,
            effective_initial_notsent_lowat_bytes: initial_notsent_lowat,
            effective_second_notsent_lowat_bytes: second_notsent_lowat,
            adaptive_notsent_lowat_bytes: args.adaptive_notsent_lowat_bytes,
            sample_tcp_info: args.sample_tcp_info,
            sample_rate_decrease_recovery: args.sample_rate_decrease_recovery,
            sample_rate_decrease_flight: args.sample_rate_decrease_flight,
            sample_partial_notsent_every: args.sample_partial_notsent_every,
            sample_writable_wake_every: args.sample_writable_wake_every,
            destination_ready_acquisitions_total,
            destination_ready_acquisitions_per_connection: round(
                destination_ready_acquisitions_total as f64
                    / args.connections as f64,
            ),
            destination_would_blocks_total,
            destination_would_blocks_per_connection: round(
                destination_would_blocks_total as f64 / args.connections as f64,
            ),
            source_ready_acquisitions_total,
            source_ready_acquisitions_per_connection: round(
                source_ready_acquisitions_total as f64 / args.connections as f64,
            ),
            source_try_first_successes_total,
            source_try_first_successes_per_connection: round(
                source_try_first_successes_total as f64 / args.connections as f64,
            ),
            relay_elapsed_us_median: round(relay_elapsed_us_median),
            relay_elapsed_us_max: round(relay_elapsed_us_max),
            relay_elapsed_max_to_median_ratio: round(
                relay_elapsed_us_max / relay_elapsed_us_median,
            ),
            source_would_blocks_total,
            source_splice_successes_total,
            source_splice_bytes_per_success: round(
                source_splice_bytes_total as f64
                    / source_splice_successes_total as f64,
            ),
            source_partial_splices_total,
            destination_splice_successes_total,
            destination_splice_bytes_per_success: round(
                destination_splice_bytes_total as f64
                    / destination_splice_successes_total as f64,
            ),
            destination_partial_splices_total,
            destination_partial_notsent_samples_total,
            destination_partial_notsent_bytes_mean:
                (destination_partial_notsent_samples_total > 0).then(|| {
                    round(
                        destination_partial_notsent_bytes_total as f64
                            / destination_partial_notsent_samples_total as f64,
                    )
                }),
            destination_partial_notsent_min,
            destination_partial_notsent_max,
            writable_wake_samples_total,
            writable_wake_at_or_below_lowat_ratio: (writable_wake_samples_total > 0)
                .then(|| {
                    round(
                        writable_wake_at_or_below_lowat_total as f64
                            / writable_wake_samples_total as f64,
                    )
                }),
            writable_wake_notsent_bytes_mean: (writable_wake_samples_total > 0)
                .then(|| {
                    round(
                        writable_wake_notsent_bytes_total as f64
                            / writable_wake_samples_total as f64,
                    )
                }),
            writable_wake_unacked_bytes_mean: (writable_wake_samples_total > 0)
                .then(|| {
                    round(
                        writable_wake_unacked_bytes_total as f64
                            / writable_wake_samples_total as f64,
                    )
                }),
            writable_wake_cwnd_bytes_mean: (writable_wake_samples_total > 0).then(
                || {
                    round(
                        writable_wake_cwnd_bytes_total as f64
                            / writable_wake_samples_total as f64,
                    )
                },
            ),
            writer_elapsed_us_median: round(writer_elapsed_us_median),
            writer_elapsed_us_max: round(writer_elapsed_us_max),
            writer_elapsed_max_to_median_ratio: round(
                writer_elapsed_us_max / writer_elapsed_us_median,
            ),
            sink_elapsed_us_median: round(sink_elapsed_us_median),
            sink_elapsed_us_max: round(sink_elapsed_us_max),
            sink_elapsed_max_to_median_ratio: round(
                sink_elapsed_us_max / sink_elapsed_us_median,
            ),
            notsent_bytes_at_rate_update_median: (!notsent.is_empty())
                .then(|| round(median(&notsent))),
            tcp_rtt_us_at_rate_update_median: (!tcp_rtt.is_empty())
                .then(|| round(median(&tcp_rtt))),
            tcp_unacked_bytes_at_rate_update_median: (!tcp_unacked.is_empty())
                .then(|| round(median(&tcp_unacked))),
            tcp_snd_cwnd_bytes_at_rate_update_median: (!tcp_cwnd.is_empty())
                .then(|| round(median(&tcp_cwnd))),
            notsent_bytes_at_lowat_restore_median: (!restore_notsent.is_empty())
                .then(|| round(median(&restore_notsent))),
            adaptive_lowat_applied_total,
            adaptive_lowat_restores_total,
            pacing_updates_total,
            notsent_lowat_updates_total,
            rate_decrease_recoveries_total,
            rate_decrease_flight_samples_total: rate_decrease_flight_samples.len()
                as u64,
            rate_decrease_flight_unsent_bytes_median: (!flight_unsent.is_empty())
                .then(|| round(median(&flight_unsent))),
            rate_decrease_flight_unacked_bytes_median: (!flight_unacked.is_empty())
                .then(|| round(median(&flight_unacked))),
            rate_decrease_flight_cwnd_bytes_median: (!flight_cwnd.is_empty())
                .then(|| round(median(&flight_cwnd))),
            rate_decrease_flight_bdp_bytes_median: (!flight_bdp.is_empty())
                .then(|| round(median(&flight_bdp))),
            rate_decrease_flight_admitted_to_bdp_ratio_median:
                (!flight_admitted_ratio.is_empty())
                    .then(|| round(median(&flight_admitted_ratio))),
            rate_decrease_flight_unacked_to_bdp_ratio_median:
                (!flight_unacked_ratio.is_empty())
                    .then(|| round(median(&flight_unacked_ratio))),
            incomplete_rate_decrease_recoveries_total,
            rate_decrease_recovery_elapsed_us_median: (!recovery_elapsed_us
                .is_empty())
            .then(|| round(median(&recovery_elapsed_us))),
            rate_decrease_recovery_forwarded_bytes_median:
                (!recovery_forwarded_bytes.is_empty())
                    .then(|| round(median(&recovery_forwarded_bytes))),
            rate_decrease_recovery_would_blocks_median: (!recovery_would_blocks
                .is_empty())
            .then(|| round(median(&recovery_would_blocks))),
            rate_decrease_recovery_start_notsent_bytes_median:
                (!recovery_start_notsent.is_empty())
                    .then(|| round(median(&recovery_start_notsent))),
            rate_decrease_recovery_target_notsent_bytes_median:
                (!recovery_target_notsent.is_empty())
                    .then(|| round(median(&recovery_target_notsent))),
            elapsed_seconds: round(elapsed),
            aggregate_throughput_gbps: round(
                total_bytes as f64 * 8.0 / elapsed / 1e9,
            ),
            per_connection_rate_ratio: expected_rate
                .map(|expected| round(per_connection_observed_rate / expected)),
            cpu_seconds: round(cpu_seconds),
            cpu_seconds_per_gib: round(cpu_seconds / (total_bytes as f64 / GIB)),
            voluntary_context_switches: usage_after.voluntary_context_switches
                - usage_before.voluntary_context_switches,
            involuntary_context_switches: usage_after.involuntary_context_switches
                - usage_before.involuntary_context_switches,
        })
    }

    async fn write_payload(
        mut stream: tokio::net::TcpStream,
        barrier: Arc<Barrier>,
        bytes: u64,
        chunk_size: usize,
    ) -> io::Result<f64> {
        let buffer = vec![PATTERN_BYTE; chunk_size];
        barrier.wait().await;
        let started = Instant::now();
        let mut written = 0_u64;
        while written < bytes {
            let count = usize::try_from((bytes - written).min(chunk_size as u64))
                .expect("chunk size fits usize");
            stream.write_all(&buffer[..count]).await?;
            written += count as u64;
        }
        stream.shutdown().await?;
        Ok(started.elapsed().as_secs_f64() * 1e6)
    }

    async fn read_payload(
        mut stream: tokio::net::TcpStream,
        barrier: Arc<Barrier>,
        expected_bytes: u64,
        chunk_size: usize,
        verify: bool,
    ) -> io::Result<f64> {
        let mut buffer = vec![0_u8; chunk_size];
        barrier.wait().await;
        let started = Instant::now();
        let mut received = 0_u64;
        while received < expected_bytes {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            if verify && buffer[..count].iter().any(|byte| *byte != PATTERN_BYTE) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "asyncfd pacing payload verification failed",
                ));
            }
            received += count as u64;
        }
        if received == expected_bytes {
            Ok(started.elapsed().as_secs_f64() * 1e6)
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("sink received {received} bytes, expected {expected_bytes}"),
            ))
        }
    }

    async fn splice_relay(
        source: Arc<AsyncFd<OwnedFd>>,
        destination: Arc<AsyncFd<OwnedFd>>,
        barrier: Arc<Barrier>,
        options: RelayOptions,
    ) -> io::Result<RelayStats> {
        let (pipe_read, pipe_write, pipe_capacity) =
            nonblocking_pipe(options.requested_pipe_size)?;
        let mut pending = 0_usize;
        let mut transferred = 0_u64;
        let mut destination_ready_acquisitions = 0_u64;
        let mut destination_would_blocks = 0_u64;
        let mut source_ready_acquisitions = 0_u64;
        let mut source_try_first_successes = 0_u64;
        let mut source_would_blocks = 0_u64;
        let mut source_splice_successes = 0_u64;
        let mut source_splice_bytes = 0_u64;
        let mut source_partial_splices = 0_u64;
        let mut destination_splice_successes = 0_u64;
        let mut destination_splice_bytes = 0_u64;
        let mut destination_partial_splices = 0_u64;
        let mut destination_partial_notsent_samples = 0_u64;
        let mut destination_partial_notsent_bytes = 0_u64;
        let mut destination_partial_notsent_min = None;
        let mut destination_partial_notsent_max = None;
        let mut writable_wake_samples = 0_u64;
        let mut writable_wake_at_or_below_lowat = 0_u64;
        let mut writable_wake_notsent_bytes = 0_u64;
        let mut writable_wake_unacked_bytes = 0_u64;
        let mut writable_wake_cwnd_bytes = 0_u64;
        let mut writable_wakes_after_block = 0_u64;
        let mut sample_next_writable_wake = false;
        let mut notsent_bytes_at_rate_update = None;
        let mut tcp_info_at_rate_update = None;
        let mut notsent_bytes_at_lowat_restore = None;
        let mut adaptive_lowat_applied = false;
        let mut adaptive_lowat_active = false;
        let mut adaptive_lowat_observed_block = false;
        let mut adaptive_lowat_restores = 0_u64;
        let mut pacing_updates = 0_u64;
        let mut notsent_lowat_updates = 0_u64;
        let mut next_rate_update = 0_usize;
        let mut current_rate = options.initial_rate;
        let mut last_published_lowat = options.initial_notsent_lowat;
        let mut active_rate_decrease_recovery: Option<PendingRateDecreaseRecovery> =
            None;
        let mut rate_decrease_recoveries = Vec::new();
        let mut rate_decrease_flight_samples = Vec::new();
        let mut incomplete_rate_decrease_recoveries = 0_u64;
        barrier.wait().await;
        let relay_started = Instant::now();

        loop {
            if pending > 0 {
                let pipe_read_fd = pipe_read.as_raw_fd();
                let mut writable = destination.writable().await?;
                destination_ready_acquisitions =
                    destination_ready_acquisitions.saturating_add(1);
                if sample_next_writable_wake {
                    writable_wakes_after_block =
                        writable_wakes_after_block.saturating_add(1);
                    if options.sample_writable_wake_every > 0
                        && writable_wakes_after_block
                            .is_multiple_of(options.sample_writable_wake_every)
                    {
                        let destination_fd = destination.get_ref().as_raw_fd();
                        let queued = get_notsent_bytes(destination_fd)?;
                        let tcp_info = get_tcp_info(destination_fd)?;
                        writable_wake_samples =
                            writable_wake_samples.saturating_add(1);
                        writable_wake_notsent_bytes = writable_wake_notsent_bytes
                            .saturating_add(u64::from(queued));
                        writable_wake_unacked_bytes = writable_wake_unacked_bytes
                            .saturating_add(tcp_info.unacked_bytes);
                        writable_wake_cwnd_bytes = writable_wake_cwnd_bytes
                            .saturating_add(tcp_info.snd_cwnd_bytes);
                        if last_published_lowat.is_some_and(|lowat| queued <= lowat)
                        {
                            writable_wake_at_or_below_lowat =
                                writable_wake_at_or_below_lowat.saturating_add(1);
                        }
                    }
                    sample_next_writable_wake = false;
                }
                if options.destination_drain_mode != DestinationDrainMode::Single {
                    let max_splice_attempts =
                        options.destination_drain_mode.max_splice_attempts();
                    let mut splice_attempts = 0_usize;
                    loop {
                        match writable.try_io(|destination| {
                            splice_once(
                                pipe_read_fd,
                                destination.get_ref().as_raw_fd(),
                                pending,
                            )
                        }) {
                            Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                            Ok(Ok(written)) => {
                                destination_splice_successes =
                                    destination_splice_successes.saturating_add(1);
                                destination_splice_bytes = destination_splice_bytes
                                    .saturating_add(written as u64);
                                if written < pending {
                                    destination_partial_splices =
                                        destination_partial_splices
                                            .saturating_add(1);
                                }
                                pending -= written;
                                transferred =
                                    transferred.saturating_add(written as u64);
                                splice_attempts += 1;
                                if pending == 0
                                    || max_splice_attempts.is_some_and(|maximum| {
                                        splice_attempts >= maximum
                                    })
                                {
                                    break;
                                }
                            }
                            Ok(Err(error)) => return Err(error),
                            Err(_would_block) => {
                                destination_would_blocks =
                                    destination_would_blocks.saturating_add(1);
                                break;
                            }
                        }
                    }
                    continue;
                }
                if active_rate_decrease_recovery
                    .as_ref()
                    .is_some_and(|recovery| recovery.would_blocks > 0)
                {
                    let destination_fd = destination.get_ref().as_raw_fd();
                    let queued = get_notsent_bytes(destination_fd)?;
                    if active_rate_decrease_recovery.as_ref().is_some_and(
                        |recovery| queued <= recovery.target_notsent_bytes,
                    ) {
                        let recovery = active_rate_decrease_recovery
                            .take()
                            .expect("rate decrease recovery is active");
                        rate_decrease_recoveries.push(RateDecreaseRecovery {
                            elapsed_us: recovery.started.elapsed().as_secs_f64()
                                * 1e6,
                            forwarded_bytes: transferred
                                .saturating_sub(recovery.transferred_at_start),
                            would_blocks: recovery.would_blocks,
                            start_notsent_bytes: recovery.start_notsent_bytes,
                            target_notsent_bytes: recovery.target_notsent_bytes,
                        });
                    }
                }
                if adaptive_lowat_active && adaptive_lowat_observed_block {
                    let destination_fd = destination.get_ref().as_raw_fd();
                    notsent_bytes_at_lowat_restore =
                        Some(get_notsent_bytes(destination_fd)?);
                    set_tcp_notsent_lowat(destination_fd, 0)?;
                    adaptive_lowat_active = false;
                    adaptive_lowat_restores =
                        adaptive_lowat_restores.saturating_add(1);
                }
                match writable.try_io(|destination| {
                    splice_once(
                        pipe_read_fd,
                        destination.get_ref().as_raw_fd(),
                        pending,
                    )
                }) {
                    Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(Ok(written)) => {
                        destination_splice_successes =
                            destination_splice_successes.saturating_add(1);
                        destination_splice_bytes =
                            destination_splice_bytes.saturating_add(written as u64);
                        if written < pending {
                            destination_partial_splices =
                                destination_partial_splices.saturating_add(1);
                            if options.sample_partial_notsent_every > 0
                                && destination_partial_splices.is_multiple_of(
                                    options.sample_partial_notsent_every,
                                )
                            {
                                let queued = get_notsent_bytes(
                                    destination.get_ref().as_raw_fd(),
                                )?;
                                destination_partial_notsent_samples =
                                    destination_partial_notsent_samples
                                        .saturating_add(1);
                                destination_partial_notsent_bytes =
                                    destination_partial_notsent_bytes
                                        .saturating_add(u64::from(queued));
                                destination_partial_notsent_min = Some(
                                    destination_partial_notsent_min
                                        .map_or(queued, |value: u32| {
                                            value.min(queued)
                                        }),
                                );
                                destination_partial_notsent_max = Some(
                                    destination_partial_notsent_max
                                        .map_or(queued, |value: u32| {
                                            value.max(queued)
                                        }),
                                );
                            }
                        }
                        pending -= written;
                        transferred += written as u64;
                        while let Some(update) = options
                            .rate_updates
                            .get(next_rate_update)
                            .copied()
                            .filter(|update| transferred >= update.after_bytes)
                        {
                            let destination_fd = destination.get_ref().as_raw_fd();
                            let rate_decreased = update.rate < current_rate;
                            let need_queued = notsent_bytes_at_rate_update.is_none()
                                || options.adaptive_notsent_lowat.is_some()
                                || ((options.sample_rate_decrease_recovery
                                    || options.sample_rate_decrease_flight)
                                    && rate_decreased);
                            let queued = need_queued
                                .then(|| get_notsent_bytes(destination_fd))
                                .transpose()?;
                            if notsent_bytes_at_rate_update.is_none() {
                                notsent_bytes_at_rate_update = queued;
                                if options.sample_tcp_info {
                                    tcp_info_at_rate_update =
                                        Some(get_tcp_info(destination_fd)?);
                                }
                            }
                            if options.sample_rate_decrease_flight && rate_decreased
                            {
                                let queued = queued.expect(
                                    "rate-decrease flight sampling requires queue depth",
                                );
                                let tcp_info = get_tcp_info(destination_fd)?;
                                let bdp = (u128::from(update.rate)
                                    * u128::from(tcp_info.rtt_us)
                                    / 1_000_000)
                                    .max(1);
                                rate_decrease_flight_samples.push(
                                    RateDecreaseFlightSample {
                                        unsent_bytes: queued,
                                        unacked_bytes: tcp_info.unacked_bytes,
                                        snd_cwnd_bytes: tcp_info.snd_cwnd_bytes,
                                        new_rate_bdp_bytes: u64::try_from(bdp)
                                            .unwrap_or(u64::MAX),
                                    },
                                );
                            }
                            if let Some(candidate) = update.notsent_lowat {
                                let publish = match last_published_lowat {
                                    Some(last) => should_publish_lowat(
                                        last,
                                        candidate,
                                        options
                                            .notsent_lowat_update_threshold_percent,
                                        options.notsent_lowat_gate_decreases_only,
                                    ),
                                    None => true,
                                };
                                if publish {
                                    set_tcp_notsent_lowat(
                                        destination_fd,
                                        candidate,
                                    )?;
                                    last_published_lowat = Some(candidate);
                                    notsent_lowat_updates =
                                        notsent_lowat_updates.saturating_add(1);
                                }
                            }
                            set_max_pacing_rate(destination_fd, update.rate)?;
                            pacing_updates = pacing_updates.saturating_add(1);
                            if options.sample_rate_decrease_recovery
                                && rate_decreased
                            {
                                if active_rate_decrease_recovery.take().is_some() {
                                    incomplete_rate_decrease_recoveries =
                                        incomplete_rate_decrease_recoveries
                                            .saturating_add(1);
                                }
                                let target_notsent_bytes = update.notsent_lowat.expect(
                                    "rate-decrease recovery sampling requires queue-time low-water",
                                );
                                let start_notsent_bytes = queued.expect(
                                    "rate-decrease recovery sampling requires queue depth",
                                );
                                if start_notsent_bytes <= target_notsent_bytes {
                                    rate_decrease_recoveries.push(
                                        RateDecreaseRecovery {
                                            elapsed_us: 0.0,
                                            forwarded_bytes: 0,
                                            would_blocks: 0,
                                            start_notsent_bytes,
                                            target_notsent_bytes,
                                        },
                                    );
                                } else {
                                    active_rate_decrease_recovery =
                                        Some(PendingRateDecreaseRecovery {
                                            started: Instant::now(),
                                            transferred_at_start: transferred,
                                            would_blocks: 0,
                                            start_notsent_bytes,
                                            target_notsent_bytes,
                                        });
                                }
                            }
                            current_rate = update.rate;
                            if let Some(lowat) = options.adaptive_notsent_lowat
                                && queued.is_some_and(|queued| queued > lowat)
                            {
                                set_tcp_notsent_lowat(destination_fd, lowat)?;
                                adaptive_lowat_applied = true;
                                adaptive_lowat_active = true;
                            }
                            next_rate_update += 1;
                        }
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_would_block) => {
                        destination_would_blocks =
                            destination_would_blocks.saturating_add(1);
                        sample_next_writable_wake = true;
                        if let Some(recovery) = &mut active_rate_decrease_recovery {
                            recovery.would_blocks =
                                recovery.would_blocks.saturating_add(1);
                        }
                        if adaptive_lowat_active {
                            adaptive_lowat_observed_block = true;
                        }
                    }
                }
                continue;
            }

            let pipe_write_fd = pipe_write.as_raw_fd();
            let source_read = if options.source_readiness_mode
                == SourceReadinessMode::TryFirst
            {
                match source.try_io(Interest::READABLE, |source| {
                    splice_once(source.as_raw_fd(), pipe_write_fd, pipe_capacity)
                }) {
                    Ok(read) => {
                        source_try_first_successes =
                            source_try_first_successes.saturating_add(1);
                        Some(read)
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            let source_read = if let Some(read) = source_read {
                Some(read)
            } else {
                source_ready_acquisitions =
                    source_ready_acquisitions.saturating_add(1);
                let mut readable = source.readable().await?;
                match readable.try_io(|source| {
                    splice_once(
                        source.get_ref().as_raw_fd(),
                        pipe_write_fd,
                        pipe_capacity,
                    )
                }) {
                    Ok(Ok(read)) => Some(read),
                    Ok(Err(error)) => return Err(error),
                    Err(_would_block) => None,
                }
            };
            match source_read {
                Some(0) => {
                    shutdown_write(destination.get_ref().as_raw_fd())?;
                    if active_rate_decrease_recovery.is_some() {
                        incomplete_rate_decrease_recoveries =
                            incomplete_rate_decrease_recoveries.saturating_add(1);
                    }
                    return Ok(RelayStats {
                        bytes: transferred,
                        elapsed_us: relay_started.elapsed().as_secs_f64() * 1e6,
                        pipe_capacity,
                        destination_ready_acquisitions,
                        destination_would_blocks,
                        source_ready_acquisitions,
                        source_try_first_successes,
                        source_would_blocks,
                        source_splice_successes,
                        source_splice_bytes,
                        source_partial_splices,
                        destination_splice_successes,
                        destination_splice_bytes,
                        destination_partial_splices,
                        destination_partial_notsent_samples,
                        destination_partial_notsent_bytes,
                        destination_partial_notsent_min,
                        destination_partial_notsent_max,
                        writable_wake_samples,
                        writable_wake_at_or_below_lowat,
                        writable_wake_notsent_bytes,
                        writable_wake_unacked_bytes,
                        writable_wake_cwnd_bytes,
                        notsent_bytes_at_rate_update,
                        tcp_info_at_rate_update,
                        notsent_bytes_at_lowat_restore,
                        adaptive_lowat_applied,
                        adaptive_lowat_restores,
                        pacing_updates,
                        notsent_lowat_updates,
                        rate_decrease_recoveries,
                        rate_decrease_flight_samples,
                        incomplete_rate_decrease_recoveries,
                    });
                }
                Some(read) => {
                    source_splice_successes =
                        source_splice_successes.saturating_add(1);
                    source_splice_bytes =
                        source_splice_bytes.saturating_add(read as u64);
                    if read < pipe_capacity {
                        source_partial_splices =
                            source_partial_splices.saturating_add(1);
                    }
                    pending = read;
                }
                None => {
                    source_would_blocks = source_would_blocks.saturating_add(1);
                }
            }
        }
    }

    fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }

    fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }

    fn nonblocking_pipe(
        requested_capacity: usize,
    ) -> io::Result<(OwnedFd, OwnedFd, usize)> {
        let mut fds = [-1; 2];
        let result = unsafe {
            libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK)
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe_read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let pipe_write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let current = pipe_capacity(pipe_write.as_raw_fd())?;
        let actual = if requested_capacity > current {
            let resized = unsafe {
                libc::fcntl(
                    pipe_write.as_raw_fd(),
                    libc::F_SETPIPE_SZ,
                    requested_capacity as libc::c_int,
                )
            };
            if resized > 0 {
                resized as usize
            } else {
                current
            }
        } else {
            current
        };
        Ok((pipe_read, pipe_write, actual))
    }

    fn pipe_capacity(fd: RawFd) -> io::Result<usize> {
        let capacity = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
        if capacity < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(capacity as usize)
    }

    fn splice_once(
        source: RawFd,
        destination: RawFd,
        len: usize,
    ) -> io::Result<usize> {
        loop {
            let result = unsafe {
                libc::splice(
                    source,
                    std::ptr::null_mut(),
                    destination,
                    std::ptr::null_mut(),
                    len,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };
            if result >= 0 {
                return Ok(result as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    fn shutdown_write(fd: RawFd) -> io::Result<()> {
        let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENOTCONN | libc::EPIPE)) {
            return Ok(());
        }
        Err(error)
    }

    fn set_max_pacing_rate(fd: RawFd, rate: u64) -> io::Result<()> {
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MAX_PACING_RATE,
                (&rate as *const u64).cast(),
                std::mem::size_of::<u64>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn set_tcp_notsent_lowat(fd: RawFd, bytes: u32) -> io::Result<()> {
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NOTSENT_LOWAT,
                (&bytes as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn get_notsent_bytes(fd: RawFd) -> io::Result<u32> {
        let mut bytes = 0_i32;
        let result = unsafe { libc::ioctl(fd, libc::SIOCOUTQNSD, &mut bytes) };
        if result == 0 {
            u32::try_from(bytes).map_err(|_| {
                io::Error::other(format!(
                    "SIOCOUTQNSD returned negative bytes: {bytes}"
                ))
            })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn get_tcp_info(fd: RawFd) -> io::Result<TcpInfoSample> {
        let mut info = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let info = unsafe { info.assume_init() };
        Ok(TcpInfoSample {
            rtt_us: info.tcpi_rtt,
            unacked_bytes: u64::from(info.tcpi_unacked)
                * u64::from(info.tcpi_snd_mss),
            snd_cwnd_bytes: u64::from(info.tcpi_snd_cwnd)
                * u64::from(info.tcpi_snd_mss),
        })
    }

    fn effective_requested_rate(args: &Args) -> f64 {
        let updates = requested_rate_updates(args);
        let phase_count = updates.len() as f64 + 1.0;
        let reciprocal_sum = 1.0 / args.rate_bytes_per_sec as f64
            + updates.iter().map(|rate| 1.0 / *rate as f64).sum::<f64>();
        phase_count / reciprocal_sum
    }

    fn usage() -> io::Result<Usage> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let result =
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let usage = unsafe { usage.assume_init() };
        Ok(Usage {
            cpu_seconds: timeval_seconds(usage.ru_utime)
                + timeval_seconds(usage.ru_stime),
            voluntary_context_switches: usage.ru_nvcsw,
            involuntary_context_switches: usage.ru_nivcsw,
        })
    }

    fn timeval_seconds(value: libc::timeval) -> f64 {
        value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0
    }

    fn round(value: f64) -> f64 {
        (value * 1_000_000.0).round() / 1_000_000.0
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn base_args() -> Args {
            Args {
                connections: 1,
                worker_threads: 1,
                bytes_per_connection: 1,
                chunk_size: 1,
                rate_bytes_per_sec: 100,
                unpaced: false,
                second_rate_bytes_per_sec: None,
                rate_updates_bytes_per_sec: Vec::new(),
                notsent_lowat_bytes: None,
                notsent_lowat_ms: None,
                notsent_lowat_min_bytes: None,
                notsent_lowat_max_bytes: None,
                notsent_lowat_update_threshold_percent: 0.0,
                notsent_lowat_gate_decreases_only: false,
                adaptive_notsent_lowat_bytes: None,
                pipe_size: 4096,
                destination_drain_mode: DestinationDrainMode::Single,
                source_readiness_mode: SourceReadinessMode::Guarded,
                warmup: 0,
                runs: 1,
                sample_tcp_info: false,
                sample_rate_decrease_recovery: false,
                sample_rate_decrease_flight: false,
                sample_partial_notsent_every: 0,
                sample_writable_wake_every: 0,
                verify: false,
            }
        }

        #[test]
        fn writable_wake_sampling_requires_static_lowat() {
            let mut args = base_args();
            args.sample_writable_wake_every = 8;
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_ms = Some(32);
            assert!(validate_args(&args).is_ok());

            args.destination_drain_mode = DestinationDrainMode::TwoSplices;
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn partial_notsent_sampling_requires_static_lowat() {
            let mut args = base_args();
            args.sample_partial_notsent_every = 8;
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_bytes = Some(32 * 1024);
            assert!(validate_args(&args).is_ok());

            args.destination_drain_mode = DestinationDrainMode::TwoSplices;
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn rejects_zero_connections() {
            let mut args = base_args();
            args.connections = 0;
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn unpaced_rejects_pacing_specific_options() {
            let mut args = base_args();
            args.unpaced = true;
            assert!(validate_args(&args).is_ok());

            args.second_rate_bytes_per_sec = Some(50);
            assert!(validate_args(&args).is_err());
            args.second_rate_bytes_per_sec = None;

            args.notsent_lowat_bytes = Some(64 * 1024);
            assert!(validate_args(&args).is_err());
            args.notsent_lowat_bytes = None;

            args.sample_tcp_info = true;
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn destination_drain_modes_allow_static_lowat_but_reject_dynamic_pacing() {
            let mut args = base_args();
            args.destination_drain_mode = DestinationDrainMode::TwoSplices;
            args.notsent_lowat_ms = Some(32);
            assert!(validate_args(&args).is_ok());
            args.destination_drain_mode = DestinationDrainMode::UntilWouldBlock;
            assert!(validate_args(&args).is_ok());

            args.second_rate_bytes_per_sec = Some(50);
            assert!(validate_args(&args).is_err());
            args.second_rate_bytes_per_sec = None;

            args.notsent_lowat_ms = None;
            args.unpaced = true;
            assert!(validate_args(&args).is_ok());
        }

        #[test]
        fn rate_decrease_recovery_sampling_requires_queue_time_lowat() {
            let mut args = base_args();
            args.sample_rate_decrease_recovery = true;
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_ms = Some(32);
            assert!(validate_args(&args).is_ok());
        }

        #[test]
        fn rate_decrease_flight_sampling_requires_a_decrease() {
            let mut args = base_args();
            args.sample_rate_decrease_flight = true;
            assert!(validate_args(&args).is_err());

            args.rate_updates_bytes_per_sec = vec![110, 90];
            assert!(validate_args(&args).is_ok());

            args.rate_updates_bytes_per_sec = vec![110, 120];
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn tcp_info_reports_sender_window() {
            let (client, _server) = tcp_pair().unwrap();
            let info = get_tcp_info(client.as_raw_fd()).unwrap();
            assert!(info.snd_cwnd_bytes > 0);
        }

        #[test]
        fn effective_rate_uses_equal_byte_harmonic_mean() {
            let mut args = base_args();
            args.second_rate_bytes_per_sec = Some(25);
            assert_eq!(effective_requested_rate(&args), 40.0);

            args.second_rate_bytes_per_sec = None;
            args.rate_updates_bytes_per_sec = vec![50, 25];
            assert!((effective_requested_rate(&args) - 300.0 / 7.0).abs() < 1e-12);
        }

        #[test]
        fn rate_updates_split_transfer_into_equal_byte_phases() {
            let mut args = base_args();
            args.bytes_per_connection = 400;
            args.rate_updates_bytes_per_sec = vec![95, 105, 90];
            let updates = build_rate_updates(&args).unwrap();
            assert_eq!(
                updates
                    .iter()
                    .map(|update| update.after_bytes)
                    .collect::<Vec<_>>(),
                vec![100, 200, 300]
            );
            assert_eq!(
                updates.iter().map(|update| update.rate).collect::<Vec<_>>(),
                vec![95, 105, 90]
            );
        }

        #[test]
        fn lowat_publication_gate_accumulates_against_last_publication() {
            assert!(!should_publish_lowat(1_000, 1_090, 12.5, false));
            assert!(should_publish_lowat(1_000, 1_125, 12.5, false));
            assert!(should_publish_lowat(1_000, 870, 12.5, false));
            assert!(!should_publish_lowat(1_000, 1_000, 0.0, false));
        }

        #[test]
        fn decrease_only_gate_publishes_lowat_increases_immediately() {
            assert!(should_publish_lowat(1_000, 1_010, 12.5, true));
            assert!(!should_publish_lowat(1_000, 900, 12.5, true));
            assert!(should_publish_lowat(1_000, 875, 12.5, true));
        }

        #[test]
        fn queue_time_lowat_tracks_active_rate() {
            let mut args = base_args();
            args.rate_bytes_per_sec = 32 * 1024 * 1024;
            args.second_rate_bytes_per_sec = Some(25 * 1024 * 1024);
            args.notsent_lowat_ms = Some(32);

            let (initial, second) = resolved_static_lowats(&args).unwrap();
            assert_eq!(initial, Some(1_073_741));
            assert_eq!(second, Some(838_860));
        }

        #[test]
        fn queue_time_lowat_rejects_zero_or_unrepresentable_values() {
            let mut args = base_args();
            args.notsent_lowat_ms = Some(0);
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_ms = Some(1);
            args.rate_bytes_per_sec = u64::MAX;
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_max_bytes = Some(1024 * 1024);
            assert!(validate_args(&args).is_ok());
            assert_eq!(resolved_static_lowats(&args).unwrap().0, Some(1024 * 1024));
        }

        #[test]
        fn bounded_queue_time_lowat_clamps_each_active_rate() {
            let mut args = base_args();
            args.rate_bytes_per_sec = 64 * 1024 * 1024;
            args.second_rate_bytes_per_sec = Some(25 * 1024 * 1024);
            args.notsent_lowat_ms = Some(32);
            args.notsent_lowat_min_bytes = Some(512 * 1024);
            args.notsent_lowat_max_bytes = Some(1024 * 1024);

            let (initial, second) = resolved_static_lowats(&args).unwrap();
            assert_eq!(initial, Some(1024 * 1024));
            assert_eq!(second, Some(838_860));
        }

        #[test]
        fn bounded_queue_time_lowat_requires_valid_bounds() {
            let mut args = base_args();
            args.notsent_lowat_min_bytes = Some(512 * 1024);
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_ms = Some(32);
            args.notsent_lowat_max_bytes = Some(256 * 1024);
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_min_bytes = Some(0);
            args.notsent_lowat_max_bytes = Some(1024 * 1024);
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn publication_sequence_and_lowat_gate_validate_together() {
            let mut args = base_args();
            args.second_rate_bytes_per_sec = Some(90);
            args.rate_updates_bytes_per_sec = vec![95, 105];
            assert!(validate_args(&args).is_err());

            args.second_rate_bytes_per_sec = None;
            args.notsent_lowat_update_threshold_percent = 12.5;
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_update_threshold_percent = 0.0;
            args.notsent_lowat_gate_decreases_only = true;
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_ms = Some(32);
            assert!(validate_args(&args).is_ok());
        }

        #[test]
        fn adaptive_lowat_requires_a_rate_decrease() {
            let mut args = base_args();
            args.second_rate_bytes_per_sec = Some(100);
            args.adaptive_notsent_lowat_bytes = Some(512 * 1024);
            assert!(validate_args(&args).is_err());
            args.second_rate_bytes_per_sec = Some(25);
            assert!(validate_args(&args).is_ok());
        }

        #[test]
        fn lowat_modes_are_mutually_exclusive() {
            let mut args = base_args();
            args.second_rate_bytes_per_sec = Some(25);
            args.notsent_lowat_bytes = Some(512 * 1024);
            args.notsent_lowat_ms = Some(32);
            assert!(validate_args(&args).is_err());

            args.notsent_lowat_bytes = None;
            args.adaptive_notsent_lowat_bytes = Some(512 * 1024);
            assert!(validate_args(&args).is_err());
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn multi_stage_rate_updates_preserve_payload_and_gate_lowat() {
            let mut args = base_args();
            args.worker_threads = 2;
            args.bytes_per_connection = 512 * 1024;
            args.chunk_size = 16 * 1024;
            args.rate_bytes_per_sec = 64 * 1024 * 1024;
            args.rate_updates_bytes_per_sec =
                vec![56 * 1024 * 1024, 64 * 1024 * 1024];
            args.notsent_lowat_ms = Some(32);
            args.notsent_lowat_update_threshold_percent = 10.0;
            args.pipe_size = 128 * 1024;
            args.verify = true;

            let record = run_once(&args, 0, false).await.unwrap();
            assert_eq!(record.total_bytes, args.bytes_per_connection);
            assert_eq!(record.pacing_updates_total, 2);
            assert_eq!(record.notsent_lowat_updates_total, 2);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn rate_decrease_recovery_sampling_completes() {
            let mut args = base_args();
            args.worker_threads = 2;
            args.bytes_per_connection = 4 * 1024 * 1024;
            args.chunk_size = 16 * 1024;
            args.rate_bytes_per_sec = 32 * 1024 * 1024;
            args.second_rate_bytes_per_sec = Some(25 * 1024 * 1024);
            args.notsent_lowat_ms = Some(32);
            args.sample_rate_decrease_recovery = true;
            args.pipe_size = 128 * 1024;
            args.verify = true;

            let record = run_once(&args, 0, false).await.unwrap();
            assert_eq!(record.rate_decrease_recoveries_total, 1);
            assert_eq!(record.incomplete_rate_decrease_recoveries_total, 0);
            assert!(record.rate_decrease_recovery_elapsed_us_median.is_some());
            assert_eq!(
                record.rate_decrease_recovery_target_notsent_bytes_median,
                Some(
                    queue_time_lowat_bytes(25 * 1024 * 1024, 32, None, None).unwrap()
                        as f64
                )
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn rate_decrease_flight_sampling_records_bdp_ratios() {
            let mut args = base_args();
            args.worker_threads = 2;
            args.bytes_per_connection = 4 * 1024 * 1024;
            args.chunk_size = 16 * 1024;
            args.rate_bytes_per_sec = 32 * 1024 * 1024;
            args.second_rate_bytes_per_sec = Some(25 * 1024 * 1024);
            args.notsent_lowat_ms = Some(32);
            args.sample_rate_decrease_flight = true;
            args.pipe_size = 128 * 1024;
            args.verify = true;

            let record = run_once(&args, 0, false).await.unwrap();
            assert_eq!(record.rate_decrease_flight_samples_total, 1);
            assert!(record.rate_decrease_flight_bdp_bytes_median.unwrap() > 0.0);
            assert!(
                record
                    .rate_decrease_flight_admitted_to_bdp_ratio_median
                    .unwrap()
                    > 0.0
            );
            assert!(
                record
                    .rate_decrease_flight_unacked_to_bdp_ratio_median
                    .unwrap()
                    >= 0.0
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn unpaced_asyncfd_splice_roundtrip_reports_no_rate_ratio() {
            let mut args = base_args();
            args.unpaced = true;
            args.destination_drain_mode = DestinationDrainMode::UntilWouldBlock;
            args.worker_threads = 2;
            args.bytes_per_connection = 256 * 1024;
            args.chunk_size = 16 * 1024;
            args.pipe_size = 128 * 1024;
            args.verify = true;

            let record = run_once(&args, 0, false).await.unwrap();
            assert_eq!(record.total_bytes, args.bytes_per_connection);
            assert_eq!(record.requested_rate_bytes_per_sec, None);
            assert_eq!(record.per_connection_rate_ratio, None);
            assert_eq!(record.pacing_updates_total, 0);
            assert_eq!(record.destination_drain_mode, "until-would-block");
            assert_eq!(
                record.actual_pipe_capacity_min,
                record.actual_pipe_capacity_max
            );
            assert!(record.actual_pipe_capacity_min > 0);
            assert_eq!(record.pipe_capacity_shortfall_connections, 0);
            assert!(record.relay_elapsed_us_median > 0.0);
            assert!(record.relay_elapsed_us_max >= record.relay_elapsed_us_median);
            assert!(record.relay_elapsed_max_to_median_ratio >= 1.0);
            assert!(record.writer_elapsed_us_median > 0.0);
            assert!(record.writer_elapsed_us_max >= record.writer_elapsed_us_median);
            assert!(record.writer_elapsed_max_to_median_ratio >= 1.0);
            assert!(record.sink_elapsed_us_median > 0.0);
            assert!(record.sink_elapsed_us_max >= record.sink_elapsed_us_median);
            assert!(record.sink_elapsed_max_to_median_ratio >= 1.0);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn asyncfd_splice_roundtrip_preserves_payload() {
            let mut args = base_args();
            args.worker_threads = 2;
            args.bytes_per_connection = 256 * 1024;
            args.chunk_size = 16 * 1024;
            args.rate_bytes_per_sec = 64 * 1024 * 1024;
            args.notsent_lowat_bytes = Some(512 * 1024);
            args.pipe_size = 128 * 1024;
            args.sample_tcp_info = true;
            args.verify = true;

            let record = run_once(&args, 0, false).await.unwrap();
            assert_eq!(record.total_bytes, args.bytes_per_connection);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn try_first_source_readiness_preserves_payload_and_hits_cached_ready()
        {
            let mut args = base_args();
            args.worker_threads = 2;
            args.bytes_per_connection = 512 * 1024;
            args.chunk_size = 16 * 1024;
            args.rate_bytes_per_sec = 64 * 1024 * 1024;
            args.notsent_lowat_bytes = Some(512 * 1024);
            args.pipe_size = 128 * 1024;
            args.source_readiness_mode = SourceReadinessMode::TryFirst;
            args.verify = true;

            let record = run_once(&args, 0, false).await.unwrap();
            assert_eq!(record.total_bytes, args.bytes_per_connection);
            assert!(record.source_try_first_successes_total > 0);
            assert!(
                record.source_ready_acquisitions_total
                    < record.source_splice_successes_total
            );
        }
    }
}
