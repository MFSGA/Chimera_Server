#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("udp_shared_socket_probe requires Linux");
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
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
        os::fd::AsRawFd,
        ptr,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use anyhow::{Context, Result, bail};
    use chimera_perf::stats::{coefficient_of_variation, median};
    use clap::{Parser, ValueEnum};
    use serde::Serialize;
    use tokio::{
        io::Interest,
        net::UdpSocket,
        sync::{Notify, mpsc},
        time::{Sleep, sleep},
    };

    const PATTERN_BYTE: u8 = 0x5a;
    const HEADER_SIZE: usize = 12;
    const MAX_BATCH_SIZE: usize = 128;
    const MAX_SESSIONS: usize = 4096;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Single,
        Mmsg,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Multi-session freedom UDP shared-response-socket probe")]
    struct Args {
        #[arg(long, value_enum)]
        backend: Backend,
        #[arg(long, default_value_t = 8)]
        worker_threads: usize,
        #[arg(long, default_value_t = 16)]
        sessions: usize,
        #[arg(long, default_value_t = 8192)]
        packets_per_session: usize,
        #[arg(long, default_value_t = 1200)]
        datagram_size: usize,
        #[arg(long, default_value_t = 8)]
        uplink_batch_size: usize,
        #[arg(long, default_value_t = 16)]
        downlink_batch_size: usize,
        #[arg(long, default_value_t = 64)]
        channel_capacity: usize,
        #[arg(long, default_value_t = 64)]
        inflight_window: usize,
        #[arg(long, default_value_t = 10_000)]
        idle_timeout_ms: u64,
        #[arg(long, default_value_t = 2)]
        warmup: usize,
        #[arg(long, default_value_t = 5)]
        runs: usize,
        #[arg(long)]
        verify: bool,
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct SessionStats {
        uplink_packets: u64,
        downlink_packets: u64,
        uplink_socket_calls: u64,
        downlink_receive_calls: u64,
        shared_send_calls: u64,
        shared_send_would_block: u64,
        max_uplink_batch_packets: u64,
        max_downlink_batch_packets: u64,
        idle_resets: u64,
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct AggregateStats {
        uplink_packets: u64,
        downlink_packets: u64,
        uplink_socket_calls: u64,
        downlink_receive_calls: u64,
        shared_send_calls: u64,
        shared_send_would_block: u64,
        max_uplink_batch_packets: u64,
        max_downlink_batch_packets: u64,
        idle_resets: u64,
    }

    impl AggregateStats {
        fn add(&mut self, session: SessionStats) {
            self.uplink_packets =
                self.uplink_packets.saturating_add(session.uplink_packets);
            self.downlink_packets = self
                .downlink_packets
                .saturating_add(session.downlink_packets);
            self.uplink_socket_calls = self
                .uplink_socket_calls
                .saturating_add(session.uplink_socket_calls);
            self.downlink_receive_calls = self
                .downlink_receive_calls
                .saturating_add(session.downlink_receive_calls);
            self.shared_send_calls = self
                .shared_send_calls
                .saturating_add(session.shared_send_calls);
            self.shared_send_would_block = self
                .shared_send_would_block
                .saturating_add(session.shared_send_would_block);
            self.max_uplink_batch_packets = self
                .max_uplink_batch_packets
                .max(session.max_uplink_batch_packets);
            self.max_downlink_batch_packets = self
                .max_downlink_batch_packets
                .max(session.max_downlink_batch_packets);
            self.idle_resets = self.idle_resets.saturating_add(session.idle_resets);
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct SinkStats {
        packets: usize,
        receive_batches: usize,
        max_consecutive_session_packets: usize,
        mean_distinct_sessions_per_receive_batch: f64,
        max_distinct_sessions_per_receive_batch: usize,
        completion_span_seconds: f64,
    }

    #[derive(Debug, Clone, Copy)]
    struct Sample {
        packets_per_second: f64,
        throughput_gbps: f64,
        cpu_seconds_per_million_packets: f64,
        uplink_socket_calls: u64,
        downlink_receive_calls: u64,
        shared_send_calls: u64,
        shared_send_would_block: u64,
        max_uplink_batch_packets: u64,
        max_downlink_batch_packets: u64,
        sink_receive_batches: u64,
        max_consecutive_session_packets: u64,
        mean_distinct_sessions_per_receive_batch: f64,
        max_distinct_sessions_per_receive_batch: u64,
        completion_span_fraction: f64,
        idle_resets: u64,
        producer_window_wait_events: u64,
    }

    struct SessionProgress {
        received: AtomicUsize,
        notify: Notify,
    }

    impl SessionProgress {
        fn new() -> Self {
            Self {
                received: AtomicUsize::new(0),
                notify: Notify::new(),
            }
        }
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.worker_threads)
            .enable_io()
            .enable_time()
            .build()?;

        for _ in 0..args.warmup {
            let _ = runtime.block_on(run_once(&args))?;
        }

        let mut packet_rates = Vec::with_capacity(args.runs);
        let mut throughput = Vec::with_capacity(args.runs);
        let mut cpu = Vec::with_capacity(args.runs);
        let mut uplink_calls = Vec::with_capacity(args.runs);
        let mut downlink_receive_calls = Vec::with_capacity(args.runs);
        let mut shared_send_calls = Vec::with_capacity(args.runs);
        let mut shared_send_would_block = Vec::with_capacity(args.runs);
        let mut max_uplink_batch = Vec::with_capacity(args.runs);
        let mut max_downlink_batch = Vec::with_capacity(args.runs);
        let mut sink_receive_batches = Vec::with_capacity(args.runs);
        let mut max_consecutive_session_packets = Vec::with_capacity(args.runs);
        let mut mean_distinct_sessions_per_receive_batch =
            Vec::with_capacity(args.runs);
        let mut max_distinct_sessions_per_receive_batch =
            Vec::with_capacity(args.runs);
        let mut completion_span_fraction = Vec::with_capacity(args.runs);
        let mut idle_resets = Vec::with_capacity(args.runs);
        let mut producer_window_wait_events = Vec::with_capacity(args.runs);

        for _ in 0..args.runs {
            let sample = runtime.block_on(run_once(&args))?;
            packet_rates.push(sample.packets_per_second);
            throughput.push(sample.throughput_gbps);
            cpu.push(sample.cpu_seconds_per_million_packets);
            uplink_calls.push(sample.uplink_socket_calls as f64);
            downlink_receive_calls.push(sample.downlink_receive_calls as f64);
            shared_send_calls.push(sample.shared_send_calls as f64);
            shared_send_would_block.push(sample.shared_send_would_block as f64);
            max_uplink_batch.push(sample.max_uplink_batch_packets as f64);
            max_downlink_batch.push(sample.max_downlink_batch_packets as f64);
            sink_receive_batches.push(sample.sink_receive_batches as f64);
            max_consecutive_session_packets
                .push(sample.max_consecutive_session_packets as f64);
            mean_distinct_sessions_per_receive_batch
                .push(sample.mean_distinct_sessions_per_receive_batch);
            max_distinct_sessions_per_receive_batch
                .push(sample.max_distinct_sessions_per_receive_batch as f64);
            completion_span_fraction.push(sample.completion_span_fraction);
            idle_resets.push(sample.idle_resets as f64);
            producer_window_wait_events
                .push(sample.producer_window_wait_events as f64);
        }

        let total_packets = total_packets(&args);
        let uplink_calls_median = median(&uplink_calls);
        let downlink_receive_calls_median = median(&downlink_receive_calls);
        let shared_send_calls_median = median(&shared_send_calls);
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "record_type": "summary",
                "backend": args.backend,
                "worker_threads": args.worker_threads,
                "sessions": args.sessions,
                "packets_per_session": args.packets_per_session,
                "total_packets": total_packets,
                "datagram_size": args.datagram_size,
                "uplink_batch_size": args.uplink_batch_size,
                "downlink_batch_size": args.downlink_batch_size,
                "channel_capacity": args.channel_capacity,
                "inflight_window": args.inflight_window,
                "idle_timeout_ms": args.idle_timeout_ms,
                "verify": args.verify,
                "warmup_runs": args.warmup,
                "runs": args.runs,
                "shared_response_socket": true,
                "outbound_socket_connected": false,
                "shared_send_cross_session_batching": false,
                "packets_per_second_median": round(median(&packet_rates)),
                "packets_per_second_cv": round(coefficient_of_variation(&packet_rates)),
                "throughput_median_gbps": round(median(&throughput)),
                "cpu_seconds_per_million_packets_median": round(median(&cpu)),
                "cpu_seconds_per_million_packets_cv": round(coefficient_of_variation(&cpu)),
                "uplink_socket_calls_median": round(uplink_calls_median),
                "uplink_packets_per_socket_call_median": round(
                    total_packets as f64 / uplink_calls_median,
                ),
                "downlink_receive_calls_median": round(downlink_receive_calls_median),
                "downlink_packets_per_receive_call_median": round(
                    total_packets as f64 / downlink_receive_calls_median,
                ),
                "shared_send_calls_median": round(shared_send_calls_median),
                "shared_send_packets_per_call_median": round(
                    total_packets as f64 / shared_send_calls_median,
                ),
                "shared_send_would_block_median": round(median(&shared_send_would_block)),
                "max_uplink_batch_packets_median": round(median(&max_uplink_batch)),
                "max_downlink_batch_packets_median": round(median(&max_downlink_batch)),
                "sink_receive_batches_median": round(median(&sink_receive_batches)),
                "sink_packets_per_receive_batch_median": round(
                    total_packets as f64 / median(&sink_receive_batches),
                ),
                "max_consecutive_session_packets_at_sink_median": round(
                    median(&max_consecutive_session_packets),
                ),
                "mean_distinct_sessions_per_sink_receive_batch_median": round(
                    median(&mean_distinct_sessions_per_receive_batch),
                ),
                "max_distinct_sessions_per_sink_receive_batch_median": round(
                    median(&max_distinct_sessions_per_receive_batch),
                ),
                "session_completion_span_fraction_median": round(
                    median(&completion_span_fraction),
                ),
                "idle_resets_median": round(median(&idle_resets)),
                "producer_window_wait_events_median": round(
                    median(&producer_window_wait_events),
                ),
            })
        );
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        if args.worker_threads == 0 {
            bail!("--worker-threads must be greater than zero");
        }
        if args.sessions == 0 || args.sessions > MAX_SESSIONS {
            bail!("--sessions must be between 1 and {MAX_SESSIONS}");
        }
        if args.packets_per_session == 0 {
            bail!("--packets-per-session must be greater than zero");
        }
        if !(HEADER_SIZE..=65_507).contains(&args.datagram_size) {
            bail!("--datagram-size must be between {HEADER_SIZE} and 65507");
        }
        for (name, size) in [
            ("--uplink-batch-size", args.uplink_batch_size),
            ("--downlink-batch-size", args.downlink_batch_size),
        ] {
            if size == 0 || size > MAX_BATCH_SIZE {
                bail!("{name} must be between 1 and {MAX_BATCH_SIZE}");
            }
        }
        if args.channel_capacity == 0 {
            bail!("--channel-capacity must be greater than zero");
        }
        if args.inflight_window == 0 {
            bail!("--inflight-window must be greater than zero");
        }
        if args.idle_timeout_ms == 0 {
            bail!("--idle-timeout-ms must be greater than zero");
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        let _ = total_packets_checked(args)?;
        Ok(())
    }

    fn total_packets(args: &Args) -> usize {
        args.sessions * args.packets_per_session
    }

    fn total_packets_checked(args: &Args) -> Result<usize> {
        args.sessions
            .checked_mul(args.packets_per_session)
            .context("session packet count overflow")
    }

    async fn run_once(args: &Args) -> Result<Sample> {
        let total_packets = total_packets_checked(args)?;
        let target = bind_std_udp_loopback()?;
        let sink = bind_std_udp_any()?;
        set_socket_buffers(&target, 8 * 1024 * 1024)?;
        set_socket_buffers(&sink, 8 * 1024 * 1024)?;
        target.set_read_timeout(Some(Duration::from_secs(10)))?;
        target.set_write_timeout(Some(Duration::from_secs(10)))?;
        sink.set_read_timeout(Some(Duration::from_secs(10)))?;
        let target_addr = target.local_addr()?;
        let sink_port = sink.local_addr()?.port();

        let barrier = Arc::new(Barrier::new(3));
        let progress = (0..args.sessions)
            .map(|_| Arc::new(SessionProgress::new()))
            .collect::<Vec<_>>();

        let echo_barrier = Arc::clone(&barrier);
        let datagram_size = args.datagram_size;
        let echo_thread = thread::spawn(move || {
            echo_target(target, total_packets, datagram_size, echo_barrier)
        });

        let sink_barrier = Arc::clone(&barrier);
        let sink_progress = progress.clone();
        let sessions = args.sessions;
        let packets_per_session = args.packets_per_session;
        let verify = args.verify;
        let sink_thread = thread::spawn(move || {
            receive_sink(
                sink,
                sessions,
                packets_per_session,
                datagram_size,
                verify,
                sink_barrier,
                &sink_progress,
            )
        });

        let server_std = bind_std_udp_loopback()?;
        set_socket_buffers(&server_std, 8 * 1024 * 1024)?;
        server_std.set_nonblocking(true)?;
        let server_socket = Arc::new(UdpSocket::from_std(server_std)?);

        let mut receivers = Vec::with_capacity(args.sessions);
        let mut producers = Vec::with_capacity(args.sessions);
        for (session_id, session_progress) in progress.iter().enumerate() {
            let (sender, receiver) = mpsc::channel(args.channel_capacity);
            receivers.push(receiver);
            let progress = Arc::clone(session_progress);
            let packets = args.packets_per_session;
            let datagram_size = args.datagram_size;
            let inflight_window = args.inflight_window;
            producers.push(tokio::spawn(async move {
                produce_payloads(
                    session_id,
                    sender,
                    packets,
                    datagram_size,
                    inflight_window,
                    &progress,
                )
                .await
            }));
        }

        barrier.wait();
        let cpu_before = cpu_seconds()?;
        let started = Instant::now();
        let mut sessions_tasks = Vec::with_capacity(args.sessions);
        for (session_id, receiver) in receivers.into_iter().enumerate() {
            let outbound_std = bind_std_udp_loopback()?;
            set_socket_buffers(&outbound_std, 4 * 1024 * 1024)?;
            outbound_std.set_nonblocking(true)?;
            let outbound_socket = UdpSocket::from_std(outbound_std)?;
            let server_socket = Arc::clone(&server_socket);
            let client_addr = client_addr_for_session(session_id, sink_port);
            let config = SessionConfig {
                backend: args.backend,
                packets: args.packets_per_session,
                datagram_size: args.datagram_size,
                uplink_batch_size: args.uplink_batch_size,
                downlink_batch_size: args.downlink_batch_size,
                idle_timeout: Duration::from_millis(args.idle_timeout_ms),
                target_addr,
                client_addr,
            };
            sessions_tasks.push(tokio::spawn(async move {
                run_session(outbound_socket, server_socket, receiver, config).await
            }));
        }

        let mut aggregate = AggregateStats::default();
        for task in sessions_tasks {
            aggregate.add(task.await.context("session task panicked")??);
        }
        let mut producer_window_wait_events = 0_u64;
        for producer in producers {
            producer_window_wait_events = producer_window_wait_events
                .saturating_add(producer.await.context("producer task panicked")??);
        }
        let sink_stats = sink_thread
            .join()
            .map_err(|_| anyhow::anyhow!("sink thread panicked"))??;
        echo_thread
            .join()
            .map_err(|_| anyhow::anyhow!("echo thread panicked"))??;
        let elapsed = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds()? - cpu_before;

        if aggregate.uplink_packets != total_packets as u64
            || aggregate.downlink_packets != total_packets as u64
            || sink_stats.packets != total_packets
        {
            bail!(
                "packet mismatch: uplink={}, downlink={}, sink={}, expected={total_packets}",
                aggregate.uplink_packets,
                aggregate.downlink_packets,
                sink_stats.packets,
            );
        }

        let packets_per_second =
            total_packets as f64 / elapsed.max(f64::MIN_POSITIVE);
        Ok(Sample {
            packets_per_second,
            throughput_gbps: packets_per_second * args.datagram_size as f64 * 8.0
                / 1e9,
            cpu_seconds_per_million_packets: cpu
                / (total_packets as f64 / 1_000_000.0),
            uplink_socket_calls: aggregate.uplink_socket_calls,
            downlink_receive_calls: aggregate.downlink_receive_calls,
            shared_send_calls: aggregate.shared_send_calls,
            shared_send_would_block: aggregate.shared_send_would_block,
            max_uplink_batch_packets: aggregate.max_uplink_batch_packets,
            max_downlink_batch_packets: aggregate.max_downlink_batch_packets,
            sink_receive_batches: sink_stats.receive_batches as u64,
            max_consecutive_session_packets: sink_stats
                .max_consecutive_session_packets
                as u64,
            mean_distinct_sessions_per_receive_batch: sink_stats
                .mean_distinct_sessions_per_receive_batch,
            max_distinct_sessions_per_receive_batch: sink_stats
                .max_distinct_sessions_per_receive_batch
                as u64,
            completion_span_fraction: sink_stats.completion_span_seconds
                / elapsed.max(f64::MIN_POSITIVE),
            idle_resets: aggregate.idle_resets,
            producer_window_wait_events,
        })
    }

    async fn produce_payloads(
        session_id: usize,
        sender: mpsc::Sender<Vec<u8>>,
        packets: usize,
        datagram_size: usize,
        inflight_window: usize,
        progress: &SessionProgress,
    ) -> Result<u64> {
        let mut wait_events = 0_u64;
        for sequence in 0..packets {
            while sequence.saturating_sub(progress.received.load(Ordering::Acquire))
                >= inflight_window
            {
                wait_events = wait_events.saturating_add(1);
                let notified = progress.notify.notified();
                if sequence.saturating_sub(progress.received.load(Ordering::Acquire))
                    < inflight_window
                {
                    break;
                }
                notified.await;
            }
            let mut payload = vec![PATTERN_BYTE; datagram_size];
            payload[..4].copy_from_slice(&(session_id as u32).to_ne_bytes());
            payload[4..12].copy_from_slice(&(sequence as u64).to_ne_bytes());
            sender.send(payload).await.map_err(|_| {
                anyhow::anyhow!("session channel closed during production")
            })?;
        }
        Ok(wait_events)
    }

    #[derive(Debug, Clone, Copy)]
    struct SessionConfig {
        backend: Backend,
        packets: usize,
        datagram_size: usize,
        uplink_batch_size: usize,
        downlink_batch_size: usize,
        idle_timeout: Duration,
        target_addr: SocketAddr,
        client_addr: SocketAddr,
    }

    #[derive(Debug, Clone, Copy)]
    enum ReceivedBatch {
        Single { len: usize, source: SocketAddr },
        Mmsg { count: usize },
    }

    async fn run_session(
        outbound_socket: UdpSocket,
        server_socket: Arc<UdpSocket>,
        mut receiver: mpsc::Receiver<Vec<u8>>,
        config: SessionConfig,
    ) -> Result<SessionStats> {
        let mut idle = Box::pin(sleep(config.idle_timeout));
        let mut stats = SessionStats::default();
        let mut channel_batch = Vec::with_capacity(config.uplink_batch_size);
        let mut response_batch =
            MmsgBatch::new(config.downlink_batch_size, config.datagram_size);
        let mut single_response = vec![0u8; config.datagram_size];

        while stats.downlink_packets < config.packets as u64 {
            tokio::select! {
                _ = idle.as_mut() => {
                    bail!(
                        "session expired with {} uplink and {} downlink packets",
                        stats.uplink_packets,
                        stats.downlink_packets,
                    );
                }
                maybe_payload = receiver.recv(), if stats.uplink_packets < config.packets as u64 => {
                    let Some(payload) = maybe_payload else {
                        bail!("session channel closed before all packets were sent");
                    };
                    match config.backend {
                        Backend::Single => {
                            let calls = send_one_to(
                                &outbound_socket,
                                &payload,
                                config.target_addr,
                            ).await?;
                            stats.uplink_packets = stats.uplink_packets.saturating_add(1);
                            stats.uplink_socket_calls = stats
                                .uplink_socket_calls
                                .saturating_add(calls as u64);
                            stats.max_uplink_batch_packets = stats.max_uplink_batch_packets.max(1);
                        }
                        Backend::Mmsg => {
                            channel_batch.clear();
                            channel_batch.push(payload);
                            while channel_batch.len() < config.uplink_batch_size {
                                match receiver.try_recv() {
                                    Ok(payload) => channel_batch.push(payload),
                                    Err(mpsc::error::TryRecvError::Empty) => break,
                                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                                }
                            }
                            let calls = send_vec_batch_to(
                                &outbound_socket,
                                &channel_batch,
                                config.target_addr,
                            ).await?;
                            stats.uplink_packets = stats
                                .uplink_packets
                                .saturating_add(channel_batch.len() as u64);
                            stats.uplink_socket_calls = stats
                                .uplink_socket_calls
                                .saturating_add(calls as u64);
                            stats.max_uplink_batch_packets = stats
                                .max_uplink_batch_packets
                                .max(channel_batch.len() as u64);
                        }
                    }
                    stats.idle_resets = stats.idle_resets.saturating_add(1);
                    reset_idle(&mut idle, config.idle_timeout);
                }
                response = receive_response_batch(
                    config.backend,
                    &outbound_socket,
                    &mut response_batch,
                    &mut single_response,
                    config.downlink_batch_size,
                ) => {
                    let (received, receive_calls) = response?;
                    match received {
                        ReceivedBatch::Single { len, source } => {
                            let payload = &single_response[..len];
                            validate_response_source_addr(source, config.target_addr)?;
                            let (calls, would_block) = send_one_shared(
                                &server_socket,
                                payload,
                                config.client_addr,
                            ).await?;
                            stats.shared_send_calls = stats.shared_send_calls.saturating_add(calls as u64);
                            stats.shared_send_would_block = stats
                                .shared_send_would_block
                                .saturating_add(would_block as u64);
                            stats.downlink_packets = stats.downlink_packets.saturating_add(1);
                            stats.max_downlink_batch_packets = stats.max_downlink_batch_packets.max(1);
                        }
                        ReceivedBatch::Mmsg { count } => {
                            for index in 0..count {
                                let source = response_batch
                                    .source_addr(index)
                                    .context("recvmmsg response omitted source address")?;
                                validate_response_source_addr(source, config.target_addr)?;
                            }
                            let (calls, would_block) = send_buffer_batch_to(
                                &server_socket,
                                &mut response_batch,
                                count,
                                config.client_addr,
                            ).await?;
                            stats.shared_send_calls = stats.shared_send_calls.saturating_add(calls as u64);
                            stats.shared_send_would_block = stats
                                .shared_send_would_block
                                .saturating_add(would_block as u64);
                            stats.downlink_packets = stats.downlink_packets.saturating_add(count as u64);
                            stats.max_downlink_batch_packets = stats
                                .max_downlink_batch_packets
                                .max(count as u64);
                        }
                    }
                    stats.downlink_receive_calls = stats
                        .downlink_receive_calls
                        .saturating_add(receive_calls as u64);
                    stats.idle_resets = stats.idle_resets.saturating_add(1);
                    reset_idle(&mut idle, config.idle_timeout);
                }
            }
        }
        Ok(stats)
    }

    fn reset_idle(idle: &mut std::pin::Pin<Box<Sleep>>, timeout: Duration) {
        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
    }

    async fn receive_response_batch(
        backend: Backend,
        socket: &UdpSocket,
        batch: &mut MmsgBatch,
        single_buffer: &mut [u8],
        batch_size: usize,
    ) -> Result<(ReceivedBatch, usize)> {
        match backend {
            Backend::Single => {
                let mut calls = 0usize;
                loop {
                    socket.readable().await?;
                    let result = socket.try_io(Interest::READABLE, || {
                        recvfrom_nonblocking(socket.as_raw_fd(), single_buffer)
                    });
                    calls = calls.saturating_add(1);
                    match result {
                        Ok((len, source)) => {
                            return Ok((
                                ReceivedBatch::Single { len, source },
                                calls,
                            ));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            Backend::Mmsg => {
                let mut calls = 0usize;
                loop {
                    socket.readable().await?;
                    let result = socket.try_io(Interest::READABLE, || {
                        batch.recv_from_nonblocking(socket.as_raw_fd(), batch_size)
                    });
                    calls = calls.saturating_add(1);
                    match result {
                        Ok(count) => {
                            return Ok((ReceivedBatch::Mmsg { count }, calls));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
    }

    fn validate_response_source_addr(
        actual: SocketAddr,
        expected: SocketAddr,
    ) -> Result<()> {
        if actual != expected {
            bail!("response from unexpected {actual}; expected {expected}");
        }
        Ok(())
    }

    async fn send_one_to(
        socket: &UdpSocket,
        payload: &[u8],
        target: SocketAddr,
    ) -> Result<usize> {
        let mut calls = 0usize;
        loop {
            socket.writable().await?;
            let result = socket.try_io(Interest::WRITABLE, || {
                sendto_nonblocking(socket.as_raw_fd(), payload, target)
            });
            calls = calls.saturating_add(1);
            match result {
                Ok(sent) if sent == payload.len() => return Ok(calls),
                Ok(_) => bail!("short UDP uplink send_to"),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn send_vec_batch_to(
        socket: &UdpSocket,
        payloads: &[Vec<u8>],
        target: SocketAddr,
    ) -> Result<usize> {
        let mut offset = 0usize;
        let mut calls = 0usize;
        while offset < payloads.len() {
            socket.writable().await?;
            let result = socket.try_io(Interest::WRITABLE, || {
                sendmmsg_vecs_to_nonblocking(
                    socket.as_raw_fd(),
                    &payloads[offset..],
                    target,
                )
            });
            calls = calls.saturating_add(1);
            match result {
                Ok(sent) => {
                    offset = advance_send_offset(offset, payloads.len(), sent)?
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(calls)
    }

    async fn send_one_shared(
        socket: &UdpSocket,
        payload: &[u8],
        target: SocketAddr,
    ) -> Result<(usize, usize)> {
        let mut calls = 0usize;
        let mut would_block = 0usize;
        loop {
            socket.writable().await?;
            let result = socket.try_io(Interest::WRITABLE, || {
                sendto_nonblocking(socket.as_raw_fd(), payload, target)
            });
            calls = calls.saturating_add(1);
            match result {
                Ok(sent) if sent == payload.len() => {
                    return Ok((calls, would_block));
                }
                Ok(_) => bail!("short shared UDP send_to"),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    would_block = would_block.saturating_add(1);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn send_buffer_batch_to(
        socket: &UdpSocket,
        batch: &mut MmsgBatch,
        count: usize,
        target: SocketAddr,
    ) -> Result<(usize, usize)> {
        let mut offset = 0usize;
        let mut calls = 0usize;
        let mut would_block = 0usize;
        while offset < count {
            socket.writable().await?;
            let result = socket.try_io(Interest::WRITABLE, || {
                batch.send_nonblocking_to(socket.as_raw_fd(), offset, count, target)
            });
            calls = calls.saturating_add(1);
            match result {
                Ok(sent) => offset = advance_send_offset(offset, count, sent)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    would_block = would_block.saturating_add(1);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok((calls, would_block))
    }

    fn advance_send_offset(
        offset: usize,
        count: usize,
        sent: usize,
    ) -> io::Result<usize> {
        if sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "datagram batch send returned zero",
            ));
        }
        let next = offset.checked_add(sent).ok_or_else(|| {
            io::Error::other("datagram batch send offset overflow")
        })?;
        if next > count {
            return Err(io::Error::other(
                "datagram batch send exceeded batch length",
            ));
        }
        Ok(next)
    }

    fn recvfrom_nonblocking(
        fd: libc::c_int,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr)> {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len =
            std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let result = unsafe {
            libc::recvfrom(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let source = sockaddr_to_socket_addr(&storage, len).ok_or_else(|| {
            io::Error::other("recvfrom returned a non-IPv4 source")
        })?;
        Ok((result as usize, source))
    }

    fn sendto_nonblocking(
        fd: libc::c_int,
        payload: &[u8],
        target: SocketAddr,
    ) -> io::Result<usize> {
        let (storage, len) = socket_addr_storage(target);
        let result = unsafe {
            libc::sendto(
                fd,
                payload.as_ptr().cast(),
                payload.len(),
                libc::MSG_DONTWAIT,
                (&storage as *const libc::sockaddr_storage).cast(),
                len,
            )
        };
        if result >= 0 {
            Ok(result as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn sendmmsg_vecs_to_nonblocking(
        fd: libc::c_int,
        payloads: &[Vec<u8>],
        target: SocketAddr,
    ) -> io::Result<usize> {
        let mut iovecs = payloads
            .iter()
            .map(|payload| libc::iovec {
                iov_base: payload.as_ptr().cast_mut().cast(),
                iov_len: payload.len(),
            })
            .collect::<Vec<_>>();
        let (storage, len) = socket_addr_storage(target);
        let mut addresses = vec![storage; payloads.len()];
        let mut messages = iovecs
            .iter_mut()
            .zip(addresses.iter_mut())
            .map(|(iov, address)| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: (address as *mut libc::sockaddr_storage).cast(),
                    msg_namelen: len,
                    msg_iov: iov,
                    msg_iovlen: 1,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect::<Vec<_>>();
        let result = unsafe {
            libc::sendmmsg(
                fd,
                messages.as_mut_ptr(),
                messages.len() as u32,
                libc::MSG_DONTWAIT,
            )
        };
        if result > 0 {
            Ok(result as usize)
        } else if result == 0 {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sendmmsg sent zero datagrams",
            ))
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn echo_target(
        socket: StdUdpSocket,
        packets: usize,
        datagram_size: usize,
        barrier: Arc<Barrier>,
    ) -> Result<()> {
        barrier.wait();
        let mut batch = MmsgBatch::new(64, datagram_size);
        let mut total = 0usize;
        while total < packets {
            let count = batch.recv_from(
                socket.as_raw_fd(),
                (packets - total).min(batch.capacity()),
            )?;
            batch.send_back_to_sources(socket.as_raw_fd(), count)?;
            total += count;
        }
        Ok(())
    }

    fn receive_sink(
        socket: StdUdpSocket,
        sessions: usize,
        packets_per_session: usize,
        datagram_size: usize,
        verify: bool,
        barrier: Arc<Barrier>,
        progress: &[Arc<SessionProgress>],
    ) -> Result<SinkStats> {
        barrier.wait();
        let total_packets = sessions
            .checked_mul(packets_per_session)
            .context("sink packet count overflow")?;
        let mut batch = MmsgBatch::new(64, datagram_size);
        let mut received_per_session = vec![0usize; sessions];
        let mut completion = vec![None::<Instant>; sessions];
        let mut distinct_marks = vec![false; sessions];
        let mut touched = Vec::with_capacity(64);
        let mut total = 0usize;
        let mut last_session = None;
        let mut consecutive = 0usize;
        let mut max_consecutive = 0usize;
        let mut distinct_sum = 0usize;
        let mut receive_batches = 0usize;
        let mut max_distinct = 0usize;

        while total < total_packets {
            let count = batch.recv(
                socket.as_raw_fd(),
                (total_packets - total).min(batch.capacity()),
            )?;
            touched.clear();
            for index in 0..count {
                let payload = batch.buffer(index);
                if payload.len() != datagram_size {
                    bail!(
                        "sink received {} bytes; expected {datagram_size}",
                        payload.len()
                    );
                }
                let session_id =
                    u32::from_ne_bytes(payload[..4].try_into()?) as usize;
                if session_id >= sessions {
                    bail!("sink received invalid session id {session_id}");
                }
                let sequence =
                    u64::from_ne_bytes(payload[4..12].try_into()?) as usize;
                let expected = received_per_session[session_id];
                if verify {
                    if sequence != expected {
                        bail!(
                            "session {session_id} sequence {sequence}; expected {expected}"
                        );
                    }
                    if payload[HEADER_SIZE..]
                        .iter()
                        .any(|byte| *byte != PATTERN_BYTE)
                    {
                        bail!(
                            "sink payload mismatch for session {session_id} sequence {sequence}"
                        );
                    }
                }
                received_per_session[session_id] = expected.saturating_add(1);
                progress[session_id]
                    .received
                    .store(received_per_session[session_id], Ordering::Release);
                progress[session_id].notify.notify_one();
                if received_per_session[session_id] == packets_per_session {
                    completion[session_id] = Some(Instant::now());
                }

                if last_session == Some(session_id) {
                    consecutive = consecutive.saturating_add(1);
                } else {
                    last_session = Some(session_id);
                    consecutive = 1;
                }
                max_consecutive = max_consecutive.max(consecutive);
                if !distinct_marks[session_id] {
                    distinct_marks[session_id] = true;
                    touched.push(session_id);
                }
            }
            receive_batches = receive_batches.saturating_add(1);
            distinct_sum = distinct_sum.saturating_add(touched.len());
            max_distinct = max_distinct.max(touched.len());
            for session_id in touched.iter().copied() {
                distinct_marks[session_id] = false;
            }
            total += count;
        }

        if received_per_session
            .iter()
            .any(|count| *count != packets_per_session)
        {
            bail!(
                "sink did not receive the expected packet count for every session"
            );
        }
        let earliest = completion
            .iter()
            .flatten()
            .min()
            .copied()
            .context("sink recorded no session completion")?;
        let latest = completion
            .iter()
            .flatten()
            .max()
            .copied()
            .context("sink recorded no session completion")?;
        Ok(SinkStats {
            packets: total,
            receive_batches,
            max_consecutive_session_packets: max_consecutive,
            mean_distinct_sessions_per_receive_batch: distinct_sum as f64
                / receive_batches.max(1) as f64,
            max_distinct_sessions_per_receive_batch: max_distinct,
            completion_span_seconds: latest.duration_since(earliest).as_secs_f64(),
        })
    }

    struct MmsgBatch {
        buffers: Vec<Vec<u8>>,
        lengths: Vec<usize>,
        addresses: Vec<libc::sockaddr_storage>,
        address_lengths: Vec<libc::socklen_t>,
    }

    impl MmsgBatch {
        fn new(capacity: usize, datagram_size: usize) -> Self {
            Self {
                buffers: (0..capacity).map(|_| vec![0u8; datagram_size]).collect(),
                lengths: vec![0; capacity],
                addresses: vec![unsafe { std::mem::zeroed() }; capacity],
                address_lengths: vec![0; capacity],
            }
        }

        fn capacity(&self) -> usize {
            self.buffers.len()
        }

        fn buffer(&self, index: usize) -> &[u8] {
            &self.buffers[index][..self.lengths[index]]
        }

        fn recv(&mut self, fd: libc::c_int, count: usize) -> io::Result<usize> {
            self.recv_with_flags(fd, count, libc::MSG_WAITFORONE, false)
        }

        fn recv_from(&mut self, fd: libc::c_int, count: usize) -> io::Result<usize> {
            self.recv_with_flags(fd, count, libc::MSG_WAITFORONE, true)
        }

        fn recv_from_nonblocking(
            &mut self,
            fd: libc::c_int,
            count: usize,
        ) -> io::Result<usize> {
            self.recv_with_flags(fd, count, libc::MSG_DONTWAIT, true)
        }

        fn recv_with_flags(
            &mut self,
            fd: libc::c_int,
            count: usize,
            flags: libc::c_int,
            with_addresses: bool,
        ) -> io::Result<usize> {
            let Self {
                buffers,
                lengths,
                addresses,
                address_lengths,
            } = self;
            let mut iovecs = buffers[..count]
                .iter_mut()
                .map(|buffer| libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: buffer.len(),
                })
                .collect::<Vec<_>>();
            let mut messages = (0..count)
                .map(|index| libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: if with_addresses {
                            (&mut addresses[index] as *mut libc::sockaddr_storage)
                                .cast()
                        } else {
                            ptr::null_mut()
                        },
                        msg_namelen: if with_addresses {
                            std::mem::size_of::<libc::sockaddr_storage>() as _
                        } else {
                            0
                        },
                        msg_iov: &mut iovecs[index],
                        msg_iovlen: 1,
                        msg_control: ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                })
                .collect::<Vec<_>>();
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    messages.as_mut_ptr(),
                    count as u32,
                    flags,
                    ptr::null_mut(),
                )
            };
            if result <= 0 {
                return Err(io::Error::last_os_error());
            }
            let received = result as usize;
            for index in 0..received {
                lengths[index] = messages[index].msg_len as usize;
                address_lengths[index] = messages[index].msg_hdr.msg_namelen;
            }
            Ok(received)
        }

        fn send_nonblocking_to(
            &mut self,
            fd: libc::c_int,
            offset: usize,
            count: usize,
            target: SocketAddr,
        ) -> io::Result<usize> {
            let (storage, len) = socket_addr_storage(target);
            for index in offset..count {
                self.addresses[index] = storage;
                self.address_lengths[index] = len;
            }
            self.send_range(fd, offset, count, libc::MSG_DONTWAIT)
        }

        fn send_back_to_sources(
            &mut self,
            fd: libc::c_int,
            count: usize,
        ) -> io::Result<()> {
            let mut offset = 0usize;
            while offset < count {
                let sent = self.send_range(fd, offset, count, 0)?;
                offset = advance_send_offset(offset, count, sent)?;
            }
            Ok(())
        }

        fn send_range(
            &mut self,
            fd: libc::c_int,
            offset: usize,
            count: usize,
            flags: libc::c_int,
        ) -> io::Result<usize> {
            let Self {
                buffers,
                lengths,
                addresses,
                address_lengths,
            } = self;
            let mut iovecs = (offset..count)
                .map(|index| libc::iovec {
                    iov_base: buffers[index].as_ptr().cast_mut().cast(),
                    iov_len: lengths[index],
                })
                .collect::<Vec<_>>();
            let mut messages = (offset..count)
                .enumerate()
                .map(|(message_index, buffer_index)| libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: (&mut addresses[buffer_index]
                            as *mut libc::sockaddr_storage)
                            .cast(),
                        msg_namelen: address_lengths[buffer_index],
                        msg_iov: &mut iovecs[message_index],
                        msg_iovlen: 1,
                        msg_control: ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                })
                .collect::<Vec<_>>();
            let result = unsafe {
                libc::sendmmsg(
                    fd,
                    messages.as_mut_ptr(),
                    messages.len() as u32,
                    flags,
                )
            };
            if result > 0 {
                Ok(result as usize)
            } else if result == 0 {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sendmmsg sent zero datagrams",
                ))
            } else {
                Err(io::Error::last_os_error())
            }
        }

        fn source_addr(&self, index: usize) -> Option<SocketAddr> {
            sockaddr_to_socket_addr(
                &self.addresses[index],
                self.address_lengths[index],
            )
        }
    }

    fn bind_std_udp_loopback() -> io::Result<StdUdpSocket> {
        StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    fn bind_std_udp_any() -> io::Result<StdUdpSocket> {
        StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    }

    fn client_addr_for_session(session_id: usize, port: u16) -> SocketAddr {
        let third = ((session_id / 250) % 256) as u8;
        let fourth = (session_id % 250 + 1) as u8;
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, third, fourth),
            port,
        ))
    }

    fn set_socket_buffers(
        socket: &StdUdpSocket,
        bytes: libc::c_int,
    ) -> io::Result<()> {
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&bytes as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as _,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn socket_addr_storage(
        addr: SocketAddr,
    ) -> (libc::sockaddr_storage, libc::socklen_t) {
        match addr {
            SocketAddr::V4(addr) => {
                let mut storage: libc::sockaddr_storage =
                    unsafe { std::mem::zeroed() };
                let raw = libc::sockaddr_in {
                    sin_family: libc::AF_INET as _,
                    sin_port: addr.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(addr.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    ptr::write(
                        (&mut storage as *mut libc::sockaddr_storage).cast(),
                        raw,
                    );
                }
                (storage, std::mem::size_of::<libc::sockaddr_in>() as _)
            }
            SocketAddr::V6(_) => unreachable!("probe binds only IPv4 sockets"),
        }
    }

    fn sockaddr_to_socket_addr(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        if storage.ss_family as libc::c_int != libc::AF_INET
            || len < std::mem::size_of::<libc::sockaddr_in>() as _
        {
            return None;
        }
        let raw = unsafe {
            &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
        };
        let ip = Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes());
        Some(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(raw.sin_port),
        )))
    }

    fn cpu_seconds() -> io::Result<f64> {
        let mut raw = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, raw.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe { raw.assume_init() };
        Ok(timeval_seconds(raw.ru_utime) + timeval_seconds(raw.ru_stime))
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

        fn args() -> Args {
            Args {
                backend: Backend::Mmsg,
                worker_threads: 2,
                sessions: 2,
                packets_per_session: 32,
                datagram_size: 128,
                uplink_batch_size: 8,
                downlink_batch_size: 16,
                channel_capacity: 32,
                inflight_window: 32,
                idle_timeout_ms: 2_000,
                warmup: 0,
                runs: 1,
                verify: true,
            }
        }

        #[test]
        fn validates_session_and_batch_bounds() {
            let mut args = args();
            assert!(validate_args(&args).is_ok());
            args.sessions = 0;
            assert!(validate_args(&args).is_err());
            args.sessions = 2;
            args.uplink_batch_size = MAX_BATCH_SIZE + 1;
            assert!(validate_args(&args).is_err());
        }

        #[test]
        fn loopback_aliases_are_distinct_and_keep_sink_port() {
            let first = client_addr_for_session(0, 12345);
            let second = client_addr_for_session(1, 12345);
            let later = client_addr_for_session(251, 12345);
            assert_ne!(first, second);
            assert_ne!(second, later);
            assert_eq!(first.port(), 12345);
            assert_eq!(later.port(), 12345);
            assert!(first.ip().is_loopback());
            assert!(later.ip().is_loopback());
        }

        #[test]
        fn partial_batch_send_progress_resumes_without_skipping() {
            let offset = advance_send_offset(0, 8, 3).unwrap();
            assert_eq!(offset, 3);
            let offset = advance_send_offset(offset, 8, 2).unwrap();
            assert_eq!(offset, 5);
            assert_eq!(advance_send_offset(offset, 8, 3).unwrap(), 8);
            assert!(advance_send_offset(0, 8, 0).is_err());
            assert!(advance_send_offset(7, 8, 2).is_err());
        }

        #[test]
        fn mmsg_send_to_multiple_loopback_aliases_preserves_datagrams() {
            let sink = bind_std_udp_any().unwrap();
            sink.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let port = sink.local_addr().unwrap().port();
            let sender = bind_std_udp_loopback().unwrap();
            let payload_a = b"session-a".to_vec();
            let payload_b = b"session-b".to_vec();

            sendmmsg_vecs_to_nonblocking(
                sender.as_raw_fd(),
                std::slice::from_ref(&payload_a),
                client_addr_for_session(0, port),
            )
            .unwrap();
            sendmmsg_vecs_to_nonblocking(
                sender.as_raw_fd(),
                std::slice::from_ref(&payload_b),
                client_addr_for_session(1, port),
            )
            .unwrap();

            let mut received = [false; 2];
            let mut buffer = [0u8; 64];
            for _ in 0..2 {
                let (len, _) = sink.recv_from(&mut buffer).unwrap();
                match &buffer[..len] {
                    b"session-a" => received[0] = true,
                    b"session-b" => received[1] = true,
                    other => panic!("unexpected payload {other:?}"),
                }
            }
            assert_eq!(received, [true, true]);
        }

        #[test]
        fn both_backends_roundtrip_multiple_sessions_over_shared_socket() {
            for backend in [Backend::Single, Backend::Mmsg] {
                let mut args = args();
                args.backend = backend;
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_io()
                    .enable_time()
                    .build()
                    .unwrap();
                let sample = runtime.block_on(run_once(&args)).unwrap();
                assert!(sample.packets_per_second.is_finite());
                assert_eq!(sample.shared_send_would_block, 0);
            }
        }
    }
}
