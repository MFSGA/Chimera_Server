#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("udp_session_probe requires Linux");
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
    const DEFAULT_CHANNEL_CAPACITY: usize = 64;
    const MAX_BATCH_SIZE: usize = 128;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Single,
        Mmsg,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Production-shaped Tokio freedom UDP session batching probe")]
    struct Args {
        #[arg(long, value_enum)]
        backend: Backend,
        #[arg(long, default_value_t = 8)]
        worker_threads: usize,
        #[arg(long, default_value_t = 300_000)]
        packets: usize,
        #[arg(long, default_value_t = 1200)]
        datagram_size: usize,
        #[arg(long, default_value_t = 16)]
        batch_size: usize,
        #[arg(long, default_value_t = DEFAULT_CHANNEL_CAPACITY)]
        channel_capacity: usize,
        #[arg(long, default_value_t = DEFAULT_CHANNEL_CAPACITY)]
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

    #[derive(Debug, Clone, Copy)]
    struct Sample {
        packets_per_second: f64,
        throughput_gbps: f64,
        cpu_seconds_per_million_packets: f64,
        uplink_batches: u64,
        uplink_socket_calls: u64,
        downlink_receive_calls: u64,
        downlink_send_calls: u64,
        max_uplink_batch_packets: u64,
        max_downlink_batch_packets: u64,
        max_outstanding_packets: u64,
        max_consecutive_uplink_packets: u64,
        max_steady_outstanding_packets: u64,
        max_steady_consecutive_uplink_packets: u64,
        idle_resets: u64,
        producer_window_wait_events: u64,
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct SessionStats {
        uplink_packets: u64,
        downlink_packets: u64,
        uplink_batches: u64,
        uplink_socket_calls: u64,
        downlink_receive_calls: u64,
        downlink_send_calls: u64,
        max_uplink_batch_packets: u64,
        max_downlink_batch_packets: u64,
        max_outstanding_packets: u64,
        max_consecutive_uplink_packets: u64,
        max_steady_outstanding_packets: u64,
        max_steady_consecutive_uplink_packets: u64,
        consecutive_uplink_packets: u64,
        idle_resets: u64,
    }

    impl SessionStats {
        fn record_uplink(&mut self, packets: usize, socket_calls: usize) {
            self.uplink_packets = self.uplink_packets.saturating_add(packets as u64);
            self.uplink_batches = self.uplink_batches.saturating_add(1);
            self.uplink_socket_calls =
                self.uplink_socket_calls.saturating_add(socket_calls as u64);
            self.max_uplink_batch_packets =
                self.max_uplink_batch_packets.max(packets as u64);
            self.consecutive_uplink_packets = self
                .consecutive_uplink_packets
                .saturating_add(packets as u64);
            self.max_consecutive_uplink_packets = self
                .max_consecutive_uplink_packets
                .max(self.consecutive_uplink_packets);
            let outstanding =
                self.uplink_packets.saturating_sub(self.downlink_packets);
            self.max_outstanding_packets =
                self.max_outstanding_packets.max(outstanding);
            if self.downlink_packets > 0 {
                self.max_steady_outstanding_packets =
                    self.max_steady_outstanding_packets.max(outstanding);
                self.max_steady_consecutive_uplink_packets = self
                    .max_steady_consecutive_uplink_packets
                    .max(self.consecutive_uplink_packets);
            }
            self.idle_resets = self.idle_resets.saturating_add(1);
        }

        fn record_downlink(
            &mut self,
            packets: usize,
            receive_calls: usize,
            send_calls: usize,
        ) {
            self.downlink_packets =
                self.downlink_packets.saturating_add(packets as u64);
            self.downlink_receive_calls = self
                .downlink_receive_calls
                .saturating_add(receive_calls as u64);
            self.downlink_send_calls =
                self.downlink_send_calls.saturating_add(send_calls as u64);
            self.max_downlink_batch_packets =
                self.max_downlink_batch_packets.max(packets as u64);
            self.consecutive_uplink_packets = 0;
            self.idle_resets = self.idle_resets.saturating_add(1);
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
        let mut uplink_batches = Vec::with_capacity(args.runs);
        let mut uplink_socket_calls = Vec::with_capacity(args.runs);
        let mut downlink_receive_calls = Vec::with_capacity(args.runs);
        let mut downlink_send_calls = Vec::with_capacity(args.runs);
        let mut max_uplink_batch_packets = Vec::with_capacity(args.runs);
        let mut max_downlink_batch_packets = Vec::with_capacity(args.runs);
        let mut max_outstanding_packets = Vec::with_capacity(args.runs);
        let mut max_consecutive_uplink_packets = Vec::with_capacity(args.runs);
        let mut max_steady_outstanding_packets = Vec::with_capacity(args.runs);
        let mut max_steady_consecutive_uplink_packets =
            Vec::with_capacity(args.runs);
        let mut idle_resets = Vec::with_capacity(args.runs);
        let mut producer_window_wait_events = Vec::with_capacity(args.runs);

        for _ in 0..args.runs {
            let sample = runtime.block_on(run_once(&args))?;
            packet_rates.push(sample.packets_per_second);
            throughput.push(sample.throughput_gbps);
            cpu.push(sample.cpu_seconds_per_million_packets);
            uplink_batches.push(sample.uplink_batches as f64);
            uplink_socket_calls.push(sample.uplink_socket_calls as f64);
            downlink_receive_calls.push(sample.downlink_receive_calls as f64);
            downlink_send_calls.push(sample.downlink_send_calls as f64);
            max_uplink_batch_packets.push(sample.max_uplink_batch_packets as f64);
            max_downlink_batch_packets
                .push(sample.max_downlink_batch_packets as f64);
            max_outstanding_packets.push(sample.max_outstanding_packets as f64);
            max_consecutive_uplink_packets
                .push(sample.max_consecutive_uplink_packets as f64);
            max_steady_outstanding_packets
                .push(sample.max_steady_outstanding_packets as f64);
            max_steady_consecutive_uplink_packets
                .push(sample.max_steady_consecutive_uplink_packets as f64);
            idle_resets.push(sample.idle_resets as f64);
            producer_window_wait_events
                .push(sample.producer_window_wait_events as f64);
        }

        let uplink_batches_median = median(&uplink_batches);
        let uplink_socket_calls_median = median(&uplink_socket_calls);
        let downlink_receive_calls_median = median(&downlink_receive_calls);
        let downlink_send_calls_median = median(&downlink_send_calls);
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "record_type": "summary",
                "backend": args.backend,
                "worker_threads": args.worker_threads,
                "runs": args.runs,
                "warmup_runs": args.warmup,
                "packets": args.packets,
                "datagram_size": args.datagram_size,
                "batch_size": args.batch_size,
                "channel_capacity": args.channel_capacity,
                "inflight_window": args.inflight_window,
                "idle_timeout_ms": args.idle_timeout_ms,
                "verify": args.verify,
                "packets_per_second_median": round(median(&packet_rates)),
                "packets_per_second_cv": round(coefficient_of_variation(&packet_rates)),
                "throughput_median_gbps": round(median(&throughput)),
                "cpu_seconds_per_million_packets_median": round(median(&cpu)),
                "cpu_seconds_per_million_packets_cv": round(coefficient_of_variation(&cpu)),
                "uplink_batches_median": round(uplink_batches_median),
                "uplink_packets_per_batch_median": round(
                    args.packets as f64 / uplink_batches_median,
                ),
                "uplink_socket_calls_median": round(uplink_socket_calls_median),
                "uplink_packets_per_socket_call_median": round(
                    args.packets as f64 / uplink_socket_calls_median,
                ),
                "downlink_receive_calls_median": round(downlink_receive_calls_median),
                "downlink_packets_per_receive_call_median": round(
                    args.packets as f64 / downlink_receive_calls_median,
                ),
                "downlink_send_calls_median": round(downlink_send_calls_median),
                "downlink_packets_per_send_call_median": round(
                    args.packets as f64 / downlink_send_calls_median,
                ),
                "max_uplink_batch_packets_median": round(median(&max_uplink_batch_packets)),
                "max_downlink_batch_packets_median": round(median(&max_downlink_batch_packets)),
                "max_outstanding_packets_median": round(median(&max_outstanding_packets)),
                "max_consecutive_uplink_packets_median": round(
                    median(&max_consecutive_uplink_packets),
                ),
                "max_steady_outstanding_packets_median": round(
                    median(&max_steady_outstanding_packets),
                ),
                "max_steady_consecutive_uplink_packets_median": round(
                    median(&max_steady_consecutive_uplink_packets),
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
        if args.packets == 0 {
            bail!("--packets must be greater than zero");
        }
        if !(8..=65_507).contains(&args.datagram_size) {
            bail!("--datagram-size must be between 8 and 65507");
        }
        if args.batch_size == 0 || args.batch_size > MAX_BATCH_SIZE {
            bail!("--batch-size must be between 1 and {MAX_BATCH_SIZE}");
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
        Ok(())
    }

    async fn run_once(args: &Args) -> Result<Sample> {
        let target = bind_std_udp()?;
        let sink = bind_std_udp()?;
        set_socket_buffers(&target, 4 * 1024 * 1024)?;
        set_socket_buffers(&sink, 4 * 1024 * 1024)?;
        target.set_read_timeout(Some(Duration::from_secs(10)))?;
        target.set_write_timeout(Some(Duration::from_secs(10)))?;
        sink.set_read_timeout(Some(Duration::from_secs(10)))?;

        let target_addr = target.local_addr()?;
        let sink_addr = sink.local_addr()?;
        let barrier = Arc::new(Barrier::new(3));
        let sink_progress = Arc::new(AtomicUsize::new(0));
        let sink_notify = Arc::new(Notify::new());

        let echo_barrier = Arc::clone(&barrier);
        let datagram_size = args.datagram_size;
        let packets = args.packets;
        let echo_thread = thread::spawn(move || {
            echo_target(target, packets, datagram_size, echo_barrier)
        });

        let sink_barrier = Arc::clone(&barrier);
        let sink_done = Arc::clone(&sink_progress);
        let sink_notify_thread = Arc::clone(&sink_notify);
        let verify = args.verify;
        let sink_thread = thread::spawn(move || {
            receive_sink(
                sink,
                packets,
                datagram_size,
                verify,
                sink_barrier,
                &sink_done,
                &sink_notify_thread,
            )
        });

        let outbound_std = bind_std_udp()?;
        let server_std = bind_std_udp()?;
        set_socket_buffers(&outbound_std, 4 * 1024 * 1024)?;
        set_socket_buffers(&server_std, 4 * 1024 * 1024)?;
        outbound_std.connect(target_addr)?;
        server_std.connect(sink_addr)?;
        outbound_std.set_nonblocking(true)?;
        server_std.set_nonblocking(true)?;
        let outbound_socket = UdpSocket::from_std(outbound_std)?;
        let server_socket = UdpSocket::from_std(server_std)?;

        let (sender, receiver) = mpsc::channel(args.channel_capacity);
        let producer_packets = args.packets;
        let producer_datagram_size = args.datagram_size;
        let producer_inflight_window = args.inflight_window;
        let producer_sink_progress = Arc::clone(&sink_progress);
        let producer_sink_notify = Arc::clone(&sink_notify);
        let producer = tokio::spawn(async move {
            produce_payloads(
                sender,
                producer_packets,
                producer_datagram_size,
                producer_inflight_window,
                &producer_sink_progress,
                &producer_sink_notify,
            )
            .await
        });

        barrier.wait();
        let cpu_before = cpu_seconds()?;
        let started = Instant::now();
        let stats = run_session(
            args.backend,
            &outbound_socket,
            &server_socket,
            receiver,
            args,
        )
        .await?;
        let producer_window_wait_events =
            producer.await.context("producer task panicked")??;
        let sink_count = sink_thread
            .join()
            .map_err(|_| anyhow::anyhow!("sink thread panicked"))??;
        echo_thread
            .join()
            .map_err(|_| anyhow::anyhow!("echo thread panicked"))??;
        let elapsed = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds()? - cpu_before;

        if sink_count != args.packets {
            bail!(
                "sink received {sink_count} packets; expected {}",
                args.packets
            );
        }
        if stats.downlink_packets != args.packets as u64 {
            bail!(
                "session forwarded {} responses; expected {}",
                stats.downlink_packets,
                args.packets
            );
        }

        let packets_per_second =
            args.packets as f64 / elapsed.max(f64::MIN_POSITIVE);
        Ok(Sample {
            packets_per_second,
            throughput_gbps: packets_per_second * args.datagram_size as f64 * 8.0
                / 1e9,
            cpu_seconds_per_million_packets: cpu
                / (args.packets as f64 / 1_000_000.0),
            uplink_batches: stats.uplink_batches,
            uplink_socket_calls: stats.uplink_socket_calls,
            downlink_receive_calls: stats.downlink_receive_calls,
            downlink_send_calls: stats.downlink_send_calls,
            max_uplink_batch_packets: stats.max_uplink_batch_packets,
            max_downlink_batch_packets: stats.max_downlink_batch_packets,
            max_outstanding_packets: stats.max_outstanding_packets,
            max_consecutive_uplink_packets: stats.max_consecutive_uplink_packets,
            max_steady_outstanding_packets: stats.max_steady_outstanding_packets,
            max_steady_consecutive_uplink_packets: stats
                .max_steady_consecutive_uplink_packets,
            idle_resets: stats.idle_resets,
            producer_window_wait_events,
        })
    }

    async fn produce_payloads(
        sender: mpsc::Sender<Vec<u8>>,
        packets: usize,
        datagram_size: usize,
        inflight_window: usize,
        sink_progress: &AtomicUsize,
        sink_notify: &Notify,
    ) -> Result<u64> {
        let mut window_wait_events = 0_u64;
        for sequence in 0..packets {
            while sequence.saturating_sub(sink_progress.load(Ordering::Acquire))
                >= inflight_window
            {
                window_wait_events = window_wait_events.saturating_add(1);
                let notified = sink_notify.notified();
                if sequence.saturating_sub(sink_progress.load(Ordering::Acquire))
                    < inflight_window
                {
                    break;
                }
                notified.await;
            }
            let mut payload = vec![PATTERN_BYTE; datagram_size];
            payload[..8].copy_from_slice(&(sequence as u64).to_ne_bytes());
            sender.send(payload).await.map_err(|_| {
                anyhow::anyhow!("session channel closed during production")
            })?;
        }
        Ok(window_wait_events)
    }

    async fn run_session(
        backend: Backend,
        outbound_socket: &UdpSocket,
        server_socket: &UdpSocket,
        mut receiver: mpsc::Receiver<Vec<u8>>,
        args: &Args,
    ) -> Result<SessionStats> {
        let idle_timeout = Duration::from_millis(args.idle_timeout_ms);
        let mut idle = Box::pin(sleep(idle_timeout));
        let mut stats = SessionStats::default();
        let mut response_batch = MmsgBatch::new(args.batch_size, args.datagram_size);
        let mut channel_batch = Vec::with_capacity(args.batch_size);

        while stats.downlink_packets < args.packets as u64 {
            tokio::select! {
                _ = idle.as_mut() => {
                    bail!(
                        "session expired with {} uplink and {} downlink packets",
                        stats.uplink_packets,
                        stats.downlink_packets,
                    );
                }
                maybe_payload = receiver.recv(), if stats.uplink_packets < args.packets as u64 => {
                    let Some(payload) = maybe_payload else {
                        bail!("session channel closed before all packets were sent");
                    };
                    match backend {
                        Backend::Single => {
                            if outbound_socket
                                .send(&payload)
                                .await
                                .context("single session uplink send failed")?
                                != payload.len()
                            {
                                bail!("short UDP uplink send");
                            }
                            stats.record_uplink(1, 1);
                        }
                        Backend::Mmsg => {
                            channel_batch.clear();
                            channel_batch.push(payload);
                            while channel_batch.len() < args.batch_size {
                                match receiver.try_recv() {
                                    Ok(payload) => channel_batch.push(payload),
                                    Err(mpsc::error::TryRecvError::Empty) => break,
                                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                                }
                            }
                            let calls = send_vec_batch(outbound_socket, &channel_batch).await?;
                            stats.record_uplink(channel_batch.len(), calls);
                        }
                    }
                    reset_idle(&mut idle, idle_timeout);
                }
                response = receive_responses(
                    backend,
                    outbound_socket,
                    &mut response_batch,
                    args.batch_size,
                ) => {
                    let (received, receive_calls) = response?;
                    if received == 0 {
                        bail!("UDP response receive returned zero datagrams");
                    }
                    let send_calls = match backend {
                        Backend::Single => {
                            let payload = response_batch.buffer(0);
                            if server_socket
                                .send(payload)
                                .await
                                .context("single session downlink send failed")?
                                != payload.len()
                            {
                                bail!("short UDP downlink send");
                            }
                            1
                        }
                        Backend::Mmsg => {
                            send_buffer_batch(server_socket, &mut response_batch, received).await?
                        }
                    };
                    stats.record_downlink(received, receive_calls, send_calls);
                    reset_idle(&mut idle, idle_timeout);
                }
            }
        }
        Ok(stats)
    }

    fn reset_idle(idle: &mut std::pin::Pin<Box<Sleep>>, timeout: Duration) {
        idle.as_mut().reset(tokio::time::Instant::now() + timeout);
    }

    async fn receive_responses(
        backend: Backend,
        socket: &UdpSocket,
        batch: &mut MmsgBatch,
        batch_size: usize,
    ) -> Result<(usize, usize)> {
        match backend {
            Backend::Single => {
                let received = socket
                    .recv(batch.buffer_mut(0))
                    .await
                    .context("single session response receive failed")?;
                batch.set_len(0, received);
                Ok((1, 1))
            }
            Backend::Mmsg => {
                let mut calls = 0usize;
                loop {
                    socket.readable().await?;
                    let result = socket.try_io(Interest::READABLE, || {
                        batch.recv_nonblocking(socket.as_raw_fd(), batch_size)
                    });
                    calls = calls.saturating_add(1);
                    match result {
                        Ok(received) => return Ok((received, calls)),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
    }

    async fn send_vec_batch(
        socket: &UdpSocket,
        payloads: &[Vec<u8>],
    ) -> Result<usize> {
        let mut offset = 0usize;
        let mut calls = 0usize;
        while offset < payloads.len() {
            socket.writable().await?;
            let result = socket.try_io(Interest::WRITABLE, || {
                sendmmsg_vecs_nonblocking(socket.as_raw_fd(), &payloads[offset..])
            });
            calls = calls.saturating_add(1);
            match result {
                Ok(sent) => offset += sent,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(calls)
    }

    async fn send_buffer_batch(
        socket: &UdpSocket,
        batch: &mut MmsgBatch,
        count: usize,
    ) -> Result<usize> {
        let mut offset = 0usize;
        let mut calls = 0usize;
        while offset < count {
            socket.writable().await?;
            let result = socket.try_io(Interest::WRITABLE, || {
                batch.send_nonblocking(socket.as_raw_fd(), offset, count)
            });
            calls = calls.saturating_add(1);
            match result {
                Ok(sent) => offset += sent,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(calls)
    }

    fn sendmmsg_vecs_nonblocking(
        fd: libc::c_int,
        payloads: &[Vec<u8>],
    ) -> io::Result<usize> {
        let mut iovecs = payloads
            .iter()
            .map(|payload| libc::iovec {
                iov_base: payload.as_ptr().cast_mut().cast(),
                iov_len: payload.len(),
            })
            .collect::<Vec<_>>();
        let mut messages = iovecs
            .iter_mut()
            .map(|iov| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: ptr::null_mut(),
                    msg_namelen: 0,
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
        let mut peer = None;
        while total < packets {
            let count = batch.recv_from(
                socket.as_raw_fd(),
                (packets - total).min(batch.capacity()),
            )?;
            if peer.is_none() {
                peer = batch.source_addr(0);
            }
            let peer = peer.context("echo target did not receive a peer address")?;
            batch.send_to(socket.as_raw_fd(), count, peer)?;
            total += count;
        }
        Ok(())
    }

    fn receive_sink(
        socket: StdUdpSocket,
        packets: usize,
        datagram_size: usize,
        verify: bool,
        barrier: Arc<Barrier>,
        sink_progress: &AtomicUsize,
        sink_notify: &Notify,
    ) -> Result<usize> {
        barrier.wait();
        let mut batch = MmsgBatch::new(64, datagram_size);
        let mut total = 0usize;
        while total < packets {
            let count = batch
                .recv(socket.as_raw_fd(), (packets - total).min(batch.capacity()))?;
            for index in 0..count {
                let payload = batch.buffer(index);
                if payload.len() != datagram_size {
                    bail!(
                        "sink received {} bytes; expected {datagram_size}",
                        payload.len()
                    );
                }
                if verify {
                    let sequence = u64::from_ne_bytes(payload[..8].try_into()?);
                    let expected = (total + index) as u64;
                    if sequence != expected {
                        bail!("sink sequence {sequence}; expected {expected}");
                    }
                    if payload[8..].iter().any(|byte| *byte != PATTERN_BYTE) {
                        bail!("sink payload mismatch at sequence {sequence}");
                    }
                }
            }
            total += count;
            sink_progress.store(total, Ordering::Release);
            sink_notify.notify_one();
        }
        Ok(total)
    }

    struct MmsgBatch {
        buffers: Vec<Vec<u8>>,
        iovecs: Vec<libc::iovec>,
        messages: Vec<libc::mmsghdr>,
        addresses: Vec<libc::sockaddr_storage>,
    }

    impl MmsgBatch {
        fn new(capacity: usize, datagram_size: usize) -> Self {
            let mut buffers = (0..capacity)
                .map(|_| vec![0u8; datagram_size])
                .collect::<Vec<_>>();
            let mut iovecs = buffers
                .iter_mut()
                .map(|buffer| libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: buffer.len(),
                })
                .collect::<Vec<_>>();
            let mut addresses = vec![unsafe { std::mem::zeroed() }; capacity];
            let messages = (0..capacity)
                .map(|index| libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: (&mut addresses[index]
                            as *mut libc::sockaddr_storage)
                            .cast(),
                        msg_namelen: std::mem::size_of::<libc::sockaddr_storage>()
                            as _,
                        msg_iov: &mut iovecs[index],
                        msg_iovlen: 1,
                        msg_control: ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                })
                .collect();
            Self {
                buffers,
                iovecs,
                messages,
                addresses,
            }
        }

        fn capacity(&self) -> usize {
            self.messages.len()
        }

        fn buffer(&self, index: usize) -> &[u8] {
            &self.buffers[index][..self.messages[index].msg_len as usize]
        }

        fn buffer_mut(&mut self, index: usize) -> &mut [u8] {
            &mut self.buffers[index]
        }

        fn set_len(&mut self, index: usize, len: usize) {
            self.messages[index].msg_len = len as u32;
        }

        fn reset_for_receive(&mut self, count: usize, with_addresses: bool) {
            for index in 0..count {
                self.iovecs[index].iov_len = self.buffers[index].len();
                self.messages[index].msg_len = 0;
                self.messages[index].msg_hdr.msg_flags = 0;
                self.messages[index].msg_hdr.msg_namelen = if with_addresses {
                    std::mem::size_of::<libc::sockaddr_storage>() as _
                } else {
                    0
                };
                self.messages[index].msg_hdr.msg_name = if with_addresses {
                    (&mut self.addresses[index] as *mut libc::sockaddr_storage)
                        .cast()
                } else {
                    ptr::null_mut()
                };
            }
        }

        fn recv(&mut self, fd: libc::c_int, count: usize) -> io::Result<usize> {
            self.reset_for_receive(count, false);
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    count as u32,
                    libc::MSG_WAITFORONE,
                    ptr::null_mut(),
                )
            };
            if result > 0 {
                Ok(result as usize)
            } else {
                Err(io::Error::last_os_error())
            }
        }

        fn recv_from(&mut self, fd: libc::c_int, count: usize) -> io::Result<usize> {
            self.reset_for_receive(count, true);
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    count as u32,
                    libc::MSG_WAITFORONE,
                    ptr::null_mut(),
                )
            };
            if result > 0 {
                Ok(result as usize)
            } else {
                Err(io::Error::last_os_error())
            }
        }

        fn recv_nonblocking(
            &mut self,
            fd: libc::c_int,
            count: usize,
        ) -> io::Result<usize> {
            self.reset_for_receive(count, false);
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    count as u32,
                    libc::MSG_DONTWAIT,
                    ptr::null_mut(),
                )
            };
            if result > 0 {
                Ok(result as usize)
            } else {
                Err(io::Error::last_os_error())
            }
        }

        fn send_nonblocking(
            &mut self,
            fd: libc::c_int,
            offset: usize,
            count: usize,
        ) -> io::Result<usize> {
            for index in offset..count {
                self.iovecs[index].iov_len = self.messages[index].msg_len as usize;
                self.messages[index].msg_hdr.msg_name = ptr::null_mut();
                self.messages[index].msg_hdr.msg_namelen = 0;
            }
            let result = unsafe {
                libc::sendmmsg(
                    fd,
                    self.messages[offset..count].as_mut_ptr(),
                    (count - offset) as u32,
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

        fn send_to(
            &mut self,
            fd: libc::c_int,
            count: usize,
            peer: SocketAddr,
        ) -> io::Result<()> {
            let (storage, len) = socket_addr_storage(peer);
            for index in 0..count {
                self.iovecs[index].iov_len = self.messages[index].msg_len as usize;
                self.addresses[index] = storage;
                self.messages[index].msg_hdr.msg_name = (&mut self.addresses[index]
                    as *mut libc::sockaddr_storage)
                    .cast();
                self.messages[index].msg_hdr.msg_namelen = len;
            }
            let mut offset = 0usize;
            while offset < count {
                let result = unsafe {
                    libc::sendmmsg(
                        fd,
                        self.messages[offset..count].as_mut_ptr(),
                        (count - offset) as u32,
                        0,
                    )
                };
                if result <= 0 {
                    return Err(io::Error::last_os_error());
                }
                offset += result as usize;
            }
            Ok(())
        }

        fn source_addr(&self, index: usize) -> Option<SocketAddr> {
            sockaddr_to_socket_addr(
                &self.addresses[index],
                self.messages[index].msg_hdr.msg_namelen,
            )
        }
    }

    fn bind_std_udp() -> io::Result<StdUdpSocket> {
        StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
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
            SocketAddr::V6(_) => {
                unreachable!("probe binds only IPv4 loopback sockets")
            }
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

        fn args(backend: Backend) -> Args {
            Args {
                backend,
                worker_threads: 2,
                packets: 1024,
                datagram_size: 256,
                batch_size: 16,
                channel_capacity: DEFAULT_CHANNEL_CAPACITY,
                inflight_window: DEFAULT_CHANNEL_CAPACITY,
                idle_timeout_ms: 1000,
                warmup: 0,
                runs: 1,
                verify: true,
            }
        }

        #[test]
        fn validates_batch_and_channel_boundaries() {
            let mut value = args(Backend::Mmsg);
            value.batch_size = 0;
            assert!(validate_args(&value).is_err());
            value.batch_size = MAX_BATCH_SIZE + 1;
            assert!(validate_args(&value).is_err());
            value.batch_size = 16;
            value.channel_capacity = 0;
            assert!(validate_args(&value).is_err());
            value.channel_capacity = DEFAULT_CHANNEL_CAPACITY;
            value.inflight_window = 0;
            assert!(validate_args(&value).is_err());
        }

        #[test]
        fn both_backends_preserve_session_datagrams() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            for backend in [Backend::Single, Backend::Mmsg] {
                let sample = runtime.block_on(run_once(&args(backend))).unwrap();
                assert!(sample.uplink_batches > 0);
                assert!(sample.downlink_receive_calls > 0);
            }
        }

        #[test]
        fn idle_timeout_ends_quiet_session() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            let mut value = args(Backend::Single);
            value.packets = 1;
            value.idle_timeout_ms = 20;
            let result = runtime.block_on(async {
                let outbound =
                    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let server =
                    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let (_sender, receiver) = mpsc::channel(value.channel_capacity);
                run_session(value.backend, &outbound, &server, receiver, &value)
                    .await
            });
            assert!(result.unwrap_err().to_string().contains("session expired"));
        }

        #[test]
        fn batching_never_exceeds_configured_bound() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            let value = args(Backend::Mmsg);
            let sample = runtime.block_on(run_once(&value)).unwrap();
            assert!(
                sample.uplink_batches >= (value.packets / value.batch_size) as u64
            );
            assert!(sample.max_uplink_batch_packets <= value.batch_size as u64);
            assert!(sample.max_downlink_batch_packets <= value.batch_size as u64);
            assert!(sample.max_consecutive_uplink_packets <= value.packets as u64);
        }
    }
}
