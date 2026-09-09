#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("udp_probe requires Linux");
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
        net::{Ipv4Addr, SocketAddrV4, UdpSocket},
        os::fd::AsRawFd,
        ptr,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use anyhow::{Result, bail};
    use chimera_perf::stats::{coefficient_of_variation, median};
    use clap::{Parser, ValueEnum};
    use serde::Serialize;
    use tokio::{io::Interest, runtime::Runtime, sync::Notify};

    const PATTERN_BYTE: u8 = 0x5a;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Single,
        Mmsg,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum RelayModel {
        Blocking,
        Tokio,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Loopback UDP relay microbenchmark for syscall batching")]
    struct Args {
        #[arg(long, value_enum)]
        backend: Backend,
        #[arg(long, value_enum, default_value_t = RelayModel::Blocking)]
        relay_model: RelayModel,
        #[arg(long, default_value_t = 1)]
        worker_threads: usize,
        #[arg(long, default_value_t = 200_000)]
        packets: usize,
        #[arg(long, default_value_t = 1200)]
        datagram_size: usize,
        #[arg(long, default_value_t = 32)]
        batch_size: usize,
        #[arg(long)]
        harness_batch_size: Option<usize>,
        #[arg(long, default_value_t = 64)]
        inflight_window: usize,
        #[arg(long, default_value_t = 2)]
        warmup: usize,
        #[arg(long, default_value_t = 10)]
        runs: usize,
        #[arg(long)]
        verify: bool,
    }

    #[derive(Debug, Clone, Copy)]
    struct Sample {
        packets_per_second: f64,
        throughput_gbps: f64,
        cpu_seconds_per_million_packets: f64,
        relay_calling_thread_cpu_seconds_per_million_packets: f64,
        relay_receive_calls: u64,
        relay_send_calls: u64,
        relay_window_wait_events: u64,
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct RelayStats {
        receive_calls: u64,
        send_calls: u64,
        window_wait_events: u64,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        let runtime = match args.relay_model {
            RelayModel::Blocking => None,
            RelayModel::Tokio => Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(args.worker_threads)
                    .enable_io()
                    .build()?,
            ),
        };
        for _ in 0..args.warmup {
            let _ = run_once(&args, runtime.as_ref())?;
        }

        let mut packet_rates = Vec::with_capacity(args.runs);
        let mut throughput = Vec::with_capacity(args.runs);
        let mut cpu = Vec::with_capacity(args.runs);
        let mut relay_calling_thread_cpu = Vec::with_capacity(args.runs);
        let mut relay_receive_calls = Vec::with_capacity(args.runs);
        let mut relay_send_calls = Vec::with_capacity(args.runs);
        let mut relay_window_wait_events = Vec::with_capacity(args.runs);
        for _ in 0..args.runs {
            let sample = run_once(&args, runtime.as_ref())?;
            packet_rates.push(sample.packets_per_second);
            throughput.push(sample.throughput_gbps);
            cpu.push(sample.cpu_seconds_per_million_packets);
            relay_calling_thread_cpu
                .push(sample.relay_calling_thread_cpu_seconds_per_million_packets);
            relay_receive_calls.push(sample.relay_receive_calls as f64);
            relay_send_calls.push(sample.relay_send_calls as f64);
            relay_window_wait_events.push(sample.relay_window_wait_events as f64);
        }

        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "record_type": "summary",
                "backend": args.backend,
                "relay_model": args.relay_model,
                "worker_threads": args.worker_threads,
                "runs": args.runs,
                "warmup_runs": args.warmup,
                "packets": args.packets,
                "datagram_size": args.datagram_size,
                "batch_size": args.batch_size,
                "harness_batch_size": args.harness_batch_size.unwrap_or(args.batch_size),
                "inflight_window": args.inflight_window,
                "verify": args.verify,
                "packets_per_second_median": round(median(&packet_rates)),
                "packets_per_second_cv": round(coefficient_of_variation(&packet_rates)),
                "throughput_median_gbps": round(median(&throughput)),
                "cpu_seconds_per_million_packets_median": round(median(&cpu)),
                "cpu_seconds_per_million_packets_cv": round(coefficient_of_variation(&cpu)),
                "relay_calling_thread_cpu_seconds_per_million_packets_median": round(
                    median(&relay_calling_thread_cpu),
                ),
                "relay_calling_thread_cpu_seconds_per_million_packets_cv": round(
                    coefficient_of_variation(&relay_calling_thread_cpu),
                ),
                "relay_receive_calls_median": round(median(&relay_receive_calls)),
                "relay_send_calls_median": round(median(&relay_send_calls)),
                "relay_packets_per_receive_call_median": round(
                    args.packets as f64 / median(&relay_receive_calls),
                ),
                "relay_packets_per_send_call_median": round(
                    args.packets as f64 / median(&relay_send_calls),
                ),
                "relay_window_wait_events_median": round(median(&relay_window_wait_events)),
            })
        );
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        if args.packets == 0 {
            bail!("--packets must be greater than zero");
        }
        if args.worker_threads == 0 {
            bail!("--worker-threads must be greater than zero");
        }
        if !(8..=65_507).contains(&args.datagram_size) {
            bail!("--datagram-size must be between 8 and 65507");
        }
        if args.batch_size == 0 || args.batch_size > 128 {
            bail!("--batch-size must be between 1 and 128");
        }
        if args
            .harness_batch_size
            .is_some_and(|size| size == 0 || size > 128)
        {
            bail!("--harness-batch-size must be between 1 and 128");
        }
        if args.inflight_window == 0 {
            bail!("--inflight-window must be greater than zero");
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        Ok(())
    }

    fn run_once(args: &Args, runtime: Option<&Runtime>) -> Result<Sample> {
        let relay_ingress = bind_udp()?;
        let relay_egress = bind_udp()?;
        let source = bind_udp()?;
        let sink = bind_udp()?;
        source.connect(relay_ingress.local_addr()?)?;
        relay_egress.connect(sink.local_addr()?)?;
        for socket in [&relay_ingress, &relay_egress, &source, &sink] {
            socket.set_read_timeout(Some(Duration::from_secs(10)))?;
            socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        }

        let barrier = Arc::new(Barrier::new(3));
        let relay_progress = Arc::new(AtomicUsize::new(0));
        let sink_progress = Arc::new(AtomicUsize::new(0));
        let sink_notify = Arc::new(Notify::new());

        let source_barrier = Arc::clone(&barrier);
        let source_progress = Arc::clone(&relay_progress);
        let packets = args.packets;
        let datagram_size = args.datagram_size;
        let batch_size = args.harness_batch_size.unwrap_or(args.batch_size);
        let inflight_window = args.inflight_window;
        let source_thread = thread::spawn(move || {
            source_barrier.wait();
            send_generated(
                &source,
                packets,
                datagram_size,
                batch_size,
                inflight_window,
                &source_progress,
            )
        });

        let sink_barrier = Arc::clone(&barrier);
        let sink_done = Arc::clone(&sink_progress);
        let sink_notify_thread = Arc::clone(&sink_notify);
        let verify = args.verify;
        let sink_thread = thread::spawn(move || {
            sink_barrier.wait();
            receive_sink(
                &sink,
                packets,
                datagram_size,
                batch_size,
                verify,
                &sink_done,
                &sink_notify_thread,
            )
        });

        let cpu_before = cpu_seconds()?;
        let relay_calling_thread_cpu_before = thread_cpu_seconds()?;
        let started = Instant::now();
        barrier.wait();
        let relay_stats = match args.relay_model {
            RelayModel::Blocking => match args.backend {
                Backend::Single => relay_single(
                    &relay_ingress,
                    &relay_egress,
                    args,
                    &relay_progress,
                    &sink_progress,
                )?,
                Backend::Mmsg => relay_mmsg(
                    &relay_ingress,
                    &relay_egress,
                    args,
                    &relay_progress,
                    &sink_progress,
                )?,
            },
            RelayModel::Tokio => {
                relay_ingress.set_nonblocking(true)?;
                relay_egress.set_nonblocking(true)?;
                let runtime = runtime.expect("tokio relay model has a runtime");
                let enter = runtime.enter();
                let ingress = tokio::net::UdpSocket::from_std(relay_ingress)?;
                let egress = tokio::net::UdpSocket::from_std(relay_egress)?;
                drop(enter);
                match args.backend {
                    Backend::Single => runtime.block_on(relay_single_tokio(
                        &ingress,
                        &egress,
                        args,
                        &relay_progress,
                        &sink_progress,
                        &sink_notify,
                    ))?,
                    Backend::Mmsg => runtime.block_on(relay_mmsg_tokio(
                        &ingress,
                        &egress,
                        args,
                        &relay_progress,
                        &sink_progress,
                        &sink_notify,
                    ))?,
                }
            }
        };
        let relay_calling_thread_cpu =
            thread_cpu_seconds()? - relay_calling_thread_cpu_before;
        source_thread
            .join()
            .map_err(|_| anyhow::anyhow!("source thread panicked"))??;
        sink_thread
            .join()
            .map_err(|_| anyhow::anyhow!("sink thread panicked"))??;
        let elapsed = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds()? - cpu_before;
        let packets_per_second =
            args.packets as f64 / elapsed.max(f64::MIN_POSITIVE);
        Ok(Sample {
            packets_per_second,
            throughput_gbps: packets_per_second * args.datagram_size as f64 * 8.0
                / 1e9,
            cpu_seconds_per_million_packets: cpu
                / (args.packets as f64 / 1_000_000.0),
            relay_calling_thread_cpu_seconds_per_million_packets:
                relay_calling_thread_cpu / (args.packets as f64 / 1_000_000.0),
            relay_receive_calls: relay_stats.receive_calls,
            relay_send_calls: relay_stats.send_calls,
            relay_window_wait_events: relay_stats.window_wait_events,
        })
    }

    fn bind_udp() -> io::Result<UdpSocket> {
        UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    fn relay_single(
        ingress: &UdpSocket,
        egress: &UdpSocket,
        args: &Args,
        relay_progress: &AtomicUsize,
        sink_progress: &AtomicUsize,
    ) -> Result<RelayStats> {
        let mut buffer = vec![0_u8; args.datagram_size];
        let mut window_wait_events = 0_u64;
        for relayed in 0..args.packets {
            let len = ingress.recv(&mut buffer)?;
            if len != args.datagram_size {
                bail!(
                    "unexpected UDP datagram size {len}; expected {}",
                    args.datagram_size
                );
            }
            window_wait_events = window_wait_events.saturating_add(wait_for_window(
                relayed,
                sink_progress,
                args.inflight_window,
            ));
            if egress.send(&buffer[..len])? != len {
                bail!("short UDP send");
            }
            relay_progress.store(relayed + 1, Ordering::Release);
        }
        Ok(RelayStats {
            receive_calls: args.packets as u64,
            send_calls: args.packets as u64,
            window_wait_events,
        })
    }

    fn relay_mmsg(
        ingress: &UdpSocket,
        egress: &UdpSocket,
        args: &Args,
        relay_progress: &AtomicUsize,
        sink_progress: &AtomicUsize,
    ) -> Result<RelayStats> {
        let mut batch = MmsgBatch::new(args.batch_size, args.datagram_size);
        let mut relayed = 0usize;
        let mut receive_calls = 0_u64;
        let mut send_calls = 0_u64;
        let mut window_wait_events = 0_u64;
        while relayed < args.packets {
            let received = batch.recv(
                ingress.as_raw_fd(),
                (args.packets - relayed).min(args.batch_size),
            )?;
            receive_calls = receive_calls.saturating_add(1);
            if received == 0 {
                bail!("recvmmsg returned zero datagrams");
            }
            window_wait_events = window_wait_events.saturating_add(wait_for_window(
                relayed.saturating_add(received - 1),
                sink_progress,
                args.inflight_window,
            ));
            send_calls = send_calls
                .saturating_add(batch.send(egress.as_raw_fd(), received)? as u64);
            relayed += received;
            relay_progress.store(relayed, Ordering::Release);
        }
        Ok(RelayStats {
            receive_calls,
            send_calls,
            window_wait_events,
        })
    }

    async fn relay_single_tokio(
        ingress: &tokio::net::UdpSocket,
        egress: &tokio::net::UdpSocket,
        args: &Args,
        relay_progress: &AtomicUsize,
        sink_progress: &AtomicUsize,
        sink_notify: &Notify,
    ) -> Result<RelayStats> {
        let mut buffer = vec![0_u8; args.datagram_size];
        let mut window_wait_events = 0_u64;
        for relayed in 0..args.packets {
            let len = ingress.recv(&mut buffer).await?;
            if len != args.datagram_size {
                bail!(
                    "unexpected UDP datagram size {len}; expected {}",
                    args.datagram_size
                );
            }
            window_wait_events = window_wait_events.saturating_add(
                wait_for_window_async(
                    relayed,
                    sink_progress,
                    args.inflight_window,
                    sink_notify,
                )
                .await,
            );
            if egress.send(&buffer[..len]).await? != len {
                bail!("short UDP send");
            }
            relay_progress.store(relayed + 1, Ordering::Release);
        }
        Ok(RelayStats {
            receive_calls: args.packets as u64,
            send_calls: args.packets as u64,
            window_wait_events,
        })
    }

    async fn relay_mmsg_tokio(
        ingress: &tokio::net::UdpSocket,
        egress: &tokio::net::UdpSocket,
        args: &Args,
        relay_progress: &AtomicUsize,
        sink_progress: &AtomicUsize,
        sink_notify: &Notify,
    ) -> Result<RelayStats> {
        let mut batch = MmsgBatch::new(args.batch_size, args.datagram_size);
        let mut relayed = 0usize;
        let mut receive_calls = 0_u64;
        let mut send_calls = 0_u64;
        let mut window_wait_events = 0_u64;
        while relayed < args.packets {
            let count = (args.packets - relayed).min(args.batch_size);
            let received = loop {
                ingress.readable().await?;
                let result = ingress.try_io(Interest::READABLE, || {
                    batch.recv_nonblocking(ingress.as_raw_fd(), count)
                });
                receive_calls = receive_calls.saturating_add(1);
                match result {
                    Ok(received) => break received,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            if received == 0 {
                bail!("recvmmsg returned zero datagrams");
            }
            window_wait_events = window_wait_events.saturating_add(
                wait_for_window_async(
                    relayed.saturating_add(received - 1),
                    sink_progress,
                    args.inflight_window,
                    sink_notify,
                )
                .await,
            );

            let mut sent = 0usize;
            while sent < received {
                egress.writable().await?;
                let result = egress.try_io(Interest::WRITABLE, || {
                    batch.send_nonblocking(egress.as_raw_fd(), sent, received)
                });
                send_calls = send_calls.saturating_add(1);
                match result {
                    Ok(count) => sent += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            relayed += received;
            relay_progress.store(relayed, Ordering::Release);
        }
        Ok(RelayStats {
            receive_calls,
            send_calls,
            window_wait_events,
        })
    }

    fn send_generated(
        socket: &UdpSocket,
        packets: usize,
        datagram_size: usize,
        batch_size: usize,
        inflight_window: usize,
        relay_progress: &AtomicUsize,
    ) -> Result<()> {
        let mut batch = MmsgBatch::new(batch_size, datagram_size);
        let mut sent = 0usize;
        while sent < packets {
            let consumed = relay_progress.load(Ordering::Acquire);
            let available =
                inflight_window.saturating_sub(sent.saturating_sub(consumed));
            if available == 0 {
                thread::yield_now();
                continue;
            }
            let count = (packets - sent).min(batch_size).min(available);
            for index in 0..count {
                let sequence = (sent + index) as u64;
                let buffer = batch.buffer_mut(index);
                buffer.fill(PATTERN_BYTE);
                buffer[..8].copy_from_slice(&sequence.to_ne_bytes());
                batch.set_len(index, datagram_size);
            }
            batch.send(socket.as_raw_fd(), count)?;
            sent += count;
        }
        Ok(())
    }

    fn receive_sink(
        socket: &UdpSocket,
        packets: usize,
        datagram_size: usize,
        batch_size: usize,
        verify: bool,
        sink_progress: &AtomicUsize,
        sink_notify: &Notify,
    ) -> Result<()> {
        let mut batch = MmsgBatch::new(batch_size, datagram_size);
        let mut total = 0usize;
        while total < packets {
            let count =
                batch.recv(socket.as_raw_fd(), (packets - total).min(batch_size))?;
            for index in 0..count {
                let buffer = batch.buffer(index);
                if buffer.len() != datagram_size {
                    bail!("unexpected sink datagram size {}", buffer.len());
                }
                if verify {
                    let sequence = u64::from_ne_bytes(buffer[..8].try_into()?);
                    let expected = (total + index) as u64;
                    if sequence != expected {
                        bail!(
                            "UDP sequence mismatch: got {sequence}, expected {expected}"
                        );
                    }
                    if buffer[8..].iter().any(|byte| *byte != PATTERN_BYTE) {
                        bail!(
                            "UDP payload verification failed at sequence {sequence}"
                        );
                    }
                }
            }
            total += count;
            sink_progress.store(total, Ordering::Release);
            sink_notify.notify_one();
        }
        Ok(())
    }

    fn wait_for_window(
        produced: usize,
        consumed: &AtomicUsize,
        window: usize,
    ) -> u64 {
        let waited = u64::from(
            produced.saturating_sub(consumed.load(Ordering::Acquire)) >= window,
        );
        while produced.saturating_sub(consumed.load(Ordering::Acquire)) >= window {
            thread::yield_now();
        }
        waited
    }

    async fn wait_for_window_async(
        produced: usize,
        consumed: &AtomicUsize,
        window: usize,
        notify: &Notify,
    ) -> u64 {
        let mut waited = false;
        while produced.saturating_sub(consumed.load(Ordering::Acquire)) >= window {
            waited = true;
            let notified = notify.notified();
            if produced.saturating_sub(consumed.load(Ordering::Acquire)) < window {
                break;
            }
            notified.await;
        }
        u64::from(waited)
    }

    struct MmsgBatch {
        buffers: Vec<Vec<u8>>,
        iovecs: Vec<libc::iovec>,
        messages: Vec<libc::mmsghdr>,
    }

    impl MmsgBatch {
        fn new(batch_size: usize, datagram_size: usize) -> Self {
            let mut buffers = (0..batch_size)
                .map(|_| vec![0_u8; datagram_size])
                .collect::<Vec<_>>();
            let mut iovecs = buffers
                .iter_mut()
                .map(|buffer| libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: buffer.len(),
                })
                .collect::<Vec<_>>();
            let messages = iovecs
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
                .collect();
            Self {
                buffers,
                iovecs,
                messages,
            }
        }

        fn buffer(&self, index: usize) -> &[u8] {
            &self.buffers[index][..self.messages[index].msg_len as usize]
        }

        fn buffer_mut(&mut self, index: usize) -> &mut [u8] {
            &mut self.buffers[index]
        }

        fn set_len(&mut self, index: usize, len: usize) {
            self.iovecs[index].iov_len = len;
            self.messages[index].msg_len = len as u32;
        }

        fn recv(&mut self, fd: libc::c_int, count: usize) -> io::Result<usize> {
            self.recv_with_flags(fd, count, libc::MSG_WAITFORONE)
        }

        fn recv_nonblocking(
            &mut self,
            fd: libc::c_int,
            count: usize,
        ) -> io::Result<usize> {
            self.recv_with_flags(fd, count, libc::MSG_DONTWAIT)
        }

        fn recv_with_flags(
            &mut self,
            fd: libc::c_int,
            count: usize,
            flags: libc::c_int,
        ) -> io::Result<usize> {
            for index in 0..count {
                self.iovecs[index].iov_len = self.buffers[index].len();
                self.messages[index].msg_len = 0;
            }
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    count as u32,
                    flags,
                    ptr::null_mut(),
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }

        fn send(&mut self, fd: libc::c_int, count: usize) -> io::Result<usize> {
            let mut offset = 0usize;
            let mut calls = 0usize;
            while offset < count {
                offset += self.send_with_flags(fd, offset, count, 0)?;
                calls += 1;
            }
            Ok(calls)
        }

        fn send_nonblocking(
            &mut self,
            fd: libc::c_int,
            offset: usize,
            count: usize,
        ) -> io::Result<usize> {
            self.send_with_flags(fd, offset, count, libc::MSG_DONTWAIT)
        }

        fn send_with_flags(
            &mut self,
            fd: libc::c_int,
            offset: usize,
            count: usize,
            flags: libc::c_int,
        ) -> io::Result<usize> {
            for index in offset..count {
                self.iovecs[index].iov_len = self.messages[index].msg_len as usize;
            }
            let result = unsafe {
                libc::sendmmsg(
                    fd,
                    self.messages[offset..count].as_mut_ptr(),
                    (count - offset) as u32,
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
    }

    fn cpu_seconds() -> io::Result<f64> {
        rusage_cpu_seconds(libc::RUSAGE_SELF)
    }

    fn thread_cpu_seconds() -> io::Result<f64> {
        rusage_cpu_seconds(libc::RUSAGE_THREAD)
    }

    fn rusage_cpu_seconds(who: libc::c_int) -> io::Result<f64> {
        let mut raw = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        if unsafe { libc::getrusage(who, raw.as_mut_ptr()) } != 0 {
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
                relay_model: RelayModel::Blocking,
                worker_threads: 1,
                packets: 512,
                datagram_size: 256,
                batch_size: 16,
                harness_batch_size: None,
                inflight_window: 64,
                warmup: 0,
                runs: 1,
                verify: true,
            }
        }

        #[test]
        fn single_backend_preserves_datagrams() {
            run_once(&args(Backend::Single), None).unwrap();
        }

        #[test]
        fn mmsg_backend_preserves_datagrams() {
            run_once(&args(Backend::Mmsg), None).unwrap();
        }

        #[test]
        fn tokio_backends_preserve_datagrams() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_io()
                .build()
                .unwrap();
            for backend in [Backend::Single, Backend::Mmsg] {
                let mut args = args(backend);
                args.relay_model = RelayModel::Tokio;
                run_once(&args, Some(&runtime)).unwrap();
            }
        }
    }
}
