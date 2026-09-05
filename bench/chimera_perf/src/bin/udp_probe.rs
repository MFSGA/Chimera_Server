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

    const PATTERN_BYTE: u8 = 0x5a;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Single,
        Mmsg,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Loopback UDP relay microbenchmark for syscall batching")]
    struct Args {
        #[arg(long, value_enum)]
        backend: Backend,
        #[arg(long, default_value_t = 200_000)]
        packets: usize,
        #[arg(long, default_value_t = 1200)]
        datagram_size: usize,
        #[arg(long, default_value_t = 32)]
        batch_size: usize,
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
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        for _ in 0..args.warmup {
            let _ = run_once(&args)?;
        }

        let mut packet_rates = Vec::with_capacity(args.runs);
        let mut throughput = Vec::with_capacity(args.runs);
        let mut cpu = Vec::with_capacity(args.runs);
        for _ in 0..args.runs {
            let sample = run_once(&args)?;
            packet_rates.push(sample.packets_per_second);
            throughput.push(sample.throughput_gbps);
            cpu.push(sample.cpu_seconds_per_million_packets);
        }

        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "record_type": "summary",
                "backend": args.backend,
                "runs": args.runs,
                "warmup_runs": args.warmup,
                "packets": args.packets,
                "datagram_size": args.datagram_size,
                "batch_size": args.batch_size,
                "inflight_window": args.inflight_window,
                "verify": args.verify,
                "packets_per_second_median": round(median(&packet_rates)),
                "packets_per_second_cv": round(coefficient_of_variation(&packet_rates)),
                "throughput_median_gbps": round(median(&throughput)),
                "cpu_seconds_per_million_packets_median": round(median(&cpu)),
            })
        );
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        if args.packets == 0 {
            bail!("--packets must be greater than zero");
        }
        if !(8..=65_507).contains(&args.datagram_size) {
            bail!("--datagram-size must be between 8 and 65507");
        }
        if args.batch_size == 0 || args.batch_size > 128 {
            bail!("--batch-size must be between 1 and 128");
        }
        if args.inflight_window == 0 {
            bail!("--inflight-window must be greater than zero");
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        Ok(())
    }

    fn run_once(args: &Args) -> Result<Sample> {
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

        let source_barrier = Arc::clone(&barrier);
        let source_progress = Arc::clone(&relay_progress);
        let packets = args.packets;
        let datagram_size = args.datagram_size;
        let batch_size = args.batch_size;
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
            )
        });

        let cpu_before = cpu_seconds()?;
        let started = Instant::now();
        barrier.wait();
        match args.backend {
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
        }
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
    ) -> Result<()> {
        let mut buffer = vec![0_u8; args.datagram_size];
        for relayed in 0..args.packets {
            let len = ingress.recv(&mut buffer)?;
            if len != args.datagram_size {
                bail!(
                    "unexpected UDP datagram size {len}; expected {}",
                    args.datagram_size
                );
            }
            wait_for_window(relayed, sink_progress, args.inflight_window);
            if egress.send(&buffer[..len])? != len {
                bail!("short UDP send");
            }
            relay_progress.store(relayed + 1, Ordering::Release);
        }
        Ok(())
    }

    fn relay_mmsg(
        ingress: &UdpSocket,
        egress: &UdpSocket,
        args: &Args,
        relay_progress: &AtomicUsize,
        sink_progress: &AtomicUsize,
    ) -> Result<()> {
        let mut batch = MmsgBatch::new(args.batch_size, args.datagram_size);
        let mut relayed = 0usize;
        while relayed < args.packets {
            let received = batch.recv(
                ingress.as_raw_fd(),
                (args.packets - relayed).min(args.batch_size),
            )?;
            if received == 0 {
                bail!("recvmmsg returned zero datagrams");
            }
            wait_for_window(
                relayed.saturating_add(received - 1),
                sink_progress,
                args.inflight_window,
            );
            batch.send(egress.as_raw_fd(), received)?;
            relayed += received;
            relay_progress.store(relayed, Ordering::Release);
        }
        Ok(())
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
        }
        Ok(())
    }

    fn wait_for_window(produced: usize, consumed: &AtomicUsize, window: usize) {
        while produced.saturating_sub(consumed.load(Ordering::Acquire)) >= window {
            thread::yield_now();
        }
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
            for index in 0..count {
                self.iovecs[index].iov_len = self.buffers[index].len();
                self.messages[index].msg_len = 0;
            }
            let result = unsafe {
                libc::recvmmsg(
                    fd,
                    self.messages.as_mut_ptr(),
                    count as u32,
                    libc::MSG_WAITFORONE,
                    ptr::null_mut(),
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result as usize)
            }
        }

        fn send(&mut self, fd: libc::c_int, count: usize) -> io::Result<()> {
            let mut offset = 0usize;
            while offset < count {
                for index in offset..count {
                    self.iovecs[index].iov_len =
                        self.messages[index].msg_len as usize;
                }
                let result = unsafe {
                    libc::sendmmsg(
                        fd,
                        self.messages[offset..count].as_mut_ptr(),
                        (count - offset) as u32,
                        0,
                    )
                };
                if result <= 0 {
                    return if result == 0 {
                        Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "sendmmsg sent zero datagrams",
                        ))
                    } else {
                        Err(io::Error::last_os_error())
                    };
                }
                offset += result as usize;
            }
            Ok(())
        }
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
                packets: 512,
                datagram_size: 256,
                batch_size: 16,
                inflight_window: 64,
                warmup: 0,
                runs: 1,
                verify: true,
            }
        }

        #[test]
        fn single_backend_preserves_datagrams() {
            run_once(&args(Backend::Single)).unwrap();
        }

        #[test]
        fn mmsg_backend_preserves_datagrams() {
            run_once(&args(Backend::Mmsg)).unwrap();
        }
    }
}
