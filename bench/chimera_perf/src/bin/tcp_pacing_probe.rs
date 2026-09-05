#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp_pacing_probe requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{self, Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        os::fd::AsRawFd,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, Instant},
    };

    use anyhow::{Result, bail};
    use chimera_perf::stats::{coefficient_of_variation, median};
    use clap::{Parser, ValueEnum};
    use serde::Serialize;

    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const PATTERN_BYTE: u8 = 0x5a;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum PacingMode {
        Unpaced,
        Kernel,
        Userspace,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Loopback TCP pacing probe for Brutal2 design work")]
    struct Args {
        #[arg(long, value_enum)]
        mode: PacingMode,

        #[arg(long, default_value_t = 256 * 1024 * 1024_u64)]
        bytes: u64,

        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,

        #[arg(long, default_value_t = 100 * 1024 * 1024_u64)]
        rate_bytes_per_sec: u64,

        #[arg(long, default_value_t = 1)]
        warmup: usize,

        #[arg(long, default_value_t = 5)]
        runs: usize,

        #[arg(long)]
        verify: bool,
    }

    #[derive(Debug, Clone, Copy)]
    struct Usage {
        cpu_seconds: f64,
        voluntary_context_switches: i64,
        involuntary_context_switches: i64,
    }

    #[derive(Debug, Serialize)]
    struct RunRecord {
        schema_version: u32,
        record_type: &'static str,
        mode: PacingMode,
        run_index: usize,
        warmup: bool,
        bytes: u64,
        chunk_size: usize,
        requested_rate_bytes_per_sec: u64,
        kernel_pacing_rate_bytes_per_sec: Option<u64>,
        elapsed_seconds: f64,
        throughput_gbps: f64,
        observed_rate_bytes_per_sec: f64,
        requested_rate_ratio: f64,
        cpu_seconds: f64,
        cpu_seconds_per_gib: f64,
        voluntary_context_switches: i64,
        involuntary_context_switches: i64,
    }

    #[derive(Debug, Serialize)]
    struct Summary {
        schema_version: u32,
        record_type: &'static str,
        mode: PacingMode,
        runs: usize,
        warmup_runs: usize,
        bytes: u64,
        chunk_size: usize,
        requested_rate_bytes_per_sec: u64,
        throughput_median_gbps: f64,
        throughput_cv: f64,
        observed_rate_bytes_per_sec_median: f64,
        requested_rate_ratio_median: f64,
        cpu_seconds_per_gib_median: f64,
        context_switches_median: f64,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;

        for run_index in 0..args.warmup {
            println!(
                "{}",
                serde_json::to_string(&run_once(&args, run_index, true)?)?
            );
        }

        let mut throughput = Vec::with_capacity(args.runs);
        let mut observed_rates = Vec::with_capacity(args.runs);
        let mut requested_ratios = Vec::with_capacity(args.runs);
        let mut cpu_per_gib = Vec::with_capacity(args.runs);
        let mut context_switches = Vec::with_capacity(args.runs);
        for run_index in 0..args.runs {
            let record = run_once(&args, run_index, false)?;
            throughput.push(record.throughput_gbps);
            observed_rates.push(record.observed_rate_bytes_per_sec);
            requested_ratios.push(record.requested_rate_ratio);
            cpu_per_gib.push(record.cpu_seconds_per_gib);
            context_switches.push(
                (record.voluntary_context_switches
                    + record.involuntary_context_switches) as f64,
            );
            println!("{}", serde_json::to_string(&record)?);
        }

        let summary = Summary {
            schema_version: 1,
            record_type: "summary",
            mode: args.mode,
            runs: args.runs,
            warmup_runs: args.warmup,
            bytes: args.bytes,
            chunk_size: args.chunk_size,
            requested_rate_bytes_per_sec: args.rate_bytes_per_sec,
            throughput_median_gbps: round(median(&throughput)),
            throughput_cv: round(coefficient_of_variation(&throughput)),
            observed_rate_bytes_per_sec_median: round(median(&observed_rates)),
            requested_rate_ratio_median: round(median(&requested_ratios)),
            cpu_seconds_per_gib_median: round(median(&cpu_per_gib)),
            context_switches_median: round(median(&context_switches)),
        };
        println!("{}", serde_json::to_string(&summary)?);
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        if args.bytes == 0 {
            bail!("--bytes must be greater than zero");
        }
        if args.chunk_size == 0 {
            bail!("--chunk-size must be greater than zero");
        }
        if args.rate_bytes_per_sec == 0 {
            bail!("--rate-bytes-per-sec must be greater than zero");
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        Ok(())
    }

    fn run_once(args: &Args, run_index: usize, warmup: bool) -> Result<RunRecord> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let barrier = Arc::new(Barrier::new(2));
        let sink_barrier = Arc::clone(&barrier);
        let expected_bytes = args.bytes;
        let chunk_size = args.chunk_size;
        let verify = args.verify;
        let sink = thread::spawn(move || -> io::Result<u64> {
            let (mut stream, _) = listener.accept()?;
            stream.set_nodelay(true)?;
            let mut buffer = vec![0_u8; chunk_size];
            let mut received = 0_u64;
            sink_barrier.wait();
            while received < expected_bytes {
                let count = stream.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                if verify && buffer[..count].iter().any(|byte| *byte != PATTERN_BYTE)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "pacing payload verification failed",
                    ));
                }
                received = received.saturating_add(count as u64);
            }
            Ok(received)
        });

        let mut sender = TcpStream::connect(address)?;
        sender.set_nodelay(true)?;
        let kernel_pacing_rate = if args.mode == PacingMode::Kernel {
            set_max_pacing_rate(&sender, args.rate_bytes_per_sec)?;
            Some(get_max_pacing_rate(&sender)?)
        } else {
            None
        };

        let buffer = vec![PATTERN_BYTE; args.chunk_size];
        barrier.wait();
        let usage_before = usage()?;
        let started = Instant::now();
        let mut sent = 0_u64;
        while sent < args.bytes {
            let count =
                usize::try_from((args.bytes - sent).min(args.chunk_size as u64))
                    .expect("chunk size fits usize");
            sender.write_all(&buffer[..count])?;
            sent += count as u64;
            if args.mode == PacingMode::Userspace {
                pace_userspace(started, sent, args.rate_bytes_per_sec);
            }
        }
        sender.shutdown(Shutdown::Write)?;
        let received = sink
            .join()
            .map_err(|_| anyhow::anyhow!("sink thread panicked"))??;
        if received != args.bytes {
            bail!("sink received {received} bytes, expected {}", args.bytes);
        }
        let elapsed = started.elapsed().as_secs_f64();
        let usage_after = usage()?;
        let cpu_seconds = usage_after.cpu_seconds - usage_before.cpu_seconds;
        let voluntary_context_switches = usage_after.voluntary_context_switches
            - usage_before.voluntary_context_switches;
        let involuntary_context_switches = usage_after.involuntary_context_switches
            - usage_before.involuntary_context_switches;
        let observed_rate = args.bytes as f64 / elapsed.max(f64::MIN_POSITIVE);
        Ok(RunRecord {
            schema_version: 1,
            record_type: "run",
            mode: args.mode,
            run_index,
            warmup,
            bytes: args.bytes,
            chunk_size: args.chunk_size,
            requested_rate_bytes_per_sec: args.rate_bytes_per_sec,
            kernel_pacing_rate_bytes_per_sec: kernel_pacing_rate,
            elapsed_seconds: round(elapsed),
            throughput_gbps: round(observed_rate * 8.0 / 1e9),
            observed_rate_bytes_per_sec: round(observed_rate),
            requested_rate_ratio: round(
                observed_rate / args.rate_bytes_per_sec as f64,
            ),
            cpu_seconds: round(cpu_seconds),
            cpu_seconds_per_gib: round(cpu_seconds / (args.bytes as f64 / GIB)),
            voluntary_context_switches,
            involuntary_context_switches,
        })
    }

    fn pace_userspace(started: Instant, sent: u64, rate_bytes_per_sec: u64) {
        let target =
            Duration::from_secs_f64(sent as f64 / rate_bytes_per_sec as f64);
        if let Some(delay) = target.checked_sub(started.elapsed()) {
            thread::sleep(delay);
        }
    }

    fn set_max_pacing_rate(stream: &TcpStream, rate: u64) -> io::Result<()> {
        let result = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
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

    fn get_max_pacing_rate(stream: &TcpStream) -> io::Result<u64> {
        let mut rate = 0_u64;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MAX_PACING_RATE,
                (&mut rate as *mut u64).cast(),
                &mut len,
            )
        };
        if result == 0 {
            Ok(rate)
        } else {
            Err(io::Error::last_os_error())
        }
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

        #[test]
        fn kernel_pacing_rate_round_trips_on_tcp_socket() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let accept = thread::spawn(move || listener.accept().unwrap().0);
            let stream = TcpStream::connect(address).unwrap();
            let peer = accept.join().unwrap();
            set_max_pacing_rate(&stream, 12_345_678).unwrap();
            assert_eq!(get_max_pacing_rate(&stream).unwrap(), 12_345_678);
            drop(peer);
        }
    }
}
