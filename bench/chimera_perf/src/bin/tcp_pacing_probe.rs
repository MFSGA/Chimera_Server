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
        os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Send,
        Splice,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum FdPlacement {
        Original,
        Duplicate,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Loopback TCP pacing probe for Brutal2 design work")]
    struct Args {
        #[arg(long, value_enum)]
        mode: PacingMode,

        #[arg(long, value_enum, default_value_t = Backend::Send)]
        backend: Backend,

        #[arg(long, value_enum, default_value_t = FdPlacement::Original)]
        pacing_fd: FdPlacement,

        #[arg(long, value_enum, default_value_t = FdPlacement::Original)]
        splice_destination_fd: FdPlacement,

        #[arg(long, default_value_t = 256 * 1024 * 1024_u64)]
        bytes: u64,

        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,

        #[arg(long, default_value_t = 100 * 1024 * 1024_u64)]
        rate_bytes_per_sec: u64,

        #[arg(long)]
        second_rate_bytes_per_sec: Option<u64>,

        #[arg(long, default_value_t = 1)]
        warmup: usize,

        #[arg(long, default_value_t = 5)]
        runs: usize,

        #[arg(long)]
        verify: bool,
    }

    struct SpliceSource {
        file: OwnedFd,
        pipe_read: OwnedFd,
        pipe_write: OwnedFd,
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
        backend: Backend,
        pacing_fd: FdPlacement,
        splice_destination_fd: FdPlacement,
        run_index: usize,
        warmup: bool,
        bytes: u64,
        chunk_size: usize,
        requested_rate_bytes_per_sec: u64,
        second_rate_bytes_per_sec: Option<u64>,
        kernel_pacing_rate_bytes_per_sec: Option<u64>,
        pacing_updates: usize,
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
        backend: Backend,
        pacing_fd: FdPlacement,
        splice_destination_fd: FdPlacement,
        runs: usize,
        warmup_runs: usize,
        bytes: u64,
        chunk_size: usize,
        requested_rate_bytes_per_sec: u64,
        second_rate_bytes_per_sec: Option<u64>,
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
            backend: args.backend,
            pacing_fd: args.pacing_fd,
            splice_destination_fd: args.splice_destination_fd,
            runs: args.runs,
            warmup_runs: args.warmup,
            bytes: args.bytes,
            chunk_size: args.chunk_size,
            requested_rate_bytes_per_sec: args.rate_bytes_per_sec,
            second_rate_bytes_per_sec: args.second_rate_bytes_per_sec,
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
        if args.second_rate_bytes_per_sec == Some(0) {
            bail!("--second-rate-bytes-per-sec must be greater than zero");
        }
        if args.second_rate_bytes_per_sec.is_some()
            && args.mode != PacingMode::Kernel
        {
            bail!("--second-rate-bytes-per-sec currently requires --mode kernel");
        }
        if args.backend != Backend::Splice
            && args.splice_destination_fd != FdPlacement::Original
        {
            bail!("--splice-destination-fd duplicate requires --backend splice");
        }
        if args.mode != PacingMode::Kernel && args.pacing_fd != FdPlacement::Original
        {
            bail!("--pacing-fd duplicate requires --mode kernel");
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
        let duplicate_sender = needs_duplicate_fd(args)
            .then(|| duplicate_fd(sender.as_raw_fd()))
            .transpose()?;
        let pacing_fd = selected_fd(
            args.pacing_fd,
            sender.as_raw_fd(),
            duplicate_sender.as_ref(),
        );
        let splice_destination_fd = selected_fd(
            args.splice_destination_fd,
            sender.as_raw_fd(),
            duplicate_sender.as_ref(),
        );
        let kernel_pacing_rate = if args.mode == PacingMode::Kernel {
            set_max_pacing_rate(pacing_fd, args.rate_bytes_per_sec)?;
            Some(get_max_pacing_rate(sender.as_raw_fd())?)
        } else {
            None
        };

        let buffer = vec![PATTERN_BYTE; args.chunk_size];
        let splice_source = if args.backend == Backend::Splice {
            Some(build_splice_source(args.bytes, args.chunk_size, &buffer)?)
        } else {
            None
        };
        barrier.wait();
        let usage_before = usage()?;
        let started = Instant::now();
        let mut sent = 0_u64;
        let switch_after = args.bytes / 2;
        let mut pacing_updates = 0_usize;
        match args.backend {
            Backend::Send => {
                while sent < args.bytes {
                    let count = usize::try_from(
                        (args.bytes - sent).min(args.chunk_size as u64),
                    )
                    .expect("chunk size fits usize");
                    sender.write_all(&buffer[..count])?;
                    sent += count as u64;
                    maybe_update_kernel_pacing(
                        pacing_fd,
                        sent,
                        switch_after,
                        args.second_rate_bytes_per_sec,
                        &mut pacing_updates,
                    )?;
                    if args.mode == PacingMode::Userspace {
                        pace_userspace(started, sent, args.rate_bytes_per_sec);
                    }
                }
            }
            Backend::Splice => {
                let source = splice_source.expect("splice source created");
                while sent < args.bytes {
                    let count = usize::try_from(
                        (args.bytes - sent).min(args.chunk_size as u64),
                    )
                    .expect("chunk size fits usize");
                    let filled = splice_exact(
                        source.file.as_raw_fd(),
                        source.pipe_write.as_raw_fd(),
                        count,
                    )?;
                    if filled == 0 {
                        bail!("splice source reached EOF after {sent} bytes");
                    }
                    let mut drained = 0;
                    while drained < filled {
                        let moved = splice_exact(
                            source.pipe_read.as_raw_fd(),
                            splice_destination_fd,
                            filled - drained,
                        )?;
                        if moved == 0 {
                            bail!("splice pipe drained zero bytes");
                        }
                        drained += moved;
                    }
                    sent += filled as u64;
                    maybe_update_kernel_pacing(
                        pacing_fd,
                        sent,
                        switch_after,
                        args.second_rate_bytes_per_sec,
                        &mut pacing_updates,
                    )?;
                    if args.mode == PacingMode::Userspace {
                        pace_userspace(started, sent, args.rate_bytes_per_sec);
                    }
                }
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
        let effective_requested_rate = effective_requested_rate(args);
        Ok(RunRecord {
            schema_version: 1,
            record_type: "run",
            mode: args.mode,
            backend: args.backend,
            pacing_fd: args.pacing_fd,
            splice_destination_fd: args.splice_destination_fd,
            run_index,
            warmup,
            bytes: args.bytes,
            chunk_size: args.chunk_size,
            requested_rate_bytes_per_sec: args.rate_bytes_per_sec,
            second_rate_bytes_per_sec: args.second_rate_bytes_per_sec,
            kernel_pacing_rate_bytes_per_sec: kernel_pacing_rate,
            pacing_updates,
            elapsed_seconds: round(elapsed),
            throughput_gbps: round(observed_rate * 8.0 / 1e9),
            observed_rate_bytes_per_sec: round(observed_rate),
            requested_rate_ratio: round(observed_rate / effective_requested_rate),
            cpu_seconds: round(cpu_seconds),
            cpu_seconds_per_gib: round(cpu_seconds / (args.bytes as f64 / GIB)),
            voluntary_context_switches,
            involuntary_context_switches,
        })
    }

    fn build_splice_source(
        bytes: u64,
        chunk_size: usize,
        pattern: &[u8],
    ) -> io::Result<SpliceSource> {
        let name = c"chimera-tcp-pacing";
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut written = 0_u64;
        while written < bytes {
            let count = usize::try_from((bytes - written).min(chunk_size as u64))
                .expect("chunk size fits usize");
            let mut offset = 0;
            while offset < count {
                let result = unsafe {
                    libc::write(
                        fd.as_raw_fd(),
                        pattern[offset..count].as_ptr().cast(),
                        count - offset,
                    )
                };
                if result < 0 {
                    return Err(io::Error::last_os_error());
                }
                offset += result as usize;
            }
            written += count as u64;
        }
        if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pipe_fds = [0_i32; 2];
        if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let pipe_write = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
        Ok(SpliceSource {
            file: fd,
            pipe_read,
            pipe_write,
        })
    }

    fn splice_exact(
        source: i32,
        destination: i32,
        count: usize,
    ) -> io::Result<usize> {
        loop {
            let moved = unsafe {
                libc::splice(
                    source,
                    std::ptr::null_mut(),
                    destination,
                    std::ptr::null_mut(),
                    count,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_MORE,
                )
            };
            if moved >= 0 {
                return Ok(moved as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn effective_requested_rate(args: &Args) -> f64 {
        match args.second_rate_bytes_per_sec {
            Some(second) => {
                2.0 / (1.0 / args.rate_bytes_per_sec as f64 + 1.0 / second as f64)
            }
            None => args.rate_bytes_per_sec as f64,
        }
    }

    fn maybe_update_kernel_pacing(
        pacing_fd: RawFd,
        sent: u64,
        switch_after: u64,
        second_rate: Option<u64>,
        pacing_updates: &mut usize,
    ) -> io::Result<()> {
        if *pacing_updates == 0
            && sent >= switch_after
            && let Some(rate) = second_rate
        {
            set_max_pacing_rate(pacing_fd, rate)?;
            *pacing_updates = 1;
        }
        Ok(())
    }

    fn pace_userspace(started: Instant, sent: u64, rate_bytes_per_sec: u64) {
        let target =
            Duration::from_secs_f64(sent as f64 / rate_bytes_per_sec as f64);
        if let Some(delay) = target.checked_sub(started.elapsed()) {
            thread::sleep(delay);
        }
    }

    fn needs_duplicate_fd(args: &Args) -> bool {
        args.pacing_fd == FdPlacement::Duplicate
            || args.splice_destination_fd == FdPlacement::Duplicate
    }

    fn selected_fd(
        placement: FdPlacement,
        original: RawFd,
        duplicate: Option<&OwnedFd>,
    ) -> RawFd {
        match placement {
            FdPlacement::Original => original,
            FdPlacement::Duplicate => duplicate
                .expect("duplicate fd created for duplicate placement")
                .as_raw_fd(),
        }
    }

    fn duplicate_fd(fd: RawFd) -> io::Result<OwnedFd> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
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

    fn get_max_pacing_rate(fd: RawFd) -> io::Result<u64> {
        let mut rate = 0_u64;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
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
        fn splice_source_preserves_payload_bytes() {
            let pattern = vec![PATTERN_BYTE; 4096];
            let source = build_splice_source(4096, 4096, &pattern).unwrap();
            let filled = splice_exact(
                source.file.as_raw_fd(),
                source.pipe_write.as_raw_fd(),
                4096,
            )
            .unwrap();
            assert_eq!(filled, 4096);
            let mut output = vec![0_u8; 4096];
            let read = unsafe {
                libc::read(
                    source.pipe_read.as_raw_fd(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                )
            };
            assert_eq!(read, 4096);
            assert_eq!(output, pattern);
        }

        #[test]
        fn kernel_pacing_rate_round_trips_on_tcp_socket() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let accept = thread::spawn(move || listener.accept().unwrap().0);
            let stream = TcpStream::connect(address).unwrap();
            let peer = accept.join().unwrap();
            set_max_pacing_rate(stream.as_raw_fd(), 12_345_678).unwrap();
            assert_eq!(get_max_pacing_rate(stream.as_raw_fd()).unwrap(), 12_345_678);
            drop(peer);
        }

        #[test]
        fn duplicated_tcp_fd_shares_kernel_pacing_state() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let accept = thread::spawn(move || listener.accept().unwrap().0);
            let stream = TcpStream::connect(address).unwrap();
            let peer = accept.join().unwrap();
            let duplicate = duplicate_fd(stream.as_raw_fd()).unwrap();

            set_max_pacing_rate(duplicate.as_raw_fd(), 23_456_789).unwrap();
            assert_eq!(get_max_pacing_rate(stream.as_raw_fd()).unwrap(), 23_456_789);

            set_max_pacing_rate(stream.as_raw_fd(), 34_567_890).unwrap();
            assert_eq!(
                get_max_pacing_rate(duplicate.as_raw_fd()).unwrap(),
                34_567_890
            );
            drop(peer);
        }
    }
}
