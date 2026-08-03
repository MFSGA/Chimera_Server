#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("relay_probe requires Linux");
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
        ptr,
        sync::{Arc, Barrier},
        thread,
        time::Instant,
    };

    use anyhow::{Context, Result, anyhow, bail};
    use chimera_perf::stats::{coefficient_of_variation, median};
    use clap::{Parser, ValueEnum};
    use io_uring::{IoUring, Probe, opcode, squeue, types};
    use serde::Serialize;

    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const PATTERN_BYTE: u8 = 0x5a;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Copy,
        Splice,
        UringSplice,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Short-lived TCP relay microbenchmark for syscall tracing")]
    struct Args {
        #[arg(long, value_enum)]
        backend: Backend,

        #[arg(long, default_value_t = 1024 * 1024 * 1024_u64)]
        bytes: u64,

        #[arg(long, default_value_t = 64 * 1024)]
        chunk_size: usize,

        #[arg(long, default_value_t = 16)]
        uring_batch_depth: usize,

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
        backend: Backend,
        run_index: usize,
        warmup: bool,
        bytes: u64,
        chunk_size: usize,
        uring_batch_depth: usize,
        verify: bool,
        elapsed_seconds: f64,
        throughput_gbps: f64,
        cpu_seconds: f64,
        cpu_seconds_per_gib: f64,
        voluntary_context_switches: i64,
        involuntary_context_switches: i64,
    }

    #[derive(Debug, Serialize)]
    struct Summary {
        schema_version: u32,
        record_type: &'static str,
        backend: Backend,
        runs: usize,
        warmup_runs: usize,
        bytes: u64,
        chunk_size: usize,
        uring_batch_depth: usize,
        verify: bool,
        throughput_median_gbps: f64,
        throughput_cv: f64,
        cpu_seconds_median: f64,
        cpu_seconds_per_gib_median: f64,
        context_switches_median: f64,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;

        if args.backend == Backend::UringSplice {
            verify_uring_splice_support()?;
        }

        for run_index in 0..args.warmup {
            let record = run_once(&args, run_index, true)?;
            println!("{}", serde_json::to_string(&record)?);
        }

        let mut throughput = Vec::with_capacity(args.runs);
        let mut cpu_seconds = Vec::with_capacity(args.runs);
        let mut cpu_per_gib = Vec::with_capacity(args.runs);
        let mut context_switches = Vec::with_capacity(args.runs);

        for run_index in 0..args.runs {
            let record = run_once(&args, run_index, false)?;
            throughput.push(record.throughput_gbps);
            cpu_seconds.push(record.cpu_seconds);
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
            backend: args.backend,
            runs: args.runs,
            warmup_runs: args.warmup,
            bytes: args.bytes,
            chunk_size: args.chunk_size,
            uring_batch_depth: args.uring_batch_depth,
            verify: args.verify,
            throughput_median_gbps: round(median(&throughput)),
            throughput_cv: round(coefficient_of_variation(&throughput)),
            cpu_seconds_median: round(median(&cpu_seconds)),
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
        if args.chunk_size == 0 || args.chunk_size > u32::MAX as usize {
            bail!("--chunk-size must be between 1 and u32::MAX");
        }
        if args.uring_batch_depth == 0 || args.uring_batch_depth > 128 {
            bail!("--uring-batch-depth must be between 1 and 128");
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        Ok(())
    }

    fn run_once(args: &Args, run_index: usize, warmup: bool) -> Result<RunRecord> {
        let (mut source_writer, mut relay_source) = tcp_pair()?;
        let (mut relay_destination, mut sink_reader) = tcp_pair()?;
        for stream in [
            &source_writer,
            &relay_source,
            &relay_destination,
            &sink_reader,
        ] {
            stream.set_nodelay(true)?;
        }

        let start_barrier = Arc::new(Barrier::new(2));
        let writer_barrier = start_barrier.clone();
        let bytes = args.bytes;
        let chunk_size = args.chunk_size;
        let writer = thread::spawn(move || -> io::Result<u64> {
            let buffer = vec![PATTERN_BYTE; chunk_size];
            writer_barrier.wait();
            let mut remaining = bytes;
            while remaining > 0 {
                let count = usize::try_from(remaining.min(chunk_size as u64))
                    .expect("chunk length fits usize");
                source_writer.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            source_writer.shutdown(Shutdown::Write)?;
            Ok(bytes)
        });

        let verify = args.verify;
        let sink = thread::spawn(move || -> io::Result<u64> {
            let mut buffer = vec![0_u8; chunk_size];
            let mut received = 0_u64;
            loop {
                let count = sink_reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                if verify && buffer[..count].iter().any(|byte| *byte != PATTERN_BYTE)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "relay payload verification failed",
                    ));
                }
                received = received.saturating_add(count as u64);
            }
            Ok(received)
        });

        let usage_before = usage()?;
        let started = Instant::now();
        start_barrier.wait();
        let relayed = match args.backend {
            Backend::Copy => copy_relay(
                &mut relay_source,
                &mut relay_destination,
                args.chunk_size,
            )?,
            Backend::Splice => splice_relay(
                relay_source.as_raw_fd(),
                relay_destination.as_raw_fd(),
                args.chunk_size,
            )?,
            Backend::UringSplice => uring_splice_relay(
                relay_source.as_raw_fd(),
                relay_destination.as_raw_fd(),
                args.chunk_size,
                args.bytes,
                args.uring_batch_depth,
            )?,
        };
        relay_destination.shutdown(Shutdown::Write)?;
        let elapsed = started.elapsed().as_secs_f64();
        let usage_after = usage()?;

        let written = writer
            .join()
            .map_err(|_| anyhow!("writer thread panicked"))??;
        let received =
            sink.join().map_err(|_| anyhow!("sink thread panicked"))??;
        if written != args.bytes || relayed != args.bytes || received != args.bytes {
            bail!(
                "byte count mismatch: written={written}, relayed={relayed}, received={received}, expected={}",
                args.bytes,
            );
        }

        let cpu_seconds = usage_after.cpu_seconds - usage_before.cpu_seconds;
        let gib = args.bytes as f64 / GIB;
        Ok(RunRecord {
            schema_version: 1,
            record_type: "run",
            backend: args.backend,
            run_index,
            warmup,
            bytes: args.bytes,
            chunk_size: args.chunk_size,
            uring_batch_depth: args.uring_batch_depth,
            verify: args.verify,
            elapsed_seconds: round(elapsed),
            throughput_gbps: round(
                args.bytes as f64 * 8.0 / elapsed / 1_000_000_000.0,
            ),
            cpu_seconds: round(cpu_seconds),
            cpu_seconds_per_gib: round(cpu_seconds / gib),
            voluntary_context_switches: usage_after.voluntary_context_switches
                - usage_before.voluntary_context_switches,
            involuntary_context_switches: usage_after.involuntary_context_switches
                - usage_before.involuntary_context_switches,
        })
    }

    fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }

    fn copy_relay(
        source: &mut TcpStream,
        destination: &mut TcpStream,
        chunk_size: usize,
    ) -> io::Result<u64> {
        let mut buffer = vec![0_u8; chunk_size];
        let mut total = 0_u64;
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                return Ok(total);
            }
            destination.write_all(&buffer[..count])?;
            total = total.saturating_add(count as u64);
        }
    }

    fn splice_relay(
        source: RawFd,
        destination: RawFd,
        chunk_size: usize,
    ) -> io::Result<u64> {
        let (pipe_read, pipe_write) = pipe()?;
        let mut total = 0_u64;
        loop {
            let input = retry_splice(source, pipe_write.as_raw_fd(), chunk_size)?;
            if input == 0 {
                return Ok(total);
            }
            drain_pipe(pipe_read.as_raw_fd(), destination, input)?;
            total = total.saturating_add(input as u64);
        }
    }

    fn retry_splice(
        source: RawFd,
        destination: RawFd,
        len: usize,
    ) -> io::Result<usize> {
        loop {
            let result = unsafe {
                libc::splice(
                    source,
                    ptr::null_mut(),
                    destination,
                    ptr::null_mut(),
                    len,
                    libc::SPLICE_F_MOVE,
                )
            };
            if result >= 0 {
                return Ok(result as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn drain_pipe(
        pipe_read: RawFd,
        destination: RawFd,
        mut remaining: usize,
    ) -> io::Result<()> {
        while remaining > 0 {
            let moved = retry_splice(pipe_read, destination, remaining)?;
            if moved == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice drained zero bytes from a non-empty pipe",
                ));
            }
            remaining -= moved;
        }
        Ok(())
    }

    fn verify_uring_splice_support() -> Result<()> {
        let ring = IoUring::new(8).context("create io_uring")?;
        let mut probe = Probe::new();
        ring.submitter()
            .register_probe(&mut probe)
            .context("register io_uring opcode probe")?;
        if !probe.is_supported(opcode::Splice::CODE) {
            bail!("kernel does not support IORING_OP_SPLICE");
        }
        Ok(())
    }

    fn uring_splice_relay(
        source: RawFd,
        destination: RawFd,
        chunk_size: usize,
        expected_bytes: u64,
        batch_depth: usize,
    ) -> Result<u64> {
        let (pipe_read, pipe_write) = pipe()?;
        let ring_entries = (batch_depth * 2).next_power_of_two().max(8);
        let mut ring =
            IoUring::new(ring_entries as u32).context("create io_uring relay")?;
        let mut total = 0_u64;

        while total < expected_bytes {
            let remaining = expected_bytes - total;
            let pair_count = usize::try_from(
                remaining
                    .div_ceil(chunk_size as u64)
                    .min(batch_depth as u64),
            )?;
            let mut requested = Vec::with_capacity(pair_count);
            let mut batch_remaining = remaining;

            {
                let mut submission = ring.submission();
                for pair_index in 0..pair_count {
                    let len =
                        usize::try_from(batch_remaining.min(chunk_size as u64))?;
                    batch_remaining -= len as u64;
                    requested.push(len);

                    let input_entry = opcode::Splice::new(
                        types::Fd(source),
                        -1,
                        types::Fd(pipe_write.as_raw_fd()),
                        -1,
                        len as u32,
                    )
                    .flags(libc::SPLICE_F_MOVE)
                    .build()
                    .flags(squeue::Flags::IO_HARDLINK)
                    .user_data((pair_index as u64) << 1);
                    let output_entry = opcode::Splice::new(
                        types::Fd(pipe_read.as_raw_fd()),
                        -1,
                        types::Fd(destination),
                        -1,
                        len as u32,
                    )
                    .flags(libc::SPLICE_F_MOVE)
                    .build()
                    .user_data(((pair_index as u64) << 1) | 1);
                    let output_entry = if pair_index + 1 < pair_count {
                        output_entry.flags(squeue::Flags::IO_HARDLINK)
                    } else {
                        output_entry
                    };

                    unsafe {
                        submission.push(&input_entry).map_err(|_| {
                            anyhow!("io_uring submission queue is full")
                        })?;
                        submission.push(&output_entry).map_err(|_| {
                            anyhow!("io_uring submission queue is full")
                        })?;
                    }
                }
            }

            let completion_count = pair_count * 2;
            ring.submit_and_wait(completion_count)
                .context("submit batched io_uring splice operations")?;
            let mut input_results = vec![None; pair_count];
            let mut output_results = vec![None; pair_count];
            let mut completed = 0usize;

            while completed < completion_count {
                for completion in ring.completion() {
                    let user_data = completion.user_data();
                    let pair_index = usize::try_from(user_data >> 1)?;
                    if pair_index >= pair_count {
                        bail!("unexpected io_uring user_data {user_data}");
                    }
                    let slot = if user_data & 1 == 0 {
                        &mut input_results[pair_index]
                    } else {
                        &mut output_results[pair_index]
                    };
                    if slot.replace(completion.result()).is_some() {
                        bail!(
                            "duplicate io_uring completion for user_data {user_data}"
                        );
                    }
                    completed += 1;
                }
                if completed < completion_count {
                    ring.submit_and_wait(completion_count - completed)
                        .context("wait for batched io_uring splice completions")?;
                }
            }

            let mut input_total = 0usize;
            let mut output_total = 0usize;
            for pair_index in 0..pair_count {
                let input = completion_result(
                    input_results[pair_index].expect("input completion"),
                )?;
                if input == 0 {
                    bail!(
                        "io_uring splice reached EOF after {total} of {expected_bytes} bytes"
                    );
                }
                let output = completion_result(
                    output_results[pair_index].expect("output completion"),
                )?;
                if input > requested[pair_index] || output > requested[pair_index] {
                    bail!("io_uring splice completion exceeded requested length");
                }
                input_total = input_total.saturating_add(input);
                output_total = output_total.saturating_add(output);
            }

            if output_total > input_total {
                bail!(
                    "io_uring splice output {output_total} exceeds input {input_total}"
                );
            }
            if output_total < input_total {
                uring_drain_pipe(
                    &mut ring,
                    pipe_read.as_raw_fd(),
                    destination,
                    input_total - output_total,
                )?;
            }
            total = total.saturating_add(input_total as u64);
        }

        Ok(total)
    }

    fn uring_drain_pipe(
        ring: &mut IoUring,
        pipe_read: RawFd,
        destination: RawFd,
        mut remaining: usize,
    ) -> Result<()> {
        while remaining > 0 {
            let entry = opcode::Splice::new(
                types::Fd(pipe_read),
                -1,
                types::Fd(destination),
                -1,
                remaining.min(u32::MAX as usize) as u32,
            )
            .flags(libc::SPLICE_F_MOVE)
            .build()
            .user_data(0);
            {
                let mut submission = ring.submission();
                unsafe {
                    submission
                        .push(&entry)
                        .map_err(|_| anyhow!("io_uring submission queue is full"))?;
                }
            }
            ring.submit_and_wait(1)
                .context("submit io_uring pipe drain")?;
            let completion = ring
                .completion()
                .next()
                .ok_or_else(|| anyhow!("missing io_uring pipe drain completion"))?;
            let moved = completion_result(completion.result())?;
            if moved == 0 {
                bail!("io_uring drained zero bytes from a non-empty pipe");
            }
            remaining -= moved;
        }
        Ok(())
    }

    fn completion_result(result: i32) -> Result<usize> {
        if result >= 0 {
            return Ok(result as usize);
        }
        Err(io::Error::from_raw_os_error(-result)).context("io_uring splice")
    }

    fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [-1; 2];
        let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        }))
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

        fn args(backend: Backend) -> Args {
            Args {
                backend,
                bytes: 4 * 1024 * 1024,
                chunk_size: 64 * 1024,
                uring_batch_depth: 16,
                warmup: 0,
                runs: 1,
                verify: true,
            }
        }

        #[test]
        fn validates_batch_depth_boundaries() {
            let mut valid = args(Backend::UringSplice);
            assert!(validate_args(&valid).is_ok());
            valid.uring_batch_depth = 1;
            assert!(validate_args(&valid).is_ok());
            valid.uring_batch_depth = 128;
            assert!(validate_args(&valid).is_ok());
            valid.uring_batch_depth = 0;
            assert!(validate_args(&valid).is_err());
            valid.uring_batch_depth = 129;
            assert!(validate_args(&valid).is_err());
        }

        #[test]
        fn copy_and_splice_relay_roundtrip() {
            for backend in [Backend::Copy, Backend::Splice] {
                let record = run_once(&args(backend), 0, false).unwrap();
                assert!(record.throughput_gbps > 0.0);
                assert!(record.cpu_seconds >= 0.0);
            }
        }

        #[test]
        #[ignore = "requires Linux io_uring with IORING_OP_SPLICE support"]
        fn io_uring_splice_relay_roundtrip() {
            verify_uring_splice_support().unwrap();
            let record = run_once(&args(Backend::UringSplice), 0, false).unwrap();
            assert!(record.throughput_gbps > 0.0);
            assert!(record.cpu_seconds >= 0.0);
        }
    }
}
