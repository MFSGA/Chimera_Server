#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp_short_flow_relay_probe requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{self, Write},
        net::{Shutdown, TcpListener, TcpStream},
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
        io::{AsyncReadExt, AsyncWriteExt},
    };

    const PATTERN_BYTE: u8 = 0x5a;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Backend {
        Copy,
        PrefixSplice,
        Splice,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Production-like Tokio copy vs full-splice short-flow probe")]
    struct Args {
        #[arg(long, value_enum)]
        backend: Backend,

        #[arg(long, default_value_t = 64)]
        connections: usize,

        #[arg(long, default_value_t = 8)]
        worker_threads: usize,

        #[arg(long, default_value_t = 32 * 1024)]
        bytes_per_connection: usize,

        #[arg(long, default_value_t = 32 * 1024)]
        copy_buffer_size: usize,

        #[arg(long, default_value_t = 128 * 1024)]
        splice_pipe_size: usize,

        #[arg(long, default_value_t = 64 * 1024)]
        prefix_bytes: usize,

        #[arg(long, default_value_t = 1)]
        warmup: usize,

        #[arg(long, default_value_t = 7)]
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
        record_type: &'static str,
        run_index: usize,
        warmup: bool,
        backend: Backend,
        connections: usize,
        worker_threads: usize,
        bytes_per_connection: usize,
        copy_buffer_size: usize,
        splice_pipe_size: usize,
        prefix_bytes: usize,
        verify: bool,
        elapsed_seconds: f64,
        elapsed_us_per_connection: f64,
        aggregate_throughput_gbps: f64,
        cpu_seconds: f64,
        cpu_us_per_connection: f64,
        voluntary_context_switches: i64,
        involuntary_context_switches: i64,
    }

    #[derive(Debug, Serialize)]
    struct Summary {
        record_type: &'static str,
        backend: Backend,
        connections: usize,
        worker_threads: usize,
        bytes_per_connection: usize,
        copy_buffer_size: usize,
        splice_pipe_size: usize,
        prefix_bytes: usize,
        runs: usize,
        warmup_runs: usize,
        elapsed_us_per_connection_median: f64,
        elapsed_cv: f64,
        aggregate_throughput_median_gbps: f64,
        cpu_us_per_connection_median: f64,
        context_switches_median: f64,
    }

    struct PreparedFlow {
        relay_source: tokio::net::TcpStream,
        relay_destination: tokio::net::TcpStream,
        sink: tokio::net::TcpStream,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.worker_threads)
            .enable_io()
            .build()?;

        for run_index in 0..args.warmup {
            let record = runtime.block_on(run_once(&args, run_index, true))?;
            println!("{}", serde_json::to_string(&record)?);
        }

        let mut elapsed = Vec::with_capacity(args.runs);
        let mut throughput = Vec::with_capacity(args.runs);
        let mut cpu = Vec::with_capacity(args.runs);
        let mut context_switches = Vec::with_capacity(args.runs);
        for run_index in 0..args.runs {
            let record = runtime.block_on(run_once(&args, run_index, false))?;
            elapsed.push(record.elapsed_us_per_connection);
            throughput.push(record.aggregate_throughput_gbps);
            cpu.push(record.cpu_us_per_connection);
            context_switches.push(
                (record.voluntary_context_switches
                    + record.involuntary_context_switches) as f64,
            );
            println!("{}", serde_json::to_string(&record)?);
        }

        println!(
            "{}",
            serde_json::to_string(&Summary {
                record_type: "summary",
                backend: args.backend,
                connections: args.connections,
                worker_threads: args.worker_threads,
                bytes_per_connection: args.bytes_per_connection,
                copy_buffer_size: args.copy_buffer_size,
                splice_pipe_size: args.splice_pipe_size,
                prefix_bytes: args.prefix_bytes,
                runs: args.runs,
                warmup_runs: args.warmup,
                elapsed_us_per_connection_median: round(median(&elapsed)),
                elapsed_cv: round(coefficient_of_variation(&elapsed)),
                aggregate_throughput_median_gbps: round(median(&throughput)),
                cpu_us_per_connection_median: round(median(&cpu)),
                context_switches_median: round(median(&context_switches)),
            })?
        );
        Ok(())
    }

    fn validate_args(args: &Args) -> Result<()> {
        if args.connections == 0 || args.worker_threads == 0 || args.runs == 0 {
            bail!(
                "--connections, --worker-threads, and --runs must be greater than zero"
            );
        }
        if !(4 * 1024..=256 * 1024).contains(&args.bytes_per_connection) {
            bail!("--bytes-per-connection must be between 4096 and 262144 bytes");
        }
        if args.copy_buffer_size == 0
            || args.splice_pipe_size == 0
            || args.prefix_bytes == 0
        {
            bail!(
                "copy buffer, splice pipe, and prefix sizes must be greater than zero"
            );
        }
        Ok(())
    }

    async fn run_once(
        args: &Args,
        run_index: usize,
        warmup: bool,
    ) -> Result<RunRecord> {
        let mut flows = Vec::with_capacity(args.connections);
        let payload = vec![PATTERN_BYTE; args.bytes_per_connection];
        for _ in 0..args.connections {
            flows.push(prepare_flow(&payload)?);
        }

        let usage_before = usage()?;
        let started = Instant::now();
        let mut tasks = Vec::with_capacity(args.connections);
        for flow in flows {
            let backend = args.backend;
            let copy_buffer_size = args.copy_buffer_size;
            let splice_pipe_size = args.splice_pipe_size;
            let prefix_bytes = args.prefix_bytes;
            let expected = args.bytes_per_connection;
            let verify = args.verify;
            tasks.push(tokio::spawn(async move {
                run_flow(
                    flow,
                    backend,
                    copy_buffer_size,
                    splice_pipe_size,
                    prefix_bytes,
                    expected,
                    verify,
                )
                .await
            }));
        }
        for task in tasks {
            task.await
                .map_err(|_| anyhow::anyhow!("short-flow task panicked"))??;
        }
        let elapsed = started.elapsed().as_secs_f64();
        let usage_after = usage()?;

        let total_bytes = args.bytes_per_connection as u64 * args.connections as u64;
        let cpu_seconds = usage_after.cpu_seconds - usage_before.cpu_seconds;
        Ok(RunRecord {
            record_type: "run",
            run_index,
            warmup,
            backend: args.backend,
            connections: args.connections,
            worker_threads: args.worker_threads,
            bytes_per_connection: args.bytes_per_connection,
            copy_buffer_size: args.copy_buffer_size,
            splice_pipe_size: args.splice_pipe_size,
            prefix_bytes: args.prefix_bytes,
            verify: args.verify,
            elapsed_seconds: round(elapsed),
            elapsed_us_per_connection: round(
                elapsed * 1e6 / args.connections as f64,
            ),
            aggregate_throughput_gbps: round(
                total_bytes as f64 * 8.0 / elapsed / 1e9,
            ),
            cpu_seconds: round(cpu_seconds),
            cpu_us_per_connection: round(
                cpu_seconds * 1e6 / args.connections as f64,
            ),
            voluntary_context_switches: usage_after.voluntary_context_switches
                - usage_before.voluntary_context_switches,
            involuntary_context_switches: usage_after.involuntary_context_switches
                - usage_before.involuntary_context_switches,
        })
    }

    fn prepare_flow(payload: &[u8]) -> io::Result<PreparedFlow> {
        let (mut source_writer, relay_source) = tcp_pair()?;
        let (relay_destination, sink) = tcp_pair()?;
        for stream in [&source_writer, &relay_source, &relay_destination, &sink] {
            stream.set_nodelay(true)?;
        }

        source_writer.write_all(payload)?;
        source_writer.shutdown(Shutdown::Write)?;
        sink.shutdown(Shutdown::Write)?;
        relay_source.set_nonblocking(true)?;
        relay_destination.set_nonblocking(true)?;
        sink.set_nonblocking(true)?;

        Ok(PreparedFlow {
            relay_source: tokio::net::TcpStream::from_std(relay_source)?,
            relay_destination: tokio::net::TcpStream::from_std(relay_destination)?,
            sink: tokio::net::TcpStream::from_std(sink)?,
        })
    }

    async fn run_flow(
        mut flow: PreparedFlow,
        backend: Backend,
        copy_buffer_size: usize,
        splice_pipe_size: usize,
        prefix_bytes: usize,
        expected: usize,
        verify: bool,
    ) -> io::Result<()> {
        let relay = async {
            match backend {
                Backend::Copy => {
                    let (left_to_right, right_to_left) =
                        tokio::io::copy_bidirectional_with_sizes(
                            &mut flow.relay_source,
                            &mut flow.relay_destination,
                            copy_buffer_size,
                            copy_buffer_size,
                        )
                        .await?;
                    if left_to_right != expected as u64 || right_to_left != 0 {
                        return Err(io::Error::other(format!(
                            "copy relay counts {left_to_right}/{right_to_left}, expected {expected}/0"
                        )));
                    }
                    Ok(())
                }
                Backend::PrefixSplice => {
                    let (copied, complete) = copy_prefix(
                        &mut flow.relay_source,
                        &mut flow.relay_destination,
                        prefix_bytes,
                        copy_buffer_size,
                    )
                    .await?;
                    if complete {
                        if copied != expected as u64 {
                            return Err(io::Error::other(format!(
                                "prefix relay copied {copied}, expected {expected}"
                            )));
                        }
                        return Ok(());
                    }
                    let splice = SpliceRelay::new(
                        flow.relay_source.as_raw_fd(),
                        flow.relay_destination.as_raw_fd(),
                        splice_pipe_size,
                    )?;
                    let (left_to_right, right_to_left) = splice.run().await?;
                    if copied.saturating_add(left_to_right) != expected as u64
                        || right_to_left != 0
                    {
                        return Err(io::Error::other(format!(
                            "prefix/splice relay counts {copied}+{left_to_right}/{right_to_left}, expected {expected}/0"
                        )));
                    }
                    Ok(())
                }
                Backend::Splice => {
                    let splice = SpliceRelay::new(
                        flow.relay_source.as_raw_fd(),
                        flow.relay_destination.as_raw_fd(),
                        splice_pipe_size,
                    )?;
                    let (left_to_right, right_to_left) = splice.run().await?;
                    if left_to_right != expected as u64 || right_to_left != 0 {
                        return Err(io::Error::other(format!(
                            "splice relay counts {left_to_right}/{right_to_left}, expected {expected}/0"
                        )));
                    }
                    Ok(())
                }
            }
        };

        let sink = async {
            let mut buffer = vec![0_u8; 32 * 1024];
            let mut received = 0usize;
            loop {
                let count = flow.sink.read(&mut buffer).await?;
                if count == 0 {
                    break;
                }
                if verify && buffer[..count].iter().any(|byte| *byte != PATTERN_BYTE)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "payload mismatch",
                    ));
                }
                received = received.saturating_add(count);
            }
            if received != expected {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("sink received {received} bytes, expected {expected}"),
                ));
            }
            Ok(())
        };

        tokio::try_join!(relay, sink)?;
        Ok(())
    }

    async fn copy_prefix(
        source: &mut tokio::net::TcpStream,
        destination: &mut tokio::net::TcpStream,
        prefix_bytes: usize,
        copy_buffer_size: usize,
    ) -> io::Result<(u64, bool)> {
        let mut buffer = vec![0_u8; copy_buffer_size.min(prefix_bytes)];
        let mut copied = 0usize;
        while copied < prefix_bytes {
            let limit = (prefix_bytes - copied).min(buffer.len());
            let count = source.read(&mut buffer[..limit]).await?;
            if count == 0 {
                destination.shutdown().await?;
                return Ok((copied as u64, true));
            }
            destination.write_all(&buffer[..count]).await?;
            copied += count;
        }

        let mut probe = [0_u8; 1];
        match source.try_read(&mut probe) {
            Ok(0) => {
                destination.shutdown().await?;
                Ok((copied as u64, true))
            }
            Ok(1) => {
                destination.write_all(&probe).await?;
                Ok(((copied + 1) as u64, false))
            }
            Ok(_) => unreachable!("one-byte EOF probe returned more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Ok((copied as u64, false))
            }
            Err(error) => Err(error),
        }
    }

    fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, _) = listener.accept()?;
        Ok((client, server))
    }

    struct SpliceRelay {
        left_to_right: SpliceDirection,
        right_to_left: SpliceDirection,
    }

    impl SpliceRelay {
        fn new(
            left_fd: RawFd,
            right_fd: RawFd,
            requested_pipe_size: usize,
        ) -> io::Result<Self> {
            let left = Arc::new(AsyncFd::new(duplicate_fd(left_fd)?)?);
            let right = Arc::new(AsyncFd::new(duplicate_fd(right_fd)?)?);
            Ok(Self {
                left_to_right: SpliceDirection::with_endpoints(
                    Arc::clone(&left),
                    Arc::clone(&right),
                    requested_pipe_size,
                )?,
                right_to_left: SpliceDirection::with_endpoints(
                    right,
                    left,
                    requested_pipe_size,
                )?,
            })
        }

        async fn run(self) -> io::Result<(u64, u64)> {
            tokio::try_join!(self.left_to_right.run(), self.right_to_left.run())
        }
    }

    struct SpliceDirection {
        source: Arc<AsyncFd<OwnedFd>>,
        destination: Arc<AsyncFd<OwnedFd>>,
        pipe_read: OwnedFd,
        pipe_write: OwnedFd,
        pipe_capacity: usize,
    }

    impl SpliceDirection {
        fn with_endpoints(
            source: Arc<AsyncFd<OwnedFd>>,
            destination: Arc<AsyncFd<OwnedFd>>,
            requested_pipe_size: usize,
        ) -> io::Result<Self> {
            let (pipe_read, pipe_write, pipe_capacity) =
                nonblocking_pipe(requested_pipe_size)?;
            Ok(Self {
                source,
                destination,
                pipe_read,
                pipe_write,
                pipe_capacity,
            })
        }

        async fn run(self) -> io::Result<u64> {
            let mut pending = 0usize;
            let mut transferred = 0u64;
            loop {
                if pending > 0 {
                    let pipe_read_fd = self.pipe_read.as_raw_fd();
                    let mut writable = self.destination.writable().await?;
                    match writable.try_io(|destination| {
                        splice_once(
                            pipe_read_fd,
                            destination.get_ref().as_raw_fd(),
                            pending,
                        )
                    }) {
                        Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                        Ok(Ok(written)) => {
                            pending -= written;
                            transferred = transferred.saturating_add(written as u64);
                        }
                        Ok(Err(error)) => return Err(error),
                        Err(_) => continue,
                    }
                    continue;
                }

                let pipe_write_fd = self.pipe_write.as_raw_fd();
                let mut readable = self.source.readable().await?;
                match readable.try_io(|source| {
                    splice_once(
                        source.get_ref().as_raw_fd(),
                        pipe_write_fd,
                        self.pipe_capacity,
                    )
                }) {
                    Ok(Ok(0)) => {
                        shutdown_write(self.destination.get_ref().as_raw_fd())?;
                        return Ok(transferred);
                    }
                    Ok(Ok(read)) => pending = read,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => continue,
                }
            }
        }
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
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Err(error)
    }

    fn shutdown_write(fd: RawFd) -> io::Result<()> {
        let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
        if result == 0 {
            Ok(())
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
        value.tv_sec as f64 + value.tv_usec as f64 / 1e6
    }

    fn round(value: f64) -> f64 {
        (value * 1_000_000.0).round() / 1_000_000.0
    }
}
