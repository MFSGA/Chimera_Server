#[cfg(target_os = "linux")]
mod linux {
    use std::{
        hint::black_box,
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
    use tokio::io::unix::AsyncFd;

    #[derive(Debug, Clone, Copy, ValueEnum, Serialize)]
    #[serde(rename_all = "kebab-case")]
    enum EndpointMode {
        Arc,
        Owned,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Measure fixed Linux splice relay endpoint/setup overhead")]
    struct Args {
        #[arg(long, value_enum)]
        mode: EndpointMode,

        #[arg(long, default_value_t = 128 * 1024)]
        pipe_size: usize,

        #[arg(long, default_value_t = 10_000)]
        iterations: usize,

        #[arg(long, default_value_t = 2)]
        warmup: usize,

        #[arg(long, default_value_t = 7)]
        runs: usize,
    }

    #[derive(Debug, Serialize)]
    struct RunRecord {
        record_type: &'static str,
        run_index: usize,
        warmup: bool,
        mode: EndpointMode,
        iterations: usize,
        pipe_size: usize,
        ns_per_setup: f64,
    }

    #[derive(Debug, Serialize)]
    struct Summary {
        record_type: &'static str,
        mode: EndpointMode,
        iterations: usize,
        pipe_size: usize,
        runs: usize,
        ns_per_setup_median: f64,
        ns_per_setup_cv: f64,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        if args.iterations == 0 || args.runs == 0 {
            bail!("--iterations and --runs must be greater than zero");
        }
        if args.pipe_size == 0 || args.pipe_size > i32::MAX as usize {
            bail!("--pipe-size must be between 1 and i32::MAX");
        }

        let (left, right) = tcp_pair()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;

        for run_index in 0..args.warmup {
            let record = runtime.block_on(run_once(
                &args,
                left.as_raw_fd(),
                right.as_raw_fd(),
                run_index,
                true,
            ))?;
            println!("{}", serde_json::to_string(&record)?);
        }

        let mut samples = Vec::with_capacity(args.runs);
        for run_index in 0..args.runs {
            let record = runtime.block_on(run_once(
                &args,
                left.as_raw_fd(),
                right.as_raw_fd(),
                run_index,
                false,
            ))?;
            samples.push(record.ns_per_setup);
            println!("{}", serde_json::to_string(&record)?);
        }
        println!(
            "{}",
            serde_json::to_string(&Summary {
                record_type: "summary",
                mode: args.mode,
                iterations: args.iterations,
                pipe_size: args.pipe_size,
                runs: args.runs,
                ns_per_setup_median: round(median(&samples)),
                ns_per_setup_cv: round(coefficient_of_variation(&samples)),
            })?
        );
        Ok(())
    }

    async fn run_once(
        args: &Args,
        left_fd: RawFd,
        right_fd: RawFd,
        run_index: usize,
        warmup: bool,
    ) -> Result<RunRecord> {
        let started = Instant::now();
        for _ in 0..args.iterations {
            match args.mode {
                EndpointMode::Arc => setup_arc(left_fd, right_fd, args.pipe_size)?,
                EndpointMode::Owned => {
                    setup_owned(left_fd, right_fd, args.pipe_size)?
                }
            }
        }
        let elapsed = started.elapsed().as_secs_f64();
        Ok(RunRecord {
            record_type: "run",
            run_index,
            warmup,
            mode: args.mode,
            iterations: args.iterations,
            pipe_size: args.pipe_size,
            ns_per_setup: round(elapsed * 1e9 / args.iterations as f64),
        })
    }

    fn setup_arc(
        left_fd: RawFd,
        right_fd: RawFd,
        pipe_size: usize,
    ) -> io::Result<()> {
        let left = Arc::new(AsyncFd::new(duplicate_fd(left_fd)?)?);
        let right = Arc::new(AsyncFd::new(duplicate_fd(right_fd)?)?);
        let left_clone = Arc::clone(&left);
        let right_clone = Arc::clone(&right);
        let pipe_a = nonblocking_pipe(pipe_size)?;
        let pipe_b = nonblocking_pipe(pipe_size)?;
        black_box((&left, &right, &left_clone, &right_clone, &pipe_a, &pipe_b));
        Ok(())
    }

    fn setup_owned(
        left_fd: RawFd,
        right_fd: RawFd,
        pipe_size: usize,
    ) -> io::Result<()> {
        let left = AsyncFd::new(duplicate_fd(left_fd)?)?;
        let right = AsyncFd::new(duplicate_fd(right_fd)?)?;
        let pipe_a = nonblocking_pipe(pipe_size)?;
        let pipe_b = nonblocking_pipe(pipe_size)?;
        black_box((&left, &right, &pipe_a, &pipe_b));
        Ok(())
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
        let current_capacity = pipe_capacity(pipe_write.as_raw_fd())?;
        let actual_capacity = if requested_capacity > current_capacity {
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
                current_capacity
            }
        } else {
            current_capacity
        };
        Ok((pipe_read, pipe_write, actual_capacity))
    }

    fn pipe_capacity(fd: RawFd) -> io::Result<usize> {
        let capacity = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
        if capacity < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(capacity as usize)
    }

    fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address)?;
        let (server, _) = listener.accept()?;
        client.set_nonblocking(true)?;
        server.set_nonblocking(true)?;
        Ok((client, server))
    }

    fn round(value: f64) -> f64 {
        (value * 1_000_000.0).round() / 1_000_000.0
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp_splice_setup_probe is Linux-only");
}
