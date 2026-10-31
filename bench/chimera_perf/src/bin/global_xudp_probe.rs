#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("global_xudp_probe requires Linux");
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
        net::{SocketAddr, UdpSocket as StdUdpSocket},
        os::fd::AsRawFd,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use chimera_perf::stats::{coefficient_of_variation, median};
    use chimera_server_lib::traffic::{
        TrafficContext, record_transfer_ref, user_traffic,
    };
    use clap::{Parser, ValueEnum};
    use serde::Serialize;
    use std::time::Instant as StdInstant;
    use tokio::{
        net::UdpSocket,
        sync::{Barrier as AsyncBarrier, Notify, RwLock, Semaphore, mpsc, oneshot},
        task::JoinSet,
        time::{Instant, Sleep, sleep, timeout},
    };

    const HEADER_SIZE: usize = 8;
    const SHARED_PAYLOAD_THRESHOLD: usize = 1200;
    const ESTIMATED_UDP_PACKET_OVERHEAD_BYTES: usize = 2048;
    const DEFAULT_CHANNEL_CAPACITY: usize = 64;
    const DEFAULT_INFLIGHT_WINDOW: usize = 16;
    const MAX_SESSIONS: usize = 4096;

    #[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Accounting {
        Enabled,
        Disabled,
    }

    #[derive(Debug, Parser)]
    #[command(about = "Production-shaped multi-session Global XUDP UDP probe")]
    struct Args {
        #[arg(long, default_value_t = 8)]
        worker_threads: usize,
        #[arg(long, default_value_t = 16)]
        sessions: usize,
        #[arg(long, default_value_t = 4096)]
        packets_per_session: usize,
        #[arg(long, default_value_t = 1200)]
        datagram_size: usize,
        #[arg(long, default_value_t = DEFAULT_CHANNEL_CAPACITY)]
        channel_capacity: usize,
        #[arg(long, default_value_t = DEFAULT_INFLIGHT_WINDOW)]
        inflight_window: usize,
        #[arg(long, value_enum, default_value_t = Accounting::Enabled)]
        accounting: Accounting,
        #[arg(long, default_value_t = false)]
        recycle_payload: bool,
        #[arg(long, default_value_t = 3)]
        warmup: usize,
        #[arg(long, default_value_t = 10)]
        runs: usize,
    }

    #[derive(Clone)]
    struct Attachment {
        token: u64,
        traffic_context: Option<TrafficContext>,
        responses: mpsc::Sender<Response>,
    }

    enum PayloadBuffer {
        Owned(Vec<u8>),
        Shared(Bytes),
    }

    impl PayloadBuffer {
        fn as_slice(&self) -> &[u8] {
            match self {
                Self::Owned(payload) => payload,
                Self::Shared(payload) => payload,
            }
        }
    }

    struct Completion {
        result: io::Result<()>,
        recycled_payload: Option<PayloadBuffer>,
    }

    struct Request {
        token: u64,
        payload: Option<PayloadBuffer>,
        recycle_payload: bool,
        completion: Option<oneshot::Sender<Completion>>,
    }

    impl Request {
        fn payload(&self) -> &[u8] {
            self.payload
                .as_ref()
                .expect("request payload is present until completion")
                .as_slice()
        }

        fn complete(mut self, result: io::Result<()>) {
            let payload = self.payload.take();
            let recycled_payload = if self.recycle_payload {
                payload
            } else {
                drop(payload);
                None
            };
            if let Some(completion) = self.completion.take() {
                let _ = completion.send(Completion {
                    result,
                    recycled_payload,
                });
            }
        }
    }

    impl Drop for Request {
        fn drop(&mut self) {
            let Some(completion) = self.completion.take() else {
                return;
            };
            let payload = self.payload.take();
            let recycled_payload = if self.recycle_payload {
                payload
            } else {
                drop(payload);
                None
            };
            let _ = completion.send(Completion {
                result: Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Global XUDP request dropped before completion",
                )),
                recycled_payload,
            });
        }
    }

    struct Response {
        source: SocketAddr,
        payload: Vec<u8>,
        traffic_context: Option<TrafficContext>,
    }

    enum TaskOutput {
        Producer,
        Consumer,
        Worker,
    }

    #[derive(Debug, Clone, Copy)]
    struct Sample {
        packets_per_second: f64,
        uplink_gbps: f64,
        process_cpu_seconds_per_million_roundtrips: f64,
        minimum_effective_socket_rcvbuf_bytes: usize,
    }

    pub(super) fn run() -> Result<()> {
        let args = Args::parse();
        validate_args(&args)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.worker_threads)
            .enable_all()
            .build()?;

        for warmup in 0..args.warmup {
            let _ = runtime.block_on(run_once(&args, format!("warmup-{warmup}")))?;
        }

        let mut rates = Vec::with_capacity(args.runs);
        let mut uplink = Vec::with_capacity(args.runs);
        let mut cpu = Vec::with_capacity(args.runs);
        let mut socket_rcvbuf_bytes = Vec::with_capacity(args.runs);
        for run in 0..args.runs {
            let sample = runtime.block_on(run_once(&args, format!("run-{run}")))?;
            rates.push(sample.packets_per_second);
            uplink.push(sample.uplink_gbps);
            cpu.push(sample.process_cpu_seconds_per_million_roundtrips);
            socket_rcvbuf_bytes.push(sample.minimum_effective_socket_rcvbuf_bytes);
        }

        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "record_type": "summary",
                "model": "global-xudp-production-shaped",
                "accounting": args.accounting,
                "recycle_payload": args.recycle_payload,
                "worker_threads": args.worker_threads,
                "sessions": args.sessions,
                "packets_per_session": args.packets_per_session,
                "total_roundtrips": total_packets(&args),
                "datagram_size": args.datagram_size,
                "channel_capacity": args.channel_capacity,
                "inflight_window": args.inflight_window,
                "completion": "per-packet-oneshot",
                "shared_payload_threshold": SHARED_PAYLOAD_THRESHOLD,
                "socket_topology": "one-unconnected-udp-socket-per-globalid-worker",
                "warmup_runs": args.warmup,
                "runs": args.runs,
                "packets_per_second_median": round(median(&rates)),
                "packets_per_second_cv": round(coefficient_of_variation(&rates)),
                "uplink_gbps_median": round(median(&uplink)),
                "process_cpu_seconds_per_million_roundtrips_median": round(median(&cpu)),
                "process_cpu_seconds_per_million_roundtrips_cv": round(coefficient_of_variation(&cpu)),
                "minimum_effective_socket_rcvbuf_bytes": socket_rcvbuf_bytes.iter().copied().min(),
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
        if args.channel_capacity == 0 {
            bail!("--channel-capacity must be greater than zero");
        }
        if args.inflight_window == 0 || args.inflight_window > 65_536 {
            bail!("--inflight-window must be between 1 and 65536");
        }
        if args.runs == 0 {
            bail!("--runs must be greater than zero");
        }
        args.sessions
            .checked_mul(args.packets_per_session)
            .context("session packet count overflow")?;
        if args.packets_per_session > u32::MAX as usize {
            bail!("--packets-per-session must fit in the probe sequence header");
        }
        Ok(())
    }

    fn total_packets(args: &Args) -> usize {
        args.sessions.saturating_mul(args.packets_per_session)
    }

    async fn run_once(args: &Args, run_id: String) -> Result<Sample> {
        let expected_total = total_packets(args);
        let echo = StdUdpSocket::bind("127.0.0.1:0")?;
        let mut minimum_effective_rcvbuf =
            set_socket_buffers(echo.as_raw_fd(), 8 * 1024 * 1024)?;
        echo.set_read_timeout(Some(Duration::from_millis(100)))?;
        let echo_addr = echo.local_addr()?;

        let start_barrier = Arc::new(AsyncBarrier::new(args.sessions * 3 + 1));
        let mut sessions = Vec::with_capacity(args.sessions);
        for session_id in 0..args.sessions {
            let socket = UdpSocket::bind("127.0.0.1:0")
                .await
                .context("binding Global XUDP worker socket")?;
            minimum_effective_rcvbuf = minimum_effective_rcvbuf
                .min(set_socket_buffers(socket.as_raw_fd(), 8 * 1024 * 1024)?);
            let (request_sender, request_receiver) =
                mpsc::channel::<Request>(args.channel_capacity);
            let (response_sender, response_receiver) =
                mpsc::channel::<Response>(args.channel_capacity);
            let identity = format!("global-xudp-probe-{run_id}-{session_id}");
            let traffic_context = Some(
                TrafficContext::new("vless")
                    .with_identity(identity)
                    .with_inbound_tag("global-xudp-probe-in")
                    .with_outbound_tag("direct"),
            );
            let attachment = Arc::new(RwLock::new(Some(Attachment {
                token: 1,
                traffic_context,
                responses: response_sender,
            })));
            let inflight = Arc::new(Semaphore::new(args.inflight_window));
            sessions.push(Session {
                session_id,
                socket,
                request_sender,
                request_receiver,
                response_receiver,
                attachment,
                inflight,
            });
        }

        validate_receive_buffer_budget(args, minimum_effective_rcvbuf)?;
        let echo_stop = Arc::new(AtomicBool::new(false));
        let echo_thread = start_echo(echo, expected_total, Arc::clone(&echo_stop));

        let mut tasks = JoinSet::new();
        for session in sessions {
            let start_barrier = Arc::clone(&start_barrier);
            let packets = args.packets_per_session;
            let datagram_size = args.datagram_size;
            let accounting = matches!(args.accounting, Accounting::Enabled);
            let recycle_payload = args.recycle_payload;
            let session_id = session.session_id;

            let sender = session.request_sender;
            let producer_inflight = Arc::clone(&session.inflight);
            let producer_barrier = Arc::clone(&start_barrier);
            tasks.spawn(async move {
                producer_barrier.wait().await;
                for sequence in 0..packets {
                    let inflight_permit = Arc::clone(&producer_inflight)
                        .acquire_owned()
                        .await
                        .context("Global XUDP inflight semaphore closed")?;
                    let packet = encode_payload(session_id, sequence, datagram_size);
                    let (request_payload, retry_payload) =
                        prepare_payload(packet, recycle_payload);
                    let (completion, completed) = oneshot::channel();
                    let request = Request {
                        token: 1,
                        payload: Some(request_payload),
                        recycle_payload,
                        completion: Some(completion),
                    };
                    sender
                        .send(request)
                        .await
                        .context("Global XUDP request channel closed")?;
                    let completion = completed
                        .await
                        .context("Global XUDP send acknowledgement dropped")?;
                    completion.result.context("Global XUDP send failed")?;
                    drop(completion.recycled_payload);
                    drop(retry_payload);
                    inflight_permit.forget();
                }
                Ok::<_, anyhow::Error>(TaskOutput::Producer)
            });

            let mut response_receiver = session.response_receiver;
            let consumer_inflight = Arc::clone(&session.inflight);
            let consumer_barrier = Arc::clone(&start_barrier);
            tasks.spawn(async move {
                consumer_barrier.wait().await;
                let mut seen = vec![false; packets];
                for _ in 0..packets {
                    let response = response_receiver
                        .recv()
                        .await
                        .context("Global XUDP response channel closed")?;
                    if response.source != echo_addr {
                        bail!("Global XUDP response source did not match target");
                    }
                    let (received_session, sequence) =
                        decode_payload(&response.payload)?;
                    if received_session != session_id || sequence >= packets {
                        bail!(
                            "response was routed to the wrong session or sequence"
                        );
                    }
                    if std::mem::replace(&mut seen[sequence], true) {
                        bail!("duplicate response sequence {sequence}");
                    }
                    if accounting {
                        record_transfer_ref(
                            response.traffic_context.as_ref(),
                            0,
                            response.payload.len() as u64,
                        );
                    }
                    consumer_inflight.add_permits(1);
                }
                if seen.iter().any(|received| !received) {
                    bail!("one or more response sequences were missing");
                }
                Ok::<_, anyhow::Error>(TaskOutput::Consumer)
            });

            let socket = session.socket;
            let attachment = session.attachment;
            let worker_packets = packets;
            let worker_barrier = Arc::clone(&start_barrier);
            tasks.spawn(async move {
                run_worker(
                    socket,
                    echo_addr,
                    attachment,
                    session.request_receiver,
                    worker_packets,
                    accounting,
                    worker_barrier,
                )
                .await?;
                Ok::<_, anyhow::Error>(TaskOutput::Worker)
            });
        }

        let cpu_before = cpu_seconds()?;
        start_barrier.wait().await;
        let started = StdInstant::now();
        let join_result = timeout(Duration::from_secs(60), async {
            let expected_tasks = args.sessions * 3;
            let mut completed = 0;
            while completed < expected_tasks {
                let output = tasks
                    .join_next()
                    .await
                    .context("Global XUDP task set ended early")??;
                output?;
                completed += 1;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        let join_result = match join_result {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("Global XUDP probe timed out after 60s")),
        };
        if let Err(error) = join_result {
            tasks.abort_all();
            echo_stop.store(true, Ordering::Relaxed);
            let _ = echo_thread.join();
            return Err(error);
        }

        let elapsed = started.elapsed().as_secs_f64();
        let cpu = cpu_seconds()? - cpu_before;
        echo_stop.store(true, Ordering::Relaxed);
        let echoed = echo_thread
            .join()
            .map_err(|_| anyhow::anyhow!("echo thread panicked"))??;
        if echoed != expected_total {
            bail!("echo server handled {echoed} packets, expected {expected_total}");
        }

        if matches!(args.accounting, Accounting::Enabled) {
            for session_id in 0..args.sessions {
                let identity = format!("global-xudp-probe-{run_id}-{session_id}");
                let expected_bytes =
                    (args.packets_per_session * args.datagram_size) as u64;
                let actual =
                    user_traffic(&identity).context("traffic user missing")?;
                if actual != (expected_bytes, expected_bytes) {
                    bail!(
                        "traffic mismatch for session {session_id}: got {actual:?}, expected ({expected_bytes}, {expected_bytes})"
                    );
                }
            }
        }

        let packets_per_second =
            expected_total as f64 / elapsed.max(f64::MIN_POSITIVE);
        Ok(Sample {
            packets_per_second,
            uplink_gbps: packets_per_second * args.datagram_size as f64 * 8.0 / 1e9,
            process_cpu_seconds_per_million_roundtrips: cpu
                / (expected_total as f64 / 1_000_000.0),
            minimum_effective_socket_rcvbuf_bytes: minimum_effective_rcvbuf,
        })
    }

    fn validate_receive_buffer_budget(
        args: &Args,
        effective_rcvbuf: usize,
    ) -> Result<()> {
        // Include a conservative per-datagram allowance for Linux packet metadata.
        // Reserve half of the reported buffer for estimation error and scheduling bursts.
        let conservative_budget = effective_rcvbuf / 2;
        let estimated_packet_charge = args
            .datagram_size
            .checked_add(ESTIMATED_UDP_PACKET_OVERHEAD_BYTES)
            .context("estimated UDP packet charge overflow")?;
        let per_session_burst = args
            .inflight_window
            .checked_mul(estimated_packet_charge)
            .context("per-session receive burst size overflow")?;
        let aggregate_echo_burst = args
            .sessions
            .checked_mul(per_session_burst)
            .context("aggregate echo receive burst size overflow")?;
        if per_session_burst > conservative_budget
            || aggregate_echo_burst > conservative_budget
        {
            bail!(
                "estimated receive burst may exceed the effective UDP socket buffer: estimated packet charge={estimated_packet_charge} bytes, per-session={per_session_burst} bytes, aggregate-echo={aggregate_echo_burst} bytes, conservative-buffer-budget={conservative_budget} bytes (effective SO_RCVBUF={effective_rcvbuf}); reduce sessions, --inflight-window, or --datagram-size, or raise the host UDP receive-buffer limit"
            );
        }
        Ok(())
    }

    struct Session {
        session_id: usize,
        socket: UdpSocket,
        request_sender: mpsc::Sender<Request>,
        request_receiver: mpsc::Receiver<Request>,
        response_receiver: mpsc::Receiver<Response>,
        attachment: Arc<RwLock<Option<Attachment>>>,
        inflight: Arc<Semaphore>,
    }

    async fn run_worker(
        socket: UdpSocket,
        target: SocketAddr,
        attachment: Arc<RwLock<Option<Attachment>>>,
        mut requests: mpsc::Receiver<Request>,
        expected_packets: usize,
        accounting: bool,
        start_barrier: Arc<AsyncBarrier>,
    ) -> Result<()> {
        let attachment_notify = Notify::new();
        let mut response_buffer = vec![0; 65_535];
        let mut idle: std::pin::Pin<Box<Sleep>> =
            Box::pin(sleep(Duration::from_secs(60)));
        let mut sent = 0;
        let mut received = 0;
        start_barrier.wait().await;
        while sent < expected_packets || received < expected_packets {
            tokio::select! {
                _ = idle.as_mut() => bail!("Global XUDP worker idle timeout"),
                _ = attachment_notify.notified() => {},
                request = requests.recv(), if sent < expected_packets => {
                    let request = request.context("Global XUDP request queue closed")?;
                    let current = attachment.read().await.clone();
                    let Some(current) = current.filter(|current| current.token == request.token) else {
                        request.complete(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "Global XUDP attachment token is stale",
                        )));
                        continue;
                    };
                    let payload_length = request.payload().len();
                    match socket.send_to(request.payload(), target).await {
                        Ok(written) if written == payload_length => {
                            if accounting {
                                record_transfer_ref(
                                    current.traffic_context.as_ref(),
                                    written as u64,
                                    0,
                                );
                            }
                            sent += 1;
                            request.complete(Ok(()));
                            idle.as_mut().reset(Instant::now() + Duration::from_secs(60));
                        }
                        Ok(_) => {
                            request.complete(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "Global XUDP datagram send was truncated",
                            )));
                            bail!("Global XUDP datagram send was truncated");
                        }
                        Err(error) => {
                            let completion_error = io::Error::new(error.kind(), error.to_string());
                            request.complete(Err(completion_error));
                            return Err(error.into());
                        }
                    }
                }
                response = socket.recv_from(&mut response_buffer), if received < expected_packets => {
                    let (length, source) = response.context("Global XUDP socket receive failed")?;
                    if source != target {
                        continue;
                    }
                    let current = attachment.read().await.clone()
                        .context("Global XUDP attachment detached during response")?;
                    current.responses.send(Response {
                        source,
                        payload: response_buffer[..length].to_vec(),
                        traffic_context: current.traffic_context,
                    }).await.context("Global XUDP response receiver closed")?;
                    received += 1;
                    idle.as_mut().reset(Instant::now() + Duration::from_secs(60));
                }
            }
        }
        Ok(())
    }

    fn prepare_payload(
        payload: Vec<u8>,
        recycle_payload: bool,
    ) -> (PayloadBuffer, Option<PayloadBuffer>) {
        if recycle_payload {
            return (PayloadBuffer::Owned(payload), None);
        }
        if payload.len() >= SHARED_PAYLOAD_THRESHOLD {
            let shared = Bytes::from(payload);
            (
                PayloadBuffer::Shared(shared.clone()),
                Some(PayloadBuffer::Shared(shared)),
            )
        } else {
            let retry = payload.clone();
            (
                PayloadBuffer::Owned(payload),
                Some(PayloadBuffer::Owned(retry)),
            )
        }
    }

    fn encode_payload(session_id: usize, sequence: usize, size: usize) -> Vec<u8> {
        let mut payload = vec![0x5a; size];
        payload[..4].copy_from_slice(&(session_id as u32).to_be_bytes());
        payload[4..8].copy_from_slice(&(sequence as u32).to_be_bytes());
        payload
    }

    fn decode_payload(payload: &[u8]) -> Result<(usize, usize)> {
        if payload.len() < HEADER_SIZE {
            bail!("response shorter than the sequence header");
        }
        let session_id = u32::from_be_bytes(payload[..4].try_into()?) as usize;
        let sequence = u32::from_be_bytes(payload[4..8].try_into()?) as usize;
        Ok((session_id, sequence))
    }

    fn start_echo(
        socket: StdUdpSocket,
        expected_packets: usize,
        stop: Arc<AtomicBool>,
    ) -> thread::JoinHandle<Result<usize>> {
        thread::spawn(move || {
            let mut received = 0;
            let mut buffer = vec![0; 65_535];
            while received < expected_packets && !stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok((length, source)) => {
                        socket.send_to(&buffer[..length], source)?;
                        received += 1;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(received)
        })
    }

    fn set_socket_buffers(
        fd: std::os::fd::RawFd,
        bytes: usize,
    ) -> io::Result<usize> {
        let value = libc::c_int::try_from(bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket buffer size overflow",
            )
        })?;
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            // SAFETY: setsockopt reads one c_int from the valid local pointer.
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        get_socket_buffer(fd, libc::SO_RCVBUF)
    }

    fn get_socket_buffer(
        fd: std::os::fd::RawFd,
        option: libc::c_int,
    ) -> io::Result<usize> {
        let mut value = 0 as libc::c_int;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: getsockopt writes at most `length` bytes to the valid local integer.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(value).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "negative socket buffer size")
        })
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

        #[test]
        fn receive_buffer_validation_rejects_a_possible_burst_overflow() {
            let args = Args::try_parse_from([
                "global_xudp_probe",
                "--sessions",
                "64",
                "--inflight-window",
                "16",
                "--datagram-size",
                "1200",
            ])
            .unwrap();

            assert!(validate_receive_buffer_budget(&args, 1024 * 1024).is_err());
            assert!(validate_receive_buffer_budget(&args, 8 * 1024 * 1024).is_ok());
        }

        #[test]
        fn receive_buffer_validation_accounts_for_small_datagram_overhead() {
            let args = Args::try_parse_from([
                "global_xudp_probe",
                "--sessions",
                "64",
                "--inflight-window",
                "8192",
                "--datagram-size",
                "8",
            ])
            .unwrap();

            assert!(validate_receive_buffer_budget(&args, 8 * 1024 * 1024).is_err());
        }

        #[test]
        fn payload_sequence_round_trips_and_respects_size() {
            let payload = encode_payload(17, 4_203, 1200);
            assert_eq!(payload.len(), 1200);
            assert_eq!(decode_payload(&payload).unwrap(), (17, 4_203));
        }

        #[test]
        fn payload_sharing_uses_production_threshold() {
            let (small_request, small_retry) =
                prepare_payload(vec![1; SHARED_PAYLOAD_THRESHOLD - 1], false);
            assert!(matches!(small_request, PayloadBuffer::Owned(_)));
            assert!(matches!(small_retry, Some(PayloadBuffer::Owned(_))));

            let (large_request, large_retry) =
                prepare_payload(vec![1; SHARED_PAYLOAD_THRESHOLD], false);
            assert!(matches!(large_request, PayloadBuffer::Shared(_)));
            assert!(matches!(large_retry, Some(PayloadBuffer::Shared(_))));
        }

        #[test]
        fn payload_recycling_skips_retry_copy() {
            let (request, retry) =
                prepare_payload(vec![1; SHARED_PAYLOAD_THRESHOLD - 1], true);
            assert!(matches!(request, PayloadBuffer::Owned(_)));
            assert!(retry.is_none());
        }

        #[test]
        fn dropped_recycling_request_returns_payload_with_failure() {
            let (completion, mut completed) = oneshot::channel();
            let request = Request {
                token: 1,
                payload: Some(PayloadBuffer::Owned(vec![7, 8, 9])),
                recycle_payload: true,
                completion: Some(completion),
            };

            drop(request);

            let completed = completed.try_recv().unwrap();
            assert_eq!(
                completed.result.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(completed.recycled_payload.unwrap().as_slice(), &[7, 8, 9]);
        }
    }
}
