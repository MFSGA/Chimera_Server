#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("udp_retry_payload_probe requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        hint::black_box,
        time::Instant,
    };

    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use chimera_perf::stats::{coefficient_of_variation, median};
    use clap::{Parser, ValueEnum};
    use tokio::{
        runtime::{Builder, Runtime},
        sync::{mpsc, oneshot},
    };

    #[derive(Debug, Parser)]
    #[command(about = "Compare Global XUDP retry-payload ownership strategies")]
    struct Args {
        #[arg(long, value_enum, default_value_t = Model::Ownership)]
        model: Model,
        #[arg(long, default_value_t = 1_000_000)]
        packets: usize,
        #[arg(long, default_value_t = 2)]
        warmup: usize,
        #[arg(long, default_value_t = 8)]
        runs: usize,
        #[arg(long, value_delimiter = ',', default_value = "64,512,1200,4096")]
        sizes: Vec<usize>,
        #[arg(long, default_value_t = 1200)]
        shared_threshold: usize,
    }

    #[derive(Clone, Copy, Debug, ValueEnum)]
    enum Model {
        Ownership,
        ChannelAck,
    }

    #[derive(Clone, Copy)]
    enum Mode {
        VecClone,
        SharedBytes,
        ThresholdBytes,
    }

    #[allow(dead_code)]
    enum Payload {
        Owned(Vec<u8>),
        Shared(Bytes),
    }

    impl Payload {
        fn as_slice(&self) -> &[u8] {
            match self {
                Self::Owned(payload) => payload,
                Self::Shared(payload) => payload,
            }
        }
    }

    trait PayloadView {
        fn as_slice(&self) -> &[u8];
    }

    impl PayloadView for Vec<u8> {
        fn as_slice(&self) -> &[u8] {
            self
        }
    }

    impl PayloadView for Bytes {
        fn as_slice(&self) -> &[u8] {
            self
        }
    }

    impl PayloadView for Payload {
        fn as_slice(&self) -> &[u8] {
            Payload::as_slice(self)
        }
    }

    struct ChannelRequest<P> {
        payload: P,
        completion: oneshot::Sender<()>,
    }

    struct Sample {
        records_per_second: f64,
        cpu_seconds_per_million_records: f64,
    }

    fn thread_cpu_seconds() -> Result<f64> {
        // SAFETY: `usage` points to initialized writable storage and getrusage only reads it.
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        // SAFETY: The RUSAGE_THREAD selector and writable rusage pointer match libc's contract.
        let result = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut usage) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("read benchmark-thread CPU time");
        }
        Ok(usage.ru_utime.tv_sec as f64
            + usage.ru_utime.tv_usec as f64 / 1_000_000.0
            + usage.ru_stime.tv_sec as f64
            + usage.ru_stime.tv_usec as f64 / 1_000_000.0)
    }

    fn measure_ownership(
        mode: Mode,
        packets: usize,
        size: usize,
        threshold: usize,
    ) -> Result<Sample> {
        let cpu_start = thread_cpu_seconds()?;
        let wall_start = Instant::now();
        for index in 0..packets {
            let mut payload = vec![(index & 0xff) as u8; size];
            black_box(&mut payload);
            match mode {
                Mode::VecClone => {
                    let retry_payload = payload.clone();
                    black_box(&payload);
                    black_box(retry_payload);
                }
                Mode::SharedBytes => {
                    let payload = Bytes::from(payload);
                    let retry_payload = payload.clone();
                    black_box(&payload);
                    black_box(retry_payload);
                }
                Mode::ThresholdBytes => {
                    let (payload, retry_payload) = if payload.len() >= threshold {
                        let shared_payload = Bytes::from(payload);
                        let retry_payload = Payload::Shared(shared_payload.clone());
                        (Payload::Shared(shared_payload), retry_payload)
                    } else {
                        let retry_payload = payload.clone();
                        (Payload::Owned(payload), Payload::Owned(retry_payload))
                    };
                    black_box(payload.as_slice());
                    black_box(retry_payload);
                }
            }
        }
        let wall_seconds = wall_start.elapsed().as_secs_f64();
        let cpu_seconds = thread_cpu_seconds()? - cpu_start;
        Ok(Sample {
            records_per_second: packets as f64 / wall_seconds,
            cpu_seconds_per_million_records: cpu_seconds * 1_000_000.0 / packets as f64,
        })
    }

    async fn channel_worker<P: PayloadView>(mut receiver: mpsc::Receiver<ChannelRequest<P>>) {
        while let Some(request) = receiver.recv().await {
            black_box(request.payload.as_slice());
            let _ = request.completion.send(());
        }
    }

    async fn measure_channel_ack_sample<P, F>(
        packets: usize,
        size: usize,
        threshold: usize,
        make_payloads: F,
    ) -> Result<Sample>
    where
        P: PayloadView + Send + 'static,
        F: Fn(Vec<u8>, usize) -> (P, P),
    {
        let (sender, receiver) = mpsc::channel(64);
        let worker = tokio::spawn(channel_worker(receiver));
        let cpu_start = thread_cpu_seconds()?;
        let wall_start = Instant::now();
        for index in 0..packets {
            let payload = vec![(index & 0xff) as u8; size];
            let (worker_payload, retry_payload) = make_payloads(payload, threshold);
            let (completion, acknowledged) = oneshot::channel();
            sender
                .send(ChannelRequest {
                    payload: worker_payload,
                    completion,
                })
                .await
                .map_err(|_| anyhow::anyhow!("send benchmark packet to worker"))?;
            acknowledged
                .await
                .context("wait for benchmark worker acknowledgement")?;
            black_box(retry_payload);
        }
        let wall_seconds = wall_start.elapsed().as_secs_f64();
        drop(sender);
        worker.await.context("join benchmark worker")?;
        let cpu_seconds = thread_cpu_seconds()? - cpu_start;
        Ok(Sample {
            records_per_second: packets as f64 / wall_seconds,
            cpu_seconds_per_million_records: cpu_seconds * 1_000_000.0 / packets as f64,
        })
    }

    fn run_channel_ack_sample(
        runtime: &Runtime,
        mode: Mode,
        packets: usize,
        size: usize,
        threshold: usize,
    ) -> Result<Sample> {
        match mode {
            Mode::VecClone => runtime.block_on(measure_channel_ack_sample(
                packets,
                size,
                threshold,
                |payload: Vec<u8>, _| {
                    let retry_payload = payload.clone();
                    (payload, retry_payload)
                },
            )),
            Mode::SharedBytes => runtime.block_on(measure_channel_ack_sample(
                packets,
                size,
                threshold,
                |payload: Vec<u8>, _| {
                    let worker_payload = Bytes::from(payload);
                    let retry_payload = worker_payload.clone();
                    (worker_payload, retry_payload)
                },
            )),
            Mode::ThresholdBytes => runtime.block_on(measure_channel_ack_sample(
                packets,
                size,
                threshold,
                |payload: Vec<u8>, threshold| {
                    if payload.len() >= threshold {
                        let worker_payload = Bytes::from(payload);
                        let retry_payload = worker_payload.clone();
                        (
                            Payload::Shared(worker_payload),
                            Payload::Shared(retry_payload),
                        )
                    } else {
                        let retry_payload = payload.clone();
                        (Payload::Owned(payload), Payload::Owned(retry_payload))
                    }
                },
            )),
        }
    }

    pub fn run() -> Result<()> {
        let args = Args::parse();
        if args.packets == 0 || args.runs == 0 || args.sizes.is_empty() {
            bail!("packets, runs and sizes must be non-zero");
        }
        let runtime = match args.model {
            Model::Ownership => None,
            Model::ChannelAck => Some(
                Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build benchmark Tokio runtime")?,
            ),
        };
        println!(
            "model={:?} packets_per_sample={} measured_runs={} warmup_runs={} shared_threshold={}",
            args.model, args.packets, args.runs, args.warmup, args.shared_threshold
        );
        for size in args.sizes {
            let mut rates = [Vec::with_capacity(args.runs), Vec::with_capacity(args.runs), Vec::with_capacity(args.runs)];
            let mut cpu = [Vec::with_capacity(args.runs), Vec::with_capacity(args.runs), Vec::with_capacity(args.runs)];
            for run in 0..(args.warmup + args.runs) {
                let order = match run % 3 {
                    0 => [Mode::VecClone, Mode::SharedBytes, Mode::ThresholdBytes],
                    1 => [Mode::SharedBytes, Mode::ThresholdBytes, Mode::VecClone],
                    _ => [Mode::ThresholdBytes, Mode::VecClone, Mode::SharedBytes],
                };
                for mode in order {
                    let sample = match args.model {
                        Model::Ownership => {
                            measure_ownership(mode, args.packets, size, args.shared_threshold)?
                        }
                        Model::ChannelAck => run_channel_ack_sample(
                            runtime.as_ref().context("Tokio runtime is unavailable")?,
                            mode,
                            args.packets,
                            size,
                            args.shared_threshold,
                        )?,
                    };
                    if run >= args.warmup {
                        let index = match mode {
                            Mode::VecClone => 0,
                            Mode::SharedBytes => 1,
                            Mode::ThresholdBytes => 2,
                        };
                        rates[index].push(sample.records_per_second);
                        cpu[index].push(sample.cpu_seconds_per_million_records);
                    }
                }
            }
            let modes = ["vec-clone", "shared-bytes", "threshold-bytes"];
            let medians = rates.each_ref().map(|values| median(values));
            for (index, name) in modes.iter().enumerate() {
                println!(
                    "size={} mode={} records_per_sec={:.0} rate_cv_pct={:.2} cpu_s_per_million={:.3} cpu_cv_pct={:.2} rate_delta_vs_vec_pct={:.1}",
                    size,
                    name,
                    medians[index],
                    coefficient_of_variation(&rates[index]) * 100.0,
                    median(&cpu[index]),
                    coefficient_of_variation(&cpu[index]) * 100.0,
                    (medians[index] / medians[0] - 1.0) * 100.0,
                );
            }
        }
        Ok(())
    }
}
