#![cfg(feature = "traffic")]

use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Barrier},
    thread,
    time::Instant,
};

use chimera_server_lib::traffic::{
    TrafficContext, record_transfer, record_transfer_ref, snapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordMode {
    Clone,
    Ref,
}

impl RecordMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Clone => "clone",
            Self::Ref => "ref",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextShape {
    InboundOnly,
    InboundOutbound,
}

impl ContextShape {
    fn from_env() -> Self {
        match env::var("CHIMERA_TRAFFIC_PROBE_SHAPE")
            .unwrap_or_else(|_| "inbound-outbound".to_string())
            .as_str()
        {
            "inbound-only" => Self::InboundOnly,
            "inbound-outbound" => Self::InboundOutbound,
            other => panic!(
                "CHIMERA_TRAFFIC_PROBE_SHAPE must be inbound-only or inbound-outbound, got {other}"
            ),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::InboundOnly => "inbound-only",
            Self::InboundOutbound => "inbound-outbound",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    records_per_second: f64,
    nanoseconds_per_record: f64,
    cpu_seconds_per_million_records: f64,
}

#[test]
#[ignore = "performance probe; run explicitly in --release with the traffic feature"]
fn compare_owned_clone_and_borrowed_ref_recording() {
    let writers = env_usize("CHIMERA_TRAFFIC_PROBE_WRITERS", 1);
    let total_records = env_usize("CHIMERA_TRAFFIC_PROBE_TOTAL_RECORDS", 2_000_000);
    let warmup = env_usize("CHIMERA_TRAFFIC_PROBE_WARMUP", 2);
    let runs = env_usize("CHIMERA_TRAFFIC_PROBE_RUNS", 10);
    let record_bytes = env_u64("CHIMERA_TRAFFIC_PROBE_BYTES", 1200);
    let shape = ContextShape::from_env();

    assert!(writers > 0, "writers must be greater than zero");
    assert!(
        total_records >= writers,
        "total records must be at least writers"
    );
    assert!(runs > 0, "runs must be greater than zero");
    assert!(record_bytes > 0, "record bytes must be greater than zero");

    let context = make_context(shape);
    let mut schedule = Vec::with_capacity((warmup + runs) * 2);
    for pair in 0..(warmup + runs) {
        schedule.extend(pair_order(pair));
    }
    let samples =
        run_schedule(&schedule, writers, total_records, record_bytes, &context);

    let mut clone_samples = Vec::with_capacity(runs);
    let mut ref_samples = Vec::with_capacity(runs);
    for (mode, sample) in samples.into_iter().skip(warmup * 2) {
        match mode {
            RecordMode::Clone => clone_samples.push(sample),
            RecordMode::Ref => ref_samples.push(sample),
        }
    }

    let clone = summarize(&clone_samples);
    let borrowed = summarize(&ref_samples);
    let rate_gain_percent = percent_gain(
        clone.records_per_second_median,
        borrowed.records_per_second_median,
    );
    let cpu_reduction_percent = percent_reduction(
        clone.cpu_seconds_per_million_records_median,
        borrowed.cpu_seconds_per_million_records_median,
    );
    let latency_reduction_percent = percent_reduction(
        clone.nanoseconds_per_record_median,
        borrowed.nanoseconds_per_record_median,
    );

    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "record_type": "traffic_record_clone_ref_summary",
            "context_shape": shape.as_str(),
            "writers": writers,
            "total_records_per_sample": total_records,
            "record_bytes": record_bytes,
            "warmup_pairs": warmup,
            "measured_pairs": runs,
            "clone": clone.to_json(),
            "ref": borrowed.to_json(),
            "ref_records_per_second_gain_percent": round(rate_gain_percent),
            "ref_cpu_reduction_percent": round(cpu_reduction_percent),
            "ref_nanoseconds_per_record_reduction_percent": round(
                latency_reduction_percent,
            ),
        })
    );
}

fn pair_order(pair: usize) -> [RecordMode; 2] {
    if pair.is_multiple_of(2) {
        [RecordMode::Clone, RecordMode::Ref]
    } else {
        [RecordMode::Ref, RecordMode::Clone]
    }
}

fn make_context(shape: ContextShape) -> TrafficContext {
    let context = TrafficContext::new("dokodemo-door")
        .with_inbound_tag("udp-in")
        .with_client_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    match shape {
        ContextShape::InboundOnly => context,
        ContextShape::InboundOutbound => context.with_outbound_tag("direct"),
    }
}

fn run_schedule(
    schedule: &[RecordMode],
    writers: usize,
    total_records: usize,
    record_bytes: u64,
    context: &TrafficContext,
) -> Vec<(RecordMode, Sample)> {
    let barrier = Arc::new(Barrier::new(writers + 1));
    let base_records = total_records / writers;
    let remainder = total_records % writers;
    let schedule = Arc::new(schedule.to_vec());

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(writers);
        for writer in 0..writers {
            let barrier = Arc::clone(&barrier);
            let schedule = Arc::clone(&schedule);
            let context = context.clone();
            let records = base_records + usize::from(writer < remainder);
            handles.push(scope.spawn(move || {
                for mode in schedule.iter().copied() {
                    barrier.wait();
                    match mode {
                        RecordMode::Clone => {
                            for _ in 0..records {
                                record_transfer(
                                    Some(context.clone()),
                                    record_bytes,
                                    0,
                                );
                            }
                        }
                        RecordMode::Ref => {
                            for _ in 0..records {
                                record_transfer_ref(Some(&context), record_bytes, 0);
                            }
                        }
                    }
                    barrier.wait();
                }
            }));
        }

        let expected_records = total_records as u64;
        let expected_upload = expected_records.saturating_mul(record_bytes);
        let records = total_records as f64;
        let mut samples = Vec::with_capacity(schedule.len());
        for mode in schedule.iter().copied() {
            let before = snapshot();
            let cpu_before = cpu_seconds();
            let started = Instant::now();
            barrier.wait();
            barrier.wait();
            let elapsed_seconds = started.elapsed().as_secs_f64();
            let used_cpu_seconds = cpu_seconds() - cpu_before;
            let after = snapshot();
            assert_eq!(
                after
                    .total
                    .connections
                    .saturating_sub(before.total.connections),
                expected_records,
                "{} mode changed record count semantics",
                mode.as_str(),
            );
            assert_eq!(
                after
                    .total
                    .upload_bytes
                    .saturating_sub(before.total.upload_bytes),
                expected_upload,
                "{} mode changed byte accounting semantics",
                mode.as_str(),
            );
            samples.push((
                mode,
                Sample {
                    records_per_second: records
                        / elapsed_seconds.max(f64::MIN_POSITIVE),
                    nanoseconds_per_record: elapsed_seconds * 1e9 / records,
                    cpu_seconds_per_million_records: used_cpu_seconds
                        / (records / 1_000_000.0),
                },
            ));
        }

        for handle in handles {
            handle.join().expect("traffic writer thread");
        }
        samples
    })
}

#[derive(Debug, Clone, Copy)]
struct Summary {
    records_per_second_median: f64,
    records_per_second_cv: f64,
    nanoseconds_per_record_median: f64,
    cpu_seconds_per_million_records_median: f64,
    cpu_seconds_per_million_records_cv: f64,
}

impl Summary {
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "records_per_second_median": round(self.records_per_second_median),
            "records_per_second_cv": round(self.records_per_second_cv),
            "nanoseconds_per_record_median": round(self.nanoseconds_per_record_median),
            "cpu_seconds_per_million_records_median": round(
                self.cpu_seconds_per_million_records_median,
            ),
            "cpu_seconds_per_million_records_cv": round(
                self.cpu_seconds_per_million_records_cv,
            ),
        })
    }
}

fn summarize(samples: &[Sample]) -> Summary {
    let rates = samples
        .iter()
        .map(|sample| sample.records_per_second)
        .collect::<Vec<_>>();
    let ns = samples
        .iter()
        .map(|sample| sample.nanoseconds_per_record)
        .collect::<Vec<_>>();
    let cpu = samples
        .iter()
        .map(|sample| sample.cpu_seconds_per_million_records)
        .collect::<Vec<_>>();
    Summary {
        records_per_second_median: median(&rates),
        records_per_second_cv: coefficient_of_variation(&rates),
        nanoseconds_per_record_median: median(&ns),
        cpu_seconds_per_million_records_median: median(&cpu),
        cpu_seconds_per_million_records_cv: coefficient_of_variation(&cpu),
    }
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn coefficient_of_variation(values: &[f64]) -> f64 {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt() / mean
}

fn percent_gain(before: f64, after: f64) -> f64 {
    (after / before - 1.0) * 100.0
}

fn percent_reduction(before: f64, after: f64) -> f64 {
    (1.0 - after / before) * 100.0
}

fn cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(
        result,
        0,
        "getrusage failed: {}",
        std::io::Error::last_os_error()
    );
    let usage = unsafe { usage.assume_init() };
    timeval_seconds(usage.ru_utime) + timeval_seconds(usage.ru_stime)
}

fn timeval_seconds(value: libc::timeval) -> f64 {
    value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("invalid {name}"))
        })
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("invalid {name}"))
        })
        .unwrap_or(default)
}

fn round(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}
