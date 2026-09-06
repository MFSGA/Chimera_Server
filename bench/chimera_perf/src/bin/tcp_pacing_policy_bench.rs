use std::{hint::black_box, time::Instant};

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    about = "CPU/accuracy benchmark for TCP Brutal2 pacing-rate publication policies"
)]
struct Args {
    #[arg(long, value_enum, default_value_t = TraceKind::Synthetic)]
    trace: TraceKind,

    #[arg(long, default_value_t = 100)]
    sample_interval_us: u64,

    #[arg(long, default_value_t = 200_000)]
    samples: usize,

    #[arg(long, value_delimiter = ',', default_values_t = [0_u64, 1, 5, 10, 20])]
    min_update_ms: Vec<u64>,

    #[arg(long, value_delimiter = ',', default_values_t = [0.0_f64, 1.0, 5.0, 10.0])]
    delta_percent: Vec<f64>,

    #[arg(long)]
    emergency_delta_percent: Option<f64>,

    #[arg(long, default_value_t = 50)]
    cpu_repetitions: usize,

    #[arg(long)]
    emit_publication_rates: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TraceKind {
    Synthetic,
    BrutalLoss,
}

#[derive(Debug, Clone, Copy)]
struct PublicationPolicy {
    min_update_us: u64,
    delta_fraction: f64,
    emergency_delta_fraction: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct Publisher {
    policy: PublicationPolicy,
    published_rate: u64,
    last_publish_us: u64,
    initialized: bool,
}

impl Publisher {
    fn new(policy: PublicationPolicy) -> Self {
        Self {
            policy,
            published_rate: 0,
            last_publish_us: 0,
            initialized: false,
        }
    }

    #[inline]
    fn observe(&mut self, now_us: u64, target_rate: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.published_rate = target_rate;
            self.last_publish_us = now_us;
            return true;
        }

        let delta = self.published_rate.abs_diff(target_rate) as f64;
        let relative_delta = delta / self.published_rate.max(1) as f64;
        let emergency = self
            .policy
            .emergency_delta_fraction
            .is_some_and(|threshold| relative_delta >= threshold);
        if !emergency
            && now_us.saturating_sub(self.last_publish_us)
                < self.policy.min_update_us
        {
            return false;
        }

        if !emergency && relative_delta < self.policy.delta_fraction {
            return false;
        }

        self.published_rate = target_rate;
        self.last_publish_us = now_us;
        true
    }
}

#[derive(Debug, Serialize)]
struct PolicyRecord {
    schema_version: u32,
    record_type: &'static str,
    trace: &'static str,
    sample_interval_us: u64,
    samples: usize,
    min_update_ms: u64,
    delta_percent: f64,
    emergency_delta_percent: Option<f64>,
    target_rate_min: u64,
    target_rate_max: u64,
    publications: usize,
    publication_rates_bytes_per_sec: Option<Vec<u64>>,
    publications_per_second: f64,
    mean_absolute_error_percent: f64,
    p95_absolute_error_percent: f64,
    peak_absolute_error_percent: f64,
    cpu_nanoseconds_per_sample: f64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_args(&args)?;
    let trace = match args.trace {
        TraceKind::Synthetic => build_rate_trace(args.samples),
        TraceKind::BrutalLoss => {
            build_brutal_loss_trace(args.samples, args.sample_interval_us)
        }
    };

    for &min_update_ms in &args.min_update_ms {
        for &delta_percent in &args.delta_percent {
            let policy = PublicationPolicy {
                min_update_us: min_update_ms.saturating_mul(1000),
                delta_fraction: delta_percent / 100.0,
                emergency_delta_fraction: args
                    .emergency_delta_percent
                    .map(|percent| percent / 100.0),
            };
            let record = benchmark_policy(&args, &trace, policy);
            println!("{}", serde_json::to_string(&record)?);
        }
    }
    Ok(())
}

fn validate_args(args: &Args) -> Result<()> {
    if args.sample_interval_us == 0 {
        bail!("--sample-interval-us must be greater than zero");
    }
    if args.samples == 0 {
        bail!("--samples must be greater than zero");
    }
    if args.cpu_repetitions == 0 {
        bail!("--cpu-repetitions must be greater than zero");
    }
    if args
        .delta_percent
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        bail!("--delta-percent values must be finite and non-negative");
    }
    if args
        .emergency_delta_percent
        .is_some_and(|value| !value.is_finite() || value <= 0.0)
    {
        bail!("--emergency-delta-percent must be finite and greater than zero");
    }
    Ok(())
}

fn benchmark_policy(
    args: &Args,
    trace: &[u64],
    policy: PublicationPolicy,
) -> PolicyRecord {
    let (publication_rates, mut errors) =
        evaluate_trace(trace, args.sample_interval_us, policy);
    let publications = publication_rates.len();
    let target_rate_min = *trace.iter().min().expect("non-empty trace");
    let target_rate_max = *trace.iter().max().expect("non-empty trace");
    errors.sort_unstable_by(|left, right| left.total_cmp(right));
    let mean_error = errors.iter().sum::<f64>() / errors.len() as f64;
    let p95_index = ((errors.len() - 1) as f64 * 0.95).round() as usize;
    let p95_error = errors[p95_index];
    let peak_error = *errors.last().expect("non-empty trace");

    let started = Instant::now();
    let mut checksum = 0_u64;
    for _ in 0..args.cpu_repetitions {
        let mut publisher = Publisher::new(policy);
        for (index, &rate) in trace.iter().enumerate() {
            let now_us = index as u64 * args.sample_interval_us;
            if publisher.observe(now_us, black_box(rate)) {
                checksum = checksum.wrapping_add(publisher.published_rate);
            }
            checksum ^= publisher.published_rate.rotate_left((index & 31) as u32);
        }
    }
    black_box(checksum);
    let elapsed = started.elapsed().as_secs_f64();
    let total_samples = trace.len() as f64 * args.cpu_repetitions as f64;
    let simulated_seconds =
        trace.len() as f64 * args.sample_interval_us as f64 / 1_000_000.0;

    PolicyRecord {
        schema_version: 1,
        record_type: "pacing-policy",
        trace: match args.trace {
            TraceKind::Synthetic => "synthetic",
            TraceKind::BrutalLoss => "brutal-loss",
        },
        sample_interval_us: args.sample_interval_us,
        samples: trace.len(),
        min_update_ms: policy.min_update_us / 1000,
        delta_percent: round(policy.delta_fraction * 100.0),
        emergency_delta_percent: policy
            .emergency_delta_fraction
            .map(|fraction| round(fraction * 100.0)),
        target_rate_min,
        target_rate_max,
        publications,
        publication_rates_bytes_per_sec: args
            .emit_publication_rates
            .then_some(publication_rates),
        publications_per_second: round(publications as f64 / simulated_seconds),
        mean_absolute_error_percent: round(mean_error * 100.0),
        p95_absolute_error_percent: round(p95_error * 100.0),
        peak_absolute_error_percent: round(peak_error * 100.0),
        cpu_nanoseconds_per_sample: round(elapsed * 1e9 / total_samples),
    }
}

fn evaluate_trace(
    trace: &[u64],
    sample_interval_us: u64,
    policy: PublicationPolicy,
) -> (Vec<u64>, Vec<f64>) {
    let mut publisher = Publisher::new(policy);
    let mut publication_rates = Vec::new();
    let mut errors = Vec::with_capacity(trace.len());
    for (index, &rate) in trace.iter().enumerate() {
        let now_us = index as u64 * sample_interval_us;
        if publisher.observe(now_us, rate) {
            publication_rates.push(publisher.published_rate);
        }
        errors.push(relative_error(publisher.published_rate, rate));
    }
    (publication_rates, errors)
}

fn build_rate_trace(samples: usize) -> Vec<u64> {
    const MIB: u64 = 1024 * 1024;
    const PHASE_RATES: [u64; 8] = [40, 100, 55, 180, 80, 25, 140, 65];
    const PHASE_SAMPLES: usize = 2_500;

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut trace = Vec::with_capacity(samples);
    for index in 0..samples {
        let phase = (index / PHASE_SAMPLES) % PHASE_RATES.len();
        let base = PHASE_RATES[phase] * MIB;

        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let jitter_basis_points = (state % 601) as i64 - 300;
        let jitter = (base as i128 * jitter_basis_points as i128 / 10_000) as i64;

        let ramp_position = (index % PHASE_SAMPLES) as i64;
        let ramp_basis_points = (ramp_position * 160 / PHASE_SAMPLES as i64) - 80;
        let ramp = (base as i128 * ramp_basis_points as i128 / 10_000) as i64;

        trace.push((base as i64 + jitter + ramp).max(1) as u64);
    }
    trace
}

fn build_brutal_loss_trace(samples: usize, sample_interval_us: u64) -> Vec<u64> {
    const MIB: u64 = 1024 * 1024;
    const TARGET_BPS: u64 = 50 * MIB;
    const SLOT_COUNT: u64 = 5;
    const MIN_SAMPLE_COUNT: u64 = 50;
    const MIN_ACK_RATE: f64 = 0.8;
    const PHASE_LOSS_BASIS_POINTS: [u64; 8] =
        [0, 200, 500, 1_000, 2_000, 500, 3_000, 0];
    const PHASE_US: u64 = 2_500_000;

    #[derive(Clone, Copy, Default)]
    struct Slot {
        timestamp: u64,
        ack_count: u64,
        loss_count: u64,
    }

    let mut state = 0x243f_6a88_85a3_08d3_u64;
    let mut slots = [Slot::default(); SLOT_COUNT as usize];
    let mut rolling_ack_count = 0_u64;
    let mut rolling_loss_count = 0_u64;
    let mut rolling_timestamp = None;
    let mut trace = Vec::with_capacity(samples);

    for index in 0..samples {
        let now_us = index as u64 * sample_interval_us;
        let timestamp = now_us / 1_000_000;
        let phase = ((now_us / PHASE_US) as usize) % PHASE_LOSS_BASIS_POINTS.len();
        let loss_basis_points = PHASE_LOSS_BASIS_POINTS[phase];

        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let lost = state % 10_000 < loss_basis_points;
        let (ack_count, loss_count) = if lost { (0, 1) } else { (1, 0) };

        let slot_index = (timestamp % SLOT_COUNT) as usize;
        if slots[slot_index].timestamp == timestamp {
            slots[slot_index].ack_count += ack_count;
            slots[slot_index].loss_count += loss_count;
        } else {
            slots[slot_index] = Slot {
                timestamp,
                ack_count,
                loss_count,
            };
        }

        if rolling_timestamp == Some(timestamp) {
            rolling_ack_count += ack_count;
            rolling_loss_count += loss_count;
        } else {
            let min_timestamp = timestamp.saturating_sub(SLOT_COUNT);
            rolling_ack_count = 0;
            rolling_loss_count = 0;
            for slot in &slots {
                if slot.timestamp >= min_timestamp {
                    rolling_ack_count += slot.ack_count;
                    rolling_loss_count += slot.loss_count;
                }
            }
            rolling_timestamp = Some(timestamp);
        }

        let total = rolling_ack_count + rolling_loss_count;
        let ack_rate = if total < MIN_SAMPLE_COUNT {
            1.0
        } else {
            (rolling_ack_count as f64 / total as f64).max(MIN_ACK_RATE)
        };
        trace.push(((TARGET_BPS as f64) / ack_rate) as u64);
    }

    trace
}

#[inline]
fn relative_error(published: u64, target: u64) -> f64 {
    published.abs_diff(target) as f64 / target.max(1) as f64
}

fn round(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_update_interval_delays_publication() {
        let policy = PublicationPolicy {
            min_update_us: 5_000,
            delta_fraction: 0.0,
            emergency_delta_fraction: None,
        };
        let mut publisher = Publisher::new(policy);
        assert!(publisher.observe(0, 100));
        assert!(!publisher.observe(4_999, 200));
        assert_eq!(publisher.published_rate, 100);
        assert!(publisher.observe(5_000, 200));
        assert_eq!(publisher.published_rate, 200);
    }

    #[test]
    fn delta_gate_accumulates_against_last_publication() {
        let policy = PublicationPolicy {
            min_update_us: 0,
            delta_fraction: 0.05,
            emergency_delta_fraction: None,
        };
        let mut publisher = Publisher::new(policy);
        assert!(publisher.observe(0, 100));
        assert!(!publisher.observe(100, 104));
        assert_eq!(publisher.published_rate, 100);
        assert!(publisher.observe(200, 105));
        assert_eq!(publisher.published_rate, 105);
    }

    #[test]
    fn emergency_delta_bypasses_minimum_update_interval() {
        let policy = PublicationPolicy {
            min_update_us: 20_000,
            delta_fraction: 0.05,
            emergency_delta_fraction: Some(0.25),
        };
        let mut publisher = Publisher::new(policy);
        assert!(publisher.observe(0, 100));
        assert!(!publisher.observe(1_000, 110));
        assert_eq!(publisher.published_rate, 100);
        assert!(publisher.observe(2_000, 130));
        assert_eq!(publisher.published_rate, 130);
    }

    #[test]
    fn synthetic_trace_contains_large_steps_and_small_noise() {
        let trace = build_rate_trace(5_001);
        assert_eq!(trace.len(), 5_001);
        let first = trace[..2_500].iter().copied().sum::<u64>() / 2_500;
        let second = trace[2_500..5_000].iter().copied().sum::<u64>() / 2_500;
        assert!(second > first * 2);
    }

    #[test]
    fn brutal_loss_trace_matches_ack_rate_compensation_bounds() {
        const TARGET: u64 = 50 * 1024 * 1024;
        let trace = build_brutal_loss_trace(200_000, 100);
        assert_eq!(trace.len(), 200_000);
        assert_eq!(trace[0], TARGET);
        assert_eq!(*trace.iter().min().unwrap(), TARGET);
        assert!(*trace.iter().max().unwrap() > TARGET * 11 / 10);
        assert!(*trace.iter().max().unwrap() <= TARGET * 5 / 4);
    }

    #[test]
    fn brutal_loss_publication_rates_can_drive_socket_replay() {
        let trace = build_brutal_loss_trace(200_000, 100);
        let policy = PublicationPolicy {
            min_update_us: 0,
            delta_fraction: 0.05,
            emergency_delta_fraction: None,
        };
        let (rates, errors) = evaluate_trace(&trace, 100, policy);

        assert_eq!(
            rates,
            vec![52_428_800, 55_177_973, 57_936_973, 61_559_364, 64_637_792]
        );
        assert_eq!(errors.len(), trace.len());
        assert!(rates.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
