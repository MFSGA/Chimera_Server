use std::hint::black_box;
use std::time::{Duration, Instant};

const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const EVENTS: u64 = 20_000_000;
const RECORD_EVENTS: u64 = 10_000_000;
const BATCHED_ACK_PACKETS: u64 = 8_000_000;
const WINDOW_EVENTS: u64 = 40_000_000;
const ON_ACK_EVENTS: u64 = 10_000_000;
const RTT_CONVERSION_EVENTS: u64 = 40_000_000;
const SLOT_COUNT: u64 = 5;

#[derive(Clone, Copy)]
struct State {
    ack_count: u64,
    loss_count: u64,
    ack_rate: f64,
}

fn baseline_update(state: &mut State) {
    let ack_count = state.ack_count;
    let loss_count = state.loss_count;
    if ack_count + loss_count < MIN_SAMPLE_COUNT {
        state.ack_rate = 1.0;
        return;
    }
    let rate = ack_count as f64 / (ack_count + loss_count) as f64;
    state.ack_rate = rate.max(MIN_ACK_RATE);
}

fn no_loss_fast_path_update(state: &mut State) {
    let ack_count = state.ack_count;
    let loss_count = state.loss_count;
    if loss_count == 0 || ack_count + loss_count < MIN_SAMPLE_COUNT {
        state.ack_rate = 1.0;
        return;
    }
    let rate = ack_count as f64 / (ack_count + loss_count) as f64;
    state.ack_rate = rate.max(MIN_ACK_RATE);
}

fn run(name: &str, update: fn(&mut State), loss_every: Option<u64>) {
    let start = Instant::now();
    let mut state = State {
        ack_count: 0,
        loss_count: 0,
        ack_rate: 1.0,
    };
    for event in 1..=EVENTS {
        state.ack_count = state.ack_count.wrapping_add(1);
        if loss_every.is_some_and(|period| event % period == 0) {
            state.loss_count = state.loss_count.wrapping_add(1);
        }
        update(black_box(&mut state));
    }
    let elapsed = start.elapsed();
    println!(
        "{name}: loss_every={:?} ns_per_event={:.3} final_ack_rate={:.6}",
        loss_every,
        elapsed.as_nanos() as f64 / EVENTS as f64,
        black_box(state.ack_rate),
    );
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PacketInfo {
    timestamp: u64,
    ack_count: u64,
    loss_count: u64,
}

struct RecordState {
    start: Instant,
    slots: [PacketInfo; SLOT_COUNT as usize],
    rolling_ack_count: u64,
    rolling_loss_count: u64,
    rolling_timestamp: Option<u64>,
    current_slot: usize,
    current_second_start: Instant,
    next_rollover: Instant,
    ack_rate: f64,
}

impl RecordState {
    fn new(start: Instant) -> Self {
        Self {
            start,
            slots: [PacketInfo::default(); SLOT_COUNT as usize],
            rolling_ack_count: 0,
            rolling_loss_count: 0,
            rolling_timestamp: None,
            current_slot: 0,
            current_second_start: start,
            next_rollover: start,
            ack_rate: 1.0,
        }
    }

    fn update_rate(&mut self) {
        let total = self.rolling_ack_count + self.rolling_loss_count;
        if total < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
        } else {
            self.ack_rate =
                (self.rolling_ack_count as f64 / total as f64).max(MIN_ACK_RATE);
        }
    }

    fn baseline_record(&mut self, now: Instant, ack_count: u64, loss_count: u64) {
        let timestamp = now.saturating_duration_since(self.start).as_secs();
        let slot = (timestamp % SLOT_COUNT) as usize;
        if self.slots[slot].timestamp == timestamp {
            self.slots[slot].ack_count += ack_count;
            self.slots[slot].loss_count += loss_count;
        } else {
            self.slots[slot] = PacketInfo {
                timestamp,
                ack_count,
                loss_count,
            };
        }
        if self.rolling_timestamp == Some(timestamp) {
            self.rolling_ack_count += ack_count;
            self.rolling_loss_count += loss_count;
        } else {
            let min_timestamp = timestamp.saturating_sub(SLOT_COUNT);
            self.rolling_ack_count = 0;
            self.rolling_loss_count = 0;
            for info in &self.slots {
                if info.timestamp >= min_timestamp {
                    self.rolling_ack_count += info.ack_count;
                    self.rolling_loss_count += info.loss_count;
                }
            }
            self.rolling_timestamp = Some(timestamp);
        }
        self.update_rate();
    }

    fn cached_second_record(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
    ) {
        self.cached_second_record_inner(now, ack_count, loss_count, 0, false, false);
    }

    fn cached_second_record_pristine_assign(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
    ) {
        self.cached_second_record_inner(now, ack_count, loss_count, 1, false, false);
    }

    fn cached_second_record_skip_pristine_rate(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
    ) {
        self.cached_second_record_inner(now, ack_count, loss_count, 2, false, false);
    }

    fn cached_second_record_monotonic_fast(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
    ) {
        self.cached_second_record_inner(now, ack_count, loss_count, 2, true, false);
    }

    fn cached_second_record_rollover_only(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
    ) {
        self.cached_second_record_inner(now, ack_count, loss_count, 2, true, true);
    }

    fn cached_second_record_inner(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
        pristine_mode: u8,
        monotonic_fast: bool,
        rollover_only: bool,
    ) {
        let in_cached_second = if rollover_only {
            now < self.next_rollover
        } else if monotonic_fast {
            self.rolling_timestamp.is_some() && now < self.next_rollover
        } else {
            self.rolling_timestamp.is_some()
                && now >= self.current_second_start
                && now < self.next_rollover
        };
        if in_cached_second {
            let info = &mut self.slots[self.current_slot];
            info.ack_count += ack_count;
            info.loss_count += loss_count;
            self.rolling_ack_count += ack_count;
            self.rolling_loss_count += loss_count;
            if self.rolling_loss_count == 0 {
                if pristine_mode == 1 {
                    self.ack_rate = 1.0;
                } else if pristine_mode == 0 {
                    self.update_rate();
                }
            } else {
                self.update_rate();
            }
            return;
        }

        let timestamp = now.saturating_duration_since(self.start).as_secs();
        let slot = (timestamp % SLOT_COUNT) as usize;
        self.slots[slot] = PacketInfo {
            timestamp,
            ack_count,
            loss_count,
        };
        let min_timestamp = timestamp.saturating_sub(SLOT_COUNT);
        self.rolling_ack_count = 0;
        self.rolling_loss_count = 0;
        for info in &self.slots {
            if info.timestamp >= min_timestamp {
                self.rolling_ack_count += info.ack_count;
                self.rolling_loss_count += info.loss_count;
            }
        }
        self.rolling_timestamp = Some(timestamp);
        self.current_slot = slot;
        self.current_second_start = self.start + Duration::from_secs(timestamp);
        self.next_rollover = self.start + Duration::from_secs(timestamp + 1);
        if pristine_mode > 0 && self.rolling_loss_count == 0 {
            self.ack_rate = 1.0;
        } else {
            self.update_rate();
        }
    }
}

fn run_record_bench(name: &str, mode: u8, loss_every: Option<u64>) {
    let origin = Instant::now();
    let mut state = RecordState::new(origin);
    let started = Instant::now();
    for event in 0..RECORD_EVENTS {
        let now = origin + Duration::from_micros(event * 100);
        let loss =
            u64::from(loss_every.is_some_and(|period| (event + 1) % period == 0));
        match mode {
            0 => state.baseline_record(black_box(now), 1, loss),
            1 => state.cached_second_record(black_box(now), 1, loss),
            2 => state.cached_second_record_pristine_assign(black_box(now), 1, loss),
            3 => state.cached_second_record_skip_pristine_rate(
                black_box(now),
                1,
                loss,
            ),
            4 => state.cached_second_record_monotonic_fast(black_box(now), 1, loss),
            5 => state.cached_second_record_rollover_only(black_box(now), 1, loss),
            _ => unreachable!(),
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{name}: loss_every={:?} ns_per_event={:.3} final_ack_rate={:.6}",
        loss_every,
        elapsed.as_nanos() as f64 / RECORD_EVENTS as f64,
        black_box(state.ack_rate),
    );
}

fn modeled_window(ack_rate: f64) -> u64 {
    ((50_000_000_f64 * 0.080 * 0.8) / ack_rate) as u64
}

fn modeled_window_pristine_fast_path(ack_rate: f64) -> u64 {
    let cwnd = 50_000_000_f64 * 0.080 * 0.8;
    if ack_rate == 1.0 {
        cwnd as u64
    } else {
        (cwnd / ack_rate) as u64
    }
}

fn run_window_bench(name: &str, optimized: bool, ack_rate: f64) {
    let started = Instant::now();
    let mut window = 0_u64;
    for _ in 0..WINDOW_EVENTS {
        let rate = black_box(ack_rate);
        window = if optimized {
            modeled_window_pristine_fast_path(rate)
        } else {
            modeled_window(rate)
        };
        black_box(window);
    }
    let elapsed = started.elapsed();
    println!(
        "{name}: ack_rate={ack_rate:.6} ns_per_window={:.3} final_window={}",
        elapsed.as_nanos() as f64 / WINDOW_EVENTS as f64,
        black_box(window),
    );
}

#[inline(always)]
fn rtt_secs_subsecond_fast_path(rtt: Duration) -> f64 {
    if rtt.as_secs() == 0 {
        f64::from(rtt.subsec_nanos()) / 1_000_000_000.0
    } else {
        rtt.as_secs_f64()
    }
}

fn run_rtt_conversion_bench(
    name: &str,
    subsecond_fast_path: bool,
    base_rtt_nanos: u64,
) {
    let started = Instant::now();
    let mut seconds = 0.0;
    for event in 0..RTT_CONVERSION_EVENTS {
        let rtt = Duration::from_nanos(base_rtt_nanos + event % 1_000_001);
        seconds = if subsecond_fast_path {
            rtt_secs_subsecond_fast_path(black_box(rtt))
        } else {
            black_box(rtt).as_secs_f64()
        };
        black_box(seconds);
    }
    let elapsed = started.elapsed();
    println!(
        "{name}: subsecond_fast_path={subsecond_fast_path} base_rtt_nanos={base_rtt_nanos} ns_per_conversion={:.3} final_seconds={seconds:.9}",
        elapsed.as_nanos() as f64 / RTT_CONVERSION_EVENTS as f64,
    );
}

fn run_on_ack_component_bench(
    name: &str,
    include_record: bool,
    include_window: bool,
    cached_tx_f64: bool,
    subsecond_rtt_fast_path: bool,
    duration_is_zero: bool,
) {
    let origin = Instant::now();
    let mut state = RecordState::new(origin);
    let tx_bps = 50_000_000_u64;
    let tx_bps_f64 = tx_bps as f64;
    let mut window = modeled_window(state.ack_rate);
    let started = Instant::now();
    for event in 0..ON_ACK_EVENTS {
        let now = origin + Duration::from_micros(event * 100);
        // Live Quinn traces move the RTT input on almost every ACK. Model a small,
        // deterministic estimator movement instead of benchmarking a constant RTT.
        let last_rtt = Duration::from_nanos(79_500_000 + event % 1_000_001);
        black_box(last_rtt);
        if include_record {
            state.cached_second_record_skip_pristine_rate(black_box(now), 1, 0);
        }
        if include_window {
            let zero_rtt = if duration_is_zero {
                black_box(last_rtt).is_zero()
            } else {
                black_box(last_rtt).as_nanos() == 0
            };
            let rtt_secs = if zero_rtt {
                0.0
            } else if subsecond_rtt_fast_path {
                rtt_secs_subsecond_fast_path(black_box(last_rtt))
            } else {
                black_box(last_rtt).as_secs_f64()
            };
            let tx = if cached_tx_f64 {
                black_box(tx_bps_f64)
            } else {
                black_box(tx_bps) as f64
            };
            window = ((tx * rtt_secs * 0.8) / black_box(state.ack_rate)) as u64;
            black_box(window);
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{name}: record={include_record} window={include_window} cached_tx_f64={cached_tx_f64} subsecond_rtt_fast_path={subsecond_rtt_fast_path} duration_is_zero={duration_is_zero} ns_per_ack={:.3} final_ack_rate={:.6} final_window={}",
        elapsed.as_nanos() as f64 / ON_ACK_EVENTS as f64,
        black_box(state.ack_rate),
        black_box(window),
    );
}

fn run_ack_batch_bench(name: &str, batched: bool, batch_size: u64) {
    let origin = Instant::now();
    let mut state = RecordState::new(origin);
    let mut window = modeled_window(state.ack_rate);
    let batches = BATCHED_ACK_PACKETS / batch_size;
    let started = Instant::now();
    for batch in 0..batches {
        let now = origin + Duration::from_micros(batch * batch_size * 100);
        if batched {
            let mut pending_acks = 0_u64;
            for _ in 0..batch_size {
                pending_acks = pending_acks.wrapping_add(black_box(1));
            }
            state.cached_second_record(black_box(now), black_box(pending_acks), 0);
            window = modeled_window(black_box(state.ack_rate));
        } else {
            for _ in 0..batch_size {
                state.cached_second_record(black_box(now), 1, 0);
                window = modeled_window(black_box(state.ack_rate));
            }
        }
        if (batch + 1) % 100 == 0 {
            state.cached_second_record(black_box(now), 0, 1);
            window = modeled_window(black_box(state.ack_rate));
        }
    }
    let elapsed = started.elapsed();
    println!(
        "{name}: batch_size={batch_size} ns_per_acked_packet={:.3} final_ack_rate={:.6} final_window={}",
        elapsed.as_nanos() as f64 / BATCHED_ACK_PACKETS as f64,
        black_box(state.ack_rate),
        black_box(window),
    );
}

fn main() {
    if let Ok(mode) = std::env::var("BRUTAL_RECORD_BENCH_MODE") {
        match mode.as_str() {
            "cached" => run_record_bench("skip-pristine-rate-record", 3, None),
            "monotonic" => run_record_bench("monotonic-fast-record", 4, None),
            "rollover-only" => run_record_bench("rollover-only-record", 5, None),
            _ => panic!(
                "BRUTAL_RECORD_BENCH_MODE must be cached, monotonic, or rollover-only"
            ),
        }
        return;
    }

    println!("ack-rate arithmetic only:");
    for loss_every in [None, Some(10_000), Some(1_000), Some(100)] {
        run("baseline", baseline_update, loss_every);
        run("no-loss-fast-path", no_loss_fast_path_update, loss_every);
    }
    println!("full record path at 10 kHz:");
    for loss_every in [None, Some(10_000), Some(1_000), Some(100)] {
        run_record_bench("baseline-record", 0, loss_every);
        run_record_bench("cached-second-record", 1, loss_every);
        run_record_bench("pristine-assign-record", 2, loss_every);
        run_record_bench("skip-pristine-rate-record", 3, loss_every);
        run_record_bench("monotonic-fast-record", 4, loss_every);
        run_record_bench("rollover-only-record", 5, loss_every);
    }
    println!("record fast-path order-sensitivity check:");
    for loss_every in [None, Some(1_000), Some(100)] {
        run_record_bench("monotonic-fast-record-first", 4, loss_every);
        run_record_bench("skip-pristine-rate-record-second", 3, loss_every);
    }
    println!("window arithmetic:");
    for ack_rate in [1.0, 0.9999, 0.99, 0.9, 0.8] {
        run_window_bench("baseline-window", false, ack_rate);
        run_window_bench("pristine-fast-window", true, ack_rate);
    }
    println!("RTT seconds conversion:");
    for base_rtt_nanos in [79_500_000, 500_000_000, 998_999_999, 1_500_000_000] {
        run_rtt_conversion_bench("baseline-rtt-seconds", false, base_rtt_nanos);
        run_rtt_conversion_bench("subsecond-fast-rtt-seconds", true, base_rtt_nanos);
    }
    println!("modeled on_ack component attribution with moving RTT:");
    run_on_ack_component_bench("rtt-input-only", false, false, false, false, false);
    run_on_ack_component_bench("record-only", true, false, false, false, false);
    run_on_ack_component_bench("window-only", false, true, false, false, false);
    run_on_ack_component_bench(
        "window-subsecond-rtt",
        false,
        true,
        false,
        true,
        false,
    );
    run_on_ack_component_bench(
        "window-subsecond-rtt-is-zero",
        false,
        true,
        false,
        true,
        true,
    );
    run_on_ack_component_bench("window-cached-tx", false, true, true, false, false);
    run_on_ack_component_bench(
        "record-plus-window",
        true,
        true,
        false,
        false,
        false,
    );
    run_on_ack_component_bench(
        "record-plus-window-subsecond-rtt",
        true,
        true,
        false,
        true,
        false,
    );
    run_on_ack_component_bench(
        "record-plus-window-cached-tx",
        true,
        true,
        true,
        false,
        false,
    );
    run_on_ack_component_bench(
        "record-plus-window-subsecond-rtt-is-zero",
        true,
        true,
        false,
        true,
        true,
    );
    println!("window RTT conversion order-sensitivity check:");
    run_on_ack_component_bench(
        "record-plus-window-subsecond-rtt-first",
        true,
        true,
        false,
        true,
        false,
    );
    run_on_ack_component_bench(
        "record-plus-window-baseline-second",
        true,
        true,
        false,
        false,
        false,
    );
    println!("ACK-frame batching over cached-second record path:");
    for batch_size in [1, 2, 4, 8, 16, 32] {
        run_ack_batch_bench("per-packet-record", false, batch_size);
        run_ack_batch_bench("batched-record", true, batch_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_fast_record_matches_cached_path_for_monotonic_callbacks() {
        let origin = Instant::now();
        let mut baseline = RecordState::new(origin);
        let mut optimized = RecordState::new(origin);
        for event in 0..50_000_u64 {
            let now = origin + Duration::from_micros(event * 100);
            let loss = u64::from((event + 1).is_multiple_of(997));
            baseline.cached_second_record_skip_pristine_rate(now, 1, loss);
            optimized.cached_second_record_monotonic_fast(now, 1, loss);
            assert_eq!(baseline.rolling_ack_count, optimized.rolling_ack_count);
            assert_eq!(baseline.rolling_loss_count, optimized.rolling_loss_count);
            assert_eq!(baseline.ack_rate, optimized.ack_rate);
        }
        assert_eq!(baseline.slots, optimized.slots);
    }

    #[test]
    fn rollover_only_record_matches_monotonic_guard_for_monotonic_callbacks() {
        let origin = Instant::now();
        let mut baseline = RecordState::new(origin);
        let mut optimized = RecordState::new(origin);
        for event in 0..50_000_u64 {
            let now = origin + Duration::from_micros(event * 100);
            let loss = u64::from((event + 1).is_multiple_of(997));
            baseline.cached_second_record_monotonic_fast(now, 1, loss);
            optimized.cached_second_record_rollover_only(now, 1, loss);
            assert_eq!(baseline.rolling_ack_count, optimized.rolling_ack_count);
            assert_eq!(baseline.rolling_loss_count, optimized.rolling_loss_count);
            assert_eq!(baseline.rolling_timestamp, optimized.rolling_timestamp);
            assert_eq!(baseline.ack_rate, optimized.ack_rate);
        }
        assert_eq!(baseline.slots, optimized.slots);
    }

    #[test]
    fn rollover_only_guard_does_not_treat_initial_timestamp_as_cached() {
        let origin = Instant::now();
        let mut state = RecordState::new(origin);
        state.cached_second_record_rollover_only(origin, 1, 0);
        assert_eq!(state.rolling_timestamp, Some(0));
        assert_eq!(state.rolling_ack_count, 1);
        assert_eq!(state.slots[0].ack_count, 1);
    }

    #[test]
    fn monotonic_fast_record_is_not_equivalent_for_backdated_callbacks() {
        let origin = Instant::now();
        let mut baseline = RecordState::new(origin);
        let mut optimized = RecordState::new(origin);
        for state in [&mut baseline, &mut optimized] {
            state.cached_second_record_skip_pristine_rate(
                origin + Duration::from_millis(2_100),
                1,
                0,
            );
        }
        baseline.cached_second_record_skip_pristine_rate(
            origin + Duration::from_millis(1_900),
            1,
            0,
        );
        optimized.cached_second_record_monotonic_fast(
            origin + Duration::from_millis(1_900),
            1,
            0,
        );
        assert_ne!(baseline.slots, optimized.slots);
    }

    #[test]
    fn no_loss_fast_path_matches_baseline() {
        let mut baseline = State {
            ack_count: 0,
            loss_count: 0,
            ack_rate: 1.0,
        };
        let mut optimized = baseline;
        for _ in 0..10_000 {
            baseline.ack_count += 1;
            optimized.ack_count += 1;
            baseline_update(&mut baseline);
            no_loss_fast_path_update(&mut optimized);
            assert_eq!(baseline.ack_rate, optimized.ack_rate);
        }
    }

    #[test]
    fn loss_path_matches_baseline() {
        let mut baseline = State {
            ack_count: 0,
            loss_count: 0,
            ack_rate: 1.0,
        };
        let mut optimized = baseline;
        for event in 1..=10_000 {
            baseline.ack_count += 1;
            optimized.ack_count += 1;
            if event % 137 == 0 {
                baseline.loss_count += 1;
                optimized.loss_count += 1;
            }
            baseline_update(&mut baseline);
            no_loss_fast_path_update(&mut optimized);
            assert_eq!(baseline.ack_rate, optimized.ack_rate);
        }
    }

    #[test]
    fn pristine_record_fast_path_matches_cached_second_across_loss_lifecycle() {
        let origin = Instant::now();
        let mut baseline = RecordState::new(origin);
        let mut production = RecordState::new(origin);
        let mut optimized = RecordState::new(origin);
        let events = [
            (Duration::from_millis(100), 60, 0),
            (Duration::from_millis(200), 0, 10),
            (Duration::from_secs(1), 40, 0),
            (Duration::from_secs(7), 80, 0),
            (Duration::from_secs(7) + Duration::from_millis(100), 20, 0),
        ];

        for (elapsed, acks, losses) in events {
            let now = origin + elapsed;
            baseline.cached_second_record(now, acks, losses);
            production.cached_second_record_pristine_assign(now, acks, losses);
            optimized.cached_second_record_skip_pristine_rate(now, acks, losses);
            assert_eq!(baseline.rolling_ack_count, production.rolling_ack_count);
            assert_eq!(baseline.rolling_loss_count, production.rolling_loss_count);
            assert_eq!(baseline.ack_rate, production.ack_rate);
            assert_eq!(baseline.rolling_ack_count, optimized.rolling_ack_count);
            assert_eq!(baseline.rolling_loss_count, optimized.rolling_loss_count);
            assert_eq!(baseline.ack_rate, optimized.ack_rate);
        }
    }

    #[test]
    fn pristine_window_fast_path_matches_baseline() {
        for ack_rate in [1.0, 0.9999, 0.99, 0.9, 0.8] {
            assert_eq!(
                modeled_window(ack_rate),
                modeled_window_pristine_fast_path(ack_rate)
            );
        }
    }

    #[test]
    fn subsecond_rtt_fast_path_matches_duration_seconds_and_window() {
        for nanos in [
            1_u64,
            999,
            1_000,
            999_999,
            1_000_000,
            79_500_000,
            80_000_001,
            999_999_999,
            1_000_000_000,
            1_000_000_001,
            5_123_456_789,
        ] {
            let rtt = Duration::from_nanos(nanos);
            assert_eq!(rtt_secs_subsecond_fast_path(rtt), rtt.as_secs_f64());
            for ack_rate in [1.0, 0.9999, 0.99, 0.9, 0.8] {
                let baseline =
                    ((50_000_000_f64 * rtt.as_secs_f64() * 0.8) / ack_rate) as u64;
                let candidate =
                    ((50_000_000_f64 * rtt_secs_subsecond_fast_path(rtt) * 0.8)
                        / ack_rate) as u64;
                assert_eq!(candidate, baseline);
            }
        }
    }

    #[test]
    fn batched_ack_updates_match_per_packet_at_batch_boundaries() {
        let origin = Instant::now();
        let mut per_packet = RecordState::new(origin);
        let mut batched = RecordState::new(origin);

        for batch in 0..20_000_u64 {
            let batch_size = 1 + (batch % 17);
            let now = origin + Duration::from_micros(batch * 700);
            for _ in 0..batch_size {
                per_packet.cached_second_record(now, 1, 0);
            }
            batched.cached_second_record(now, batch_size, 0);

            if batch % 137 == 0 {
                per_packet.cached_second_record(now, 0, 1);
                batched.cached_second_record(now, 0, 1);
            }

            assert_eq!(per_packet.rolling_ack_count, batched.rolling_ack_count);
            assert_eq!(per_packet.rolling_loss_count, batched.rolling_loss_count);
            assert_eq!(per_packet.rolling_timestamp, batched.rolling_timestamp);
            assert_eq!(per_packet.ack_rate, batched.ack_rate);
        }
    }
}
