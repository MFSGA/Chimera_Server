use std::hint::black_box;
use std::time::{Duration, Instant};

const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const EVENTS: u64 = 20_000_000;
const RECORD_EVENTS: u64 = 10_000_000;
const BATCHED_ACK_PACKETS: u64 = 8_000_000;
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

#[derive(Clone, Copy, Default)]
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
        self.cached_second_record_inner(now, ack_count, loss_count, false);
    }

    fn cached_second_record_skip_pristine_rate(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
    ) {
        self.cached_second_record_inner(now, ack_count, loss_count, true);
    }

    fn cached_second_record_inner(
        &mut self,
        now: Instant,
        ack_count: u64,
        loss_count: u64,
        skip_pristine_rate: bool,
    ) {
        if self.rolling_timestamp.is_some()
            && now >= self.current_second_start
            && now < self.next_rollover
        {
            let info = &mut self.slots[self.current_slot];
            info.ack_count += ack_count;
            info.loss_count += loss_count;
            self.rolling_ack_count += ack_count;
            self.rolling_loss_count += loss_count;
            if !(skip_pristine_rate && self.rolling_loss_count == 0) {
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
        if skip_pristine_rate && self.rolling_loss_count == 0 {
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
            2 => state.cached_second_record_skip_pristine_rate(black_box(now), 1, loss),
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
    println!("ack-rate arithmetic only:");
    for loss_every in [None, Some(10_000), Some(1_000), Some(100)] {
        run("baseline", baseline_update, loss_every);
        run("no-loss-fast-path", no_loss_fast_path_update, loss_every);
    }
    println!("full record path at 10 kHz:");
    for loss_every in [None, Some(10_000), Some(1_000), Some(100)] {
        run_record_bench("baseline-record", 0, loss_every);
        run_record_bench("cached-second-record", 1, loss_every);
        run_record_bench("skip-pristine-rate-record", 2, loss_every);
    }
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
            optimized.cached_second_record_skip_pristine_rate(now, acks, losses);
            assert_eq!(baseline.rolling_ack_count, optimized.rolling_ack_count);
            assert_eq!(baseline.rolling_loss_count, optimized.rolling_loss_count);
            assert_eq!(baseline.ack_rate, optimized.ack_rate);
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
