use std::hint::black_box;
use std::time::{Duration, Instant};

const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const EVENTS: u64 = 20_000_000;
const RECORD_EVENTS: u64 = 10_000_000;
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
        if self.rolling_timestamp.is_some()
            && now >= self.current_second_start
            && now < self.next_rollover
        {
            let info = &mut self.slots[self.current_slot];
            info.ack_count += ack_count;
            info.loss_count += loss_count;
            self.rolling_ack_count += ack_count;
            self.rolling_loss_count += loss_count;
            self.update_rate();
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
        self.update_rate();
    }
}

fn run_record_bench(name: &str, cached: bool, loss_every: Option<u64>) {
    let origin = Instant::now();
    let mut state = RecordState::new(origin);
    let started = Instant::now();
    for event in 0..RECORD_EVENTS {
        let now = origin + Duration::from_micros(event * 100);
        let loss =
            u64::from(loss_every.is_some_and(|period| (event + 1) % period == 0));
        if cached {
            state.cached_second_record(black_box(now), 1, loss);
        } else {
            state.baseline_record(black_box(now), 1, loss);
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

fn main() {
    println!("ack-rate arithmetic only:");
    for loss_every in [None, Some(10_000), Some(1_000), Some(100)] {
        run("baseline", baseline_update, loss_every);
        run("no-loss-fast-path", no_loss_fast_path_update, loss_every);
    }
    println!("full record path at 10 kHz:");
    for loss_every in [None, Some(10_000), Some(1_000), Some(100)] {
        run_record_bench("baseline-record", false, loss_every);
        run_record_bench("cached-second-record", true, loss_every);
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
}
