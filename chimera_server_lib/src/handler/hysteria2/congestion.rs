use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use std::time::{Duration, Instant};

use quinn_proto::{
    RttEstimator,
    congestion::{Bbr, BbrConfig, Controller, ControllerFactory},
};
use tracing::debug;

const PACKET_INFO_SLOT_COUNT: u64 = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
// Quinn's pacer refills at ~1.25x cwnd per RTT, so scale cwnd to keep target rate.
const CONGESTION_WINDOW_MULTIPLIER: f64 = 0.8;
const DEFAULT_CONGESTION_WINDOW: u64 = 10_240;
// Xray Brutal allows another datagram when bytes-in-flight is exactly cwnd.
// Quinn treats `window()` as a hard maximum for ack-eliciting bytes in flight,
// so preserve Xray's effective one-extra-datagram allowance at the minimum.
const MIN_CONGESTION_WINDOW_DATAGRAMS: u64 = 2;
const DEBUG_ENV: &str = "HYSTERIA_BRUTAL_DEBUG";
const DEBUG_PRINT_INTERVAL: u64 = 2;
#[cfg(feature = "brutal-ack-batch-trace")]
const ACK_BATCH_TRACE_REPORT_INTERVAL: u64 = 64;

#[derive(Clone)]
pub(crate) struct BrutalConfig {
    tx_bps: Arc<AtomicU64>,
    bbr_config: Arc<BbrConfig>,
}

impl BrutalConfig {
    pub(crate) fn new(tx_bps: Arc<AtomicU64>) -> Self {
        Self {
            tx_bps,
            bbr_config: Arc::new(BbrConfig::default()),
        }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(
        self: Arc<Self>,
        now: Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        let brutal = BrutalState::new(now, current_mtu);
        Box::new(BrutalController {
            tx_bps: self.tx_bps.clone(),
            cached_brutal_window: brutal.initial_window(),
            brutal_tx_bps: 0,
            #[cfg(feature = "brutal-ack-batch-trace")]
            pending_ack_trace: 0,
            brutal,
            bbr: Some(Bbr::new(self.bbr_config.clone(), current_mtu)),
            brutal_active: false,
        })
    }
}

#[derive(Clone)]
struct BrutalController {
    tx_bps: Arc<AtomicU64>,
    brutal: BrutalState,
    bbr: Option<Bbr>,
    brutal_active: bool,
    brutal_tx_bps: u64,
    #[cfg(feature = "brutal-ack-batch-trace")]
    pending_ack_trace: u64,
    cached_brutal_window: u64,
}

impl BrutalController {
    fn brutal_requested(&self) -> bool {
        self.tx_bps.load(Ordering::Relaxed) > 0
    }

    fn use_brutal(&self) -> bool {
        self.brutal_active || self.brutal_requested()
    }

    fn activate_brutal_if_configured(&mut self, now: Instant) {
        if self.brutal_active {
            return;
        }
        let tx_bps = self.tx_bps.load(Ordering::Relaxed);
        if tx_bps == 0 {
            return;
        }

        // Xray replaces BBR with a fresh Brutal sender after authentication.
        // Clear handshake-era ACK/loss samples at the same boundary, but keep
        // the RTT already learned by QUIC so the first Brutal window does not
        // fall back to an uninitialized estimate. The connection publishes the
        // target rate once at this transition, so cache the derived window and
        // refresh it only when Brutal state changes instead of recomputing it on
        // every Quinn `window()` query.
        #[cfg(feature = "brutal-ack-batch-trace")]
        {
            self.pending_ack_trace = 0;
        }
        self.brutal.reset_samples(now);
        self.bbr = None;
        self.brutal_active = true;
        self.brutal_tx_bps = tx_bps;
        self.refresh_brutal_window();
    }

    #[cfg(feature = "brutal-ack-batch-trace")]
    fn queue_ack_trace(&mut self) {
        self.pending_ack_trace = self.pending_ack_trace.saturating_add(1);
    }

    #[cfg(feature = "brutal-ack-batch-trace")]
    fn flush_ack_trace(&mut self) {
        let ack_count = std::mem::take(&mut self.pending_ack_trace);
        if ack_count > 0 {
            self.brutal.record_ack_batch_trace(ack_count);
        }
    }

    fn refresh_brutal_window(&mut self) {
        if self.brutal_active {
            self.cached_brutal_window = self.brutal.window(self.brutal_tx_bps);
        }
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.activate_brutal_if_configured(now);
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.activate_brutal_if_configured(now);
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_ack(now, sent, bytes, app_limited, rtt);
        }
        self.brutal.on_ack(now, rtt);
        self.refresh_brutal_window();
        #[cfg(feature = "brutal-ack-batch-trace")]
        self.queue_ack_trace();
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.activate_brutal_if_configured(now);
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
        #[cfg(feature = "brutal-ack-batch-trace")]
        self.flush_ack_trace();
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.activate_brutal_if_configured(now);
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
        self.brutal.on_congestion_event(now, lost_bytes);
        if lost_bytes > 0 {
            self.refresh_brutal_window();
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_mtu_update(new_mtu);
        }
        self.brutal.on_mtu_update(new_mtu);
        self.refresh_brutal_window();
    }

    fn window(&self) -> u64 {
        if self.brutal_active {
            self.cached_brutal_window
        } else {
            let tx_bps = self.tx_bps.load(Ordering::Relaxed);
            if tx_bps > 0 {
                self.brutal.window(tx_bps)
            } else if let Some(bbr) = self.bbr.as_ref() {
                bbr.window()
            } else {
                self.brutal.initial_window()
            }
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        if self.use_brutal() {
            self.brutal.initial_window()
        } else if let Some(bbr) = self.bbr.as_ref() {
            bbr.initial_window()
        } else {
            self.brutal.initial_window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Clone, Copy, Default)]
struct PacketInfo {
    timestamp: u64,
    ack_count: u64,
    loss_count: u64,
}

#[cfg(feature = "brutal-ack-batch-trace")]
#[derive(Clone, Default)]
struct AckBatchTrace {
    batches: u64,
    packets: u64,
    buckets: [u64; 7],
}

#[derive(Clone)]
struct BrutalState {
    start: Instant,
    max_datagram_size: u64,
    last_rtt: Duration,
    ack_rate: f64,
    slots: [PacketInfo; PACKET_INFO_SLOT_COUNT as usize],
    rolling_ack_count: u64,
    rolling_loss_count: u64,
    rolling_timestamp: Option<u64>,
    rolling_slot: usize,
    rolling_second_start: Instant,
    next_rolling_second: Instant,
    debug: bool,
    last_debug_timestamp: u64,
    #[cfg(feature = "brutal-ack-batch-trace")]
    ack_batch_trace: AckBatchTrace,
}

impl BrutalState {
    fn new(now: Instant, current_mtu: u16) -> Self {
        let debug = std::env::var(DEBUG_ENV)
            .ok()
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(false);
        Self {
            start: now,
            max_datagram_size: current_mtu as u64,
            last_rtt: Duration::from_millis(0),
            ack_rate: 1.0,
            slots: [PacketInfo::default(); PACKET_INFO_SLOT_COUNT as usize],
            rolling_ack_count: 0,
            rolling_loss_count: 0,
            rolling_timestamp: None,
            rolling_slot: 0,
            rolling_second_start: now,
            next_rolling_second: now,
            debug,
            last_debug_timestamp: 0,
            #[cfg(feature = "brutal-ack-batch-trace")]
            ack_batch_trace: AckBatchTrace::default(),
        }
    }

    fn reset_samples(&mut self, now: Instant) {
        self.start = now;
        self.ack_rate = 1.0;
        self.slots = [PacketInfo::default(); PACKET_INFO_SLOT_COUNT as usize];
        self.rolling_ack_count = 0;
        self.rolling_loss_count = 0;
        self.rolling_timestamp = None;
        self.rolling_slot = 0;
        self.rolling_second_start = now;
        self.next_rolling_second = now;
        self.last_debug_timestamp = 0;
        #[cfg(feature = "brutal-ack-batch-trace")]
        {
            self.ack_batch_trace = AckBatchTrace::default();
        }
    }

    #[cfg(feature = "brutal-ack-batch-trace")]
    fn record_ack_batch_trace(&mut self, ack_count: u64) {
        if !self.debug {
            return;
        }

        let bucket = match ack_count {
            1 => 0,
            2 => 1,
            3..=4 => 2,
            5..=8 => 3,
            9..=16 => 4,
            17..=32 => 5,
            _ => 6,
        };
        let trace = &mut self.ack_batch_trace;
        trace.batches = trace.batches.saturating_add(1);
        trace.packets = trace.packets.saturating_add(ack_count);
        trace.buckets[bucket] = trace.buckets[bucket].saturating_add(1);

        if trace
            .batches
            .is_multiple_of(ACK_BATCH_TRACE_REPORT_INTERVAL)
        {
            debug!(
                batches = trace.batches,
                packets = trace.packets,
                mean_batch = trace.packets as f64 / trace.batches as f64,
                size_1 = trace.buckets[0],
                size_2 = trace.buckets[1],
                size_3_4 = trace.buckets[2],
                size_5_8 = trace.buckets[3],
                size_9_16 = trace.buckets[4],
                size_17_32 = trace.buckets[5],
                size_33_plus = trace.buckets[6],
                "brutal ack batch trace"
            );
        }
    }

    fn on_ack(&mut self, now: Instant, rtt: &RttEstimator) {
        self.last_rtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(&mut self, now: Instant, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        let loss_count = lost_bytes.div_ceil(self.max_datagram_size);
        self.record(now, 0, loss_count);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = new_mtu as u64;
    }

    fn window(&self, tx_bps: u64) -> u64 {
        if tx_bps == 0 {
            return self.initial_window();
        }
        let rtt = self.last_rtt;
        if rtt.as_nanos() == 0 {
            return self.initial_window();
        }

        let cwnd =
            (tx_bps as f64) * rtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER
                / self.ack_rate;
        (cwnd as u64).max(
            self.max_datagram_size
                .saturating_mul(MIN_CONGESTION_WINDOW_DATAGRAMS),
        )
    }

    fn initial_window(&self) -> u64 {
        DEFAULT_CONGESTION_WINDOW.max(self.max_datagram_size)
    }

    fn record(&mut self, now: Instant, ack_count: u64, loss_count: u64) {
        if let Some(timestamp) = self.rolling_timestamp
            && now >= self.rolling_second_start
            && now < self.next_rolling_second
        {
            let info = &mut self.slots[self.rolling_slot];
            info.ack_count += ack_count;
            info.loss_count += loss_count;
            self.rolling_ack_count += ack_count;
            self.rolling_loss_count += loss_count;
            self.refresh_ack_rate(timestamp);
            return;
        }

        let elapsed = now.saturating_duration_since(self.start);
        let timestamp = elapsed.as_secs();
        let slot = (timestamp % PACKET_INFO_SLOT_COUNT) as usize;
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
        let min_timestamp = timestamp.saturating_sub(PACKET_INFO_SLOT_COUNT);
        self.rolling_ack_count = 0;
        self.rolling_loss_count = 0;
        for info in &self.slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            self.rolling_ack_count += info.ack_count;
            self.rolling_loss_count += info.loss_count;
        }
        self.rolling_timestamp = Some(timestamp);
        self.rolling_slot = slot;
        self.rolling_second_start = self
            .start
            .checked_add(Duration::from_secs(timestamp))
            .unwrap_or(now);
        self.next_rolling_second = self
            .start
            .checked_add(Duration::from_secs(timestamp.saturating_add(1)))
            .unwrap_or(now);
        self.refresh_ack_rate(timestamp);
    }

    fn refresh_ack_rate(&mut self, timestamp: u64) {
        // A pristine rolling window always has an ACK rate of exactly 1.0.
        // Avoid repeating the floating-point division on every ACK. Keep the
        // debug path unchanged so HYSTERIA_BRUTAL_DEBUG still emits its normal
        // periodic accounting lines.
        if self.rolling_loss_count == 0 && !self.debug {
            self.ack_rate = 1.0;
            return;
        }
        self.update_ack_rate(timestamp);
    }

    fn update_ack_rate(&mut self, timestamp: u64) {
        let ack_count = self.rolling_ack_count;
        let loss_count = self.rolling_loss_count;

        if ack_count + loss_count < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            if self.can_print_ack_rate(timestamp) {
                self.last_debug_timestamp = timestamp;
                debug!(
                    "brutal ack rate: insufficient samples (total={}, ack={}, loss={}, rtt_ms={})",
                    ack_count + loss_count,
                    ack_count,
                    loss_count,
                    self.last_rtt.as_millis()
                );
            }
            return;
        }

        let rate = ack_count as f64 / (ack_count + loss_count) as f64;
        if rate < MIN_ACK_RATE {
            self.ack_rate = MIN_ACK_RATE;
            if self.can_print_ack_rate(timestamp) {
                self.last_debug_timestamp = timestamp;
                debug!(
                    "brutal ack rate: clamped {:.2} -> {:.2} (total={}, ack={}, loss={}, rtt_ms={})",
                    rate,
                    MIN_ACK_RATE,
                    ack_count + loss_count,
                    ack_count,
                    loss_count,
                    self.last_rtt.as_millis()
                );
            }
            return;
        }

        self.ack_rate = rate;
        if self.can_print_ack_rate(timestamp) {
            self.last_debug_timestamp = timestamp;
            debug!(
                "brutal ack rate: {:.2} (total={}, ack={}, loss={}, rtt_ms={})",
                rate,
                ack_count + loss_count,
                ack_count,
                loss_count,
                self.last_rtt.as_millis()
            );
        }
    }

    fn can_print_ack_rate(&self, timestamp: u64) -> bool {
        self.debug
            && timestamp.saturating_sub(self.last_debug_timestamp)
                >= DEBUG_PRINT_INTERVAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(tx_bps: Arc<AtomicU64>, now: Instant) -> BrutalController {
        let brutal = BrutalState::new(now, 1200);
        BrutalController {
            tx_bps,
            cached_brutal_window: brutal.initial_window(),
            brutal_tx_bps: 0,
            #[cfg(feature = "brutal-ack-batch-trace")]
            pending_ack_trace: 0,
            brutal,
            bbr: Some(Bbr::new(Arc::new(BbrConfig::default()), 1200)),
            brutal_active: false,
        }
    }

    #[test]
    fn brutal_activation_drops_bbr_but_preserves_rtt() {
        let tx_bps = Arc::new(AtomicU64::new(0));
        let now = Instant::now();
        let mut controller = controller(tx_bps.clone(), now);
        controller.brutal.last_rtt = Duration::from_millis(80);
        controller.brutal.ack_rate = MIN_ACK_RATE;
        controller.brutal.slots[0] = PacketInfo {
            timestamp: 1,
            ack_count: 40,
            loss_count: 10,
        };

        tx_bps.store(1_000_000, Ordering::Relaxed);
        let activated_at = now + Duration::from_secs(2);
        controller.activate_brutal_if_configured(activated_at);

        assert!(controller.brutal_active);
        assert!(controller.bbr.is_none());
        assert_eq!(controller.brutal.start, activated_at);
        assert_eq!(controller.brutal.last_rtt, Duration::from_millis(80));
        assert_eq!(controller.brutal.ack_rate, 1.0);
        assert!(
            controller
                .brutal
                .slots
                .iter()
                .all(|slot| slot.ack_count == 0 && slot.loss_count == 0)
        );
        assert_eq!(controller.window(), 64_000);

        controller
            .activate_brutal_if_configured(activated_at + Duration::from_secs(1));
        assert_eq!(controller.brutal.start, activated_at);
    }

    #[test]
    fn activated_brutal_window_cache_tracks_state_changes() {
        let tx_bps = Arc::new(AtomicU64::new(1_000_000));
        let now = Instant::now();
        let mut controller = controller(tx_bps, now);
        controller.brutal.last_rtt = Duration::from_millis(80);
        controller.activate_brutal_if_configured(now);

        assert_eq!(
            controller.cached_brutal_window,
            controller.brutal.window(controller.brutal_tx_bps)
        );
        assert_eq!(controller.window(), controller.cached_brutal_window);

        controller.brutal.last_rtt = Duration::from_millis(120);
        controller.brutal.ack_rate = MIN_ACK_RATE;
        controller.refresh_brutal_window();
        assert_eq!(
            controller.cached_brutal_window,
            controller.brutal.window(controller.brutal_tx_bps)
        );

        controller.brutal.on_mtu_update(9000);
        controller.refresh_brutal_window();
        assert_eq!(
            controller.cached_brutal_window,
            controller.brutal.window(controller.brutal_tx_bps)
        );
    }

    #[cfg(feature = "brutal-ack-batch-trace")]
    #[test]
    fn brutal_ack_batch_trace_buckets_cover_benchmark_ranges() {
        let mut state = BrutalState::new(Instant::now(), 1200);
        state.debug = true;

        for ack_count in [1, 2, 3, 4, 5, 8, 9, 16, 17, 32, 33, 64] {
            state.record_ack_batch_trace(ack_count);
        }

        assert_eq!(state.ack_batch_trace.batches, 12);
        assert_eq!(state.ack_batch_trace.packets, 194);
        assert_eq!(state.ack_batch_trace.buckets, [1, 1, 2, 2, 2, 2, 2]);
    }

    #[test]
    fn zero_brutal_bandwidth_keeps_bbr_fallback() {
        let tx_bps = Arc::new(AtomicU64::new(0));
        let now = Instant::now();
        let mut controller = controller(tx_bps, now);

        controller.activate_brutal_if_configured(now + Duration::from_secs(1));

        assert!(!controller.brutal_active);
        assert!(controller.bbr.is_some());
    }

    #[test]
    fn brutal_low_rtt_window_preserves_xray_send_allowance() {
        let now = Instant::now();
        let mut state = BrutalState::new(now, 1200);
        state.last_rtt = Duration::from_micros(100);

        // At Xray's minimum valid Brutal rate this RTT would otherwise collapse
        // Quinn's strict in-flight window to a single datagram.
        assert_eq!(state.window(65_536), 2400);

        state.on_mtu_update(1450);
        assert_eq!(state.window(65_536), 2900);
    }

    #[test]
    fn brutal_rate_derived_window_is_unchanged_above_minimum() {
        let now = Instant::now();
        let mut state = BrutalState::new(now, 1200);
        state.last_rtt = Duration::from_millis(100);

        assert_eq!(state.window(1_000_000), 80_000);
    }

    #[test]
    fn brutal_pristine_window_keeps_exact_ack_rate_and_recovers_after_loss_expires()
    {
        let start = Instant::now();
        let mut state = BrutalState::new(start, 1200);
        state.debug = false;

        state.record(start + Duration::from_millis(100), 60, 0);
        assert_eq!(state.ack_rate, 1.0);

        state.record(start + Duration::from_millis(200), 0, 10);
        assert!((state.ack_rate - (60.0 / 70.0)).abs() < f64::EPSILON);

        state.record(start + Duration::from_secs(7), 60, 0);
        assert_eq!(state.rolling_loss_count, 0);
        assert_eq!(state.ack_rate, 1.0);
    }

    #[test]
    fn brutal_cached_second_path_matches_slot_scan_with_subsecond_reordering() {
        let start = Instant::now();
        let mut state = BrutalState::new(start, 1200);
        let events = [
            (Duration::from_millis(100), 4, 0),
            (Duration::from_millis(900), 6, 1),
            (Duration::from_millis(1_100), 8, 0),
            (Duration::from_millis(4_500), 10, 2),
            (Duration::from_millis(4_200), 3, 1),
            (Duration::from_millis(7_050), 12, 0),
        ];

        for (elapsed, ack_count, loss_count) in events {
            state.record(start + elapsed, ack_count, loss_count);

            let timestamp = elapsed.as_secs();
            let min_timestamp = timestamp.saturating_sub(PACKET_INFO_SLOT_COUNT);
            let (expected_ack, expected_loss) = state
                .slots
                .iter()
                .filter(|info| info.timestamp >= min_timestamp)
                .fold((0, 0), |(acks, losses), info| {
                    (acks + info.ack_count, losses + info.loss_count)
                });
            assert_eq!(state.rolling_ack_count, expected_ack);
            assert_eq!(state.rolling_loss_count, expected_loss);
            assert_eq!(state.rolling_timestamp, Some(timestamp));
        }
    }

    #[test]
    fn brutal_rolling_sample_totals_match_slot_scan_across_time_gaps() {
        let start = Instant::now();
        let mut state = BrutalState::new(start, 1200);
        let events = [
            (0, 10, 0),
            (0, 5, 2),
            (1, 20, 1),
            (4, 8, 3),
            (7, 30, 4),
            (7, 2, 1),
            (13, 50, 5),
        ];

        for (second, ack_count, loss_count) in events {
            state.record(start + Duration::from_secs(second), ack_count, loss_count);

            let min_timestamp = second.saturating_sub(PACKET_INFO_SLOT_COUNT);
            let (expected_ack, expected_loss) = state
                .slots
                .iter()
                .filter(|info| info.timestamp >= min_timestamp)
                .fold((0, 0), |(acks, losses), info| {
                    (acks + info.ack_count, losses + info.loss_count)
                });
            assert_eq!(state.rolling_ack_count, expected_ack);
            assert_eq!(state.rolling_loss_count, expected_loss);
            assert_eq!(state.rolling_timestamp, Some(second));
        }
    }
}
