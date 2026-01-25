use std::{
    any::Any,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use std::time::{Duration, Instant};

use quinn_proto::{
    congestion::{Bbr, BbrConfig, Controller, ControllerFactory},
    RttEstimator,
};
use tracing::debug;

const PACKET_INFO_SLOT_COUNT: u64 = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
// Quinn's pacer refills at ~1.25x cwnd per RTT, so scale cwnd to keep target rate.
const CONGESTION_WINDOW_MULTIPLIER: f64 = 0.8;
const DEFAULT_CONGESTION_WINDOW: u64 = 10_240;
const DEBUG_ENV: &str = "HYSTERIA_BRUTAL_DEBUG";
const DEBUG_PRINT_INTERVAL: u64 = 2;

#[derive(Clone)]
pub(super) struct BrutalConfig {
    tx_bps: Arc<AtomicU64>,
    bbr_config: Arc<BbrConfig>,
}

impl BrutalConfig {
    pub(super) fn new(tx_bps: Arc<AtomicU64>) -> Self {
        Self {
            tx_bps,
            bbr_config: Arc::new(BbrConfig::default()),
        }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController {
            tx_bps: self.tx_bps.clone(),
            brutal: BrutalState::new(now, current_mtu),
            bbr: Bbr::new(self.bbr_config.clone(), current_mtu),
        })
    }
}

#[derive(Clone)]
struct BrutalController {
    tx_bps: Arc<AtomicU64>,
    brutal: BrutalState,
    bbr: Bbr,
}

impl BrutalController {
    fn use_brutal(&self) -> bool {
        self.tx_bps.load(Ordering::Relaxed) > 0
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.bbr.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        self.brutal.on_ack(now, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.bbr
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        self.brutal.on_congestion_event(now, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.bbr.on_mtu_update(new_mtu);
        self.brutal.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.use_brutal() {
            self.brutal.window(self.tx_bps.load(Ordering::Relaxed))
        } else {
            self.bbr.window()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        if self.use_brutal() {
            self.brutal.initial_window()
        } else {
            self.bbr.initial_window()
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

#[derive(Clone)]
struct BrutalState {
    start: Instant,
    max_datagram_size: u64,
    last_rtt: Duration,
    ack_rate: f64,
    slots: [PacketInfo; PACKET_INFO_SLOT_COUNT as usize],
    debug: bool,
    last_debug_timestamp: u64,
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
            debug,
            last_debug_timestamp: 0,
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
        let loss_count = (lost_bytes + self.max_datagram_size - 1) / self.max_datagram_size;
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
            (tx_bps as f64) * rtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER / self.ack_rate;
        (cwnd as u64).max(self.max_datagram_size)
    }

    fn initial_window(&self) -> u64 {
        DEFAULT_CONGESTION_WINDOW.max(self.max_datagram_size)
    }

    fn record(&mut self, now: Instant, ack_count: u64, loss_count: u64) {
        let timestamp = now.saturating_duration_since(self.start).as_secs();
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
        self.update_ack_rate(timestamp);
    }

    fn update_ack_rate(&mut self, timestamp: u64) {
        let min_timestamp = timestamp.saturating_sub(PACKET_INFO_SLOT_COUNT);
        let mut ack_count = 0u64;
        let mut loss_count = 0u64;
        for info in &self.slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }

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
        self.debug && timestamp.saturating_sub(self.last_debug_timestamp) >= DEBUG_PRINT_INTERVAL
    }
}
