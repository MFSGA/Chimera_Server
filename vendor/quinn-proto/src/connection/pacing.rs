//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    last_rate_override: Option<u64>,
    tokens: u64,
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            last_rate_override: None,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        pacing_rate_override: Option<u64>,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        let pacing_rate_override = pacing_rate_override.filter(|rate| *rate > 0);
        if pacing_rate_override != self.last_rate_override {
            // Settle elapsed time using the *previous* pacing policy before
            // switching rates. Otherwise ACK-driven rate changes rewrite the
            // budget earned before the change, causing artificial stalls or
            // bursts. Keep ordinary Quinn pacing untouched when no override
            // transition occurs.
            let elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
                warn!("received a timestamp early than a previous recorded time, ignoring");
                Default::default()
            });
            let earned = match self.last_rate_override {
                Some(previous_rate) => {
                    ((previous_rate as u128 * elapsed.as_nanos()) / 1_000_000_000)
                        .min(u64::MAX as u128) as u64
                }
                None if self.last_window <= u64::from(u32::MAX) && !smoothed_rtt.is_zero() => {
                    (self.last_window as f64 * 1.25
                        * (elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64())) as u64
                }
                None => 0,
            };
            self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
            self.prev = now;
        }
        if window != self.last_window
            || mtu != self.last_mtu
            || pacing_rate_override != self.last_rate_override
        {
            self.capacity = match pacing_rate_override {
                Some(rate) => optimal_capacity_for_rate(rate, mtu),
                None => optimal_capacity(smoothed_rtt, window, mtu),
            };

            // Clamp the tokens when congestion state, MTU or pacing policy changes.
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
            self.last_rate_override = pacing_rate_override;
        }

        if self.tokens >= bytes_to_send {
            return None;
        }

        // Preserve the old window-based controller behavior exactly when there
        // is no pacing override. A fixed-rate controller such as Brutal must
        // not lose pacing merely because its congestion window is very large.
        if pacing_rate_override.is_none() && window > u64::from(u32::MAX) {
            return None;
        }

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if pacing_rate_override.is_none() && smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let new_tokens = match pacing_rate_override {
            Some(rate) => ((rate as u128 * time_elapsed.as_nanos()) / 1_000_000_000)
                .min(u64::MAX as u128) as u64,
            None => (window as f64 * 1.25
                * (time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64())) as u64,
        };
        self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
        self.prev = now;

        if self.tokens >= bytes_to_send {
            return None;
        }

        if let Some(rate) = pacing_rate_override {
            // Wake before the bucket fills completely. Timer wake-ups may be
            // late by a fraction of a millisecond; waiting for 100% capacity
            // discards the tokens earned during that oversleep, lowering the
            // effective rate. Keep 25% of capacity as jitter headroom while
            // retaining the same bounded burst size and refill rate.
            let wake_budget = bytes_to_send.max(self.capacity - self.capacity / 4);
            let needed = wake_budget - self.tokens;
            let nanos = (needed as u128 * 1_000_000_000)
                .div_ceil(rate as u128)
                .min(u64::MAX as u128) as u64;
            return Some(self.prev + Duration::from_nanos(nanos.max(1)));
        }

        let window = window as u32;
        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // Keep legacy Quinn pacing unchanged for congestion controllers that
        // do not request an explicit rate.
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity_for_rate(rate_bytes_per_sec: u64, mtu: u16) -> u64 {
    // A fixed-rate sender must not lose too much bandwidth to timer wake-up
    // jitter. Unlike Quinn's RTT-derived pacer, it must not compensate for
    // that jitter by increasing the configured bytes-per-second refill rate.
    // Instead allow a larger, still bounded burst of previously earned tokens.
    let capacity = ((rate_bytes_per_sec as u128 * FIXED_RATE_BURST_INTERVAL_NANOS) / 1_000_000_000)
        .min(u64::MAX as u128) as u64;
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Fixed-rate senders retain up to 4ms of earned send budget to absorb timer
/// wake-up jitter without increasing the long-run token refill rate.
const FIXED_RATE_BURST_INTERVAL_NANOS: u128 = 4_000_000;

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, None, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, None, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, None, old_instant)
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, None, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, None, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, None, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, None, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                None,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, None, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                None,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn dynamic_rate_decrease_preserves_tokens_earned_at_previous_rate() {
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let window = 100_000;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, mtu as u64, mtu, window, Some(10_000_000), start);
        pacer.tokens = 0;

        pacer.delay(
            rtt,
            2_000,
            mtu,
            window,
            Some(1_000_000),
            start + Duration::from_millis(1),
        );
        assert_eq!(pacer.tokens, 10_000, "credit the elapsed time at the old rate");
    }

    #[test]
    fn dynamic_rate_increase_does_not_retroactively_mint_tokens() {
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let window = 100_000;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, mtu as u64, mtu, window, Some(1_000_000), start);
        pacer.tokens = 0;

        pacer.delay(
            rtt,
            2_000,
            mtu,
            window,
            Some(10_000_000),
            start + Duration::from_millis(1),
        );
        assert_eq!(pacer.tokens, 1_000, "the new rate applies only after the switch");
    }

    #[test]
    fn fixed_rate_override_is_independent_of_rtt_and_refills_at_target_rate() {
        let mtu = 1200;
        let window = 3 * mtu as u64;
        let rate_bytes_per_second = 7_500_000; // 60 Mbps
        let rtt = Duration::from_micros(100);
        let now = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, now);

        // A small Brutal window must not turn its 60 Mbps target into a
        // cwnd/100us pacing rate. The burst capacity is four milliseconds of
        // the explicitly configured bytes per second.
        assert!(pacer
            .delay(rtt, mtu as u64, mtu, window, Some(rate_bytes_per_second), now)
            .is_none());
        assert_eq!(pacer.capacity, 30_000);
        assert_eq!(pacer.last_rate_override, Some(rate_bytes_per_second));

        while pacer.tokens >= mtu as u64 {
            pacer.on_transmit(mtu);
        }
        let wake_budget = pacer.capacity - pacer.capacity / 4;
        let expected_ns = ((wake_budget - pacer.tokens) as u128 * 1_000_000_000)
            .div_ceil(rate_bytes_per_second as u128) as u64;
        let resume = pacer
            .delay(rtt, mtu as u64, mtu, window, Some(rate_bytes_per_second), now)
            .expect("exhausted fixed-rate pacing budget must delay");
        assert_eq!(resume.duration_since(now), Duration::from_nanos(expected_ns));
        assert!(pacer
            .delay(rtt, mtu as u64, mtu, window, Some(rate_bytes_per_second), resume)
            .is_none());
        assert!(pacer.tokens < pacer.capacity);

        // A 500us late timer must still have room to credit the time earned
        // after the requested wake-up. The previous 100%-capacity wake-up
        // clipped this refill and permanently lost the overslept budget.
        let mut late = Pacer::new(rtt, window, mtu, now);
        late.delay(rtt, mtu as u64, mtu, window, Some(rate_bytes_per_second), now);
        while late.tokens >= mtu as u64 {
            late.on_transmit(mtu);
        }
        let scheduled = late
            .delay(rtt, mtu as u64, mtu, window, Some(rate_bytes_per_second), now)
            .expect("budget exhausted");
        let late_now = scheduled + Duration::from_micros(500);
        assert!(late
            .delay(rtt, mtu as u64, mtu, window, Some(rate_bytes_per_second), late_now)
            .is_none());
        assert!(late.tokens < late.capacity, "late wake-up must not clip tokens");
        assert!(late.tokens >= wake_budget);

        // Switching back to a standard controller restores legacy RTT-based
        // pacing without retaining Brutal's explicit target rate.
        pacer.delay(rtt, mtu as u64, mtu, window, None, resume);
        assert_eq!(pacer.last_rate_override, None);
        assert_eq!(pacer.capacity, optimal_capacity(rtt, window, mtu));
    }
}
