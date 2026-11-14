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
    /// Fractional bytes in billionths, retained across short pacing checks.
    /// Applies only to the fixed-rate controller; legacy Quinn is unchanged.
    fractional_tokens: u32,
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
            fractional_tokens: 0,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Credit a fixed byte-per-second rate without losing sub-byte accrual
    /// when ACKs or other events invoke the pacer more often than once per
    /// whole-byte refill. Saturating arithmetic handles extreme intervals.
    fn credit_fixed_rate(&mut self, rate: u64, elapsed: Duration) {
        // When the bucket is already full, idle time cannot accumulate
        // additional credit. Avoid doing u128 arithmetic on this hot path.
        if self.tokens == self.capacity {
            self.fractional_tokens = 0;
            return;
        }
        const NANOBYTES_PER_BYTE: u128 = 1_000_000_000;
        let nanobytes = u128::from(rate)
            .saturating_mul(elapsed.as_nanos())
            .saturating_add(u128::from(self.fractional_tokens));
        let earned = (nanobytes / NANOBYTES_PER_BYTE).min(u128::from(u64::MAX)) as u64;
        self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
        // Once the bucket fills, any surplus (including fractional bytes)
        // is discarded; otherwise a later send could spend past capacity.
        self.fractional_tokens = if self.tokens == self.capacity {
            0
        } else {
            (nanobytes % NANOBYTES_PER_BYTE) as u32
        };
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
            match self.last_rate_override {
                Some(previous_rate) => self.credit_fixed_rate(previous_rate, elapsed),
                None if self.last_window <= u64::from(u32::MAX) && !smoothed_rtt.is_zero() => {
                    let earned = (self.last_window as f64
                        * 1.25
                        * (elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64())) as u64;
                    self.tokens = self.tokens.saturating_add(earned).min(self.capacity);
                }
                None => {}
            }
            // Ignore a stale caller timestamp instead of rewinding the clock
            // and crediting the same elapsed interval a second time.
            self.prev = self.prev.max(now);
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
            if pacing_rate_override.is_none() || self.tokens == self.capacity {
                // Fractional credit from a fixed-rate policy must not carry
                // across a legacy-controller boundary or full capacity.
                self.fractional_tokens = 0;
            }
            self.last_window = window;
            self.last_mtu = mtu;
            self.last_rate_override = pacing_rate_override;
        }

        if self.tokens >= bytes_to_send {
            if let Some(rate) = pacing_rate_override {
                // Even when the next datagram fits the bucket, settle the
                // previous interval before permitting a send. Otherwise an
                // idle, initially full bucket can send a whole burst and
                // then refill a *second* burst from the same idle interval.
                let elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
                    warn!("received a timestamp early than a previous recorded time, ignoring");
                    Default::default()
                });
                self.credit_fixed_rate(rate, elapsed);
                self.prev = self.prev.max(now);
            }
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

        match pacing_rate_override {
            Some(rate) => self.credit_fixed_rate(rate, time_elapsed),
            None => {
                let new_tokens = (window as f64
                    * 1.25
                    * (time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64())) as u64;
                self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            }
        }
        // No future refill may re-count time before the last account point.
        self.prev = self.prev.max(now);

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
            let wake_budget = if self.capacity == MIN_BURST_SIZE * u64::from(mtu) {
                let rate_budget = ((rate as u128 * FIXED_RATE_BURST_INTERVAL_NANOS * 3 / 4)
                    / 1_000_000_000)
                    .min(u64::MAX as u128) as u64;
                wake_budget.min(bytes_to_send.max(rate_budget))
            } else {
                wake_budget
            };
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
    fn backwards_timestamp_during_rate_change_does_not_mint_tokens() {
        let rtt = Duration::from_millis(50);
        let window = 100_000;
        let mtu = 1_000;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, 2_000, mtu, window, Some(1_000_000), start);
        pacer.tokens = 0;

        // A stale caller time must not rewind the accounting anchor.
        pacer.delay(
            rtt,
            2_000,
            mtu,
            window,
            Some(2_000_000),
            start - Duration::from_millis(1),
        );
        assert_eq!(pacer.prev, start);
        assert_eq!(pacer.tokens, 0);

        // Returning to the original time is not an elapsed 1ms.
        pacer.delay(rtt, 2_000, mtu, window, Some(2_000_000), start);
        assert_eq!(pacer.tokens, 0, "no time elapsed since the anchor");
    }

    #[test]
    fn backwards_timestamp_with_fixed_rate_does_not_mint_tokens() {
        let rtt = Duration::from_millis(50);
        let window = 100_000;
        let mtu = 1_000;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, 2_000, mtu, window, Some(2_000_000), start);
        pacer.tokens = 0;

        pacer.delay(
            rtt,
            2_000,
            mtu,
            window,
            Some(2_000_000),
            start - Duration::from_millis(1),
        );
        assert_eq!(pacer.prev, start);
        pacer.delay(rtt, 2_000, mtu, window, Some(2_000_000), start);
        assert_eq!(pacer.tokens, 0);
    }

    #[test]
    fn fixed_rate_idle_does_not_allow_a_second_full_bucket() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let rate = 65_536;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        let after_idle = start + Duration::from_secs(1);
        assert_eq!(pacer.capacity, 10 * u64::from(mtu));

        // Long idle does not permit a carry-over burst *after* the
        // initially full bucket has already been spent.
        for _ in 0..10 {
            assert!(
                pacer
                    .delay(rtt, u64::from(mtu), mtu, window, Some(rate), after_idle)
                    .is_none(),
            );
            pacer.on_transmit(mtu);
        }
        assert_eq!(pacer.tokens, 0);
        assert_eq!(pacer.prev, after_idle);
        let next = pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(rate), after_idle)
            .expect("idle time must not refill a second full bucket");
        let refill_ns = (u128::from(mtu) * 1_000_000_000)
            .div_ceil(u128::from(rate)) as u64;
        assert_eq!(next, after_idle + Duration::from_nanos(refill_ns));
    }

    #[test]
    fn fixed_rate_alternating_ack_updates_integrate_old_rate() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(50_000), start);
        pacer.tokens = 0;

        // Twenty 10us intervals, each using the previous policy:
        // 10 * (50k + 70k) * 10us = 12 whole bytes.
        for step in 1..=20 {
            let rate = if step % 2 == 1 { 70_000 } else { 50_000 };
            pacer.delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                Some(rate),
                start + Duration::from_micros(step * 10),
            );
            assert!(pacer.tokens <= pacer.capacity);
        }
        assert_eq!(pacer.tokens, 12);
        assert_eq!(pacer.fractional_tokens, 0);
    }

    #[test]
    fn fixed_rate_subbyte_credit_survives_frequent_pacing_checks() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let rate = 65_536; // bytes/s: 0.65536 bytes per 10us
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        pacer.tokens = 0;

        for step in 1..=10 {
            pacer.delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                Some(rate),
                start + Duration::from_micros(10 * step),
            );
        }
        // Total elapsed = 100us -> 6.5536 bytes, not zero.
        assert_eq!(pacer.tokens, 6);
    }

    #[test]
    fn fixed_rate_switch_keeps_accrued_subbyte_credit() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(50_000), start);
        pacer.tokens = 0;

        pacer.delay(
            rtt,
            u64::from(mtu),
            mtu,
            window,
            Some(70_000),
            start + Duration::from_micros(10),
        ); // old rate earns 0.5 bytes
        assert_eq!(pacer.tokens, 0);
        pacer.delay(
            rtt,
            u64::from(mtu),
            mtu,
            window,
            Some(70_000),
            start + Duration::from_micros(20),
        ); // new rate earns 0.7 bytes
        assert_eq!(pacer.tokens, 1);
    }

    #[test]
    fn fixed_rate_fraction_is_discarded_when_bucket_is_full() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let rate = 65_536;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        pacer.tokens = pacer.capacity - 1;

        // After 20us we hit capacity; no unused fractional budget may
        // accumulate behind a full bucket and turn into a future burst.
        pacer.delay(
            rtt,
            pacer.capacity + 1,
            mtu,
            window,
            Some(rate),
            start + Duration::from_micros(20),
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        pacer.on_transmit(mtu);
        let remaining = pacer.tokens;
        // New 15us interval earns less than one whole byte, and surplus
        // fractional credit at full capacity must have been discarded.
        pacer.delay(
            rtt,
            pacer.capacity + 1,
            mtu,
            window,
            Some(rate),
            start + Duration::from_micros(35),
        );
        assert_eq!(pacer.tokens, remaining);
    }

    #[test]
    fn fixed_rate_fraction_does_not_leak_into_legacy_pacing() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(50_000), start);
        pacer.tokens = 0;
        pacer.delay(
            rtt, u64::from(mtu), mtu, window, None,
            start + Duration::from_micros(10),
        );
        pacer.delay(
            rtt, u64::from(mtu), mtu, window, Some(50_000),
            start + Duration::from_micros(10),
        );
        pacer.delay(
            rtt, u64::from(mtu), mtu, window, Some(50_000),
            start + Duration::from_micros(20),
        );
        assert_eq!(pacer.tokens, 0, "legacy transition must drop subbyte residue");
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
    fn fixed_rate_minimum_does_not_sleep_for_most_of_a_burst() {
        // Xray Brutal's TimeUntilSend waits for the next datagram budget,
        // not an almost-full 10-datagram minimum burst. At 64KiB/s, the
        // next 1200B packet needs about 18.3ms, not ~137ms.
        let start = Instant::now();
        let mtu = 1200;
        let rate = 65_536;
        let rtt = Duration::from_micros(100);
        let window = 3 * mtu as u64;
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        assert!(pacer
            .delay(rtt, mtu as u64, mtu, window, Some(rate), start)
            .is_none());
        while pacer.tokens >= mtu as u64 {
            pacer.on_transmit(mtu);
        }
        assert_eq!(pacer.tokens, 0);
        let resume = pacer
            .delay(rtt, mtu as u64, mtu, window, Some(rate), start)
            .expect("out of tokens");
        let exact_packet_interval_ns =
            ((u128::from(mtu) * 1_000_000_000).div_ceil(u128::from(rate))) as u64;
        assert_eq!(
            resume.duration_since(start),
            Duration::from_nanos(exact_packet_interval_ns),
            "low-rate pacing should wake as soon as the next packet is budgeted",
        );
        assert!(pacer
            .delay(rtt, mtu as u64, mtu, window, Some(rate), resume)
            .is_none());
    }

    #[test]
    fn fixed_rate_high_rate_preserves_existing_early_wake_policy() {
        let mtu = 1200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let rate = 62_500_000; // 500 Mbit/s
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        assert_eq!(pacer.capacity, 250_000); // 500 Mbps * 4ms
        pacer.tokens = 0;
        let wake_budget = pacer.capacity - pacer.capacity / 4;
        let expected_ns =
            ((u128::from(wake_budget) * 1_000_000_000).div_ceil(u128::from(rate))) as u64;
        let wake = pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(rate), start)
            .expect("out of tokens");
        assert_eq!(
            wake.duration_since(start),
            Duration::from_nanos(expected_ns)
        );
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
