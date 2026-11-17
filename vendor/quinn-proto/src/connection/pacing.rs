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
    /// Budget and timestamp after the most recently transmitted packet.
    /// The fixed-rate minimum-capacity path uses this stable origin like Xray,
    /// whose pacing deadline is measured from the last send rather than from
    /// the most recent ACK-driven budget update.
    last_sent: Option<Instant>,
    tokens_at_last_sent: u64,
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
            last_sent: None,
            tokens_at_last_sent: 0,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(
        &mut self,
        packet_length: u16,
        now: Instant,
        pacing_rate_override: Option<u64>,
        mtu: u16,
    ) {
        let pacing_rate_override = pacing_rate_override.filter(|rate| *rate > 0);
        let effective_now = self
            .last_sent
            .map_or(now, |last_sent| now.max(last_sent))
            .max(self.prev);

        let Some(rate) = pacing_rate_override else {
            self.tokens = self.tokens.saturating_sub(packet_length.into());
            if self.last_rate_override.is_some() {
                self.last_sent = Some(effective_now);
                self.tokens_at_last_sent = self.tokens;
            }
            return;
        };

        let policy_changed = self.last_rate_override != Some(rate) || self.last_mtu != mtu;
        if policy_changed {
            let elapsed = effective_now
                .checked_duration_since(self.prev)
                .unwrap_or_else(|| {
                    warn!("received a timestamp early than a previous recorded time, ignoring");
                    Default::default()
                });
            if let Some(previous_rate) = self.last_rate_override {
                self.credit_fixed_rate(previous_rate, elapsed);
            }
            self.prev = self.prev.max(effective_now);
            if self.last_rate_override.is_none() {
                self.last_sent = None;
                self.tokens_at_last_sent = 0;
            }

            self.capacity = optimal_capacity_for_rate(rate, mtu);
            self.tokens = self.capacity.min(self.tokens);
            if self.tokens == self.capacity {
                self.fractional_tokens = 0;
            }
            self.last_mtu = mtu;
            self.last_rate_override = Some(rate);
        }

        if self.capacity == MIN_BURST_SIZE * u64::from(mtu) {
            self.refresh_minimum_capacity_budget(rate, mtu, effective_now);
        } else if !policy_changed {
            let elapsed = effective_now
                .checked_duration_since(self.prev)
                .unwrap_or_else(|| {
                    warn!("received a timestamp early than a previous recorded time, ignoring");
                    Default::default()
                });
            self.credit_fixed_rate(rate, elapsed);
        }
        self.prev = self.prev.max(effective_now);

        self.tokens = self.tokens.saturating_sub(packet_length.into());
        self.last_sent = Some(effective_now);
        self.tokens_at_last_sent = self.tokens;
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
            if pacing_rate_override.is_none() || self.last_rate_override.is_none() {
                // A legacy send timestamp is not part of the fixed-rate
                // budget, and a later fixed-rate controller starts tracking
                // again at its first transmitted packet.
                self.last_sent = None;
                self.tokens_at_last_sent = 0;
            }
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

        // Xray's minimum-capacity pacer recomputes its budget from the last
        // send using the current bandwidth estimate. ACK-rate compensation
        // can therefore change the calculated budget for the whole interval
        // since that send. Keep the fixed-rate minimum bucket on the same
        // accounting model; incremental old-rate credit here can schedule a
        // second wake after Xray's packet deadline.
        let minimum_capacity_budget_from_last_sent = pacing_rate_override
            .filter(|_| self.capacity == MIN_BURST_SIZE * u64::from(mtu))
            .is_some_and(|rate| self.refresh_minimum_capacity_budget(rate, mtu, now));
        let bytes_to_send = if minimum_capacity_budget_from_last_sent {
            bytes_to_send.max(u64::from(mtu))
        } else {
            bytes_to_send
        };

        if self.tokens >= bytes_to_send {
            if let Some(rate) = pacing_rate_override {
                // Even when the next datagram fits the bucket, settle the
                // previous interval before permitting a send. Otherwise an
                // idle, initially full bucket can send a whole burst and
                // then refill a *second* burst from the same idle interval.
                if !minimum_capacity_budget_from_last_sent {
                    let elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
                        warn!("received a timestamp early than a previous recorded time, ignoring");
                        Default::default()
                    });
                    self.credit_fixed_rate(rate, elapsed);
                }
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
            Some(rate) if !minimum_capacity_budget_from_last_sent => {
                self.credit_fixed_rate(rate, time_elapsed)
            }
            Some(_) => {}
            None => {
                let new_tokens = (window as f64
                    * 1.25
                    * (time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64())) as u64;
                self.tokens = self.tokens.saturating_add(new_tokens).min(self.capacity);
            }
        }
        // No future refill may re-count time before the last account point.
        self.prev = self.prev.max(now);

        if let Some(rate) = pacing_rate_override {
            if self.capacity == MIN_BURST_SIZE * u64::from(mtu) {
                if let Some(deadline) = self.minimum_capacity_deadline(rate, mtu) {
                    if now < deadline {
                        // ACK and timer callbacks can account partial budget,
                        // but must not move Xray's last-send deadline forward.
                        return Some(deadline);
                    }
                }
            }
        }

        if self.tokens >= bytes_to_send {
            return None;
        }

        if let Some(rate) = pacing_rate_override {
            // Wake before the bucket fills completely. Timer wake-ups may be
            // late by a fraction of a millisecond; waiting for 100% capacity
            // discards the tokens earned during that oversleep, lowering the
            // effective rate. Keep 25% of capacity as jitter headroom while
            // retaining the same bounded burst size and refill rate.
            let minimum_capacity = MIN_BURST_SIZE * u64::from(mtu);
            let (wake_budget, min_delay_nanos) = if self.capacity == minimum_capacity {
                // Xray's fixed-rate pacer wakes for the next datagram, with a
                // 1ms minimum delay. Keep the same low-rate behavior instead
                // of batching most of the minimum 10-packet bucket.
                (bytes_to_send, FIXED_RATE_MIN_PACING_DELAY_NANOS)
            } else {
                (bytes_to_send.max(self.capacity - self.capacity / 4), 1)
            };
            let needed = wake_budget - self.tokens;
            // The fractional bytes were already earned and carried forward
            // by credit_fixed_rate. Subtract them from the next wake's debt;
            // otherwise frequent ACK callbacks postpone the wake repeatedly.
            let remaining_nanobytes = u128::from(needed) * 1_000_000_000
                - u128::from(self.fractional_tokens);
            let nanos = remaining_nanobytes
                .div_ceil(u128::from(rate))
                .min(u128::from(u64::MAX)) as u64;
            return Some(self.prev + Duration::from_nanos(nanos.max(min_delay_nanos)));
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

    /// Recompute the minimum fixed-rate bucket from the last packet send, as
    /// Xray does when ACK-rate compensation changes the current bandwidth.
    /// Returns false until a fixed-rate packet has established a send anchor.
    fn refresh_minimum_capacity_budget(&mut self, rate: u64, mtu: u16, now: Instant) -> bool {
        let Some(last_sent) = self.last_sent else {
            return false;
        };
        let elapsed = now.checked_duration_since(last_sent).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });
        let earned = (u128::from(rate).saturating_mul(elapsed.as_nanos()) / 1_000_000_000)
            .min(u128::from(u64::MAX)) as u64;
        self.tokens = self
            .tokens_at_last_sent
            .saturating_add(earned)
            .min(MIN_BURST_SIZE * u64::from(mtu));
        // Xray recalculates the whole interval with integer byte arithmetic.
        self.fractional_tokens = 0;
        true
    }

    /// Return Xray's minimum-capacity deadline, anchored to the last send.
    fn minimum_capacity_deadline(&self, rate: u64, mtu: u16) -> Option<Instant> {
        let last_sent = self.last_sent?;
        let max_datagram_size = u64::from(mtu);
        if self.tokens_at_last_sent >= max_datagram_size {
            return None;
        }
        let remaining = max_datagram_size - self.tokens_at_last_sent;
        let interval_nanos = (u128::from(remaining) * 1_000_000_000)
            .div_ceil(u128::from(rate))
            .min(u128::from(u64::MAX)) as u64;
        Some(
            last_sent
                + Duration::from_nanos(interval_nanos.max(FIXED_RATE_MIN_PACING_DELAY_NANOS)),
        )
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

/// Xray's quic-go Brutal pacer does not schedule packet sends more frequently
/// than once per millisecond.
const FIXED_RATE_MIN_PACING_DELAY_NANOS: u64 = 1_000_000;

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

            pacer.on_transmit(mtu, old_instant, None, mtu);
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

            pacer.on_transmit(mtu, old_instant, None, mtu);
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
    fn fixed_rate_subbyte_credit_advances_next_wake() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let rate = 65_536;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        pacer.tokens = 0;

        // Ten microseconds earns 0.65536 byte. The next wake must account
        // for it instead of waiting for another full 1,200 bytes.
        let wake = pacer
            .delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                Some(rate),
                start + Duration::from_micros(10),
            )
            .expect("insufficient token balance");
        assert_eq!(pacer.fractional_tokens, 655_360_000);
        let full_packet_ns =
            (u128::from(mtu) * 1_000_000_000).div_ceil(u128::from(rate)) as u64;
        assert_eq!(wake, start + Duration::from_nanos(full_packet_ns));
    }

    #[test]
    fn fixed_rate_rate_change_reuses_fraction_in_next_wake() {
        let mtu = 1_200;
        let rtt = Duration::from_millis(50);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(50_000), start);
        pacer.tokens = 0;

        // 10us at the OLD rate earns 0.5 byte. The NEW 70k B/s
        // rate must schedule using that existing credit, not discard it.
        let switched = start + Duration::from_micros(10);
        let wake = pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(70_000), switched)
            .expect("insufficient token balance");
        assert_eq!(pacer.fractional_tokens, 500_000_000);
        let remaining_ns = (u128::from(mtu) * 1_000_000_000 - 500_000_000)
            .div_ceil(70_000) as u64;
        assert_eq!(wake, switched + Duration::from_nanos(remaining_ns));
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
            pacer.on_transmit(mtu, after_idle, Some(rate), mtu);
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
        pacer.on_transmit(
            mtu,
            start + Duration::from_micros(20),
            Some(rate),
            mtu,
        );
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
    fn fixed_rate_minimum_capacity_wake_matches_xray_packet_delay() {
        let mtu = 1200;
        let rtt = Duration::from_micros(100);
        let window = 3 * mtu as u64;
        for rate in [65_536, 2_000_000] {
            let start = Instant::now();
            let mut pacer = Pacer::new(rtt, window, mtu, start);
            assert!(pacer
                .delay(rtt, mtu as u64, mtu, window, Some(rate), start)
                .is_none());
            while pacer.tokens >= mtu as u64 {
                pacer.on_transmit(mtu, start, Some(rate), mtu);
            }
            assert_eq!(pacer.tokens, 0);
            let resume = pacer
                .delay(rtt, mtu as u64, mtu, window, Some(rate), start)
                .expect("out of tokens");
            let packet_interval_ns = ((u128::from(mtu) * 1_000_000_000)
                .div_ceil(u128::from(rate)))
                as u64;
            let expected_ns =
                packet_interval_ns.max(FIXED_RATE_MIN_PACING_DELAY_NANOS);
            assert_eq!(
                resume.duration_since(start),
                Duration::from_nanos(expected_ns),
                "at {rate} B/s, wake at Xray's next-packet deadline and 1ms minimum",
            );
            let callback_time = start + Duration::from_micros(500);
            let callback_deadline = pacer
                .delay(rtt, mtu as u64, mtu, window, Some(rate), callback_time)
                .expect("mid-interval callback must preserve the send deadline");
            assert_eq!(
                callback_deadline, resume,
                "at {rate} B/s, an ACK callback must not move Xray's deadline",
            );
            assert!(pacer
                .delay(rtt, mtu as u64, mtu, window, Some(rate), resume)
                .is_none());
            pacer.on_transmit(mtu, resume, Some(rate), mtu);
            let next = pacer
                .delay(rtt, mtu as u64, mtu, window, Some(rate), resume)
                .expect("the next datagram after a depleted budget must be paced");
            assert_eq!(
                next,
                resume + Duration::from_nanos(expected_ns),
                "at {rate} B/s, the next deadline must again be anchored to the send",
            );
        }
    }

    #[test]
    fn minimum_capacity_ack_rate_increase_uses_xray_current_rate_deadline() {
        let mtu = 1200;
        let rtt = Duration::from_micros(100);
        let window = 3 * u64::from(mtu);
        let old_rate = 125_000;
        let new_rate = 156_250;
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);

        assert!(pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(old_rate), start)
            .is_none());
        for _ in 0..MIN_BURST_SIZE {
            pacer.on_transmit(mtu, start, Some(old_rate), mtu);
        }
        assert_eq!(pacer.tokens, 0);

        let rate_change = start + Duration::from_millis(5);
        let expected_deadline = start + Duration::from_micros(7_680);
        let first_wake = pacer
            .delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                Some(new_rate),
                rate_change,
            )
            .expect("rate change must preserve Xray's packet deadline");
        assert_eq!(first_wake, expected_deadline);
        assert_eq!(pacer.tokens, 781);

        let ack_callback = start + Duration::from_micros(6_000);
        assert_eq!(
            pacer.delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                Some(new_rate),
                ack_callback,
            ),
            Some(expected_deadline),
            "ACK callbacks must not postpone the deadline or retain old-rate credit",
        );

        assert!(pacer
            .delay(
                rtt,
                u64::from(mtu),
                mtu,
                window,
                Some(new_rate),
                expected_deadline,
            )
            .is_none());
        assert_eq!(pacer.tokens, u64::from(mtu));
    }

    #[test]
    fn minimum_capacity_budget_allows_send_before_one_millisecond_deadline_when_ready() {
        let mtu = 1200;
        let rate = 2_000_000;
        let rtt = Duration::from_micros(100);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);

        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        for _ in 0..MIN_BURST_SIZE {
            pacer.on_transmit(mtu, start, Some(rate), mtu);
        }

        let ack_time = start + Duration::from_micros(700);
        assert!(pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(rate), ack_time)
            .is_none());
        assert_eq!(pacer.tokens, 1400);
    }

    #[test]
    fn minimum_capacity_probe_send_rebases_budget_at_actual_send_time() {
        let mtu = 1200;
        let rate = 125_000;
        let rtt = Duration::from_micros(100);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);

        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        for _ in 0..MIN_BURST_SIZE {
            pacer.on_transmit(mtu, start, Some(rate), mtu);
        }
        assert_eq!(pacer.tokens, 0);

        // A loss probe bypasses delay(). Xray accounts the current budget in
        // SentPacket, so 20 ms at 125 kB/s earns 2500 bytes before this send.
        let probe_time = start + Duration::from_millis(20);
        pacer.on_transmit(mtu, probe_time, Some(rate), mtu);
        assert_eq!(pacer.tokens, 1300);
        assert_eq!(pacer.tokens_at_last_sent, 1300);
        assert_eq!(pacer.last_sent, Some(probe_time));
        assert!(pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(rate), probe_time)
            .is_none());
    }

    #[test]
    fn minimum_capacity_probe_send_uses_current_rate_after_rate_decrease() {
        let mtu = 1200;
        let old_rate = 125_000;
        let new_rate = 50_000;
        let rtt = Duration::from_micros(100);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);

        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(old_rate), start);
        for _ in 0..MIN_BURST_SIZE {
            pacer.on_transmit(mtu, start, Some(old_rate), mtu);
        }
        assert_eq!(pacer.tokens, 0);

        let probe_time = start + Duration::from_millis(20);
        pacer.on_transmit(mtu, probe_time, Some(new_rate), mtu);
        assert_eq!(pacer.tokens, 0);
        assert_eq!(pacer.tokens_at_last_sent, 0);
        assert_eq!(pacer.last_rate_override, Some(new_rate));
        assert_eq!(pacer.last_sent, Some(probe_time));
        assert_eq!(
            pacer.delay(rtt, u64::from(mtu), mtu, window, Some(new_rate), probe_time),
            Some(probe_time + Duration::from_millis(24)),
        );
    }

    #[test]
    fn stale_minimum_capacity_transmit_does_not_rewind_send_anchor() {
        let mtu = 1200;
        let rate = 125_000;
        let rtt = Duration::from_micros(100);
        let window = 3 * u64::from(mtu);
        let start = Instant::now();
        let stale = start - Duration::from_millis(10);
        let mut pacer = Pacer::new(rtt, window, mtu, start);

        pacer.delay(rtt, u64::from(mtu), mtu, window, Some(rate), start);
        pacer.on_transmit(mtu, start, Some(rate), mtu);
        assert_eq!(pacer.tokens, 9 * u64::from(mtu));

        assert!(pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(rate), stale)
            .is_none());
        pacer.on_transmit(mtu, stale, Some(rate), mtu);
        assert_eq!(pacer.last_sent, Some(start));
        assert_eq!(pacer.tokens_at_last_sent, 8 * u64::from(mtu));
        assert!(pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(rate), start)
            .is_none());
        assert_eq!(pacer.tokens, 8 * u64::from(mtu));
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
            pacer.on_transmit(mtu, now, Some(rate_bytes_per_second), mtu);
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
            late.on_transmit(mtu, now, Some(rate_bytes_per_second), mtu);
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
