use std::collections::HashMap;

use crate::config::MkcpTransportConfig;

use super::MkcpSegment;

const ACK_SEGMENT_OVERHEAD: u32 = 17;
const ACK_NUMBER_LIMIT: usize = 128;
const SEGMENT_OPTION_CLOSE: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MkcpReceiveDisposition {
    Accepted,
    Duplicate,
    OutOfWindow,
}

#[derive(Debug, Clone, Copy)]
struct PendingAck {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

#[derive(Debug)]
pub(crate) struct MkcpReceivingState {
    window: HashMap<u32, Vec<u8>>,
    pending_acks: Vec<PendingAck>,
    next_number: u32,
    window_size: u32,
    mtu: u32,
    ack_dirty: bool,
}

impl MkcpReceivingState {
    pub(crate) fn new(config: MkcpTransportConfig) -> Self {
        Self {
            window: HashMap::new(),
            pending_acks: Vec::new(),
            next_number: 0,
            window_size: receiving_in_flight_size(config),
            mtu: config.mtu,
            ack_dirty: false,
        }
    }

    pub(crate) fn process_data(
        &mut self,
        timestamp: u32,
        number: u32,
        sending_next: u32,
        payload: Vec<u8>,
    ) -> MkcpReceiveDisposition {
        // Xray uses unsigned subtraction here. A sequence number behind
        // next_number therefore wraps to a large offset and is out of window.
        let offset = number.wrapping_sub(self.next_number);
        if offset >= self.window_size {
            return MkcpReceiveDisposition::OutOfWindow;
        }

        self.clear_acks_before(sending_next);
        self.pending_acks.push(PendingAck {
            number,
            timestamp,
            next_flush: 0,
        });
        self.ack_dirty = true;

        if self.window.contains_key(&number) {
            return MkcpReceiveDisposition::Duplicate;
        }
        self.window.insert(number, payload);
        MkcpReceiveDisposition::Accepted
    }

    pub(crate) fn process_sending_next(&mut self, sending_next: u32) {
        self.clear_acks_before(sending_next);
    }

    pub(crate) fn is_data_available(&self) -> bool {
        self.window.contains_key(&self.next_number)
    }

    pub(crate) fn drain_ordered_payloads(&mut self) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        while let Some(payload) = self.pop_ordered_payload() {
            payloads.push(payload);
        }
        payloads
    }

    pub(crate) fn pop_ordered_payload(&mut self) -> Option<Vec<u8>> {
        let payload = self.window.remove(&self.next_number)?;
        self.next_number = self.next_number.wrapping_add(1);
        Some(payload)
    }

    pub(crate) fn update_necessary(&self) -> bool {
        !self.pending_acks.is_empty()
    }

    pub(crate) fn next_number(&self) -> u32 {
        self.next_number
    }

    pub(crate) fn window_size(&self) -> u32 {
        self.window_size
    }

    pub(crate) fn flush_acks(
        &mut self,
        conversation: u16,
        current: u32,
        rto: u32,
        ready_to_close: bool,
    ) -> Vec<MkcpSegment> {
        let limit = ack_number_limit(self.mtu);
        let mut output = Vec::new();
        let mut resend_candidates = Vec::with_capacity(ACK_NUMBER_LIMIT);
        let mut numbers = Vec::with_capacity(limit);
        let mut timestamp = 0;
        let retry_after = (rto / 2).max(20);

        for ack in &mut self.pending_acks {
            if ack.next_flush > current {
                if resend_candidates.len() < ACK_NUMBER_LIMIT {
                    resend_candidates.push(ack.number);
                }
                continue;
            }

            numbers.push(ack.number);
            update_ack_timestamp(&mut timestamp, ack.timestamp);
            ack.next_flush = current.wrapping_add(retry_after);

            if numbers.len() == limit {
                output.push(ack_segment(
                    conversation,
                    self.next_number,
                    self.window_size,
                    timestamp,
                    std::mem::take(&mut numbers),
                    ready_to_close,
                ));
                numbers = Vec::with_capacity(limit);
                timestamp = 0;
                self.ack_dirty = false;
            }
        }

        if self.ack_dirty || !numbers.is_empty() {
            for number in resend_candidates {
                if numbers.len() == limit {
                    break;
                }
                numbers.push(number);
            }
            output.push(ack_segment(
                conversation,
                self.next_number,
                self.window_size,
                timestamp,
                numbers,
                ready_to_close,
            ));
            self.ack_dirty = false;
        }

        output
    }

    fn clear_acks_before(&mut self, sending_next: u32) {
        let before = self.pending_acks.len();
        self.pending_acks.retain(|ack| ack.number >= sending_next);
        if self.pending_acks.len() != before {
            self.ack_dirty = true;
        }
    }
}

fn receiving_in_flight_size(config: MkcpTransportConfig) -> u32 {
    // Match Xray's integer arithmetic while avoiding a panic if this internal
    // helper is ever called with a plan that bypassed config validation.
    let intervals_per_second = (1000 / config.tti.max(1)).max(1);
    config
        .downlink_capacity
        .wrapping_mul(1024)
        .wrapping_mul(1024)
        .checked_div(config.mtu.max(1))
        .unwrap_or_default()
        .checked_div(intervals_per_second)
        .unwrap_or_default()
        .max(8)
}

fn ack_number_limit(mtu: u32) -> usize {
    ((mtu.saturating_sub(ACK_SEGMENT_OVERHEAD) / 4) as usize)
        .clamp(1, ACK_NUMBER_LIMIT)
}

fn update_ack_timestamp(current: &mut u32, candidate: u32) {
    if candidate.wrapping_sub(*current) < 0x7fff_ffff {
        *current = candidate;
    }
}

fn ack_segment(
    conversation: u16,
    receiving_next: u32,
    window_size: u32,
    timestamp: u32,
    numbers: Vec<u32>,
    ready_to_close: bool,
) -> MkcpSegment {
    MkcpSegment::Ack {
        conversation,
        option: if ready_to_close {
            SEGMENT_OPTION_CLOSE
        } else {
            0
        },
        receiving_window: receiving_next.wrapping_add(window_size),
        receiving_next,
        timestamp,
        numbers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MkcpTransportConfig {
        MkcpTransportConfig {
            mtu: 1350,
            tti: 50,
            downlink_capacity: 20,
            ..MkcpTransportConfig::default()
        }
    }

    #[test]
    fn receiving_window_matches_xray_capacity_and_orders_payloads() {
        let mut state = MkcpReceivingState::new(config());
        assert_eq!(state.window_size(), 776);
        assert_eq!(state.next_number(), 0);

        assert_eq!(
            state.process_data(30, 2, 0, b"two".to_vec()),
            MkcpReceiveDisposition::Accepted
        );
        assert_eq!(
            state.process_data(20, 1, 0, b"one".to_vec()),
            MkcpReceiveDisposition::Accepted
        );
        assert!(!state.is_data_available());
        assert!(state.drain_ordered_payloads().is_empty());

        assert_eq!(
            state.process_data(10, 0, 0, b"zero".to_vec()),
            MkcpReceiveDisposition::Accepted
        );
        assert!(state.is_data_available());
        assert_eq!(
            state.drain_ordered_payloads(),
            vec![b"zero".to_vec(), b"one".to_vec(), b"two".to_vec()]
        );
        assert_eq!(state.next_number(), 3);
    }

    #[test]
    fn receiving_window_acks_duplicates_and_rejects_out_of_window_data() {
        let mut state = MkcpReceivingState::new(MkcpTransportConfig {
            mtu: 21,
            tti: 1000,
            downlink_capacity: 0,
            ..MkcpTransportConfig::default()
        });
        assert_eq!(state.window_size(), 8);

        assert_eq!(
            state.process_data(10, 0, 0, b"first".to_vec()),
            MkcpReceiveDisposition::Accepted
        );
        assert_eq!(
            state.process_data(11, 0, 0, b"duplicate".to_vec()),
            MkcpReceiveDisposition::Duplicate
        );
        assert_eq!(
            state.process_data(12, 8, 0, b"too-far".to_vec()),
            MkcpReceiveDisposition::OutOfWindow
        );

        assert_eq!(state.drain_ordered_payloads(), vec![b"first".to_vec()]);
        let acks = state.flush_acks(7, 100, 100, false);
        assert_eq!(acks.len(), 2, "MTU 21 fits one ACK number per segment");
        assert!(matches!(
            &acks[0],
            MkcpSegment::Ack {
                conversation: 7,
                receiving_next: 1,
                receiving_window: 9,
                numbers,
                ..
            } if numbers == &vec![0]
        ));
        assert!(matches!(
            &acks[1],
            MkcpSegment::Ack { numbers, .. } if numbers == &vec![0]
        ));
    }

    #[test]
    fn ack_flush_matches_xray_retry_clear_and_close_semantics() {
        let mut state = MkcpReceivingState::new(config());
        state.process_data(40, 0, 0, b"zero".to_vec());
        state.process_data(30, 1, 0, b"one".to_vec());
        state.drain_ordered_payloads();

        let first = state.flush_acks(19, 100, 100, false);
        assert_eq!(first.len(), 1);
        assert!(matches!(
            &first[0],
            MkcpSegment::Ack {
                conversation: 19,
                option: 0,
                receiving_next: 2,
                timestamp: 40,
                numbers,
                ..
            } if numbers == &vec![0, 1]
        ));

        assert!(state.flush_acks(19, 120, 100, false).is_empty());
        let retry = state.flush_acks(19, 150, 100, true);
        assert_eq!(retry.len(), 1);
        assert!(matches!(
            &retry[0],
            MkcpSegment::Ack {
                option: SEGMENT_OPTION_CLOSE,
                numbers,
                ..
            } if numbers == &vec![0, 1]
        ));

        state.process_sending_next(2);
        let cleared = state.flush_acks(19, 200, 100, false);
        assert_eq!(cleared.len(), 1);
        assert!(matches!(
            &cleared[0],
            MkcpSegment::Ack { numbers, .. } if numbers.is_empty()
        ));
    }
}
