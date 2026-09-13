use std::collections::VecDeque;

use crate::config::MkcpTransportConfig;

use super::MkcpSegment;

const SEGMENT_OPTION_CLOSE: u8 = 1;
const INITIAL_REMOTE_NEXT_NUMBER: u32 = 32;
const MIN_CONTROL_WINDOW: u32 = 16;

#[derive(Debug, Clone)]
struct PendingData {
    number: u32,
    payload: Vec<u8>,
    timestamp: u32,
    timeout: u32,
    transmit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct MkcpAckProcessResult {
    pub(crate) acknowledged: usize,
    pub(crate) rtt_sample: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct MkcpSendingState {
    window: VecDeque<PendingData>,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    sending_in_flight_size: u32,
    window_size: u32,
    cwnd_multiplier: u32,
    total_in_flight_size: u32,
    closed: bool,
}

impl MkcpSendingState {
    pub(crate) fn new(config: MkcpTransportConfig) -> Self {
        let sending_in_flight_size = sending_in_flight_size(config);
        Self {
            window: VecDeque::new(),
            first_unacknowledged: 0,
            next_number: 0,
            remote_next_number: INITIAL_REMOTE_NEXT_NUMBER,
            control_window: sending_in_flight_size,
            sending_in_flight_size,
            window_size: sending_buffer_size(config),
            cwnd_multiplier: config.cwnd_multiplier,
            total_in_flight_size: 0,
            closed: false,
        }
    }

    pub(crate) fn push(&mut self, payload: Vec<u8>) -> bool {
        if self.closed || self.window.len() as u32 > self.window_size {
            return false;
        }

        self.window.push_back(PendingData {
            number: self.next_number,
            payload,
            timestamp: 0,
            timeout: 0,
            transmit: 0,
        });
        self.next_number = self.next_number.wrapping_add(1);
        true
    }

    pub(crate) fn process_receiving_next(&mut self, next_number: u32) {
        while self
            .window
            .front()
            .is_some_and(|segment| segment.number < next_number)
        {
            self.remove_front();
        }
        self.find_first_unacknowledged();
    }

    pub(crate) fn process_ack(
        &mut self,
        current: u32,
        receiving_window: u32,
        receiving_next: u32,
        timestamp: u32,
        numbers: &[u32],
        rto: u32,
    ) -> MkcpAckProcessResult {
        if self.closed {
            return MkcpAckProcessResult::default();
        }

        if self.remote_next_number < receiving_window {
            self.remote_next_number = receiving_window;
        }
        self.process_receiving_next(receiving_next);
        if numbers.is_empty() {
            return MkcpAckProcessResult::default();
        }

        let mut max_ack = 0;
        let mut max_ack_removed = false;
        let mut acknowledged = 0;
        for &number in numbers {
            let removed = self.process_ack_number(number);
            acknowledged += usize::from(removed);
            if max_ack < number {
                max_ack = number;
                max_ack_removed = removed;
            }
        }

        if !max_ack_removed {
            return MkcpAckProcessResult {
                acknowledged,
                rtt_sample: None,
            };
        }

        self.handle_fast_ack(max_ack, rto);
        let sample = current.wrapping_sub(timestamp);
        MkcpAckProcessResult {
            acknowledged,
            rtt_sample: (sample < 10_000).then_some(sample),
        }
    }

    pub(crate) fn flush(
        &mut self,
        conversation: u16,
        current: u32,
        rto: u32,
        ready_to_close: bool,
    ) -> Vec<MkcpSegment> {
        if self.closed || self.window.is_empty() {
            return Vec::new();
        }

        let mut congestion_window = self.sending_in_flight_size;
        let remote_window = self
            .remote_next_number
            .wrapping_sub(self.first_unacknowledged);
        if congestion_window > remote_window {
            congestion_window = remote_window;
        }
        if congestion_window > self.control_window {
            congestion_window = self.control_window;
        }
        congestion_window = congestion_window.wrapping_mul(self.cwnd_multiplier);

        let first_unacknowledged = self.first_unacknowledged;
        let mut output = Vec::new();
        let mut lost = 0u32;
        let mut in_flight = 0u32;

        for segment in &mut self.window {
            if current.wrapping_sub(segment.timeout) >= 0x7fff_ffff {
                continue;
            }
            if segment.transmit == 0 {
                self.total_in_flight_size =
                    self.total_in_flight_size.wrapping_add(1);
            } else {
                lost = lost.wrapping_add(1);
            }

            segment.timeout = current.wrapping_add(rto);
            segment.timestamp = current;
            segment.transmit = segment.transmit.wrapping_add(1);
            output.push(MkcpSegment::Data {
                conversation,
                option: if ready_to_close {
                    SEGMENT_OPTION_CLOSE
                } else {
                    0
                },
                timestamp: current,
                number: segment.number,
                sending_next: first_unacknowledged,
                payload: segment.payload.clone(),
            });
            in_flight = in_flight.wrapping_add(1);
            if in_flight >= congestion_window {
                break;
            }
        }

        if in_flight > 0 && self.total_in_flight_size != 0 {
            let loss_rate = lost.wrapping_mul(100) / self.total_in_flight_size;
            self.on_packet_loss(loss_rate, rto);
        }
        output
    }

    pub(crate) fn close_write(&mut self) {
        self.process_receiving_next(u32::MAX);
    }

    pub(crate) fn release(&mut self) {
        self.window.clear();
        self.total_in_flight_size = 0;
        self.closed = true;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    pub(crate) fn first_unacknowledged(&self) -> u32 {
        self.first_unacknowledged
    }

    fn process_ack_number(&mut self, number: u32) -> bool {
        if number.wrapping_sub(self.first_unacknowledged) > 0x7fff_ffff
            || number.wrapping_sub(self.next_number) < 0x7fff_ffff
        {
            return false;
        }

        let Some(position) = self.window.iter().position(|segment| {
            if segment.number > number {
                return false;
            }
            segment.number == number
        }) else {
            return false;
        };

        self.window.remove(position);
        if self.total_in_flight_size > 0 {
            self.total_in_flight_size -= 1;
        }
        self.find_first_unacknowledged();
        true
    }

    fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        for segment in &mut self.window {
            if number == segment.number
                || number.wrapping_sub(segment.number) > 0x7fff_ffff
            {
                break;
            }
            let acceleration = rto / 3;
            if segment.transmit > 0 && segment.timeout > acceleration {
                segment.timeout -= acceleration;
            }
        }
    }

    fn find_first_unacknowledged(&mut self) {
        self.first_unacknowledged = self
            .window
            .front()
            .map_or(self.next_number, |segment| segment.number);
    }

    fn remove_front(&mut self) {
        if self.window.pop_front().is_some() && self.total_in_flight_size > 0 {
            self.total_in_flight_size -= 1;
        }
    }

    fn on_packet_loss(&mut self, loss_rate: u32, rto: u32) {
        if rto == 0 {
            return;
        }
        if loss_rate >= 15 {
            self.control_window = 3 * self.control_window / 4;
        }
        if loss_rate <= 5 {
            self.control_window += self.control_window / 4;
        }
        if self.control_window < MIN_CONTROL_WINDOW {
            self.control_window = MIN_CONTROL_WINDOW;
        }
        if self.control_window > self.sending_in_flight_size {
            self.control_window = self.sending_in_flight_size;
        }
    }
}

fn sending_in_flight_size(config: MkcpTransportConfig) -> u32 {
    let intervals_per_second = (1000 / config.tti.max(1)).max(1);
    config
        .uplink_capacity
        .wrapping_mul(1024)
        .wrapping_mul(1024)
        .checked_div(config.mtu.max(1))
        .unwrap_or_default()
        .checked_div(intervals_per_second)
        .unwrap_or_default()
        .max(8)
}

fn sending_buffer_size(config: MkcpTransportConfig) -> u32 {
    config.max_sending_window / config.mtu.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MkcpTransportConfig {
        MkcpTransportConfig::default()
    }

    #[test]
    fn sending_window_matches_xray_capacity_and_first_flush() {
        let mut state = MkcpSendingState::new(config());
        assert_eq!(state.sending_in_flight_size, 194);
        assert_eq!(state.window_size, 1553);
        assert_eq!(state.first_unacknowledged(), 0);

        assert!(state.push(b"zero".to_vec()));
        assert!(state.push(b"one".to_vec()));
        let output = state.flush(7, 100, 100, false);
        assert_eq!(output.len(), 2);
        assert!(matches!(
            &output[0],
            MkcpSegment::Data {
                conversation: 7,
                option: 0,
                timestamp: 100,
                number: 0,
                sending_next: 0,
                payload,
            } if payload == b"zero"
        ));
        assert!(matches!(&output[1], MkcpSegment::Data { number: 1, .. }));
        assert_eq!(state.total_in_flight_size, 2);
    }

    #[test]
    fn ack_processing_clears_window_updates_remote_window_and_samples_rtt() {
        let mut state = MkcpSendingState::new(config());
        for payload in [b"zero".as_slice(), b"one", b"two"] {
            assert!(state.push(payload.to_vec()));
        }
        assert_eq!(state.flush(9, 100, 90, false).len(), 3);

        let result = state.process_ack(145, 80, 1, 100, &[1], 90);
        assert_eq!(result.acknowledged, 1);
        assert_eq!(result.rtt_sample, Some(45));
        assert_eq!(state.remote_next_number, 80);
        assert_eq!(state.first_unacknowledged(), 2);
        assert_eq!(state.window.len(), 1);
        assert_eq!(state.window[0].number, 2);

        let invalid = state.process_ack(150, 80, 2, 100, &[3], 90);
        assert_eq!(invalid, MkcpAckProcessResult::default());
        assert_eq!(state.first_unacknowledged(), 2);
    }

    #[test]
    fn retransmission_fast_ack_and_cwnd_multiplier_match_xray() {
        let mut state = MkcpSendingState::new(MkcpTransportConfig {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 1,
            cwnd_multiplier: 2,
            ..config()
        });
        for index in 0..10 {
            assert!(state.push(vec![index]));
        }

        let first = state.flush(5, 100, 90, false);
        assert_eq!(first.len(), 10);
        assert!(state.flush(5, 150, 90, false).is_empty());

        let result = state.process_ack(160, 32, 0, 100, &[4], 90);
        assert_eq!(result.acknowledged, 1);
        assert_eq!(result.rtt_sample, Some(60));
        assert_eq!(state.window[0].timeout, 160);
        let retransmit = state.flush(5, 161, 90, true);
        assert!(
            retransmit.iter().any(|segment| matches!(
                segment,
                MkcpSegment::Data {
                    number: 0,
                    option: SEGMENT_OPTION_CLOSE,
                    ..
                }
            )),
            "retransmit={retransmit:?}"
        );
    }

    #[test]
    fn buffer_limit_and_close_follow_xray_edges() {
        let mut state = MkcpSendingState::new(MkcpTransportConfig {
            mtu: 100,
            max_sending_window: 100,
            ..config()
        });
        assert_eq!(state.window_size, 1);
        assert!(state.push(vec![0]));
        assert!(
            state.push(vec![1]),
            "Xray accepts one entry past windowSize"
        );
        assert!(!state.push(vec![2]));

        state.close_write();
        assert!(state.is_empty());
        assert_eq!(state.first_unacknowledged(), 2);
        state.release();
        assert!(!state.push(vec![3]));
    }
}
