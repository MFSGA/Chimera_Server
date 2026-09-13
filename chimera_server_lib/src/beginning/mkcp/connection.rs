use crate::config::MkcpTransportConfig;

use super::{
    COMMAND_PING, COMMAND_TERMINATE, MkcpSegment, receiving::MkcpReceivingState,
    sending::MkcpSendingState,
};

const SEGMENT_OPTION_CLOSE: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MkcpConnectionPhase {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MkcpInputOutcome {
    pub(crate) data_available: bool,
    pub(crate) send_progress: bool,
}

#[derive(Debug)]
struct RoundTripInfo {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_timestamp: u32,
}

impl RoundTripInfo {
    fn new(min_rtt: u32) -> Self {
        Self {
            variation: 0,
            srtt: 0,
            rto: 100,
            min_rtt,
            updated_timestamp: 0,
        }
    }

    fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_timestamp) < 3000 {
            return;
        }
        self.updated_timestamp = current;
        self.rto = rto;
    }

    fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7fff_ffff {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            self.variation = (3 * self.variation + delta) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
            self.srtt = self.srtt.max(self.min_rtt);
        }

        let variation4 = self.variation.wrapping_mul(4);
        let rto = if self.min_rtt < variation4 {
            self.srtt.wrapping_add(variation4)
        } else {
            self.srtt.wrapping_add(self.variation)
        }
        .min(10_000);
        self.rto = rto.wrapping_mul(5) / 4;
        self.updated_timestamp = current;
    }

    fn timeout(&self) -> u32 {
        self.rto
    }
}

#[derive(Debug)]
pub(crate) struct MkcpConnectionState {
    conversation: u16,
    phase: MkcpConnectionPhase,
    state_begin_time: u32,
    last_incoming_time: u32,
    last_ping_time: u32,
    round_trip: RoundTripInfo,
    receiving: MkcpReceivingState,
    sending: MkcpSendingState,
}

impl MkcpConnectionState {
    pub(crate) fn new(conversation: u16, config: MkcpTransportConfig) -> Self {
        Self {
            conversation,
            phase: MkcpConnectionPhase::Active,
            state_begin_time: 0,
            last_incoming_time: 0,
            last_ping_time: 0,
            round_trip: RoundTripInfo::new(config.tti),
            receiving: MkcpReceivingState::new(config),
            sending: MkcpSendingState::new(config),
        }
    }

    pub(crate) fn phase(&self) -> MkcpConnectionPhase {
        self.phase
    }

    pub(crate) fn receiving_mut(&mut self) -> &mut MkcpReceivingState {
        &mut self.receiving
    }

    pub(crate) fn sending_mut(&mut self) -> &mut MkcpSendingState {
        &mut self.sending
    }

    pub(crate) fn drain_ordered_payloads(&mut self) -> Vec<Vec<u8>> {
        self.receiving.drain_ordered_payloads()
    }

    pub(crate) fn input(
        &mut self,
        current: u32,
        segments: Vec<MkcpSegment>,
    ) -> MkcpInputOutcome {
        self.last_incoming_time = current;
        let mut outcome = MkcpInputOutcome::default();

        for segment in segments {
            if segment.conversation() != self.conversation {
                break;
            }
            match segment {
                MkcpSegment::Data {
                    option,
                    timestamp,
                    number,
                    sending_next,
                    payload,
                    ..
                } => {
                    self.handle_option(option, current);
                    self.receiving.process_data(
                        timestamp,
                        number,
                        sending_next,
                        payload,
                    );
                    outcome.data_available |= self.receiving.is_data_available();
                }
                MkcpSegment::Ack {
                    option,
                    receiving_window,
                    receiving_next,
                    timestamp,
                    numbers,
                    ..
                } => {
                    self.handle_option(option, current);
                    let result = self.sending.process_ack(
                        current,
                        receiving_window,
                        receiving_next,
                        timestamp,
                        &numbers,
                        self.round_trip.timeout(),
                    );
                    if let Some(rtt) = result.rtt_sample {
                        self.round_trip.update(rtt, current);
                    }
                    // Xray signals dataOutput for every ACK segment, even when
                    // receivingNext cumulatively cleared the same packet first.
                    outcome.send_progress = true;
                }
                MkcpSegment::Command {
                    command,
                    option,
                    sending_next,
                    receiving_next,
                    peer_rto,
                    ..
                } => {
                    self.handle_option(option, current);
                    if command == COMMAND_TERMINATE {
                        match self.phase {
                            MkcpConnectionPhase::Active
                            | MkcpConnectionPhase::PeerClosed => self.set_phase(
                                MkcpConnectionPhase::PeerTerminating,
                                current,
                            ),
                            MkcpConnectionPhase::ReadyToClose => self.set_phase(
                                MkcpConnectionPhase::Terminating,
                                current,
                            ),
                            MkcpConnectionPhase::Terminating => self
                                .set_phase(MkcpConnectionPhase::Terminated, current),
                            _ => {}
                        }
                    }
                    self.sending.process_receiving_next(receiving_next);
                    self.receiving.process_sending_next(sending_next);
                    self.round_trip.update_peer_rto(peer_rto, current);
                }
            }
        }
        outcome
    }

    pub(crate) fn close(&mut self, current: u32) -> bool {
        match self.phase {
            MkcpConnectionPhase::ReadyToClose
            | MkcpConnectionPhase::Terminating
            | MkcpConnectionPhase::Terminated => false,
            MkcpConnectionPhase::Active => {
                self.set_phase(MkcpConnectionPhase::ReadyToClose, current);
                true
            }
            MkcpConnectionPhase::PeerClosed => {
                self.set_phase(MkcpConnectionPhase::Terminating, current);
                true
            }
            MkcpConnectionPhase::PeerTerminating => {
                self.set_phase(MkcpConnectionPhase::Terminated, current);
                true
            }
        }
    }

    pub(crate) fn flush(&mut self, current: u32) -> Vec<MkcpSegment> {
        if self.phase == MkcpConnectionPhase::Terminated {
            return Vec::new();
        }
        if self.phase == MkcpConnectionPhase::Active
            && current.wrapping_sub(self.last_incoming_time) >= 30_000
        {
            self.close(current);
        }
        if self.phase == MkcpConnectionPhase::ReadyToClose && self.sending.is_empty()
        {
            self.set_phase(MkcpConnectionPhase::Terminating, current);
        }
        if self.phase == MkcpConnectionPhase::Terminating {
            let output = vec![self.ping(current, COMMAND_TERMINATE)];
            if current.wrapping_sub(self.state_begin_time) > 8_000 {
                self.set_phase(MkcpConnectionPhase::Terminated, current);
            }
            return output;
        }
        if self.phase == MkcpConnectionPhase::PeerTerminating
            && current.wrapping_sub(self.state_begin_time) > 4_000
        {
            self.set_phase(MkcpConnectionPhase::Terminating, current);
        }
        if self.phase == MkcpConnectionPhase::ReadyToClose
            && current.wrapping_sub(self.state_begin_time) > 15_000
        {
            self.set_phase(MkcpConnectionPhase::Terminating, current);
        }

        let ready_to_close = self.phase == MkcpConnectionPhase::ReadyToClose;
        let mut output = self.receiving.flush_acks(
            self.conversation,
            current,
            self.round_trip.timeout(),
            ready_to_close,
        );
        output.extend(self.sending.flush(
            self.conversation,
            current,
            self.round_trip.timeout(),
            ready_to_close,
        ));
        if current.wrapping_sub(self.last_ping_time) >= 3_000 {
            output.push(self.ping(current, COMMAND_PING));
        }
        output
    }

    fn handle_option(&mut self, option: u8, current: u32) {
        if option & SEGMENT_OPTION_CLOSE != 0 {
            match self.phase {
                MkcpConnectionPhase::ReadyToClose => {
                    self.set_phase(MkcpConnectionPhase::Terminating, current)
                }
                MkcpConnectionPhase::Active => {
                    self.set_phase(MkcpConnectionPhase::PeerClosed, current)
                }
                _ => {}
            }
        }
    }

    fn set_phase(&mut self, phase: MkcpConnectionPhase, current: u32) {
        self.phase = phase;
        self.state_begin_time = current;
        if matches!(
            phase,
            MkcpConnectionPhase::PeerClosed
                | MkcpConnectionPhase::Terminating
                | MkcpConnectionPhase::PeerTerminating
        ) {
            self.sending.close_write();
        }
    }

    fn ping(&mut self, current: u32, command: u8) -> MkcpSegment {
        self.last_ping_time = current;
        MkcpSegment::Command {
            conversation: self.conversation,
            command,
            option: if self.phase == MkcpConnectionPhase::ReadyToClose {
                SEGMENT_OPTION_CLOSE
            } else {
                0
            },
            sending_next: self.sending.first_unacknowledged(),
            receiving_next: self.receiving.next_number(),
            peer_rto: self.round_trip.timeout(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_info_matches_xray_updates_and_peer_rto_throttle() {
        let mut info = RoundTripInfo::new(50);
        assert_eq!(info.timeout(), 100);
        info.update(100, 100);
        assert_eq!(info.timeout(), 375);
        info.update(50, 200);
        assert_eq!(info.timeout(), 366);
        info.update_peer_rto(777, 1000);
        assert_eq!(info.timeout(), 366);
        info.update_peer_rto(777, 3200);
        assert_eq!(info.timeout(), 777);
    }

    #[test]
    fn connection_input_combines_receive_send_ack_and_conversation_boundary() {
        let mut connection =
            MkcpConnectionState::new(7, MkcpTransportConfig::default());
        assert!(connection.sending_mut().push(b"server".to_vec()));
        assert_eq!(connection.flush(100).len(), 1);

        let outcome = connection.input(
            145,
            vec![
                MkcpSegment::Data {
                    conversation: 7,
                    option: 0,
                    timestamp: 20,
                    number: 0,
                    sending_next: 0,
                    payload: b"client".to_vec(),
                },
                MkcpSegment::Ack {
                    conversation: 7,
                    option: 0,
                    receiving_window: 32,
                    receiving_next: 1,
                    timestamp: 100,
                    numbers: vec![0],
                },
                MkcpSegment::Data {
                    conversation: 8,
                    option: 0,
                    timestamp: 21,
                    number: 1,
                    sending_next: 0,
                    payload: b"wrong-conv".to_vec(),
                },
            ],
        );
        assert_eq!(
            outcome,
            MkcpInputOutcome {
                data_available: true,
                send_progress: true,
            }
        );
        assert_eq!(
            connection.drain_ordered_payloads(),
            vec![b"client".to_vec()]
        );
        assert!(connection.sending.is_empty());
        assert_eq!(connection.round_trip.timeout(), 100);
    }

    #[test]
    fn connection_close_and_terminate_flush_match_xray_state_ordering() {
        let mut connection =
            MkcpConnectionState::new(11, MkcpTransportConfig::default());
        let ping = connection.flush(3_000);
        assert!(matches!(
            ping.as_slice(),
            [MkcpSegment::Command {
                command: COMMAND_PING,
                ..
            }]
        ));

        assert!(connection.close(3_001));
        let terminate = connection.flush(3_001);
        assert_eq!(connection.phase(), MkcpConnectionPhase::Terminating);
        assert!(matches!(
            terminate.as_slice(),
            [MkcpSegment::Command {
                command: COMMAND_TERMINATE,
                option: 0,
                ..
            }]
        ));

        let final_terminate = connection.flush(11_002);
        assert!(matches!(
            final_terminate.as_slice(),
            [MkcpSegment::Command {
                command: COMMAND_TERMINATE,
                ..
            }]
        ));
        assert_eq!(connection.phase(), MkcpConnectionPhase::Terminated);
        assert!(connection.flush(11_003).is_empty());
    }

    #[test]
    fn peer_close_and_terminate_follow_xray_transition_table() {
        let mut connection =
            MkcpConnectionState::new(13, MkcpTransportConfig::default());
        connection.input(
            10,
            vec![MkcpSegment::Command {
                conversation: 13,
                command: COMMAND_PING,
                option: SEGMENT_OPTION_CLOSE,
                sending_next: 0,
                receiving_next: 0,
                peer_rto: 100,
            }],
        );
        assert_eq!(connection.phase(), MkcpConnectionPhase::PeerClosed);

        connection.input(
            20,
            vec![MkcpSegment::Command {
                conversation: 13,
                command: COMMAND_TERMINATE,
                option: 0,
                sending_next: 0,
                receiving_next: 0,
                peer_rto: 100,
            }],
        );
        assert_eq!(connection.phase(), MkcpConnectionPhase::PeerTerminating);
        connection.flush(4_021);
        assert_eq!(connection.phase(), MkcpConnectionPhase::Terminating);
    }
}
