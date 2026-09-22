use std::sync::Mutex;

use super::{
    control::{ControlState, ReverseControl},
    control_session::xray_reverse_control_target,
    mux_frame::SessionStatus,
    mux_io::MuxFrame,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BridgeWorkerPhase {
    Active,
    Draining,
    Closed,
}

#[derive(Debug)]
struct State {
    phase: BridgeWorkerPhase,
    session_id: Option<u16>,
}

#[derive(Debug)]
pub(crate) struct BridgeControlState {
    state: Mutex<State>,
}

impl BridgeControlState {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                // Xray's BridgeWorker.State zero value is Control_ACTIVE.
                phase: BridgeWorkerPhase::Active,
                session_id: None,
            }),
        }
    }

    pub(crate) fn phase(&self) -> BridgeWorkerPhase {
        self.state
            .lock()
            .expect("Reverse Bridge control lock poisoned")
            .phase
    }

    pub(crate) fn is_active(&self) -> bool {
        self.phase() == BridgeWorkerPhase::Active
    }

    pub(crate) fn close(&self) {
        self.state
            .lock()
            .expect("Reverse Bridge control lock poisoned")
            .phase = BridgeWorkerPhase::Closed;
    }

    /// Consumes Xray's internal udp://reverse:0 control session frames.
    /// Returns true when the frame belongs to that internal session.
    pub(crate) fn handle_frame(&self, frame: &MuxFrame) -> std::io::Result<bool> {
        let session_id = frame.metadata.session_id;
        let is_new_control = frame.metadata.status == SessionStatus::New
            && frame.metadata.target.as_ref()
                == Some(&xray_reverse_control_target());

        let mut state = self
            .state
            .lock()
            .expect("Reverse Bridge control lock poisoned");

        if is_new_control {
            if state.session_id.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate VLESS Reverse control session",
                ));
            }
            state.session_id = Some(session_id);
        } else if state.session_id != Some(session_id) {
            return Ok(false);
        }

        if frame.metadata.status == SessionStatus::End {
            state.session_id = None;
            return Ok(true);
        }
        if !frame.metadata.option.has_data() {
            return Ok(true);
        }

        let control = ReverseControl::decode(&frame.payload)?;
        state.phase = match (state.phase, control.state) {
            (BridgeWorkerPhase::Closed, _) => BridgeWorkerPhase::Closed,
            (BridgeWorkerPhase::Draining, ControlState::Active) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VLESS Reverse Bridge cannot return to ACTIVE after DRAIN",
                ));
            }
            (_, ControlState::Active) => BridgeWorkerPhase::Active,
            (_, ControlState::Drain) => BridgeWorkerPhase::Draining,
        };
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::handler::vless_reverse::{
        control::ReverseControl,
        control_session::xray_reverse_control_target,
        mux_frame::{FrameMetadata, FrameOption, SessionStatus},
        mux_io::MuxFrame,
    };

    use super::*;

    fn control_frame(
        session_id: u16,
        status: SessionStatus,
        control: Option<ReverseControl>,
    ) -> MuxFrame {
        let payload = control
            .map(|control| Bytes::from(control.encode().unwrap()))
            .unwrap_or_default();
        MuxFrame {
            metadata: FrameMetadata {
                session_id,
                status,
                option: if payload.is_empty() {
                    FrameOption::default()
                } else {
                    FrameOption::default().with_data()
                },
                target: (status == SessionStatus::New)
                    .then(xray_reverse_control_target),
                source: None,
                local: None,
                global_id: None,
            },
            payload,
        }
    }

    #[test]
    fn active_drain_and_end_follow_xray_control_lifecycle() {
        let state = BridgeControlState::new();
        assert_eq!(state.phase(), BridgeWorkerPhase::Active);

        assert!(
            state
                .handle_frame(&control_frame(
                    7,
                    SessionStatus::New,
                    Some(ReverseControl::active(Vec::new())),
                ))
                .unwrap()
        );
        assert!(state.is_active());

        state
            .handle_frame(&control_frame(
                7,
                SessionStatus::Keep,
                Some(ReverseControl::drain(Vec::new())),
            ))
            .unwrap();
        assert_eq!(state.phase(), BridgeWorkerPhase::Draining);

        let error = state
            .handle_frame(&control_frame(
                7,
                SessionStatus::Keep,
                Some(ReverseControl::active(vec![0x01])),
            ))
            .expect_err("DRAIN must be one-way");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        state
            .handle_frame(&control_frame(7, SessionStatus::End, None))
            .unwrap();
        assert_eq!(state.phase(), BridgeWorkerPhase::Draining);
    }

    #[test]
    fn non_control_frame_is_not_consumed() {
        let state = BridgeControlState::new();
        let mut frame = control_frame(9, SessionStatus::New, None);
        frame.metadata.target = None;
        assert!(!state.handle_frame(&frame).unwrap());
    }
}
