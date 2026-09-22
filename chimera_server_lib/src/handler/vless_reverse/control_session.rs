// Batch D models the lifetime of Xray's internal Reverse control session.
// Batch E will provide the routing/runtime owner that actually opens this
// logical Mux session and writes the protobuf heartbeats.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use crate::address::{Address, NetLocation};

use super::{
    control::{ControlState, ReverseControl},
    mux_frame::{Destination, TargetNetwork},
    worker::MuxClientWorker,
};

pub(crate) const XRAY_REVERSE_CONTROL_DOMAIN: &str = "reverse";

pub(crate) fn xray_reverse_control_target() -> Destination {
    Destination {
        network: TargetNetwork::Udp,
        location: NetLocation::new(
            Address::Hostname(XRAY_REVERSE_CONTROL_DOMAIN.to_string()),
            0,
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlSessionPhase {
    Pending,
    Active,
    Draining,
    Closed,
}

#[derive(Debug)]
pub(crate) struct PortalControlSession {
    worker: Arc<MuxClientWorker>,
    phase: Mutex<ControlSessionPhase>,
}

impl PortalControlSession {
    pub(crate) fn new(worker: Arc<MuxClientWorker>) -> Self {
        Self {
            worker,
            phase: Mutex::new(ControlSessionPhase::Pending),
        }
    }

    pub(crate) fn phase(&self) -> ControlSessionPhase {
        *self
            .phase
            .lock()
            .expect("Reverse control session lock poisoned")
    }

    /// Record a control protobuf only after its write to the internal Mux
    /// session succeeded. This makes picker eligibility follow the control
    /// channel rather than physical-connection existence alone.
    pub(crate) fn on_control_sent(
        &self,
        control: &ReverseControl,
    ) -> std::io::Result<()> {
        let mut phase = self
            .phase
            .lock()
            .expect("Reverse control session lock poisoned");
        match (*phase, control.state) {
            (ControlSessionPhase::Closed, _) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Reverse control session is closed",
            )),
            (ControlSessionPhase::Draining, ControlState::Active) => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Reverse control session cannot return to ACTIVE after DRAIN",
                ))
            }
            (_, ControlState::Active) => {
                self.worker.control_session_became_active()?;
                *phase = ControlSessionPhase::Active;
                Ok(())
            }
            (_, ControlState::Drain) => {
                self.worker.begin_drain()?;
                *phase = ControlSessionPhase::Draining;
                Ok(())
            }
        }
    }

    pub(crate) fn close(&self) {
        let mut phase = self
            .phase
            .lock()
            .expect("Reverse control session lock poisoned");
        if *phase == ControlSessionPhase::Closed {
            return;
        }
        *phase = ControlSessionPhase::Closed;
        self.worker.close();
    }
}

impl Drop for PortalControlSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{io::duplex, time::timeout};

    use crate::handler::vless_reverse::{
        session_core::SessionLimits, session_stream::ReverseSessionStream,
        worker::MuxClientPicker,
    };

    use super::*;

    fn worker(id: u64) -> (Arc<MuxClientWorker>, tokio::io::DuplexStream) {
        let (physical, peer) = duplex(4096);
        (
            Arc::new(MuxClientWorker::new(
                id,
                Box::new(ReverseSessionStream::new(physical)),
                SessionLimits::default(),
            )),
            peer,
        )
    }

    #[test]
    fn control_target_matches_xray_internal_reverse_destination() {
        let target = xray_reverse_control_target();
        assert_eq!(target.network, TargetNetwork::Udp);
        assert_eq!(target.location.port(), 0);
        assert_eq!(
            target.location.address(),
            &Address::Hostname("reverse".to_string())
        );
    }

    #[tokio::test]
    async fn picker_eligibility_follows_control_session_state() {
        let (worker, _peer) = worker(1);
        let picker = MuxClientPicker::default();
        picker.add(worker.clone());
        let control = PortalControlSession::new(worker.clone());

        assert_eq!(control.phase(), ControlSessionPhase::Pending);
        assert!(
            picker.pick_available().is_err(),
            "physical Mux alone must not make worker selectable"
        );

        control
            .on_control_sent(&ReverseControl::active(Vec::new()))
            .expect("successful ACTIVE control write activates worker");
        assert_eq!(control.phase(), ControlSessionPhase::Active);
        assert_eq!(
            picker.pick_available().expect("ACTIVE worker").id(),
            worker.id()
        );

        control
            .on_control_sent(&ReverseControl::drain(Vec::new()))
            .expect("DRAIN control stops new work");
        assert_eq!(control.phase(), ControlSessionPhase::Draining);
        assert!(picker.pick_available().is_err());

        let error = control
            .on_control_sent(&ReverseControl::active(Vec::new()))
            .expect_err("DRAIN is one-way");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn control_session_close_closes_worker_and_wakes_waiters() {
        let (worker, _peer) = worker(2);
        let control = PortalControlSession::new(worker.clone());
        control
            .on_control_sent(&ReverseControl::active(Vec::new()))
            .expect("activate worker");

        control.close();
        assert_eq!(control.phase(), ControlSessionPhase::Closed);
        timeout(Duration::from_secs(1), worker.wait_closed())
            .await
            .expect("control close propagates to worker");
    }
}
