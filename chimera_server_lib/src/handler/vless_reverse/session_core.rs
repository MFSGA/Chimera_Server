// Batch D lands the Reverse Mux state core before Batch E connects it to the
// public Portal routing/runtime owner.
#![allow(dead_code)]

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use super::control::ControlState;

const XRAY_PORTAL_DRAIN_AFTER_TOTAL_CONNECTIONS: u32 = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionLimits {
    pub(crate) max_concurrency: usize,
    pub(crate) max_connections: u32,
}

#[derive(Debug)]
struct SessionManagerState {
    active: HashSet<u16>,
    next_id: u16,
    total_connections: u32,
    closed: bool,
}

#[derive(Debug)]
pub(crate) struct SessionManager {
    limits: SessionLimits,
    state: Mutex<SessionManagerState>,
}

impl SessionManager {
    pub(crate) fn new(limits: SessionLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(SessionManagerState {
                active: HashSet::new(),
                next_id: 1,
                total_connections: 0,
                closed: false,
            }),
        }
    }

    pub(crate) fn allocate(&self) -> std::io::Result<u16> {
        let mut state = self.state.lock().expect("Reverse session lock poisoned");
        if state.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Reverse Mux session manager is closed",
            ));
        }
        if self.limits.max_concurrency > 0
            && state.active.len() >= self.limits.max_concurrency
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Reverse Mux worker reached its concurrency limit",
            ));
        }
        if self.limits.max_connections > 0
            && state.total_connections >= self.limits.max_connections
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Reverse Mux worker reached its total connection limit",
            ));
        }

        let start = state.next_id;
        loop {
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            if state.next_id == 0 {
                state.next_id = 1;
            }
            if id != 0 && !state.active.contains(&id) {
                state.active.insert(id);
                state.total_connections =
                    state.total_connections.checked_add(1).ok_or_else(|| {
                        std::io::Error::other(
                            "Reverse Mux total connection counter overflow",
                        )
                    })?;
                return Ok(id);
            }
            if state.next_id == start {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Reverse Mux has no free session IDs",
                ));
            }
        }
    }

    pub(crate) fn release(&self, session_id: u16) -> bool {
        self.state
            .lock()
            .expect("Reverse session lock poisoned")
            .active
            .remove(&session_id)
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock().expect("Reverse session lock poisoned");
        state.closed = true;
        state.active.clear();
    }

    pub(crate) fn active_count(&self) -> usize {
        self.state
            .lock()
            .expect("Reverse session lock poisoned")
            .active
            .len()
    }

    pub(crate) fn total_connections(&self) -> u32 {
        self.state
            .lock()
            .expect("Reverse session lock poisoned")
            .total_connections
    }

    pub(crate) fn is_full(&self) -> bool {
        let state = self.state.lock().expect("Reverse session lock poisoned");
        state.closed
            || (self.limits.max_concurrency > 0
                && state.active.len() >= self.limits.max_concurrency)
            || (self.limits.max_connections > 0
                && state.total_connections >= self.limits.max_connections)
    }

    pub(crate) fn should_drain_like_xray_portal(&self) -> bool {
        self.total_connections() > XRAY_PORTAL_DRAIN_AFTER_TOTAL_CONNECTIONS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerPhase {
    Pending,
    Active,
    Draining,
    Closed,
}

#[derive(Debug)]
pub(crate) struct WorkerCore {
    id: u64,
    phase: Mutex<WorkerPhase>,
    sessions: SessionManager,
}

impl WorkerCore {
    pub(crate) fn new(id: u64, limits: SessionLimits) -> Self {
        Self {
            id,
            phase: Mutex::new(WorkerPhase::Pending),
            sessions: SessionManager::new(limits),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn phase(&self) -> WorkerPhase {
        *self.phase.lock().expect("Reverse worker lock poisoned")
    }

    pub(crate) fn apply_control_state(
        &self,
        state: ControlState,
    ) -> std::io::Result<()> {
        let mut phase = self.phase.lock().expect("Reverse worker lock poisoned");
        match (*phase, state) {
            (WorkerPhase::Closed, _) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Reverse Mux worker is closed",
            )),
            (WorkerPhase::Draining, ControlState::Active) => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Reverse Mux worker cannot return to ACTIVE after DRAIN",
                ))
            }
            (_, ControlState::Active) => {
                *phase = WorkerPhase::Active;
                Ok(())
            }
            (_, ControlState::Drain) => {
                *phase = WorkerPhase::Draining;
                Ok(())
            }
        }
    }

    pub(crate) fn close(&self) {
        *self.phase.lock().expect("Reverse worker lock poisoned") =
            WorkerPhase::Closed;
        self.sessions.close();
    }

    pub(crate) fn allocate_session(&self) -> std::io::Result<u16> {
        if self.phase() != WorkerPhase::Active {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Reverse Mux worker is not ACTIVE",
            ));
        }
        self.sessions.allocate()
    }

    pub(crate) fn allocate_internal_session(&self) -> std::io::Result<u16> {
        if self.phase() == WorkerPhase::Closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Reverse Mux worker is closed",
            ));
        }
        self.sessions.allocate()
    }

    pub(crate) fn release_session(&self, session_id: u16) -> bool {
        self.sessions.release(session_id)
    }

    pub(crate) fn active_connections(&self) -> usize {
        self.sessions.active_count()
    }

    pub(crate) fn total_connections(&self) -> u32 {
        self.sessions.total_connections()
    }

    pub(crate) fn is_selectable(&self) -> bool {
        self.phase() == WorkerPhase::Active && !self.sessions.is_full()
    }

    pub(crate) fn should_begin_drain(&self) -> bool {
        self.sessions.should_drain_like_xray_portal()
    }
}

#[derive(Debug, Default)]
pub(crate) struct WorkerPicker {
    workers: Mutex<Vec<Arc<WorkerCore>>>,
}

impl WorkerPicker {
    pub(crate) fn add(&self, worker: Arc<WorkerCore>) {
        self.workers
            .lock()
            .expect("Reverse picker lock poisoned")
            .push(worker);
    }

    pub(crate) fn pick_available(&self) -> std::io::Result<Arc<WorkerCore>> {
        let mut workers = self.workers.lock().expect("Reverse picker lock poisoned");
        workers.retain(|worker| worker.phase() != WorkerPhase::Closed);

        workers
            .iter()
            .filter(|worker| worker.is_selectable())
            .min_by_key(|worker| worker.active_connections())
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "no ACTIVE Reverse Mux worker available",
                )
            })
    }

    pub(crate) fn len(&self) -> usize {
        self.workers
            .lock()
            .expect("Reverse picker lock poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_manager_enforces_concurrency_and_reuses_released_capacity() {
        let manager = SessionManager::new(SessionLimits {
            max_concurrency: 2,
            max_connections: 0,
        });
        let first = manager.allocate().expect("allocate first session");
        let second = manager.allocate().expect("allocate second session");
        assert_ne!(first, second);

        let error = manager
            .allocate()
            .expect_err("third concurrent session must backpressure");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        assert!(manager.release(first));
        manager
            .allocate()
            .expect("released concurrency capacity is reusable");
        assert_eq!(manager.active_count(), 2);
        assert_eq!(manager.total_connections(), 3);
    }

    #[test]
    fn session_manager_enforces_total_connection_limit() {
        let manager = SessionManager::new(SessionLimits {
            max_concurrency: 0,
            max_connections: 2,
        });
        let first = manager.allocate().expect("allocate first");
        assert!(manager.release(first));
        let second = manager.allocate().expect("allocate second");
        assert!(manager.release(second));

        let error = manager
            .allocate()
            .expect_err("total connection limit must close allocation");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(manager.total_connections(), 2);
    }

    #[test]
    fn worker_requires_active_control_and_drain_is_one_way() {
        let worker = WorkerCore::new(1, SessionLimits::default());
        assert_eq!(worker.phase(), WorkerPhase::Pending);
        assert!(!worker.is_selectable());
        assert_eq!(
            worker
                .allocate_session()
                .expect_err("pending worker must reject sessions")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );

        worker
            .apply_control_state(ControlState::Active)
            .expect("control session activates worker");
        let session = worker
            .allocate_session()
            .expect("ACTIVE worker accepts a session");
        assert_eq!(worker.active_connections(), 1);

        worker
            .apply_control_state(ControlState::Drain)
            .expect("control session drains worker");
        assert!(!worker.is_selectable());
        assert_eq!(worker.active_connections(), 1);
        assert!(worker.release_session(session));

        let error = worker
            .apply_control_state(ControlState::Active)
            .expect_err("DRAIN worker must never return to ACTIVE");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn picker_uses_least_loaded_active_worker_only() {
        let picker = WorkerPicker::default();
        let pending = Arc::new(WorkerCore::new(1, SessionLimits::default()));
        let busy = Arc::new(WorkerCore::new(2, SessionLimits::default()));
        let idle = Arc::new(WorkerCore::new(3, SessionLimits::default()));
        picker.add(pending);
        picker.add(busy.clone());
        picker.add(idle.clone());

        busy.apply_control_state(ControlState::Active)
            .expect("activate busy worker");
        idle.apply_control_state(ControlState::Active)
            .expect("activate idle worker");
        busy.allocate_session().expect("make worker busier");

        assert_eq!(
            picker.pick_available().expect("pick active worker").id(),
            idle.id()
        );

        idle.apply_control_state(ControlState::Drain)
            .expect("drain idle worker");
        assert_eq!(
            picker
                .pick_available()
                .expect("fallback to busy ACTIVE worker")
                .id(),
            busy.id()
        );

        busy.close();
        let error = picker
            .pick_available()
            .expect_err("pending/draining/closed workers are not selectable");
        assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
        assert_eq!(picker.len(), 2);
    }

    #[test]
    fn xray_portal_drain_threshold_is_after_256_total_connections() {
        let worker = WorkerCore::new(7, SessionLimits::default());
        worker
            .apply_control_state(ControlState::Active)
            .expect("activate worker");

        for _ in 0..256 {
            let id = worker.allocate_session().expect("allocate session");
            assert!(worker.release_session(id));
        }
        assert!(!worker.should_begin_drain());

        let id = worker.allocate_session().expect("257th session");
        assert!(worker.release_session(id));
        assert!(worker.should_begin_drain());
    }

    #[test]
    fn close_propagates_to_allocator_and_picker_cleanup() {
        let picker = WorkerPicker::default();
        let worker = Arc::new(WorkerCore::new(9, SessionLimits::default()));
        worker
            .apply_control_state(ControlState::Active)
            .expect("activate worker");
        picker.add(worker.clone());
        assert!(picker.pick_available().is_ok());

        worker.close();
        assert_eq!(worker.phase(), WorkerPhase::Closed);
        let error = worker
            .allocate_session()
            .expect_err("closed worker must reject new sessions");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        assert!(picker.pick_available().is_err());
        assert_eq!(picker.len(), 0);
    }
}
