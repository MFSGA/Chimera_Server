use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use rand::RngExt as _;
use tokio::time::{MissedTickBehavior, interval};

use crate::{
    address::{Address, NetLocation},
    async_stream::AsyncStream,
};

use super::{
    control::ReverseControl,
    control_session::{PortalControlSession, xray_reverse_control_target},
    mux_frame::{Destination, SessionStatus, TargetNetwork},
    session_core::SessionLimits,
    session_stream::ReverseSessionStream,
    worker::{MuxClientPicker, MuxClientWorker, ReversePacketSession},
};

const CONTROL_HEARTBEAT_TICK: Duration = Duration::from_secs(2);
const CONTROL_ACTIVE_EVERY_TICKS: u8 = 5;

#[derive(Debug)]
struct PortalEntry {
    picker: MuxClientPicker,
}

#[derive(Debug)]
pub(crate) struct ReversePortalRegistry {
    entries: Mutex<HashMap<String, Arc<PortalEntry>>>,
    next_worker_id: AtomicU64,
}

impl ReversePortalRegistry {
    pub(crate) fn new<I>(tags: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let entries = tags
            .into_iter()
            .map(|tag| {
                (
                    tag,
                    Arc::new(PortalEntry {
                        picker: MuxClientPicker::default(),
                    }),
                )
            })
            .collect();
        Self {
            entries: Mutex::new(entries),
            next_worker_id: AtomicU64::new(1),
        }
    }

    pub(crate) fn ensure_tag(&self, tag: &str) {
        self.entries
            .lock()
            .expect("Reverse portal registry lock poisoned")
            .entry(tag.to_string())
            .or_insert_with(|| {
                Arc::new(PortalEntry {
                    picker: MuxClientPicker::default(),
                })
            });
    }

    pub(crate) fn remove_tag(&self, tag: &str) -> bool {
        self.entries
            .lock()
            .expect("Reverse portal registry lock poisoned")
            .remove(tag)
            .is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_tag(&self, tag: &str) -> bool {
        self.entries
            .lock()
            .expect("Reverse portal registry lock poisoned")
            .contains_key(tag)
    }

    pub(crate) async fn attach_physical(
        &self,
        tag: &str,
        physical: Box<dyn AsyncStream>,
    ) -> std::io::Result<PortalWorkerLease> {
        let entry = self
            .entries
            .lock()
            .expect("Reverse portal registry lock poisoned")
            .get(tag)
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("VLESS Reverse portal tag {tag} is not configured"),
                )
            })?;

        let worker_id = self.next_worker_id.fetch_add(1, Ordering::Relaxed);
        let worker = Arc::new(MuxClientWorker::new(
            worker_id,
            physical,
            SessionLimits::default(),
        ));
        let control_session_id = worker.allocate_internal_session()?;
        let control = Arc::new(PortalControlSession::new(worker.clone()));

        let active = ReverseControl::active(random_control_padding());
        if let Err(error) = send_control_packet(
            &worker,
            control_session_id,
            SessionStatus::New,
            &active,
        )
        .await
        {
            worker.release_internal_session(control_session_id);
            worker.close();
            return Err(error);
        }
        control.on_control_sent(&active)?;
        entry.picker.add(worker.clone());

        Ok(PortalWorkerLease {
            worker,
            control,
            control_session_id: Some(control_session_id),
        })
    }

    pub(crate) fn open_udp(
        &self,
        tag: &str,
        target: NetLocation,
        source: SocketAddr,
        local: Option<SocketAddr>,
    ) -> std::io::Result<ReversePacketSession> {
        let entry = self
            .entries
            .lock()
            .expect("Reverse portal registry lock poisoned")
            .get(tag)
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("VLESS Reverse portal tag {tag} is not configured"),
                )
            })?;
        let worker = entry.picker.pick_available()?;
        worker.open_packet_session(
            Destination {
                network: TargetNetwork::Udp,
                location: target,
            },
            Some(udp_socket_destination(source)),
            local.map(udp_socket_destination),
        )
    }

    pub(crate) fn open_tcp(
        &self,
        tag: &str,
        target: NetLocation,
        source: SocketAddr,
        local: Option<SocketAddr>,
    ) -> std::io::Result<ReverseSessionStream> {
        let entry = self
            .entries
            .lock()
            .expect("Reverse portal registry lock poisoned")
            .get(tag)
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("VLESS Reverse portal tag {tag} is not configured"),
                )
            })?;
        let worker = entry.picker.pick_available()?;
        worker.open_tcp_session(
            Destination {
                network: TargetNetwork::Tcp,
                location: target,
            },
            Some(socket_destination(source)),
            local.map(socket_destination),
        )
    }
}

pub(crate) struct PortalWorkerLease {
    worker: Arc<MuxClientWorker>,
    control: Arc<PortalControlSession>,
    control_session_id: Option<u16>,
}

impl std::fmt::Debug for PortalWorkerLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PortalWorkerLease")
            .field("worker_id", &self.worker.id())
            .field("worker_phase", &self.worker.phase())
            .field("control_session_id", &self.control_session_id)
            .finish()
    }
}

impl PortalWorkerLease {
    pub(crate) fn worker_id(&self) -> u64 {
        self.worker.id()
    }

    pub(crate) async fn run(mut self) -> std::io::Result<()> {
        let mut ticks = interval(CONTROL_HEARTBEAT_TICK);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The initial ACTIVE packet was sent during attach.
        ticks.tick().await;
        let mut counter = 0u8;

        loop {
            tokio::select! {
                biased;
                _ = self.worker.wait_closed() => return Ok(()),
                _ = ticks.tick() => {}
            }

            if self.worker.should_begin_drain() {
                let drain = ReverseControl::drain(random_control_padding());
                self.send_control(SessionStatus::Keep, &drain).await?;
                self.control.on_control_sent(&drain)?;
                self.end_control_session().await?;
                while self.worker.active_connections() != 0 {
                    tokio::select! {
                        biased;
                        _ = self.worker.wait_closed() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                    }
                }
                self.worker.close();
                return Ok(());
            }

            counter = counter.wrapping_add(1) % CONTROL_ACTIVE_EVERY_TICKS;
            if counter == 0 {
                let active = ReverseControl::active(random_control_padding());
                self.send_control(SessionStatus::Keep, &active).await?;
                self.control.on_control_sent(&active)?;
            }
        }
    }

    async fn send_control(
        &self,
        status: SessionStatus,
        control: &ReverseControl,
    ) -> std::io::Result<()> {
        let session_id = self.control_session_id.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Reverse control session is already closed",
            )
        })?;
        send_control_packet(&self.worker, session_id, status, control).await
    }

    async fn end_control_session(&mut self) -> std::io::Result<()> {
        let Some(session_id) = self.control_session_id.take() else {
            return Ok(());
        };
        let result = self.worker.end_internal_session(session_id).await;
        self.worker.release_internal_session(session_id);
        result
    }
}

impl Drop for PortalWorkerLease {
    fn drop(&mut self) {
        if let Some(session_id) = self.control_session_id.take() {
            self.worker.release_internal_session(session_id);
        }
    }
}

async fn send_control_packet(
    worker: &MuxClientWorker,
    session_id: u16,
    status: SessionStatus,
    control: &ReverseControl,
) -> std::io::Result<()> {
    let payload = Bytes::from(control.encode()?);
    let target = match status {
        SessionStatus::New | SessionStatus::Keep => {
            Some(xray_reverse_control_target())
        }
        SessionStatus::End | SessionStatus::KeepAlive => None,
    };
    worker
        .send_internal_packet(session_id, status, target, payload)
        .await
}

fn random_control_padding() -> Vec<u8> {
    let mut rng = rand::rng();
    let length = rng.random_range(1..=64);
    let mut random = vec![0u8; length];
    rng.fill(&mut random[..]);
    random
}

fn socket_destination(address: SocketAddr) -> Destination {
    socket_destination_with_network(address, TargetNetwork::Tcp)
}

fn udp_socket_destination(address: SocketAddr) -> Destination {
    socket_destination_with_network(address, TargetNetwork::Udp)
}

fn socket_destination_with_network(
    address: SocketAddr,
    network: TargetNetwork,
) -> Destination {
    let net_location = match address {
        SocketAddr::V4(address) => {
            NetLocation::new(Address::Ipv4(*address.ip()), address.port())
        }
        SocketAddr::V6(address) => {
            NetLocation::new(Address::Ipv6(*address.ip()), address.port())
        }
    };
    Destination {
        network,
        location: net_location,
    }
}

#[cfg(test)]
#[path = "portal_tests.rs"]
mod tests;
