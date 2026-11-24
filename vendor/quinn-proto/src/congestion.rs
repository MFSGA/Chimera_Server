//! Logic for controlling the rate at which data is sent

use crate::connection::RttEstimator;
use crate::Instant;
use std::any::Any;
use std::sync::Arc;

mod bbr;
mod cubic;
mod new_reno;

pub use bbr::{Bbr, BbrConfig};
pub use cubic::{Cubic, CubicConfig};
pub use new_reno::{NewReno, NewRenoConfig};

/// Common interface for different congestion controllers
pub trait Controller: Send + Sync {
    /// One congestion-controlled packet was just sent.
    #[allow(unused_variables)]
    fn on_packet_sent(
        &mut self,
        now: Instant,
        space: crate::SpaceId,
        packet_number: u64,
        bytes: u64,
        bytes_in_flight: u64,
        app_limited: bool,
        ack_eliciting: bool,
    ) {
    }

    /// The controller was cloned for a newly established network path.
    ///
    /// Implementations may clear path-local sampling state while retaining congestion estimates.
    fn on_path_migration(&mut self) {}

    /// A packet's send-time state is no longer needed.
    #[allow(unused_variables)]
    fn on_packet_discarded(&mut self, space: crate::SpaceId, packet_number: u64) {}

    /// A packet-number space was discarded with its keys.
    #[allow(unused_variables)]
    fn on_space_discarded(&mut self, space: crate::SpaceId) {}

    /// One or more packets were just sent
    #[allow(unused_variables)]
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {}

    /// Packet deliveries were confirmed
    ///
    /// `app_limited` indicates whether the connection was blocked on outgoing
    /// application data prior to receiving these acknowledgements.
    #[allow(unused_variables)]
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
    }

    /// Packet deliveries were confirmed with a packet number identifying their send-time state.
    ///
    /// The default preserves existing controller implementations by forwarding to [`Self::on_ack`].
    #[allow(unused_variables)]
    fn on_ack_with_packet_state(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        space: crate::SpaceId,
        packet_number: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.on_ack(now, sent, bytes, app_limited, rtt);
    }

    /// Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has completed.
    #[allow(unused_variables)]
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
    }

    /// Packet deliveries were confirmed as one batch, including the bytes in flight immediately
    /// before and after processing that batch.
    ///
    /// The default preserves controllers that only implement [`Self::on_end_acks`].
    #[allow(unused_variables)]
    fn on_ack_batch(
        &mut self,
        now: Instant,
        prior_in_flight: u64,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    /// Packets were deemed lost or marked congested
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    /// `lost_bytes` indicates how many bytes were lost. This value will be 0 for ECN triggers.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    );

    /// The known MTU for the current network path has been updated
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Optional sender pacing rate in bytes per second, independent of the
    /// congestion window. Defaults to the existing cwnd/RTT-based pacer for
    /// congestion controllers that do not require a fixed target rate.
    fn pacing_rate_override(&self) -> Option<u64> {
        None
    }

    /// Retrieve implementation-specific metrics used to populate `qlog` traces when they are enabled
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
            bbr_bandwidth_bytes_per_second: None,
            bbr_mode: None,
            bbr_round_count: None,
            bbr_app_limited: None,
        }
    }

    /// Duplicate the controller's state
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Initial congestion window
    fn initial_window(&self) -> u64;

    /// Returns Self for use in down-casting to extract implementation details
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Common congestion controller metrics
#[derive(Default)]
#[non_exhaustive]
pub struct ControllerMetrics {
    /// Congestion window (bytes)
    pub congestion_window: u64,
    /// Slow start threshold (bytes)
    pub ssthresh: Option<u64>,
    /// Pacing rate (bits/s)
    pub pacing_rate: Option<u64>,
    /// BBR's current maximum bandwidth estimate (bytes/s), when available.
    pub bbr_bandwidth_bytes_per_second: Option<u64>,
    /// BBR's current operating mode, when available.
    pub bbr_mode: Option<&'static str>,
    /// BBR's completed round-trip count, when available.
    pub bbr_round_count: Option<u64>,
    /// Whether the most recent BBR ACK sample was marked application-limited, when available.
    pub bbr_app_limited: Option<bool>,
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16)
        -> Box<dyn Controller>;
}

const BASE_DATAGRAM_SIZE: u64 = 1200;
