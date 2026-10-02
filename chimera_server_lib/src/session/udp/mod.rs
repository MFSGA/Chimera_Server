use std::{
    collections::HashMap, future::poll_fn, net::SocketAddr, pin::Pin, sync::Arc,
    time::Duration,
};

use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::{Instant, sleep},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, warn};

#[cfg(feature = "trojan")]
use crate::outbound::connect_trojan_udp_via_outbound;

use crate::{
    address::NetLocation,
    async_stream::{
        AsyncMessageStream, AsyncSessionMessageStream, AsyncTargetedMessageStream,
        SessionMessage,
    },
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    traffic::{TrafficContext, record_transfer, register_connection},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const VMESS_UDP_MESSAGE_BUFFER_SIZE: usize = 8192;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_CHANNEL_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TargetedUdpSessionKey {
    pub(crate) target_addr: SocketAddr,
    pub(crate) outbound_tag: Option<String>,
}

pub(crate) struct SessionUdpResponse {
    pub(crate) session_id: u16,
    pub(crate) generation: u64,
    pub(crate) source: SocketAddr,
    pub(crate) payload: Vec<u8>,
    pub(crate) traffic_context: Option<TrafficContext>,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum SessionUdpEvent {
    Data(SessionUdpResponse),
    End {
        session_id: u16,
        generation: u64,
        has_error: bool,
    },
}

pub(crate) struct LocalUdpPayload {
    pub(crate) target_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

mod bidirectional;
pub(crate) mod dokodemo;
pub(crate) mod global_xudp;
use global_xudp::*;
mod session_based;
pub(crate) mod session_worker;
#[cfg(feature = "shadowsocks")]
pub(crate) mod shadowsocks;
use session_worker::*;
mod targeted;

pub(crate) use bidirectional::run_bidirectional_udp;
pub(crate) use session_based::run_session_based_udp;
#[cfg(feature = "trojan")]
pub(crate) use targeted::shutdown_targeted_message;

pub(crate) async fn shutdown_global_xudp_workers() -> usize {
    global_xudp::shutdown_workers().await
}

pub(crate) async fn run_multi_directional_udp(
    server_stream: Box<dyn AsyncTargetedMessageStream>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    traffic_context: Option<TrafficContext>,
) -> std::io::Result<()> {
    targeted::run_multi_directional_udp_with_tasks(
        server_stream,
        resolver,
        runtime,
        peer_addr,
        local_addr,
        traffic_context,
        TaskTracker::new(),
    )
    .await
}

#[cfg(test)]
pub(crate) use targeted::run_multi_directional_udp_with_tasks;
