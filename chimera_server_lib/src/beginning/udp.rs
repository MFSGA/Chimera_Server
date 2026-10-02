#[cfg(test)]
use std::{collections::HashMap, net::SocketAddr};

#[cfg(test)]
use crate::{
    async_stream::{AsyncSessionMessageStream, SessionMessage},
    runtime::DataPlaneRuntime,
    traffic::TrafficContext,
    xudp_registry::XUDP_GLOBAL_REATTACH_TTL,
};
#[cfg(test)]
use tokio::{
    sync::{Notify, RwLock, mpsc, oneshot},
    time::{Instant, sleep},
};
#[cfg(test)]
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use crate::session::udp::{
    SessionUdpEvent, SessionUdpResponse, TargetedUdpSessionKey, global_xudp::*,
    run_bidirectional_udp, run_session_based_udp, session_worker::*,
};
#[cfg(test)]
use crate::transport::udp::{bind_location_to_socket_addr, create_udp_listener};

#[cfg(test)]
use crate::session::udp::dokodemo::{
    UdpOutboundAction, run_dokodemo_udp_server, select_udp_outbound,
};
#[cfg(all(test, feature = "shadowsocks"))]
use crate::session::udp::shadowsocks::{
    relay_shadowsocks_udp_packet, run_shadowsocks_udp_server,
};
#[cfg(test)]
mod tests;
