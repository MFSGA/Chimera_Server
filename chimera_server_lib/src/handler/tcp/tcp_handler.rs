use std::{fmt::Debug, time::Duration};

use async_trait::async_trait;

use crate::{
    address::NetLocation,
    async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream},
    runtime::RuntimeState,
    traffic::TrafficContext,
};

#[derive(Debug, Clone, Default)]
pub struct TcpServerConnectionContext {
    pub original_destination: Option<NetLocation>,
    pub peer_addr: Option<std::net::SocketAddr>,
    pub local_addr: Option<std::net::SocketAddr>,
    pub listener_addr: Option<std::net::SocketAddr>,
    pub server_name: Option<String>,
    pub alpn_protocol: Option<String>,
    pub runtime: Option<RuntimeState>,
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    fn requires_original_destination(&self) -> bool {
        false
    }

    fn manages_handshake_timeout(&self) -> bool {
        false
    }

    fn pre_transport_handshake_timeout(
        &self,
        _context: &TcpServerConnectionContext,
    ) -> Option<Duration> {
        None
    }

    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        _context: TcpServerConnectionContext,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream(server_stream).await
    }
}

pub enum TcpServerSetupResult {
    PeerAddrOverride {
        peer_addr: std::net::SocketAddr,
        inner: Box<TcpServerSetupResult>,
    },
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,

        connection_success_response: Option<Box<[u8]>>,
        traffic_context: Option<TrafficContext>,
    },
    HttpPlainForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        request_head: Box<[u8]>,
        request_method: String,
        keep_alive: bool,
        next_handler: Box<dyn TcpServerHandler>,
        traffic_context: Option<TrafficContext>,
    },
    TcpFallback {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        proxy_protocol_version: u8,
        traffic_context: Option<TrafficContext>,
    },
    UdpAssociate {
        stream: Box<dyn AsyncStream>,
        udp_socket: std::sync::Arc<tokio::net::UdpSocket>,
        expected_client: std::net::SocketAddr,
        traffic_context: Option<TrafficContext>,
    },
    BidirectionalUdp {
        remote_location: NetLocation,
        stream: Box<dyn AsyncMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    MultiDirectionalUdp {
        stream: Box<dyn AsyncTargetedMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    SessionBasedUdp {
        stream: Box<dyn crate::async_stream::AsyncSessionMessageStream>,
        traffic_context: Option<TrafficContext>,
    },
    /// The handler has taken full ownership of the stream and all work is
    /// already handled (via a spawned task). `process_stream` should
    /// return `Ok(())` immediately.
    AlreadyHandled,
}

impl TcpServerSetupResult {
    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        if let TcpServerSetupResult::TcpForward {
            need_initial_flush: flush,
            ..
        } = self
        {
            *flush = need_initial_flush;
        }
    }
}
