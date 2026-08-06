use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::{
    address::NetLocation,
    async_stream::{AsyncMessageStream, AsyncStream, AsyncTargetedMessageStream},
    resolver::Resolver,
    traffic::TrafficContext,
};

#[derive(Clone, Default)]
pub struct TcpServerConnectionContext {
    pub original_destination: Option<NetLocation>,
    pub local_addr: Option<std::net::SocketAddr>,
    pub server_name: Option<String>,
    pub alpn_protocol: Option<String>,
    pub resolver: Option<Arc<dyn Resolver>>,
}

impl Debug for TcpServerConnectionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpServerConnectionContext")
            .field("original_destination", &self.original_destination)
            .field("local_addr", &self.local_addr)
            .field("server_name", &self.server_name)
            .field("alpn_protocol", &self.alpn_protocol)
            .field("resolver", &self.resolver.as_ref().map(|_| "dyn Resolver"))
            .finish()
    }
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    fn requires_original_destination(&self) -> bool {
        false
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
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,

        connection_success_response: Option<Box<[u8]>>,
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
        socket: Arc<UdpSocket>,
        client_udp_port_hint: Option<u16>,
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
