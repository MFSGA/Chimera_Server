use std::{fmt::Debug, sync::Arc};

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::{
    address::NetLocation, async_stream::AsyncStream, traffic::TrafficContext,
};

#[async_trait]
pub trait TcpServerHandler: Send + Sync + Debug {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult>;
}

pub enum TcpServerSetupResult {
    TcpForward {
        remote_location: NetLocation,
        stream: Box<dyn AsyncStream>,
        need_initial_flush: bool,

        connection_success_response: Option<Box<[u8]>>,
        traffic_context: Option<TrafficContext>,
    },
    UdpAssociate {
        stream: Box<dyn AsyncStream>,
        socket: Arc<UdpSocket>,
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
