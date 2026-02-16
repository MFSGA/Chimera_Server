use std::fmt::Debug;

use async_trait::async_trait;

use crate::{address::NetLocation, async_stream::AsyncStream, traffic::TrafficContext};

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
}

impl TcpServerSetupResult {
    pub fn set_need_initial_flush(&mut self, need_initial_flush: bool) {
        match self {
            TcpServerSetupResult::TcpForward {
                need_initial_flush: flush,
                ..
            } => {
                *flush = need_initial_flush;
            }
        };
    }
}
