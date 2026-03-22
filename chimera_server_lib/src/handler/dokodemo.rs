use async_trait::async_trait;

use crate::{
    async_stream::AsyncStream,
    config::server_config::DokodemoDoorConfig,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
    traffic::TrafficContext,
};

#[derive(Debug)]
pub struct DokodemoDoorTcpHandler {
    config: DokodemoDoorConfig,
    inbound_tag: String,
}

impl DokodemoDoorTcpHandler {
    pub fn new(config: DokodemoDoorConfig, inbound_tag: &str) -> Self {
        Self {
            config,
            inbound_tag: inbound_tag.to_string(),
        }
    }
}

#[async_trait]
impl TcpServerHandler for DokodemoDoorTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if self.config.follow_redirect {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "dokodemo-door followRedirect is not supported yet",
            ));
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location: self.config.target.clone(),
            stream: server_stream,
            need_initial_flush: true,
            connection_success_response: None,
            traffic_context: Some(
                TrafficContext::new("dokodemo-door")
                    .with_inbound_tag(self.inbound_tag.clone()),
            ),
        })
    }
}
