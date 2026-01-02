use std::sync::Arc;

use crate::config::server_config::ServerConfig;

#[derive(Debug, Clone)]
pub struct OutboundSummary {
    pub tag: String,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inbounds: Arc<Vec<ServerConfig>>,
    outbounds: Arc<Vec<OutboundSummary>>,
}

impl RuntimeState {
    pub fn new(inbounds: Vec<ServerConfig>, outbounds: Vec<OutboundSummary>) -> Self {
        Self {
            inbounds: Arc::new(inbounds),
            outbounds: Arc::new(outbounds),
        }
    }

    pub fn inbounds(&self) -> &[ServerConfig] {
        self.inbounds.as_slice()
    }

    pub fn inbound_by_tag(&self, tag: &str) -> Option<&ServerConfig> {
        self.inbounds.iter().find(|cfg| cfg.tag == tag)
    }

    pub fn outbounds(&self) -> &[OutboundSummary] {
        self.outbounds.as_slice()
    }
}
