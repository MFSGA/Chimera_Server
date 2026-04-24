use std::sync::{Arc, RwLock};

use crate::config::server_config::ServerConfig;

#[derive(Debug, Clone)]
pub struct OutboundSummary {
    pub tag: String,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inbounds: Arc<RwLock<Vec<ServerConfig>>>,
    outbounds: Arc<RwLock<Vec<OutboundSummary>>>,
}

impl RuntimeState {
    pub fn new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Self {
        Self {
            inbounds: Arc::new(RwLock::new(inbounds)),
            outbounds: Arc::new(RwLock::new(outbounds)),
        }
    }

    pub fn inbounds(&self) -> Vec<ServerConfig> {
        self.inbounds
            .read()
            .expect("runtime inbounds lock poisoned")
            .clone()
    }

    pub fn inbound_by_tag(&self, tag: &str) -> Option<ServerConfig> {
        self.inbounds
            .read()
            .expect("runtime inbounds lock poisoned")
            .iter()
            .find(|cfg| cfg.tag == tag)
            .cloned()
    }

    pub fn with_inbound_mut<R, F>(&self, tag: &str, mutator: F) -> Option<R>
    where
        F: FnOnce(&mut ServerConfig) -> R,
    {
        let mut guard = self
            .inbounds
            .write()
            .expect("runtime inbounds lock poisoned");
        let inbound = guard.iter_mut().find(|cfg| cfg.tag == tag)?;
        Some(mutator(inbound))
    }

    pub fn remove_inbound(&self, tag: &str) -> Option<ServerConfig> {
        let mut guard = self
            .inbounds
            .write()
            .expect("runtime inbounds lock poisoned");
        let index = guard.iter().position(|cfg| cfg.tag == tag)?;
        Some(guard.remove(index))
    }

    pub fn add_inbound(&self, inbound: ServerConfig) -> Result<(), String> {
        let mut guard = self
            .inbounds
            .write()
            .expect("runtime inbounds lock poisoned");
        if guard.iter().any(|cfg| cfg.tag == inbound.tag) {
            return Err(format!("inbound {} already exists", inbound.tag));
        }
        guard.push(inbound);
        Ok(())
    }

    pub fn outbounds(&self) -> Vec<OutboundSummary> {
        self.outbounds
            .read()
            .expect("runtime outbounds lock poisoned")
            .clone()
    }

    pub fn remove_outbound(&self, tag: &str) -> Option<OutboundSummary> {
        let mut guard = self
            .outbounds
            .write()
            .expect("runtime outbounds lock poisoned");
        let index = guard.iter().position(|cfg| cfg.tag == tag)?;
        Some(guard.remove(index))
    }

    pub fn add_outbound(&self, outbound: OutboundSummary) -> Result<(), String> {
        let mut guard = self
            .outbounds
            .write()
            .expect("runtime outbounds lock poisoned");
        if guard.iter().any(|cfg| cfg.tag == outbound.tag) {
            return Err(format!("outbound {} already exists", outbound.tag));
        }
        guard.push(outbound);
        Ok(())
    }
}
