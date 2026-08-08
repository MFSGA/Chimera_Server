use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use tokio::task::JoinHandle;

use crate::{
    config::server_config::ServerConfig,
    routing_state::{RoutingInput, RoutingState},
};

#[derive(Debug, Clone)]
pub struct OutboundSummary {
    pub tag: String,
    pub protocol: String,
    pub proxy_settings_type: Option<String>,
    pub proxy_settings_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inbounds: Arc<RwLock<Vec<ServerConfig>>>,
    outbounds: Arc<RwLock<Vec<OutboundSummary>>>,
    inbound_tasks: Arc<RwLock<HashMap<String, Vec<JoinHandle<()>>>>>,
    routing: Arc<RwLock<RoutingState>>,
}

impl RuntimeState {
    pub fn new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Self {
        Self {
            inbounds: Arc::new(RwLock::new(inbounds)),
            outbounds: Arc::new(RwLock::new(outbounds)),
            inbound_tasks: Arc::new(RwLock::new(HashMap::new())),
            routing: Arc::new(RwLock::new(RoutingState::default())),
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

    pub fn register_inbound_tasks(&self, tag: &str, handles: Vec<JoinHandle<()>>) {
        self.inbound_tasks
            .write()
            .expect("runtime inbound tasks lock poisoned")
            .insert(tag.to_string(), handles);
    }

    pub async fn stop_inbound_tasks(&self, tag: &str) -> bool {
        let Some(handles) = self
            .inbound_tasks
            .write()
            .expect("runtime inbound tasks lock poisoned")
            .remove(tag)
        else {
            return false;
        };

        for handle in &handles {
            handle.abort();
        }

        for handle in handles {
            let _ = handle.await;
        }

        true
    }

    pub fn outbounds(&self) -> Vec<OutboundSummary> {
        self.outbounds
            .read()
            .expect("runtime outbounds lock poisoned")
            .clone()
    }

    pub fn select_outbound(&self, input: &RoutingInput) -> Option<OutboundSummary> {
        self.select_outbound_checked(input).ok().flatten()
    }

    pub(crate) fn select_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        let outbounds = self.outbounds();
        let Some(route) = self.routing().route(input, &outbounds, &HashMap::new())
        else {
            return Ok(outbounds.first().cloned());
        };
        if let Some(error) = route.resolution_error {
            return Err(error);
        }
        outbounds
            .iter()
            .find(|outbound| outbound.tag == route.outbound_tag)
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                format!("routing selected missing outbound {}", route.outbound_tag)
            })
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

    pub fn routing(&self) -> RoutingState {
        self.routing
            .read()
            .expect("runtime routing lock poisoned")
            .clone()
    }

    pub fn replace_routing(&self, routing: RoutingState) {
        *self.routing.write().expect("runtime routing lock poisoned") = routing;
    }

    pub fn with_routing_mut<R, F>(&self, mutator: F) -> R
    where
        F: FnOnce(&mut RoutingState) -> R,
    {
        let mut guard = self.routing.write().expect("runtime routing lock poisoned");
        mutator(&mut guard)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;

    use super::RuntimeState;

    #[tokio::test]
    async fn stopping_inbound_tasks_releases_listener_before_return() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime.register_inbound_tasks("test", vec![task]);

        assert!(runtime.stop_inbound_tasks("test").await);
        TcpListener::bind(address)
            .await
            .expect("listener should be released before stop returns");
    }
}
