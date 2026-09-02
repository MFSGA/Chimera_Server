use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{
    config::{def::PolicyConfig, server_config::ServerConfig},
    routing_state::{RoutingInput, RoutingState},
    user_domain::{
        UserDomainAccessFailure, UserDomainAccessRevision, UserDomainAccessStatus,
        UserDomainAccessStore, parse_publication,
    },
};
use tokio::task::JoinHandle;

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
    policy: Arc<RwLock<PolicyConfig>>,
    user_domain_access: UserDomainAccessStore,
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
            policy: Arc::new(RwLock::new(PolicyConfig::default())),
            user_domain_access: UserDomainAccessStore::default(),
        }
    }

    pub fn replace_policy(&self, policy: Option<&PolicyConfig>) {
        *self.policy.write().expect("runtime policy lock poisoned") =
            policy.cloned().unwrap_or_default();
    }

    pub fn xray_handshake_timeout_for_level(&self, level: u32) -> Duration {
        const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 60;

        let seconds = self
            .policy
            .read()
            .expect("runtime policy lock poisoned")
            .levels
            .get(&level)
            .and_then(Option::as_ref)
            .and_then(|policy| policy.handshake)
            .map(u64::from)
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS);
        Duration::from_secs(seconds)
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

    pub(crate) fn apply_user_domain_policy(
        &self,
        json_config: &str,
    ) -> Result<UserDomainAccessRevision, UserDomainAccessFailure> {
        let publication = parse_publication(json_config)?;
        self.user_domain_access.apply(publication)
    }

    pub(crate) fn rollback_user_domain_policy(
        &self,
        version: u64,
    ) -> Result<UserDomainAccessRevision, UserDomainAccessFailure> {
        self.user_domain_access.rollback(version)
    }

    pub(crate) fn user_domain_policy_status(&self) -> UserDomainAccessStatus {
        self.user_domain_access.status()
    }

    pub(crate) fn allows_user_domain_access(
        &self,
        identity: &str,
        target_domain: &str,
    ) -> bool {
        self.user_domain_access.allows(identity, target_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeState;
    use crate::config::def::{PolicyConfig, PolicyLevelConfig};
    use std::{collections::HashMap, time::Duration};

    #[test]
    fn xray_handshake_policy_uses_level_override_and_default() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        assert_eq!(
            runtime.xray_handshake_timeout_for_level(7),
            Duration::from_secs(60)
        );

        let mut levels = HashMap::new();
        levels.insert(
            7,
            Some(PolicyLevelConfig {
                handshake: Some(5),
                ..PolicyLevelConfig::default()
            }),
        );
        levels.insert(
            8,
            Some(PolicyLevelConfig {
                handshake: Some(0),
                ..PolicyLevelConfig::default()
            }),
        );
        levels.insert(9, Some(PolicyLevelConfig::default()));
        levels.insert(10, None);
        runtime.replace_policy(Some(&PolicyConfig {
            levels,
            ..PolicyConfig::default()
        }));

        assert_eq!(
            runtime.xray_handshake_timeout_for_level(7),
            Duration::from_secs(5)
        );
        assert_eq!(runtime.xray_handshake_timeout_for_level(8), Duration::ZERO);
        assert_eq!(
            runtime.xray_handshake_timeout_for_level(9),
            Duration::from_secs(60)
        );
        assert_eq!(
            runtime.xray_handshake_timeout_for_level(10),
            Duration::from_secs(60)
        );
        assert_eq!(
            runtime.xray_handshake_timeout_for_level(11),
            Duration::from_secs(60)
        );
    }
}
