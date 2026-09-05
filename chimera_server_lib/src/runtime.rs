use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use tokio::{sync::broadcast, task::JoinHandle};

use crate::{
    config::{def::PolicyConfig, server_config::ServerConfig},
    routing_state::{
        OutboundObservation, RouteMatch, RoutingEvent, RoutingInput, RoutingState,
    },
    user_domain::{
        UserDomainAccessFailure, UserDomainAccessRevision, UserDomainAccessStatus,
        UserDomainAccessStore, parse_publication,
    },
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
    routing_updates: Arc<Mutex<()>>,
    policy: Arc<RwLock<PolicyConfig>>,
    user_domain_access: UserDomainAccessStore,
    balancer_overrides: Arc<RwLock<HashMap<String, String>>>,
    routing_events: broadcast::Sender<RoutingEvent>,
}

impl RuntimeState {
    pub fn new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Self {
        let (routing_events, _) = broadcast::channel(256);
        Self {
            inbounds: Arc::new(RwLock::new(inbounds)),
            outbounds: Arc::new(RwLock::new(outbounds)),
            inbound_tasks: Arc::new(RwLock::new(HashMap::new())),
            routing: Arc::new(RwLock::new(RoutingState::default())),
            routing_updates: Arc::new(Mutex::new(())),
            policy: Arc::new(RwLock::new(PolicyConfig::default())),
            user_domain_access: UserDomainAccessStore::default(),
            balancer_overrides: Arc::new(RwLock::new(HashMap::new())),
            routing_events,
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

    pub fn xray_connection_idle_timeout_for_level(&self, level: u32) -> Duration {
        const DEFAULT_CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;

        let seconds = self
            .policy
            .read()
            .expect("runtime policy lock poisoned")
            .levels
            .get(&level)
            .and_then(Option::as_ref)
            .and_then(|policy| policy.connection_idle)
            .map(u64::from)
            .unwrap_or(DEFAULT_CONNECTION_IDLE_TIMEOUT_SECS);
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
        let overrides = self.balancer_overrides();
        let Some(route) = self.routing().route(input, &outbounds, &overrides) else {
            let selected = outbounds.first().cloned();
            if let Some(outbound) = selected.as_ref() {
                self.publish_routing_event(RoutingEvent {
                    input: input.clone(),
                    route: RouteMatch {
                        outbound_tag: outbound.tag.clone(),
                        outbound_group_tags: Vec::new(),
                        rule_tag: String::new(),
                        resolution_error: None,
                    },
                });
            }
            return Ok(selected);
        };
        if let Some(error) = route.resolution_error.clone() {
            return Err(error);
        }
        let selected = outbounds
            .iter()
            .find(|outbound| outbound.tag == route.outbound_tag)
            .cloned()
            .ok_or_else(|| {
                format!("routing selected missing outbound {}", route.outbound_tag)
            })?;
        self.publish_routing_event(RoutingEvent {
            input: input.clone(),
            route,
        });
        Ok(Some(selected))
    }

    pub(crate) fn subscribe_routing_events(
        &self,
    ) -> broadcast::Receiver<RoutingEvent> {
        self.routing_events.subscribe()
    }

    pub(crate) fn publish_routing_event(&self, event: RoutingEvent) {
        let _ = self.routing_events.send(event);
    }

    pub(crate) fn balancer_overrides(&self) -> HashMap<String, String> {
        self.balancer_overrides
            .read()
            .expect("runtime balancer overrides lock poisoned")
            .clone()
    }

    pub(crate) fn balancer_override(&self, tag: &str) -> Option<String> {
        self.balancer_overrides
            .read()
            .expect("runtime balancer overrides lock poisoned")
            .get(tag)
            .cloned()
    }

    pub(crate) fn set_balancer_override(
        &self,
        balancer_tag: impl Into<String>,
        outbound_tag: impl Into<String>,
    ) {
        self.balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned")
            .insert(balancer_tag.into(), outbound_tag.into());
    }

    pub(crate) fn remove_balancer_override(&self, tag: &str) -> bool {
        self.balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned")
            .remove(tag)
            .is_some()
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
        let _update = self
            .routing_updates
            .lock()
            .expect("runtime routing update lock poisoned");
        self.publish_routing(routing);
    }

    fn publish_routing(&self, mut routing: RoutingState) {
        let mut current =
            self.routing.write().expect("runtime routing lock poisoned");
        routing.inherit_observations_from(&current);
        *current = routing;
    }

    pub(crate) fn record_outbound_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.routing().record_observation(tag, observation);
    }

    pub(crate) fn outbound_observations(
        &self,
    ) -> HashMap<String, OutboundObservation> {
        self.routing().observations()
    }

    pub fn with_routing_mut<R, F>(&self, mutator: F) -> R
    where
        F: FnOnce(&mut RoutingState) -> R,
    {
        let _update = self
            .routing_updates
            .lock()
            .expect("runtime routing update lock poisoned");
        let mut next = self.routing();
        let result = mutator(&mut next);
        self.publish_routing(next);
        result
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
    use std::{
        collections::HashMap,
        sync::{Arc, mpsc},
        time::Duration,
    };

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

    #[test]
    fn xray_connection_idle_policy_uses_level_override_and_default() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        assert_eq!(
            runtime.xray_connection_idle_timeout_for_level(7),
            Duration::from_secs(300)
        );

        let mut levels = HashMap::new();
        levels.insert(
            7,
            Some(PolicyLevelConfig {
                connection_idle: Some(5),
                ..PolicyLevelConfig::default()
            }),
        );
        levels.insert(
            8,
            Some(PolicyLevelConfig {
                connection_idle: Some(0),
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
            runtime.xray_connection_idle_timeout_for_level(7),
            Duration::from_secs(5)
        );
        assert_eq!(
            runtime.xray_connection_idle_timeout_for_level(8),
            Duration::ZERO
        );
        assert_eq!(
            runtime.xray_connection_idle_timeout_for_level(9),
            Duration::from_secs(300)
        );
        assert_eq!(
            runtime.xray_connection_idle_timeout_for_level(10),
            Duration::from_secs(300)
        );
        assert_eq!(
            runtime.xray_connection_idle_timeout_for_level(11),
            Duration::from_secs(300)
        );
    }
    #[test]
    fn routing_update_compilation_does_not_hold_data_plane_write_lock() {
        let runtime = Arc::new(RuntimeState::new(Vec::new(), Vec::new()));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let update_runtime = Arc::clone(&runtime);
        let update = std::thread::spawn(move || {
            update_runtime.with_routing_mut(|_| {
                started_tx.send(()).expect("signal update start");
                release_rx.recv().expect("release routing update");
            });
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("routing update should start");

        let (read_tx, read_rx) = mpsc::channel();
        let read_runtime = Arc::clone(&runtime);
        let reader = std::thread::spawn(move || {
            let _ = read_runtime.routing();
            read_tx.send(()).expect("signal routing read");
        });
        let read_result = read_rx.recv_timeout(Duration::from_millis(200));

        release_tx.send(()).expect("release routing update");
        update.join().expect("routing update thread");
        reader.join().expect("routing reader thread");
        assert!(
            read_result.is_ok(),
            "data-plane routing reads must remain available while a control-plane update is prepared"
        );
    }
}
