use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use tokio::{sync::broadcast, task::JoinHandle};

#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "trojan")]
use crate::handler::trojan::TrojanUserStore;
#[cfg(feature = "vmess")]
use crate::{
    config::server_config::VmessUser, handler::vmess::vmess_handler::VmessUserStore,
};
use crate::{
    config::{def::PolicyConfig, server_config::ServerConfig},
    inbound::InboundManager,
    routing_state::{
        BalancerTargetMap, OutboundObservation, RouteMatch, RoutingEvent,
        RoutingInput, RoutingState,
    },
    traffic::TrafficContext,
    user_domain::{
        UserDomainAccessFailure, UserDomainAccessRevision, UserDomainAccessStatus,
        UserDomainAccessStore, parse_publication,
    },
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyUserStats {
    pub uplink: bool,
    pub downlink: bool,
    pub online: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicySystemStats {
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyRelayTimeouts {
    pub connection_idle: Option<Duration>,
    pub uplink_only: Option<Duration>,
    pub downlink_only: Option<Duration>,
    pub buffer_size: Option<usize>,
}

impl PolicyRelayTimeouts {
    pub const fn is_empty(self) -> bool {
        self.connection_idle.is_none()
            && self.uplink_only.is_none()
            && self.downlink_only.is_none()
            && self.buffer_size.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSummary {
    pub tag: String,
    pub protocol: String,
    pub proxy_settings_type: Option<String>,
    pub proxy_settings_value: Option<Vec<u8>>,
    pub sender_settings_type: Option<String>,
    pub sender_settings_value: Option<Vec<u8>>,
}

#[derive(Debug)]
struct RoutingPublication {
    routing: Arc<RoutingState>,
    outbounds: Arc<Vec<OutboundSummary>>,
    balancer_targets: BalancerTargetMap,
}

impl RoutingPublication {
    fn new(
        routing: Arc<RoutingState>,
        outbounds: Arc<Vec<OutboundSummary>>,
    ) -> Self {
        let balancer_targets = routing.compile_balancer_targets(&outbounds);
        Self {
            routing,
            outbounds,
            balancer_targets,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    inbound_manager: Arc<InboundManager>,
    routing_publication: Arc<RwLock<Arc<RoutingPublication>>>,
    routing_updates: Arc<Mutex<()>>,
    policy: Arc<RwLock<PolicyConfig>>,
    user_domain_access: UserDomainAccessStore,
    balancer_overrides: Arc<RwLock<Arc<HashMap<String, String>>>>,
    routing_events: broadcast::Sender<RoutingEvent>,
}

impl RuntimeState {
    pub fn new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Self {
        let (routing_events, _) = broadcast::channel(256);
        let routing = Arc::new(RoutingState::default());
        let outbounds = Arc::new(outbounds);
        Self {
            inbound_manager: Arc::new(InboundManager::new(inbounds)),
            routing_publication: Arc::new(RwLock::new(Arc::new(
                RoutingPublication::new(routing, outbounds),
            ))),
            routing_updates: Arc::new(Mutex::new(())),
            policy: Arc::new(RwLock::new(PolicyConfig::default())),
            user_domain_access: UserDomainAccessStore::default(),
            balancer_overrides: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
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

    pub(crate) fn policy_user_stats(&self, level: u32) -> PolicyUserStats {
        let policy = self.policy.read().expect("runtime policy lock poisoned");
        let level_policy = policy.levels.get(&level).and_then(Option::as_ref);
        PolicyUserStats {
            uplink: level_policy.is_some_and(|policy| policy.stats_user_uplink),
            downlink: level_policy.is_some_and(|policy| policy.stats_user_downlink),
            online: level_policy.is_some_and(|policy| policy.stats_user_online),
        }
    }

    pub(crate) fn policy_system_stats(&self) -> PolicySystemStats {
        let policy = self.policy.read().expect("runtime policy lock poisoned");
        let system = policy.system.as_ref();
        PolicySystemStats {
            inbound_uplink: system.is_some_and(|policy| policy.stats_inbound_uplink),
            inbound_downlink: system
                .is_some_and(|policy| policy.stats_inbound_downlink),
            outbound_uplink: system
                .is_some_and(|policy| policy.stats_outbound_uplink),
            outbound_downlink: system
                .is_some_and(|policy| policy.stats_outbound_downlink),
        }
    }

    pub(crate) fn apply_traffic_stats_policy(&self, context: &mut TrafficContext) {
        let user = self.policy_user_stats(context.user_level);
        let system = self.policy_system_stats();
        context.set_user_stats_policy(user.uplink, user.downlink, user.online);
        context.set_system_stats_policy(
            system.inbound_uplink,
            system.inbound_downlink,
            system.outbound_uplink,
            system.outbound_downlink,
        );
    }

    pub(crate) fn policy_relay_timeouts(&self, level: u32) -> PolicyRelayTimeouts {
        const DEFAULT_CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;
        const DEFAULT_UPLINK_ONLY_TIMEOUT_SECS: u64 = 1;
        const DEFAULT_DOWNLINK_ONLY_TIMEOUT_SECS: u64 = 1;

        let policy = self.policy.read().expect("runtime policy lock poisoned");
        let level_policy = policy.levels.get(&level).and_then(Option::as_ref);
        let buffer_size = level_policy
            .and_then(|policy| policy.buffer_size)
            .filter(|size| *size >= 0)
            .map(|kibibytes| {
                usize::try_from(kibibytes)
                    .unwrap_or(usize::MAX)
                    .saturating_mul(1024)
                    .max(1)
            });

        PolicyRelayTimeouts {
            connection_idle: Some(Duration::from_secs(
                level_policy
                    .and_then(|policy| policy.connection_idle)
                    .map(u64::from)
                    .unwrap_or(DEFAULT_CONNECTION_IDLE_TIMEOUT_SECS),
            )),
            uplink_only: Some(Duration::from_secs(
                level_policy
                    .and_then(|policy| policy.uplink_only)
                    .map(u64::from)
                    .unwrap_or(DEFAULT_UPLINK_ONLY_TIMEOUT_SECS),
            )),
            downlink_only: Some(Duration::from_secs(
                level_policy
                    .and_then(|policy| policy.downlink_only)
                    .map(u64::from)
                    .unwrap_or(DEFAULT_DOWNLINK_ONLY_TIMEOUT_SECS),
            )),
            buffer_size,
        }
    }

    pub(crate) fn inbound_manager(&self) -> Arc<InboundManager> {
        Arc::clone(&self.inbound_manager)
    }

    pub fn inbounds(&self) -> Vec<ServerConfig> {
        self.inbound_manager.configs()
    }

    pub fn inbound_by_tag(&self, tag: &str) -> Option<ServerConfig> {
        self.inbound_manager.config_by_tag(tag)
    }

    pub fn with_inbound_mut<R, F>(&self, tag: &str, mutator: F) -> Option<R>
    where
        F: FnOnce(&mut ServerConfig) -> R,
    {
        self.inbound_manager.with_config_mut(tag, mutator)
    }

    pub fn remove_inbound(&self, tag: &str) -> Option<ServerConfig> {
        self.inbound_manager.remove_config(tag)
    }

    pub fn add_inbound(&self, inbound: ServerConfig) -> Result<(), String> {
        self.inbound_manager.add_config(inbound)
    }

    pub fn register_inbound_tasks(&self, tag: &str, handles: Vec<JoinHandle<()>>) {
        self.inbound_manager.register_tasks(tag, handles);
    }

    pub async fn stop_inbound_tasks(&self, tag: &str) -> bool {
        self.inbound_manager.stop_tasks(tag).await
    }

    #[cfg(feature = "vless")]
    pub(crate) fn vless_users_snapshot(&self, tag: &str) -> Option<Vec<VlessUser>> {
        self.inbound_manager.vless_users_snapshot(tag)
    }

    #[cfg(feature = "vless")]
    pub(crate) async fn alter_inbound_users<E, F, U>(
        &self,
        tag: &str,
        update_config: F,
        update_vless_users: U,
    ) -> Result<(), crate::inbound::AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&mut Vec<VlessUser>) -> Result<bool, E> + Send,
    {
        self.inbound_manager
            .alter_users(self.clone(), tag, update_config, update_vless_users)
            .await
    }

    #[cfg(feature = "vmess")]
    pub(crate) fn vmess_user_store(&self, tag: &str) -> Option<Arc<VmessUserStore>> {
        self.inbound_manager.vmess_user_store(tag)
    }

    #[cfg(feature = "trojan")]
    pub(crate) fn trojan_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<TrojanUserStore>> {
        self.inbound_manager.trojan_user_store(tag)
    }

    #[cfg(feature = "vmess")]
    pub(crate) async fn alter_vmess_users<E, F, U>(
        &self,
        tag: &str,
        update_config: F,
        update_vmess_users: U,
    ) -> Result<(), crate::inbound::AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&mut Vec<VmessUser>) -> Result<(), E> + Send,
    {
        self.inbound_manager
            .alter_vmess_users(self.clone(), tag, update_config, update_vmess_users)
            .await
    }

    #[cfg(feature = "trojan")]
    pub(crate) async fn alter_trojan_users<E, F, U>(
        &self,
        tag: &str,
        update_config: F,
        update_trojan_users: U,
    ) -> Result<(), crate::inbound::AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&TrojanUserStore) -> Result<(), E> + Send,
    {
        self.inbound_manager
            .alter_trojan_users(
                self.clone(),
                tag,
                update_config,
                update_trojan_users,
            )
            .await
    }

    pub fn outbounds(&self) -> Vec<OutboundSummary> {
        self.outbound_snapshot().as_ref().clone()
    }

    fn routing_publication(&self) -> Arc<RoutingPublication> {
        Arc::clone(
            &self
                .routing_publication
                .read()
                .expect("runtime routing publication lock poisoned"),
        )
    }

    fn outbound_snapshot(&self) -> Arc<Vec<OutboundSummary>> {
        Arc::clone(&self.routing_publication().outbounds)
    }

    pub fn select_outbound(&self, input: &RoutingInput) -> Option<OutboundSummary> {
        self.select_outbound_checked(input).ok().flatten()
    }

    pub(crate) fn select_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        self.select_outbound_checked_internal(input, true)
    }

    pub(crate) fn match_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        self.select_outbound_checked_internal(input, false)
    }

    fn select_outbound_checked_internal(
        &self,
        input: &RoutingInput,
        use_default: bool,
    ) -> Result<Option<OutboundSummary>, String> {
        let publication = self.routing_publication();
        let outbounds = &publication.outbounds;
        let overrides = self.balancer_override_snapshot();
        let Some(route) = publication.routing.route_with_balancer_targets(
            input,
            outbounds.as_ref(),
            overrides.as_ref(),
            &publication.balancer_targets,
        ) else {
            if !use_default {
                return Ok(None);
            }
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
        self.balancer_override_snapshot().as_ref().clone()
    }

    fn balancer_override_snapshot(&self) -> Arc<HashMap<String, String>> {
        Arc::clone(
            &self
                .balancer_overrides
                .read()
                .expect("runtime balancer overrides lock poisoned"),
        )
    }

    pub(crate) fn balancer_override(&self, tag: &str) -> Option<String> {
        self.balancer_override_snapshot().get(tag).cloned()
    }

    pub(crate) fn set_balancer_override(
        &self,
        balancer_tag: impl Into<String>,
        outbound_tag: impl Into<String>,
    ) {
        let mut current = self
            .balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned");
        let mut next = current.as_ref().clone();
        next.insert(balancer_tag.into(), outbound_tag.into());
        *current = Arc::new(next);
    }

    pub(crate) fn remove_balancer_override(&self, tag: &str) -> bool {
        let mut current = self
            .balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned");
        let mut next = current.as_ref().clone();
        let removed = next.remove(tag).is_some();
        if removed {
            *current = Arc::new(next);
        }
        removed
    }

    pub fn remove_outbound(&self, tag: &str) -> Option<OutboundSummary> {
        let _update = self
            .routing_updates
            .lock()
            .expect("runtime routing update lock poisoned");
        let current = self.routing_publication();
        let mut outbounds = current.outbounds.as_ref().clone();
        let index = outbounds.iter().position(|cfg| cfg.tag == tag)?;
        let removed = outbounds.remove(index);
        current.routing.remove_observation(tag);
        self.publish_routing_publication(RoutingPublication::new(
            Arc::clone(&current.routing),
            Arc::new(outbounds),
        ));
        Some(removed)
    }

    pub fn add_outbound(&self, outbound: OutboundSummary) -> Result<(), String> {
        let _update = self
            .routing_updates
            .lock()
            .expect("runtime routing update lock poisoned");
        let current = self.routing_publication();
        if current.outbounds.iter().any(|cfg| cfg.tag == outbound.tag) {
            return Err(format!("outbound {} already exists", outbound.tag));
        }
        let mut outbounds = current.outbounds.as_ref().clone();
        outbounds.push(outbound);
        self.publish_routing_publication(RoutingPublication::new(
            Arc::clone(&current.routing),
            Arc::new(outbounds),
        ));
        Ok(())
    }

    pub fn routing(&self) -> Arc<RoutingState> {
        Arc::clone(&self.routing_publication().routing)
    }

    pub fn replace_routing(&self, routing: RoutingState) {
        let _update = self
            .routing_updates
            .lock()
            .expect("runtime routing update lock poisoned");
        let current = self.routing_publication();
        self.publish_routing_against(&current, routing);
    }

    fn publish_routing_against(
        &self,
        current: &RoutingPublication,
        mut routing: RoutingState,
    ) {
        routing.inherit_observations_from(&current.routing);
        self.publish_routing_publication(RoutingPublication::new(
            Arc::new(routing),
            Arc::clone(&current.outbounds),
        ));
    }

    fn publish_routing_publication(&self, publication: RoutingPublication) {
        *self
            .routing_publication
            .write()
            .expect("runtime routing publication lock poisoned") =
            Arc::new(publication);
    }

    pub(crate) fn record_outbound_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.routing().record_observation(tag, observation);
    }

    pub(crate) fn record_passive_outbound_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.routing().record_passive_observation(tag, observation);
    }

    pub(crate) fn outbound_observation(
        &self,
        tag: &str,
    ) -> Option<OutboundObservation> {
        self.routing().observation(tag)
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
        let current = self.routing_publication();
        let mut next = (*current.routing).clone();
        let result = mutator(&mut next);
        self.publish_routing_against(&current, next);
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
    use crate::{
        config::{
            def::{PolicyConfig, PolicyLevelConfig, SystemPolicyConfig},
            rule::BalancerConfig,
        },
        routing_state::{OutboundObservation, RoutingState},
    };
    use std::{
        collections::HashMap,
        sync::{Arc, mpsc},
        time::Duration,
    };

    #[tokio::test]
    async fn stopping_inbound_tasks_releases_listener_before_return() {
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        runtime.register_inbound_tasks("listener-release", vec![task]);

        assert!(runtime.stop_inbound_tasks("listener-release").await);
        tokio::net::TcpListener::bind(address)
            .await
            .expect("listener should be released before stop returns");
    }

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
    fn xray_relay_policy_preserves_default_and_per_level_timeouts() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let defaults = runtime.policy_relay_timeouts(7);
        assert_eq!(defaults.connection_idle, Some(Duration::from_secs(300)));
        assert_eq!(defaults.uplink_only, Some(Duration::from_secs(1)));
        assert_eq!(defaults.downlink_only, Some(Duration::from_secs(1)));
        assert_eq!(defaults.buffer_size, None);

        let mut levels = HashMap::new();
        levels.insert(
            7,
            Some(PolicyLevelConfig {
                connection_idle: Some(5),
                uplink_only: Some(6),
                downlink_only: Some(7),
                buffer_size: Some(64),
                ..PolicyLevelConfig::default()
            }),
        );
        levels.insert(
            8,
            Some(PolicyLevelConfig {
                connection_idle: Some(0),
                uplink_only: Some(0),
                downlink_only: Some(0),
                buffer_size: Some(-1),
                ..PolicyLevelConfig::default()
            }),
        );
        runtime.replace_policy(Some(&PolicyConfig {
            levels,
            ..PolicyConfig::default()
        }));

        let configured = runtime.policy_relay_timeouts(7);
        assert_eq!(configured.connection_idle, Some(Duration::from_secs(5)));
        assert_eq!(configured.uplink_only, Some(Duration::from_secs(6)));
        assert_eq!(configured.downlink_only, Some(Duration::from_secs(7)));
        assert_eq!(configured.buffer_size, Some(64 * 1024));

        let zeroed = runtime.policy_relay_timeouts(8);
        assert_eq!(zeroed.connection_idle, Some(Duration::ZERO));
        assert_eq!(zeroed.uplink_only, Some(Duration::ZERO));
        assert_eq!(zeroed.downlink_only, Some(Duration::ZERO));
        assert_eq!(zeroed.buffer_size, None);
    }

    #[test]
    fn xray_stats_policy_uses_level_and_system_switches() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let default_user = runtime.policy_user_stats(7);
        assert!(!default_user.uplink);
        assert!(!default_user.downlink);
        assert!(!default_user.online);
        let default_system = runtime.policy_system_stats();
        assert!(!default_system.inbound_uplink);
        assert!(!default_system.inbound_downlink);
        assert!(!default_system.outbound_uplink);
        assert!(!default_system.outbound_downlink);

        let mut levels = HashMap::new();
        levels.insert(
            7,
            Some(PolicyLevelConfig {
                stats_user_uplink: true,
                stats_user_downlink: false,
                stats_user_online: true,
                ..PolicyLevelConfig::default()
            }),
        );
        runtime.replace_policy(Some(&PolicyConfig {
            levels,
            system: Some(SystemPolicyConfig {
                stats_inbound_uplink: false,
                stats_inbound_downlink: true,
                stats_outbound_uplink: true,
                stats_outbound_downlink: false,
            }),
        }));

        let user = runtime.policy_user_stats(7);
        assert!(user.uplink);
        assert!(!user.downlink);
        assert!(user.online);
        let missing = runtime.policy_user_stats(8);
        assert_eq!(missing, super::PolicyUserStats::default());

        let system = runtime.policy_system_stats();
        assert!(!system.inbound_uplink);
        assert!(system.inbound_downlink);
        assert!(system.outbound_uplink);
        assert!(!system.outbound_downlink);
    }

    #[test]
    fn outbound_and_override_snapshots_are_copy_on_write() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![super::OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let first_outbounds = runtime.outbound_snapshot();
        let second_outbounds = runtime.outbound_snapshot();
        assert!(Arc::ptr_eq(&first_outbounds, &second_outbounds));

        runtime
            .add_outbound(super::OutboundSummary {
                tag: "backup".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            })
            .expect("add outbound");
        let replaced_outbounds = runtime.outbound_snapshot();
        assert!(!Arc::ptr_eq(&first_outbounds, &replaced_outbounds));
        assert_eq!(first_outbounds.len(), 1);
        assert_eq!(replaced_outbounds.len(), 2);

        let first_overrides = runtime.balancer_override_snapshot();
        runtime.set_balancer_override("auto", "backup");
        let replaced_overrides = runtime.balancer_override_snapshot();
        assert!(!Arc::ptr_eq(&first_overrides, &replaced_overrides));
        assert!(first_overrides.is_empty());
        assert_eq!(
            replaced_overrides.get("auto").map(String::as_str),
            Some("backup")
        );
    }

    #[test]
    fn routing_publication_recompiles_balancer_targets_on_control_updates() {
        fn outbound(tag: &str) -> super::OutboundSummary {
            super::OutboundSummary {
                tag: tag.into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }
        }

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![outbound("direct-a"), outbound("backup")],
        );
        runtime.replace_routing(
            RoutingState::from_parts(
                Vec::new(),
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["direct".into()],
                    ..BalancerConfig::default()
                }],
            )
            .expect("compile routing balancer"),
        );

        let first = runtime.routing_publication();
        assert_eq!(first.balancer_targets["auto"].as_ref(), ["direct-a"]);

        runtime
            .add_outbound(outbound("direct-b"))
            .expect("add matching outbound");
        let added = runtime.routing_publication();
        assert!(!Arc::ptr_eq(&first, &added));
        assert_eq!(first.balancer_targets["auto"].as_ref(), ["direct-a"]);
        assert_eq!(
            added.balancer_targets["auto"].as_ref(),
            ["direct-a", "direct-b"]
        );
        runtime.record_outbound_observation(
            "direct-a",
            OutboundObservation {
                alive: true,
                delay_ms: 12,
                ..OutboundObservation::default()
            },
        );
        assert!(runtime.outbound_observation("direct-a").is_some());

        runtime
            .remove_outbound("direct-a")
            .expect("remove matching outbound");
        let removed = runtime.routing_publication();
        assert_eq!(removed.balancer_targets["auto"].as_ref(), ["direct-b"]);
        assert!(runtime.outbound_observation("direct-a").is_none());
    }

    #[test]
    fn routing_reads_share_immutable_snapshots_until_publish() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let first = runtime.routing();
        let second = runtime.routing();
        assert!(Arc::ptr_eq(&first, &second));

        runtime.replace_routing(RoutingState::default());
        let replaced = runtime.routing();
        assert!(!Arc::ptr_eq(&first, &replaced));
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
