use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use tokio::{sync::broadcast, task::JoinHandle};

#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "hysteria")]
use crate::handler::hysteria2::connection::HysteriaUserStore;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::ShadowsocksUserStore;
#[cfg(feature = "trojan")]
use crate::handler::trojan::TrojanUserStore;
#[cfg(feature = "vmess")]
use crate::{
    config::server_config::VmessUser, handler::vmess::vmess_handler::VmessUserStore,
};
use crate::{
    config::{def::PolicyConfig, server_config::ServerConfig},
    inbound::{InboundFailure, InboundManager},
    routing_state::{
        BalancerTargetMap, OutboundObservation, RouteMatch, RoutingEvent,
        RoutingInput, RoutingState,
    },
    session_tasks::{ConnectionTaskOwner, ConnectionTaskShutdown},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RuntimeLifecycleState {
    Starting = 0,
    Running = 1,
    Draining = 2,
    Stopped = 3,
    Failed = 4,
}

impl RuntimeLifecycleState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Running,
            2 => Self::Draining,
            3 => Self::Stopped,
            4 => Self::Failed,
            _ => unreachable!("invalid runtime lifecycle state"),
        }
    }
}

mod data_plane;
use data_plane::DataPlaneState;
pub use data_plane::{DataPlaneRuntime, InboundHandshakeRuntime};

#[derive(Debug, Clone)]
pub struct RuntimeState {
    data_plane: DataPlaneRuntime,
    routing_updates: Arc<Mutex<()>>,
    lifecycle: Arc<AtomicU8>,
}

impl RuntimeState {
    pub fn data_plane(&self) -> DataPlaneRuntime {
        self.data_plane.clone()
    }

    pub fn new(
        inbounds: Vec<ServerConfig>,
        outbounds: Vec<OutboundSummary>,
    ) -> Self {
        let (routing_events, _) = broadcast::channel(256);
        let routing = Arc::new(RoutingState::default());
        let outbounds = Arc::new(outbounds);
        let data_plane = DataPlaneRuntime(Arc::new(DataPlaneState {
            inbound_manager: Arc::new(InboundManager::new(inbounds)),
            routing_publication: Arc::new(RwLock::new(Arc::new(
                RoutingPublication::new(routing, outbounds),
            ))),
            policy: Arc::new(RwLock::new(PolicyConfig::default())),
            user_domain_access: UserDomainAccessStore::default(),
            balancer_overrides: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
            routing_events,
            connection_tasks: ConnectionTaskOwner::default(),
        }));
        Self {
            data_plane,
            routing_updates: Arc::new(Mutex::new(())),
            lifecycle: Arc::new(AtomicU8::new(
                RuntimeLifecycleState::Starting as u8,
            )),
        }
    }

    pub(crate) fn lifecycle_state(&self) -> RuntimeLifecycleState {
        RuntimeLifecycleState::from_u8(self.lifecycle.load(Ordering::Acquire))
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.lifecycle_state() == RuntimeLifecycleState::Running
            && !self.data_plane.0.inbound_manager.has_unhealthy_inbound()
    }

    pub(crate) fn unhealthy_inbound(&self) -> Option<InboundFailure> {
        self.data_plane.0.inbound_manager.unhealthy_inbound()
    }

    pub(crate) async fn wait_for_inbound_failure(&self) -> InboundFailure {
        self.data_plane.0.inbound_manager.wait_for_failure().await
    }

    pub(crate) fn mark_running(&self) -> bool {
        self.lifecycle
            .compare_exchange(
                RuntimeLifecycleState::Starting as u8,
                RuntimeLifecycleState::Running as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub(crate) fn begin_draining(&self) -> bool {
        loop {
            let current = self.lifecycle.load(Ordering::Acquire);
            let state = RuntimeLifecycleState::from_u8(current);
            match state {
                RuntimeLifecycleState::Starting | RuntimeLifecycleState::Running => {
                    if self
                        .lifecycle
                        .compare_exchange(
                            current,
                            RuntimeLifecycleState::Draining as u8,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                RuntimeLifecycleState::Draining
                | RuntimeLifecycleState::Stopped
                | RuntimeLifecycleState::Failed => return false,
            }
        }
    }

    pub(crate) fn finish_shutdown(&self, failed: bool) {
        let state = if failed {
            RuntimeLifecycleState::Failed
        } else {
            RuntimeLifecycleState::Stopped
        };
        self.lifecycle.store(state as u8, Ordering::Release);
    }

    pub(crate) fn spawn_inbound_connection<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.data_plane.0.connection_tasks.spawn(future)
    }

    pub(crate) fn close_inbound_connection_tasks(&self) -> bool {
        self.data_plane.0.connection_tasks.close()
    }

    pub(crate) async fn drain_inbound_connection_tasks(
        &self,
        grace_period: Duration,
    ) -> ConnectionTaskShutdown {
        self.data_plane
            .0
            .connection_tasks
            .drain_or_cancel(grace_period)
            .await
    }

    #[cfg(test)]
    pub(crate) fn tracked_inbound_connection_count(&self) -> usize {
        self.data_plane.0.connection_tasks.len()
    }

    pub fn replace_policy(&self, policy: Option<&PolicyConfig>) {
        *self
            .data_plane
            .0
            .policy
            .write()
            .expect("runtime policy lock poisoned") =
            policy.cloned().unwrap_or_default();
    }

    pub fn xray_handshake_timeout_for_level(&self, level: u32) -> Duration {
        const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 60;

        let seconds = self
            .data_plane
            .0
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
            .data_plane
            .0
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
        let policy = self
            .data_plane
            .0
            .policy
            .read()
            .expect("runtime policy lock poisoned");
        let level_policy = policy.levels.get(&level).and_then(Option::as_ref);
        PolicyUserStats {
            uplink: level_policy.is_some_and(|policy| policy.stats_user_uplink),
            downlink: level_policy.is_some_and(|policy| policy.stats_user_downlink),
            online: level_policy.is_some_and(|policy| policy.stats_user_online),
        }
    }

    pub(crate) fn policy_system_stats(&self) -> PolicySystemStats {
        let policy = self
            .data_plane
            .0
            .policy
            .read()
            .expect("runtime policy lock poisoned");
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
        let user = self.data_plane.0.policy_user_stats(context.user_level);
        let system = self.data_plane.0.policy_system_stats();
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

        let policy = self
            .data_plane
            .0
            .policy
            .read()
            .expect("runtime policy lock poisoned");
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
        Arc::clone(&self.data_plane.0.inbound_manager)
    }

    pub fn inbounds(&self) -> Vec<ServerConfig> {
        self.data_plane.0.inbound_manager.configs()
    }

    pub fn inbound_by_tag(&self, tag: &str) -> Option<ServerConfig> {
        self.data_plane.0.inbound_manager.config_by_tag(tag)
    }

    pub fn with_inbound_mut<R, F>(&self, tag: &str, mutator: F) -> Option<R>
    where
        F: FnOnce(&mut ServerConfig) -> R,
    {
        self.data_plane
            .0
            .inbound_manager
            .with_config_mut(tag, mutator)
    }

    pub fn remove_inbound(&self, tag: &str) -> Option<ServerConfig> {
        self.data_plane.0.inbound_manager.remove_config(tag)
    }

    pub fn add_inbound(&self, inbound: ServerConfig) -> Result<(), String> {
        self.data_plane.0.inbound_manager.add_config(inbound)
    }

    pub fn register_inbound_tasks(&self, tag: &str, handles: Vec<JoinHandle<()>>) {
        self.data_plane
            .0
            .inbound_manager
            .register_tasks(tag, handles);
    }

    pub async fn stop_inbound_tasks(&self, tag: &str) -> bool {
        self.data_plane.0.inbound_manager.stop_tasks(tag).await
    }

    #[cfg(feature = "vless")]
    pub(crate) fn vless_users_snapshot(&self, tag: &str) -> Option<Vec<VlessUser>> {
        self.data_plane.0.inbound_manager.vless_users_snapshot(tag)
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
        self.data_plane
            .0
            .inbound_manager
            .alter_users(self.clone(), tag, update_config, update_vless_users)
            .await
    }

    #[cfg(feature = "vmess")]
    pub(crate) fn vmess_user_store(&self, tag: &str) -> Option<Arc<VmessUserStore>> {
        self.data_plane.0.inbound_manager.vmess_user_store(tag)
    }

    #[cfg(feature = "trojan")]
    pub(crate) fn trojan_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<TrojanUserStore>> {
        self.data_plane.0.inbound_manager.trojan_user_store(tag)
    }

    #[cfg(feature = "hysteria")]
    pub(crate) fn hysteria_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<HysteriaUserStore>> {
        self.data_plane.0.inbound_manager.hysteria_user_store(tag)
    }

    #[cfg(feature = "shadowsocks")]
    pub(crate) fn shadowsocks_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<ShadowsocksUserStore>> {
        self.data_plane
            .0
            .inbound_manager
            .shadowsocks_user_store(tag)
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
        self.data_plane
            .0
            .inbound_manager
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
        self.data_plane
            .0
            .inbound_manager
            .alter_trojan_users(
                self.clone(),
                tag,
                update_config,
                update_trojan_users,
            )
            .await
    }

    #[cfg(feature = "hysteria")]
    pub(crate) async fn alter_hysteria_users<E, F, U>(
        &self,
        tag: &str,
        update_config: F,
        update_hysteria_users: U,
    ) -> Result<(), crate::inbound::AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&HysteriaUserStore) -> Result<(), E> + Send,
    {
        self.data_plane
            .0
            .inbound_manager
            .alter_hysteria_users(
                self.clone(),
                tag,
                update_config,
                update_hysteria_users,
            )
            .await
    }

    #[cfg(feature = "shadowsocks")]
    pub(crate) async fn alter_shadowsocks_users<E, F, U>(
        &self,
        tag: &str,
        update_config: F,
        update_shadowsocks_users: U,
    ) -> Result<(), crate::inbound::AlterInboundError<E>>
    where
        E: Send,
        F: FnOnce(&ServerConfig) -> Result<ServerConfig, E> + Send,
        U: FnOnce(&ShadowsocksUserStore) -> Result<(), E> + Send,
    {
        self.data_plane
            .0
            .inbound_manager
            .alter_shadowsocks_users(
                self.clone(),
                tag,
                update_config,
                update_shadowsocks_users,
            )
            .await
    }

    pub fn outbounds(&self) -> Vec<OutboundSummary> {
        self.outbound_snapshot().as_ref().clone()
    }

    fn routing_publication(&self) -> Arc<RoutingPublication> {
        Arc::clone(
            &self
                .data_plane
                .0
                .routing_publication
                .read()
                .expect("runtime routing publication lock poisoned"),
        )
    }

    fn outbound_snapshot(&self) -> Arc<Vec<OutboundSummary>> {
        Arc::clone(&self.data_plane.0.routing_publication().outbounds)
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
        let publication = self.data_plane.0.routing_publication();
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
        self.data_plane.0.routing_events.subscribe()
    }

    pub(crate) fn publish_routing_event(&self, event: RoutingEvent) {
        let _ = self.data_plane.0.routing_events.send(event);
    }

    pub(crate) fn balancer_overrides(&self) -> HashMap<String, String> {
        self.balancer_override_snapshot().as_ref().clone()
    }

    fn balancer_override_snapshot(&self) -> Arc<HashMap<String, String>> {
        Arc::clone(
            &self
                .data_plane
                .0
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
            .data_plane
            .0
            .balancer_overrides
            .write()
            .expect("runtime balancer overrides lock poisoned");
        let mut next = current.as_ref().clone();
        next.insert(balancer_tag.into(), outbound_tag.into());
        *current = Arc::new(next);
    }

    pub(crate) fn remove_balancer_override(&self, tag: &str) -> bool {
        let mut current = self
            .data_plane
            .0
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
        let current = self.data_plane.0.routing_publication();
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
        let current = self.data_plane.0.routing_publication();
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
        Arc::clone(&self.data_plane.0.routing_publication().routing)
    }

    pub fn replace_routing(&self, routing: RoutingState) {
        let _update = self
            .routing_updates
            .lock()
            .expect("runtime routing update lock poisoned");
        let current = self.data_plane.0.routing_publication();
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
            .data_plane
            .0
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
        let current = self.data_plane.0.routing_publication();
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
        self.data_plane.0.user_domain_access.apply(publication)
    }

    pub(crate) fn rollback_user_domain_policy(
        &self,
        version: u64,
    ) -> Result<UserDomainAccessRevision, UserDomainAccessFailure> {
        self.data_plane.0.user_domain_access.rollback(version)
    }

    pub(crate) fn user_domain_policy_status(&self) -> UserDomainAccessStatus {
        self.data_plane.0.user_domain_access.status()
    }

    pub(crate) fn allows_user_domain_access(
        &self,
        identity: &str,
        target_domain: &str,
    ) -> bool {
        self.data_plane
            .0
            .user_domain_access
            .allows(identity, target_domain)
    }
}

#[cfg(test)]
mod tests;
