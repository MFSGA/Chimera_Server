use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use tokio::sync::broadcast;

#[cfg(feature = "vless")]
use crate::config::server_config::VlessUser;
#[cfg(feature = "hysteria")]
use crate::handler::hysteria2::connection::HysteriaUserStore;
#[cfg(feature = "shadowsocks")]
use crate::handler::shadowsocks::ShadowsocksUserStore;
#[cfg(feature = "trojan")]
use crate::handler::trojan::TrojanUserStore;
#[cfg(feature = "vmess")]
use crate::handler::vmess::vmess_handler::VmessUserStore;
use crate::{
    config::def::PolicyConfig,
    inbound::InboundManager,
    routing_state::{
        OutboundObservation, RouteMatch, RoutingEvent, RoutingInput, RoutingState,
    },
    session_tasks::ConnectionTaskOwner,
    traffic::TrafficContext,
    user_domain::UserDomainAccessStore,
};

use super::{
    OutboundSummary, PolicyRelayTimeouts, PolicySystemStats, PolicyUserStats,
    RoutingPublication,
};

#[derive(Debug)]
pub(super) struct DataPlaneState {
    pub(super) inbound_manager: Arc<InboundManager>,
    pub(super) routing_publication: Arc<RwLock<Arc<RoutingPublication>>>,
    pub(super) policy: Arc<RwLock<PolicyConfig>>,
    pub(super) user_domain_access: UserDomainAccessStore,
    pub(super) balancer_overrides: Arc<RwLock<Arc<HashMap<String, String>>>>,
    pub(super) routing_events: broadcast::Sender<RoutingEvent>,
    pub(super) connection_tasks: ConnectionTaskOwner,
}

impl DataPlaneState {
    pub(super) fn spawn_inbound_connection<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.connection_tasks.spawn(future)
    }

    #[cfg(test)]
    pub(super) fn tracked_inbound_connection_count(&self) -> usize {
        self.connection_tasks.len()
    }

    pub(super) fn xray_handshake_timeout_for_level(&self, level: u32) -> Duration {
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

    pub(super) fn xray_connection_idle_timeout_for_level(
        &self,
        level: u32,
    ) -> Duration {
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

    pub(super) fn policy_user_stats(&self, level: u32) -> PolicyUserStats {
        let policy = self.policy.read().expect("runtime policy lock poisoned");
        let level_policy = policy.levels.get(&level).and_then(Option::as_ref);
        PolicyUserStats {
            uplink: level_policy.is_some_and(|policy| policy.stats_user_uplink),
            downlink: level_policy.is_some_and(|policy| policy.stats_user_downlink),
            online: level_policy.is_some_and(|policy| policy.stats_user_online),
        }
    }

    pub(super) fn policy_system_stats(&self) -> PolicySystemStats {
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

    pub(super) fn apply_traffic_stats_policy(&self, context: &mut TrafficContext) {
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

    pub(super) fn policy_relay_timeouts(&self, level: u32) -> PolicyRelayTimeouts {
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

    pub(super) fn routing_publication(&self) -> Arc<RoutingPublication> {
        Arc::clone(
            &self
                .routing_publication
                .read()
                .expect("runtime routing publication lock poisoned"),
        )
    }

    pub(super) fn routing(&self) -> Arc<RoutingState> {
        Arc::clone(&self.routing_publication().routing)
    }

    pub(super) fn balancer_override_snapshot(&self) -> Arc<HashMap<String, String>> {
        Arc::clone(
            &self
                .balancer_overrides
                .read()
                .expect("runtime balancer overrides lock poisoned"),
        )
    }

    fn publish_routing_event(&self, event: RoutingEvent) {
        let _ = self.routing_events.send(event);
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

    pub(super) fn select_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        self.select_outbound_checked_internal(input, true)
    }

    pub(super) fn match_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        self.select_outbound_checked_internal(input, false)
    }

    pub(super) fn allows_user_domain_access(
        &self,
        identity: &str,
        target_domain: &str,
    ) -> bool {
        self.user_domain_access.allows(identity, target_domain)
    }

    pub(super) fn record_passive_outbound_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.routing().record_passive_observation(tag, observation);
    }
}

#[derive(Debug, Clone)]
pub struct DataPlaneRuntime(pub(super) Arc<DataPlaneState>);

impl DataPlaneRuntime {
    pub(crate) fn spawn_inbound_connection<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.0.spawn_inbound_connection(future)
    }

    #[cfg(test)]
    pub(crate) fn tracked_inbound_connection_count(&self) -> usize {
        self.0.tracked_inbound_connection_count()
    }

    pub fn xray_handshake_timeout_for_level(&self, level: u32) -> Duration {
        self.0.xray_handshake_timeout_for_level(level)
    }

    pub fn xray_connection_idle_timeout_for_level(&self, level: u32) -> Duration {
        self.0.xray_connection_idle_timeout_for_level(level)
    }

    pub(crate) fn policy_user_stats(&self, level: u32) -> PolicyUserStats {
        self.0.policy_user_stats(level)
    }

    pub(crate) fn apply_traffic_stats_policy(&self, context: &mut TrafficContext) {
        self.0.apply_traffic_stats_policy(context)
    }

    pub(crate) fn policy_relay_timeouts(&self, level: u32) -> PolicyRelayTimeouts {
        self.0.policy_relay_timeouts(level)
    }

    #[cfg(feature = "vless")]
    pub(crate) fn vless_users_snapshot(&self, tag: &str) -> Option<Vec<VlessUser>> {
        self.0.inbound_manager.vless_users_snapshot(tag)
    }

    #[cfg(feature = "vmess")]
    pub(crate) fn vmess_user_store(&self, tag: &str) -> Option<Arc<VmessUserStore>> {
        self.0.inbound_manager.vmess_user_store(tag)
    }

    #[cfg(feature = "trojan")]
    pub(crate) fn trojan_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<TrojanUserStore>> {
        self.0.inbound_manager.trojan_user_store(tag)
    }

    #[cfg(feature = "hysteria")]
    pub(crate) fn hysteria_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<HysteriaUserStore>> {
        self.0.inbound_manager.hysteria_user_store(tag)
    }

    #[cfg(feature = "shadowsocks")]
    pub(crate) fn shadowsocks_user_store(
        &self,
        tag: &str,
    ) -> Option<Arc<ShadowsocksUserStore>> {
        self.0.inbound_manager.shadowsocks_user_store(tag)
    }

    pub(crate) fn select_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        self.0.select_outbound_checked(input)
    }

    pub(crate) fn match_outbound_checked(
        &self,
        input: &RoutingInput,
    ) -> Result<Option<OutboundSummary>, String> {
        self.0.match_outbound_checked(input)
    }

    pub(crate) fn routing_domain_strategy(
        &self,
    ) -> crate::routing_state::DomainStrategy {
        self.0.routing().domain_strategy()
    }

    pub(crate) fn routing_needs_target_ip_resolution(
        &self,
        input: &RoutingInput,
    ) -> bool {
        self.0.routing().needs_target_ip_resolution(input)
    }

    pub(crate) fn routing_needs_process_lookup(&self, input: &RoutingInput) -> bool {
        self.0.routing().needs_process_lookup(input)
    }

    pub(crate) fn allows_user_domain_access(
        &self,
        identity: &str,
        target_domain: &str,
    ) -> bool {
        self.0.allows_user_domain_access(identity, target_domain)
    }

    pub(crate) fn record_passive_outbound_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.0.record_passive_outbound_observation(tag, observation);
    }
}
