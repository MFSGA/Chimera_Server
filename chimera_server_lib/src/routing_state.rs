use std::{collections::HashMap, net::IpAddr, sync::Arc};

use crate::{
    config::rule::{BalancerConfig, RoutingConfig, RuleConfig},
    geodata::GeodataStore,
    runtime::OutboundSummary,
};

mod balancer;
mod rule;

pub(crate) use balancer::BalancerTargetMap;
use balancer::*;
use rule::*;

#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    balancers: HashMap<String, CompiledBalancer>,
    rules: Vec<CompiledRule>,
    domain_strategy: DomainStrategy,
    geodata: GeodataStore,
    // Active Observatory results are authoritative for balancers. Passive
    // connect results are retained separately and are only used as a fallback
    // when no active sample exists for a tag.
    observations: Arc<ObservationStore>,
    passive_observations: Arc<ObservationStore>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SniffExclusionMatcher {
    domains: Vec<DomainMatcher>,
    ips: IpMatcher,
}

impl SniffExclusionMatcher {
    pub(crate) fn compile(
        domains: Vec<String>,
        ips: Vec<String>,
    ) -> Result<Self, String> {
        let mut geodata = GeodataStore::default();
        let rule = RuleConfig {
            domain: domains,
            ip: ips,
            outbound_tag: Some("__sniff_exclusion__".into()),
            ..RuleConfig::default()
        };
        if rule_uses_geoip(&rule) {
            geodata.ensure_default_geoip()?;
        }
        if rule_uses_geosite(&rule) {
            geodata.ensure_default_geosite()?;
        }

        let domains = expand_geosite_values(&geodata, rule.domain)?
            .into_iter()
            .map(|value| parse_domain_matcher(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let ips =
            IpMatcher::from_xray_values(expand_geoip_values(&geodata, rule.ip)?)?;
        Ok(Self { domains, ips })
    }

    pub(crate) fn excludes_domain(&self, domain: &str) -> bool {
        !self.domains.is_empty() && matches_domains(&self.domains, domain)
    }

    pub(crate) fn excludes_ip(&self, ip: IpAddr) -> bool {
        if !self.ips.configured {
            return false;
        }
        let encoded = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        self.ips.matches(&[encoded])
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundObservation {
    pub alive: bool,
    pub delay_ms: i64,
    pub last_error_reason: String,
    pub last_seen_time: i64,
    pub last_try_time: i64,
    pub health_all: i64,
    pub health_fail: i64,
    pub health_deviation_ms: i64,
    pub health_average_ms: i64,
    pub health_max_ms: i64,
    pub health_min_ms: i64,
}

fn merge_outbound_observation(
    previous: Option<&OutboundObservation>,
    mut observation: OutboundObservation,
) -> OutboundObservation {
    let Some(previous) = previous else {
        return observation;
    };

    if observation.last_seen_time == 0 {
        observation.last_seen_time = previous.last_seen_time;
    }
    if observation.health_all == 0 && previous.health_all > 0 {
        observation.health_all = previous.health_all;
        observation.health_fail = previous.health_fail;
        observation.health_deviation_ms = previous.health_deviation_ms;
        observation.health_average_ms = previous.health_average_ms;
        observation.health_max_ms = previous.health_max_ms;
        observation.health_min_ms = previous.health_min_ms;
    }
    observation
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

impl DomainStrategy {
    pub(crate) fn from_xray_name(value: Option<&str>) -> Self {
        match value
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "ipifnonmatch" => Self::IpIfNonMatch,
            "ipondemand" => Self::IpOnDemand,
            _ => Self::AsIs,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RoutingInput {
    pub inbound_tag: String,
    pub network: i32,
    pub source_ips: Vec<Vec<u8>>,
    pub target_ips: Vec<Vec<u8>>,
    pub source_port: u32,
    pub target_port: u32,
    pub target_domain: String,
    pub protocol: String,
    pub user: String,
    pub process_id: u32,
    pub process_name: String,
    pub process_path: String,
    pub attributes: HashMap<String, String>,
    pub local_ips: Vec<Vec<u8>>,
    pub local_port: u32,
    pub vless_route: u32,
}

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub outbound_tag: String,
    pub outbound_group_tags: Vec<String>,
    pub rule_tag: String,
    pub resolution_error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RoutingEvent {
    pub input: RoutingInput,
    pub route: RouteMatch,
}

impl RoutingState {
    pub fn from_config(config: Option<&RoutingConfig>) -> Result<Self, String> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        let mut state = Self::default();
        state.merge_with_domain_strategy(
            config.rules.clone(),
            config.balancers.clone(),
            false,
            Some(DomainStrategy::from_xray_name(
                config.domain_strategy.as_deref(),
            )),
        )?;
        Ok(state)
    }

    pub fn from_parts(
        rules: Vec<RuleConfig>,
        balancers: Vec<BalancerConfig>,
    ) -> Result<Self, String> {
        let mut state = Self::default();
        state.merge(rules, balancers, false)?;
        Ok(state)
    }

    pub fn merge(
        &mut self,
        rules: Vec<RuleConfig>,
        balancers: Vec<BalancerConfig>,
        should_append: bool,
    ) -> Result<(), String> {
        self.merge_with_domain_strategy(rules, balancers, should_append, None)
    }

    pub(crate) fn merge_with_domain_strategy(
        &mut self,
        rules: Vec<RuleConfig>,
        balancers: Vec<BalancerConfig>,
        should_append: bool,
        domain_strategy: Option<DomainStrategy>,
    ) -> Result<(), String> {
        let mut next = if should_append {
            self.clone()
        } else {
            Self {
                geodata: self.geodata.clone(),
                observations: Arc::clone(&self.observations),
                passive_observations: Arc::clone(&self.passive_observations),
                ..Self::default()
            }
        };
        if let Some(domain_strategy) = domain_strategy {
            next.domain_strategy = domain_strategy;
        }
        let rules = rules
            .into_iter()
            .map(normalize_rule_aliases)
            .collect::<Vec<_>>();
        next.ensure_geodata_for_rules(&rules)?;
        let rules = rules
            .into_iter()
            .map(|rule| next.expand_geodata_rule(rule))
            .collect::<Result<Vec<_>, _>>()?;

        for balancer in balancers {
            let tag = balancer.tag.clone();
            if next.balancers.contains_key(&tag) {
                return Err(format!("duplicate routing balancer {tag}"));
            }
            next.balancers
                .insert(tag, CompiledBalancer::try_from(balancer)?);
        }

        for rule in rules {
            let compiled = CompiledRule::try_from(rule)?;
            if let RuleTarget::Balancer(tag) = &compiled.target
                && !next.balancers.contains_key(tag)
            {
                return Err(format!("routing balancer {tag} not found"));
            }
            if !compiled.rule_tag.is_empty()
                && next
                    .rules
                    .iter()
                    .any(|item| item.rule_tag == compiled.rule_tag)
            {
                return Err(format!(
                    "duplicate routing ruleTag {}",
                    compiled.rule_tag
                ));
            }
            next.rules.push(compiled);
        }

        *self = next;
        Ok(())
    }

    fn ensure_geodata_for_rules(
        &mut self,
        rules: &[RuleConfig],
    ) -> Result<(), String> {
        let needs_geoip = rules.iter().any(rule_uses_geoip);
        let needs_geosite = rules.iter().any(rule_uses_geosite);
        if needs_geoip {
            self.geodata.ensure_default_geoip()?;
        }
        if needs_geosite {
            self.geodata.ensure_default_geosite()?;
        }
        Ok(())
    }

    fn expand_geodata_rule(
        &self,
        mut rule: RuleConfig,
    ) -> Result<RuleConfig, String> {
        rule.ip = expand_geoip_values(&self.geodata, rule.ip)?;
        rule.source_ip = expand_geoip_values(&self.geodata, rule.source_ip)?;
        rule.source = expand_geoip_values(&self.geodata, rule.source)?;
        rule.local_ip = expand_geoip_values(&self.geodata, rule.local_ip)?;
        rule.domain = expand_geosite_values(&self.geodata, rule.domain)?;
        rule.domains = expand_geosite_values(&self.geodata, rule.domains)?;
        Ok(rule)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_with_geodata(
        rules: Vec<RuleConfig>,
        balancers: Vec<BalancerConfig>,
        geodata: GeodataStore,
    ) -> Result<Self, String> {
        let mut state = Self {
            geodata,
            ..Self::default()
        };
        state.merge(rules, balancers, false)?;
        Ok(state)
    }

    pub(crate) fn inherit_observations_from(&mut self, other: &RoutingState) {
        self.observations = Arc::clone(&other.observations);
        self.passive_observations = Arc::clone(&other.passive_observations);
    }

    pub(crate) fn record_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.observations.record(tag.into(), observation);
    }

    pub(crate) fn record_passive_observation(
        &self,
        tag: impl Into<String>,
        observation: OutboundObservation,
    ) {
        self.passive_observations.record(tag.into(), observation);
    }

    pub(crate) fn observation(&self, tag: &str) -> Option<OutboundObservation> {
        self.observations
            .get(tag)
            .or_else(|| self.passive_observations.get(tag))
            .map(|observation| observation.as_ref().clone())
    }

    pub(crate) fn remove_observation(
        &self,
        tag: &str,
    ) -> Option<OutboundObservation> {
        let active = self.observations.remove(tag);
        let passive = self.passive_observations.remove(tag);
        active.or(passive)
    }

    pub(crate) fn observations(&self) -> HashMap<String, OutboundObservation> {
        let mut observations = self.passive_observations.snapshot_all();
        observations.extend(self.observations.snapshot_all());
        observations
    }

    fn observation_snapshot_for(
        &self,
        targets: &BalancerTargetSet,
    ) -> ObservationSnapshot {
        let active = self.observations.snapshot_for(targets);
        let passive = self.passive_observations.snapshot_for(targets);
        active
            .into_iter()
            .zip(passive)
            .map(|(active, passive)| active.or(passive))
            .collect()
    }

    pub(crate) fn requires_process_lookup(&self) -> bool {
        self.rules.iter().any(|rule| rule.processes.configured)
    }

    pub(crate) fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }

    pub(crate) fn needs_target_ip_resolution(&self, input: &RoutingInput) -> bool {
        if self.domain_strategy != DomainStrategy::IpOnDemand
            || input.target_domain.is_empty()
            || !input.target_ips.is_empty()
        {
            return false;
        }
        for rule in &self.rules {
            if !rule.matches_before_target_ip(input) {
                continue;
            }
            if rule.target_ips.configured {
                return true;
            }
            if rule.matches_with_target_ips(input, &[]) {
                return false;
            }
        }
        false
    }

    pub(crate) fn needs_process_lookup(&self, input: &RoutingInput) -> bool {
        if input.process_id != 0
            || !input.process_name.is_empty()
            || !input.process_path.is_empty()
        {
            return false;
        }
        for rule in &self.rules {
            if !rule.matches_before_process(input) {
                continue;
            }
            if rule.processes.configured {
                return true;
            }
            return false;
        }
        false
    }

    pub(crate) fn list_rules(&self) -> Vec<RoutingRuleSummary> {
        self.rules
            .iter()
            .map(|rule| RoutingRuleSummary {
                outbound_tag: match &rule.target {
                    RuleTarget::Outbound(tag) => tag.clone(),
                    RuleTarget::Balancer(_) => String::new(),
                },
                rule_tag: rule.rule_tag.clone(),
            })
            .collect()
    }

    pub fn remove_rule(&mut self, rule_tag: &str) -> bool {
        let original_len = self.rules.len();
        self.rules.retain(|rule| rule.rule_tag != rule_tag);
        self.rules.len() != original_len
    }

    pub fn route(
        &self,
        input: &RoutingInput,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
    ) -> Option<RouteMatch> {
        self.route_with_target_map(input, outbounds, balancer_overrides, None)
    }

    pub(crate) fn route_with_balancer_targets(
        &self,
        input: &RoutingInput,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
        balancer_targets: &BalancerTargetMap,
    ) -> Option<RouteMatch> {
        self.route_with_target_map(
            input,
            outbounds,
            balancer_overrides,
            Some(balancer_targets),
        )
    }

    fn route_with_target_map(
        &self,
        input: &RoutingInput,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
        balancer_targets: Option<&BalancerTargetMap>,
    ) -> Option<RouteMatch> {
        if input.target_domain.is_empty()
            || self.domain_strategy == DomainStrategy::IpOnDemand
        {
            return self.route_once(
                input,
                outbounds,
                balancer_overrides,
                balancer_targets,
            );
        }

        let domain_match = self.route_once_with_target_ips(
            input,
            &[],
            outbounds,
            balancer_overrides,
            balancer_targets,
        );
        if domain_match.is_some() || self.domain_strategy == DomainStrategy::AsIs {
            return domain_match;
        }

        self.route_once(input, outbounds, balancer_overrides, balancer_targets)
    }

    fn route_once(
        &self,
        input: &RoutingInput,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
        balancer_targets: Option<&BalancerTargetMap>,
    ) -> Option<RouteMatch> {
        self.route_once_with_target_ips(
            input,
            &input.target_ips,
            outbounds,
            balancer_overrides,
            balancer_targets,
        )
    }

    fn route_once_with_target_ips(
        &self,
        input: &RoutingInput,
        target_ips: &[Vec<u8>],
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
        balancer_targets: Option<&BalancerTargetMap>,
    ) -> Option<RouteMatch> {
        for rule in &self.rules {
            if !rule.matches_with_target_ips(input, target_ips) {
                continue;
            }
            let (outbound_tag, outbound_group_tags) = self.resolve_target(
                &rule.target,
                outbounds,
                balancer_overrides,
                balancer_targets,
            );
            if let (Some(webhook), Some(outbound_tag)) =
                (&rule.webhook, outbound_tag.as_deref())
            {
                webhook.fire(input, outbound_tag);
            }
            let resolution_error = outbound_tag.is_none().then(|| {
                format!(
                    "routing balancer {} has no available outbound",
                    outbound_group_tags
                        .first()
                        .map(String::as_str)
                        .unwrap_or("<unknown>")
                )
            });
            return Some(RouteMatch {
                outbound_tag: outbound_tag.unwrap_or_default(),
                outbound_group_tags,
                rule_tag: rule.rule_tag.clone(),
                resolution_error,
            });
        }
        None
    }

    pub(crate) fn has_balancer(&self, tag: &str) -> bool {
        self.balancers.contains_key(tag)
    }

    pub fn balancer_targets(
        &self,
        balancer_tag: &str,
        outbounds: &[OutboundSummary],
    ) -> Vec<String> {
        let Some(balancer) = self.balancers.get(balancer_tag) else {
            return outbounds
                .iter()
                .filter(|outbound| outbound.tag == balancer_tag)
                .map(|outbound| outbound.tag.clone())
                .collect();
        };

        let mut targets = outbounds
            .iter()
            .filter(|outbound| {
                balancer
                    .outbound_selector
                    .iter()
                    .any(|selector| outbound.tag.starts_with(selector))
            })
            .map(|outbound| outbound.tag.clone())
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        targets
    }

    pub(crate) fn compile_balancer_targets(
        &self,
        outbounds: &[OutboundSummary],
    ) -> BalancerTargetMap {
        self.balancers
            .keys()
            .map(|tag| {
                (
                    tag.clone(),
                    BalancerTargetSet::new(self.balancer_targets(tag, outbounds)),
                )
            })
            .collect()
    }

    pub(crate) fn balancer_principle_targets(
        &self,
        balancer_tag: &str,
        outbounds: &[OutboundSummary],
    ) -> Vec<String> {
        let targets =
            BalancerTargetSet::new(self.balancer_targets(balancer_tag, outbounds));
        let Some(balancer) = self.balancers.get(balancer_tag) else {
            return targets.tags.as_ref().to_vec();
        };
        let observations = balancer
            .needs_observations()
            .then(|| self.observation_snapshot_for(&targets));
        balancer.principle_targets(
            targets.tags.as_ref(),
            outbounds,
            observations.as_deref(),
        )
    }

    fn resolve_target(
        &self,
        target: &RuleTarget,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
        balancer_targets: Option<&BalancerTargetMap>,
    ) -> (Option<String>, Vec<String>) {
        match target {
            RuleTarget::Outbound(tag) => (Some(tag.clone()), Vec::new()),
            RuleTarget::Balancer(balancer_tag) => {
                if let Some(target) = balancer_overrides.get(balancer_tag) {
                    return (Some(target.clone()), vec![balancer_tag.clone()]);
                }
                let owned_targets;
                let targets = match balancer_targets
                    .and_then(|targets| targets.get(balancer_tag))
                {
                    Some(targets) => targets,
                    None => {
                        owned_targets = BalancerTargetSet::new(
                            self.balancer_targets(balancer_tag, outbounds),
                        );
                        &owned_targets
                    }
                };
                let target = self.balancers.get(balancer_tag).and_then(|balancer| {
                    let observations = balancer
                        .needs_observations()
                        .then(|| self.observation_snapshot_for(targets));
                    balancer.pick(
                        targets.tags.as_ref(),
                        outbounds,
                        observations.as_deref(),
                    )
                });
                (target, vec![balancer_tag.clone()])
            }
        }
    }
}

#[cfg(test)]
mod tests;
