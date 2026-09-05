use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use rand::RngExt;
use regex::Regex;

use crate::{
    config::rule::{
        BalancerConfig, NetworkListConfig, PortRangeConfig, RoutingConfig,
        RuleConfig,
    },
    geodata::GeodataStore,
    routing_webhook::RoutingWebhook,
    runtime::OutboundSummary,
};

const INTERNAL_NEVER_IP_RULE: &str = "\0chimera:never-ip";
const INTERNAL_NEVER_DOMAIN_RULE: &str = "\0chimera:never-domain";
const LEAST_PING_MAX_DELAY_MS: i64 = 99_999_999;

#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    balancers: HashMap<String, CompiledBalancer>,
    rules: Vec<CompiledRule>,
    domain_strategy: DomainStrategy,
    geodata: GeodataStore,
    observations: Arc<RwLock<HashMap<String, OutboundObservation>>>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoutingRuleSummary {
    pub outbound_tag: String,
    pub rule_tag: String,
}

#[derive(Debug, Clone)]
struct CompiledBalancer {
    outbound_selector: Vec<String>,
    fallback_tag: Option<String>,
    strategy: BalancerStrategy,
}

#[derive(Debug, Clone)]
enum BalancerStrategy {
    Random,
    RoundRobin(Arc<AtomicU64>),
    LeastPing,
    LeastLoad(LeastLoadConfig),
}

#[derive(Debug, Clone, Default)]
struct LeastLoadConfig {
    costs: Vec<StrategyWeight>,
    baselines_ms: Vec<f64>,
    expected: usize,
    max_rtt_ms: Option<f64>,
    tolerance: f64,
}

#[derive(Debug, Clone)]
struct StrategyWeight {
    matcher: WeightMatcher,
    value: f64,
}

#[derive(Debug, Clone)]
enum WeightMatcher {
    Never,
    Substring(String),
    Regexp(Regex),
}

#[derive(Debug, Clone)]
struct LeastLoadNode {
    tag: String,
    all: i64,
    fail: i64,
    average_ms: f64,
    deviation_cost_ms: f64,
}

#[derive(Debug, Clone)]
enum RuleTarget {
    Outbound(String),
    Balancer(String),
}

#[derive(Debug, Clone)]
struct CompiledRule {
    attrs: AttributeMatcher,
    inbound_tags: Vec<String>,
    local_ips: IpMatcher,
    local_ports: Vec<PortRangeConfig>,
    networks: Vec<String>,
    processes: ProcessMatcher,
    protocols: ProtocolMatcher,
    rule_tag: String,
    source_ips: IpMatcher,
    source_ports: Vec<PortRangeConfig>,
    target: RuleTarget,
    target_domains: Vec<DomainMatcher>,
    target_ips: IpMatcher,
    target_ports: Vec<PortRangeConfig>,
    users: UserMatcher,
    vless_routes: Vec<PortRangeConfig>,
    webhook: Option<Arc<RoutingWebhook>>,
}

#[derive(Debug, Clone)]
enum DomainMatcher {
    Never,
    Plain(String),
    Domain(String),
    Full(String),
    Regexp(Regex),
}

#[derive(Debug, Clone)]
struct CidrMatcher {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Default)]
struct IpMatcher {
    configured: bool,
    positive: Vec<CidrMatcher>,
    negative: Vec<CidrMatcher>,
}

impl IpMatcher {
    fn from_xray_values(values: Vec<String>) -> Result<Self, String> {
        let configured = !values.is_empty();
        let mut positive = Vec::new();
        let mut negative = Vec::new();
        for value in values {
            if value == INTERNAL_NEVER_IP_RULE {
                continue;
            }
            if let Some(value) = value.trim().strip_prefix('!') {
                negative.push(parse_cidr_matcher(value)?);
            } else {
                positive.push(parse_cidr_matcher(&value)?);
            }
        }
        Ok(Self {
            configured,
            positive,
            negative,
        })
    }

    fn matches(&self, inputs: &[Vec<u8>]) -> bool {
        if !self.configured {
            return true;
        }
        inputs
            .iter()
            .filter_map(|input| decode_ip(input))
            .any(|ip| {
                self.positive.iter().any(|matcher| matcher.matches(ip))
                    || self.matches_reverse(ip)
            })
    }

    fn matches_reverse(&self, input: IpAddr) -> bool {
        let mut has_family = false;
        for matcher in &self.negative {
            if !matches!(
                (matcher.addr, input),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            ) {
                continue;
            }
            has_family = true;
            if matcher.matches(input) {
                return false;
            }
        }
        has_family
    }
}

#[derive(Debug, Clone, Default)]
struct ProtocolMatcher {
    configured: bool,
    prefixes: Vec<String>,
}

impl ProtocolMatcher {
    fn from_xray_values(values: Vec<String>) -> Self {
        Self {
            configured: !values.is_empty(),
            prefixes: values
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }

    fn matches(&self, protocol: &str) -> bool {
        if !self.configured {
            return true;
        }
        !protocol.is_empty()
            && self
                .prefixes
                .iter()
                .any(|prefix| protocol.starts_with(prefix))
    }
}

#[derive(Debug, Clone, Default)]
struct AttributeMatcher {
    configured: bool,
    patterns: HashMap<String, Regex>,
}

impl AttributeMatcher {
    fn from_xray_values(values: HashMap<String, String>) -> Result<Self, String> {
        let configured = !values.is_empty();
        let mut patterns = HashMap::new();
        for (key, value) in values {
            let pattern = Regex::new(&value).map_err(|error| {
                format!("invalid routing attribute regexp {key}={value}: {error}")
            })?;
            patterns.insert(key.to_ascii_lowercase(), pattern);
        }
        Ok(Self {
            configured,
            patterns,
        })
    }

    fn matches(&self, attributes: &HashMap<String, String>) -> bool {
        if !self.configured {
            return true;
        }
        if attributes.is_empty() {
            return false;
        }
        let normalized = attributes
            .iter()
            .map(|(key, value)| (key.to_ascii_lowercase(), value))
            .collect::<HashMap<_, _>>();
        self.patterns.iter().all(|(key, pattern)| {
            normalized
                .get(key)
                .is_some_and(|value| pattern.is_match(value))
        })
    }
}

#[derive(Debug, Clone, Default)]
struct ProcessMatcher {
    configured: bool,
    match_self: bool,
    names: Vec<String>,
    paths: Vec<String>,
    folders: Vec<String>,
}

impl ProcessMatcher {
    fn from_xray_values(values: Vec<String>) -> Self {
        let configured = !values.is_empty();
        let mut matcher = Self {
            configured,
            ..Self::default()
        };
        for value in values {
            if value == "self/" {
                matcher.match_self = true;
                continue;
            }
            let value = if value == "xray/" {
                std::env::current_exe()
                    .ok()
                    .and_then(|path| path.to_str().map(ToOwned::to_owned))
                    .unwrap_or_default()
            } else {
                value
            };
            if value.is_empty() {
                continue;
            }
            let value = value.replace('\\', "/");
            if value.ends_with('/') {
                matcher.folders.push(value);
            } else if value.contains('/') {
                matcher.paths.push(value);
            } else {
                matcher
                    .names
                    .push(value.strip_suffix(".exe").unwrap_or(&value).to_string());
            }
        }
        matcher
    }

    fn matches(&self, input: &RoutingInput) -> bool {
        if !self.configured {
            return true;
        }
        if self.match_self && input.process_id == std::process::id() {
            return true;
        }
        let process_name = input
            .process_name
            .strip_suffix(".exe")
            .unwrap_or(&input.process_name);
        if !process_name.is_empty()
            && self.names.iter().any(|name| name == process_name)
        {
            return true;
        }
        let process_path = input.process_path.replace('\\', "/");
        if process_path.is_empty() {
            return false;
        }
        self.paths.iter().any(|path| path == &process_path)
            || self
                .folders
                .iter()
                .any(|folder| process_path.starts_with(folder))
    }
}

#[derive(Debug, Clone, Default)]
struct UserMatcher {
    configured: bool,
    exact: Vec<String>,
    regexp: Vec<Regex>,
}

impl UserMatcher {
    fn from_xray_values(values: Vec<String>) -> Self {
        let configured = !values.is_empty();
        let mut exact = Vec::new();
        let mut regexp = Vec::new();
        for value in values {
            if value.is_empty() {
                continue;
            }
            if let Some(pattern) = value.strip_prefix("regexp:") {
                if let Ok(pattern) = Regex::new(pattern) {
                    regexp.push(pattern);
                }
            } else {
                exact.push(value);
            }
        }
        Self {
            configured,
            exact,
            regexp,
        }
    }

    fn matches(&self, user: &str) -> bool {
        if !self.configured {
            return true;
        }
        if user.is_empty() {
            return false;
        }
        self.exact.iter().any(|value| value == user)
            || self.regexp.iter().any(|value| value.is_match(user))
    }
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
    }

    pub(crate) fn record_observation(
        &self,
        tag: impl Into<String>,
        mut observation: OutboundObservation,
    ) {
        if let Ok(mut observations) = self.observations.write() {
            let tag = tag.into();
            if let Some(previous) = observations.get(&tag) {
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
            }
            observations.insert(tag, observation);
        }
    }

    pub(crate) fn observations(&self) -> HashMap<String, OutboundObservation> {
        self.observations
            .read()
            .map(|observations| observations.clone())
            .unwrap_or_default()
    }

    pub(crate) fn requires_process_lookup(&self) -> bool {
        self.rules.iter().any(|rule| rule.processes.configured)
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
        if input.target_domain.is_empty()
            || self.domain_strategy == DomainStrategy::IpOnDemand
        {
            return self.route_once(input, outbounds, balancer_overrides);
        }

        let mut domain_only_input = input.clone();
        domain_only_input.target_ips.clear();
        let domain_match =
            self.route_once(&domain_only_input, outbounds, balancer_overrides);
        if domain_match.is_some() || self.domain_strategy == DomainStrategy::AsIs {
            return domain_match;
        }

        self.route_once(input, outbounds, balancer_overrides)
    }

    fn route_once(
        &self,
        input: &RoutingInput,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
    ) -> Option<RouteMatch> {
        for rule in &self.rules {
            if !rule.matches(input) {
                continue;
            }
            let (outbound_tag, outbound_group_tags) =
                self.resolve_target(&rule.target, outbounds, balancer_overrides);
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

    pub(crate) fn balancer_principle_targets(
        &self,
        balancer_tag: &str,
        outbounds: &[OutboundSummary],
    ) -> Vec<String> {
        let targets = self.balancer_targets(balancer_tag, outbounds);
        let Some(balancer) = self.balancers.get(balancer_tag) else {
            return targets;
        };
        let observations = self
            .observations
            .read()
            .map(|observations| observations.clone())
            .unwrap_or_default();
        balancer.principle_targets(&targets, outbounds, &observations)
    }

    fn resolve_target(
        &self,
        target: &RuleTarget,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
    ) -> (Option<String>, Vec<String>) {
        match target {
            RuleTarget::Outbound(tag) => (Some(tag.clone()), Vec::new()),
            RuleTarget::Balancer(balancer_tag) => {
                if let Some(target) = balancer_overrides.get(balancer_tag) {
                    return (Some(target.clone()), vec![balancer_tag.clone()]);
                }
                let targets = self.balancer_targets(balancer_tag, outbounds);
                let observations = self
                    .observations
                    .read()
                    .map(|observations| observations.clone())
                    .unwrap_or_default();
                let target = self.balancers.get(balancer_tag).and_then(|balancer| {
                    balancer.pick(&targets, outbounds, &observations)
                });
                (target, vec![balancer_tag.clone()])
            }
        }
    }
}

impl TryFrom<BalancerConfig> for CompiledBalancer {
    type Error = String;

    fn try_from(mut config: BalancerConfig) -> Result<Self, Self::Error> {
        if config.tag.trim().is_empty() {
            return Err("routing balancer tag is required".into());
        }
        config
            .outbound_selector
            .retain(|selector| !selector.trim().is_empty());
        if config.outbound_selector.is_empty() {
            return Err(format!(
                "routing balancer {} requires at least one outbound selector",
                config.tag
            ));
        }
        let strategy_name = config.strategy.kind.trim().to_ascii_lowercase();
        let strategy = match strategy_name.as_str() {
            "" | "random" => BalancerStrategy::Random,
            "roundrobin" => {
                BalancerStrategy::RoundRobin(Arc::new(AtomicU64::new(0)))
            }
            "leastping" => BalancerStrategy::LeastPing,
            "leastload" => BalancerStrategy::LeastLoad(
                LeastLoadConfig::from_settings(config.strategy.settings)?,
            ),
            strategy => {
                return Err(format!(
                    "routing balancer {} uses unknown strategy {strategy}",
                    config.tag
                ));
            }
        };
        Ok(Self {
            outbound_selector: config.outbound_selector,
            fallback_tag: config.fallback_tag,
            strategy,
        })
    }
}

impl CompiledBalancer {
    fn pick(
        &self,
        targets: &[String],
        outbounds: &[OutboundSummary],
        observations: &HashMap<String, OutboundObservation>,
    ) -> Option<String> {
        let candidates = if self.fallback_tag.is_some() {
            targets
                .iter()
                .filter(|tag| {
                    observations.get(*tag).is_none_or(|status| status.alive)
                })
                .cloned()
                .collect::<Vec<_>>()
        } else {
            targets.to_vec()
        };
        let selected = match &self.strategy {
            BalancerStrategy::Random if !candidates.is_empty() => candidates
                .get(rand::rng().random_range(0..candidates.len()))
                .cloned(),
            BalancerStrategy::RoundRobin(index) if !candidates.is_empty() => {
                candidates
                    .get(
                        index.fetch_add(1, Ordering::Relaxed) as usize
                            % candidates.len(),
                    )
                    .cloned()
            }
            BalancerStrategy::LeastPing => {
                let target = least_ping_target(targets, observations);
                (!target.is_empty()).then_some(target)
            }
            BalancerStrategy::LeastLoad(settings) => {
                let selected = settings.select(targets, observations);
                (!selected.is_empty()).then(|| {
                    selected[rand::rng().random_range(0..selected.len())].clone()
                })
            }
            _ => None,
        };
        selected.or_else(|| {
            self.fallback_tag.as_ref().and_then(|fallback| {
                outbounds
                    .iter()
                    .any(|outbound| outbound.tag == *fallback)
                    .then(|| fallback.clone())
            })
        })
    }

    fn principle_targets(
        &self,
        targets: &[String],
        _outbounds: &[OutboundSummary],
        observations: &HashMap<String, OutboundObservation>,
    ) -> Vec<String> {
        match &self.strategy {
            BalancerStrategy::LeastPing => {
                vec![least_ping_target(targets, observations)]
            }
            BalancerStrategy::LeastLoad(settings) => {
                settings.select(targets, observations)
            }
            _ => targets.to_vec(),
        }
    }
}

fn least_ping_target(
    targets: &[String],
    observations: &HashMap<String, OutboundObservation>,
) -> String {
    targets
        .iter()
        .filter_map(|tag| {
            observations
                .get(tag)
                .filter(|status| {
                    status.alive && status.delay_ms < LEAST_PING_MAX_DELAY_MS
                })
                .map(|status| (status.delay_ms, tag))
        })
        .min_by_key(|(delay, _)| *delay)
        .map(|(_, tag)| tag.clone())
        .unwrap_or_default()
}

impl LeastLoadConfig {
    fn from_settings(settings: Option<serde_json::Value>) -> Result<Self, String> {
        let Some(settings) = settings else {
            return Ok(Self::default());
        };
        let object = settings.as_object().ok_or_else(|| {
            "routing leastLoad strategy settings must be an object".to_string()
        })?;
        let expected = object
            .get("expected")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_default()
            .max(0) as usize;
        let max_rtt_ms = object
            .get("maxRTT")
            .map(parse_duration_millis)
            .transpose()?
            .filter(|value| *value > 0.0);
        let tolerance = object
            .get("tolerance")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_default()
            .clamp(0.0, 1.0);
        let mut baselines_ms = match object.get("baselines") {
            None => Vec::new(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(parse_duration_millis)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err("routing leastLoad baselines must be an array".into());
            }
        };
        baselines_ms.retain(|value| *value > 0.0);
        let costs = match object.get("costs") {
            None => Vec::new(),
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .map(StrategyWeight::from_json)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err("routing leastLoad costs must be an array".into());
            }
        };
        Ok(Self {
            costs,
            baselines_ms,
            expected,
            max_rtt_ms,
            tolerance,
        })
    }

    fn select(
        &self,
        targets: &[String],
        observations: &HashMap<String, OutboundObservation>,
    ) -> Vec<String> {
        let mut nodes = targets
            .iter()
            .filter_map(|tag| {
                let status = observations.get(tag)?;
                if !status.alive {
                    return None;
                }
                if self
                    .max_rtt_ms
                    .is_some_and(|maximum| status.delay_ms as f64 >= maximum)
                {
                    return None;
                }
                if status.health_all > 0
                    && self.tolerance > 0.0
                    && status.health_fail as f64 / status.health_all as f64
                        > self.tolerance
                {
                    return None;
                }
                let (all, fail, average_ms, deviation_ms) = if status.health_all > 0
                {
                    (
                        status.health_all,
                        status.health_fail,
                        status.health_average_ms as f64,
                        status.health_deviation_ms as f64,
                    )
                } else {
                    (1, 1, status.delay_ms as f64, status.delay_ms as f64)
                };
                Some(LeastLoadNode {
                    tag: tag.clone(),
                    all,
                    fail,
                    average_ms,
                    deviation_cost_ms: self.apply_cost(tag, deviation_ms),
                })
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| {
            left.deviation_cost_ms
                .total_cmp(&right.deviation_cost_ms)
                .then_with(|| left.average_ms.total_cmp(&right.average_ms))
                .then_with(|| left.fail.cmp(&right.fail))
                .then_with(|| right.all.cmp(&left.all))
                .then_with(|| left.tag.cmp(&right.tag))
        });
        if nodes.is_empty() {
            return Vec::new();
        }
        if self.expected > nodes.len() {
            return nodes.into_iter().map(|node| node.tag).collect();
        }
        let expected = self.expected.max(1);
        let count = if self.baselines_ms.is_empty() {
            expected
        } else {
            let mut count = 0;
            for baseline in &self.baselines_ms {
                for (index, node) in nodes.iter().enumerate().skip(count) {
                    if node.deviation_cost_ms >= *baseline {
                        break;
                    }
                    count = index + 1;
                }
                if count >= expected {
                    break;
                }
            }
            if self.expected > 0 && count < expected {
                expected
            } else {
                count
            }
        };
        let count = count.min(nodes.len());
        nodes.into_iter().take(count).map(|node| node.tag).collect()
    }

    fn apply_cost(&self, tag: &str, value: f64) -> f64 {
        let cost = self
            .costs
            .iter()
            .find_map(|weight| weight.matches(tag))
            .unwrap_or(1.0)
            .max(f64::EPSILON);
        value * cost.sqrt()
    }
}

impl StrategyWeight {
    fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let object = value.as_object().ok_or_else(|| {
            "routing leastLoad cost entry must be an object".to_string()
        })?;
        let pattern = object
            .get("match")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let matcher = if pattern.is_empty() {
            WeightMatcher::Never
        } else if object
            .get("regexp")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            Regex::new(&pattern)
                .map(WeightMatcher::Regexp)
                .unwrap_or(WeightMatcher::Never)
        } else {
            WeightMatcher::Substring(pattern)
        };
        Ok(Self {
            matcher,
            value: object
                .get("value")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_default(),
        })
    }

    fn matches(&self, tag: &str) -> Option<f64> {
        let matched = match &self.matcher {
            WeightMatcher::Never => None,
            WeightMatcher::Substring(pattern) => {
                tag.contains(pattern).then_some(pattern.as_str())
            }
            WeightMatcher::Regexp(pattern) => {
                pattern.find(tag).map(|value| value.as_str())
            }
        }?;
        if self.value > 0.0 {
            return Some(self.value);
        }
        first_number(matched).or(Some(1.0))
    }
}

fn first_number(value: &str) -> Option<f64> {
    let start = value.find(|character: char| character.is_ascii_digit())?;
    let number = value[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect::<String>();
    number.parse().ok()
}

fn parse_duration_millis(value: &serde_json::Value) -> Result<f64, String> {
    if let Some(value) = value.as_f64() {
        return Ok(value.max(0.0));
    }
    let Some(value) = value.as_str() else {
        return Err("routing duration must be a number or string".into());
    };
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let amount = value[..split]
        .parse::<f64>()
        .map_err(|error| format!("invalid routing duration {value}: {error}"))?;
    let multiplier = match value[split..].trim().to_ascii_lowercase().as_str() {
        "" | "ms" => 1.0,
        "ns" => 0.000_001,
        "us" | "µs" => 0.001,
        "s" => 1_000.0,
        "m" => 60_000.0,
        "h" => 3_600_000.0,
        unit => return Err(format!("unsupported routing duration unit {unit}")),
    };
    Ok((amount * multiplier).max(0.0))
}

impl TryFrom<RuleConfig> for CompiledRule {
    type Error = String;

    fn try_from(rule: RuleConfig) -> Result<Self, Self::Error> {
        if !rule_has_effective_fields(&rule) {
            return Err("routing rule has no effective fields".into());
        }

        let target = match (rule.outbound_tag, rule.balancer_tag) {
            (Some(outbound_tag), None) if !outbound_tag.trim().is_empty() => {
                RuleTarget::Outbound(outbound_tag)
            }
            (None, Some(balancer_tag)) if !balancer_tag.trim().is_empty() => {
                RuleTarget::Balancer(balancer_tag)
            }
            _ => {
                return Err(
                    "neither outboundTag nor balancerTag is specified in routing rule"
                        .into(),
                );
            }
        };

        let mut target_domains = Vec::new();
        for value in rule.domain {
            target_domains.push(parse_domain_matcher(&value)?);
        }

        let target_ips = IpMatcher::from_xray_values(rule.ip)?;
        let source_ips = IpMatcher::from_xray_values(rule.source_ip)?;
        let local_ips = IpMatcher::from_xray_values(rule.local_ip)?;

        Ok(Self {
            attrs: AttributeMatcher::from_xray_values(rule.attrs)?,
            inbound_tags: rule.inbound_tag,
            local_ips,
            local_ports: rule.local_port.0,
            networks: normalize_networks(rule.network),
            processes: ProcessMatcher::from_xray_values(rule.process),
            protocols: ProtocolMatcher::from_xray_values(rule.protocol),
            rule_tag: rule.rule_tag.unwrap_or_default(),
            source_ips,
            source_ports: rule.source_port.0,
            target,
            target_domains,
            target_ips,
            target_ports: rule.port.0,
            users: UserMatcher::from_xray_values(rule.user),
            vless_routes: rule.vless_route.0,
            webhook: rule
                .webhook
                .map(RoutingWebhook::from_config)
                .transpose()?
                .flatten(),
        })
    }
}

impl CompiledRule {
    fn matches(&self, input: &RoutingInput) -> bool {
        matches_string_list(&self.inbound_tags, &input.inbound_tag)
            && matches_networks(&self.networks, input.network)
            && self.source_ips.matches(&input.source_ips)
            && self.target_ips.matches(&input.target_ips)
            && self.local_ips.matches(&input.local_ips)
            && matches_ports(&self.source_ports, input.source_port)
            && matches_ports(&self.target_ports, input.target_port)
            && matches_ports(&self.local_ports, input.local_port)
            && matches_ports(&self.vless_routes, input.vless_route)
            && matches_domains(&self.target_domains, &input.target_domain)
            && self.processes.matches(input)
            && self.protocols.matches(&input.protocol)
            && self.users.matches(&input.user)
            && self.attrs.matches(&input.attributes)
    }
}

fn normalize_rule_aliases(mut rule: RuleConfig) -> RuleConfig {
    if !rule.domains.is_empty() {
        rule.domain = std::mem::take(&mut rule.domains);
    }
    if rule.source_ip.is_empty() {
        rule.source_ip = std::mem::take(&mut rule.source);
    } else {
        rule.source.clear();
    }
    rule
}

fn rule_has_effective_fields(rule: &RuleConfig) -> bool {
    !rule.inbound_tag.is_empty()
        || !rule.domain.is_empty()
        || !rule.ip.is_empty()
        || !rule.port.0.is_empty()
        || !rule.network.0.is_empty()
        || !rule.source_ip.is_empty()
        || !rule.source_port.0.is_empty()
        || !rule.user.is_empty()
        || !rule.vless_route.0.is_empty()
        || !rule.protocol.is_empty()
        || !rule.attrs.is_empty()
        || !rule.local_ip.is_empty()
        || !rule.local_port.0.is_empty()
        || !rule.process.is_empty()
}

fn normalize_networks(networks: NetworkListConfig) -> Vec<String> {
    networks
        .0
        .into_iter()
        .map(|network| network.trim().to_ascii_lowercase())
        .filter(|network| !network.is_empty())
        .collect()
}

fn cut_reverse_prefix(mut value: &str) -> (&str, bool) {
    let mut reverse = false;
    while let Some(rest) = value.strip_prefix('!') {
        value = rest;
        reverse = !reverse;
    }
    (value, reverse)
}

fn rule_uses_geoip(rule: &RuleConfig) -> bool {
    rule.ip
        .iter()
        .chain(&rule.source_ip)
        .chain(&rule.source)
        .chain(&rule.local_ip)
        .any(|value| {
            let rule = cut_reverse_prefix(value.trim()).0;
            if rule.starts_with("geoip:") {
                return true;
            }
            rule.strip_prefix("ext:")
                .or_else(|| rule.strip_prefix("ext-ip:"))
                .and_then(|reference| reference.split_once(':'))
                .is_some_and(|(file, _)| file == "geoip.dat")
        })
}

fn rule_uses_geosite(rule: &RuleConfig) -> bool {
    rule.domain.iter().chain(&rule.domains).any(|value| {
        let rule = value.trim();
        if rule.starts_with("geosite:") {
            return true;
        }
        rule.strip_prefix("ext:")
            .or_else(|| rule.strip_prefix("ext-domain:"))
            .or_else(|| rule.strip_prefix("ext-site:"))
            .and_then(|reference| reference.split_once(':'))
            .is_some_and(|(file, _)| file == "geosite.dat")
    })
}

fn expand_geoip_values(
    geodata: &GeodataStore,
    values: Vec<String>,
) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    for value in values {
        let (rule, mut reverse) = cut_reverse_prefix(value.trim());
        if let Some(code) = rule.strip_prefix("geoip:") {
            let (code, code_reverse) = cut_reverse_prefix(code);
            reverse ^= code_reverse;
            if code.trim().is_empty() {
                return Err("xray geoip rule code is required".into());
            }
            let entries = geodata.expand_geoip(code, reverse)?;
            if entries.is_empty() {
                expanded.push(INTERNAL_NEVER_IP_RULE.into());
            } else {
                expanded.extend(entries);
            }
            continue;
        }

        let external = rule
            .strip_prefix("ext:")
            .or_else(|| rule.strip_prefix("ext-ip:"));
        if let Some(reference) = external {
            let (file, code) = reference.split_once(':').ok_or_else(|| {
                "xray external geoip rule syntax error".to_string()
            })?;
            let (code, code_reverse) = cut_reverse_prefix(code);
            reverse ^= code_reverse;
            if file.is_empty() {
                return Err("xray external geoip file is required".into());
            }
            if code.is_empty() {
                return Err("xray external geoip code is required".into());
            }
            let entries = geodata.expand_geoip_file(file, code, reverse)?;
            if entries.is_empty() {
                expanded.push(INTERNAL_NEVER_IP_RULE.into());
            } else {
                expanded.extend(entries);
            }
            continue;
        }

        expanded.push(format!("{}{rule}", if reverse { "!" } else { "" }));
    }
    Ok(expanded)
}

fn expand_geosite_values(
    geodata: &GeodataStore,
    values: Vec<String>,
) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    for value in values {
        let rule = value.trim();
        let (file, reference) =
            if let Some(reference) = rule.strip_prefix("geosite:") {
                ("geosite.dat", reference)
            } else if let Some(reference) = rule
                .strip_prefix("ext:")
                .or_else(|| rule.strip_prefix("ext-domain:"))
                .or_else(|| rule.strip_prefix("ext-site:"))
            {
                reference.split_once(':').ok_or_else(|| {
                    "xray external geosite rule syntax error".to_string()
                })?
            } else {
                expanded.push(value);
                continue;
            };

        if file.is_empty() {
            return Err("xray external geosite file is required".into());
        }
        if reference.ends_with('@') || reference.contains("@@") {
            return Err("xray geosite rule contains an empty attr".into());
        }
        let mut parts = reference.split('@');
        let code = parts.next().unwrap_or_default().trim();
        if code.is_empty() {
            return Err("xray geosite rule code is required".into());
        }
        let attrs = parts
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        let attr_refs = attrs.iter().map(String::as_str).collect::<Vec<_>>();
        let entries = geodata
            .expand_geosite_file(file, code, &attr_refs)?
            .into_iter()
            .filter(|entry| parse_domain_matcher(entry).is_ok())
            .collect::<Vec<_>>();
        if entries.is_empty() {
            expanded.push(INTERNAL_NEVER_DOMAIN_RULE.into());
        } else {
            expanded.extend(entries);
        }
    }
    Ok(expanded)
}

fn parse_domain_matcher(value: &str) -> Result<DomainMatcher, String> {
    if value == INTERNAL_NEVER_DOMAIN_RULE {
        return Ok(DomainMatcher::Never);
    }
    let value = value.trim();
    if let Some(value) = value.strip_prefix("domain:") {
        return normalize_domain_pattern(value).map(DomainMatcher::Domain);
    }
    if let Some(value) = value.strip_prefix("full:") {
        return normalize_domain_pattern(value).map(DomainMatcher::Full);
    }
    if let Some(value) = value.strip_prefix("regexp:") {
        return Regex::new(value)
            .map(DomainMatcher::Regexp)
            .map_err(|error| {
                format!("invalid regexp routing rule {value}: {error}")
            });
    }
    if let Some(value) = value.strip_prefix("dotless:") {
        if value.contains('.') {
            return Err("substr in dotless rule should not contain a dot".into());
        }
        let pattern = if value.is_empty() {
            "^[^.]*$".to_string()
        } else {
            format!("^[^.]*{value}[^.]*$")
        };
        return Regex::new(&pattern)
            .map(DomainMatcher::Regexp)
            .map_err(|error| {
                format!("invalid dotless routing rule {value}: {error}")
            });
    }
    let value = value.strip_prefix("keyword:").unwrap_or(value);
    normalize_domain_pattern(value).map(DomainMatcher::Plain)
}

fn normalize_domain_pattern(value: &str) -> Result<String, String> {
    let value = if value.is_ascii() {
        value.to_string()
    } else {
        idna::domain_to_ascii(value).map_err(|error| {
            format!("invalid internationalized routing domain {value}: {error}")
        })?
    };
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(format!(
            "routing domain pattern does not conform to LDH subset: {value}"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_cidr_matcher(value: &str) -> Result<CidrMatcher, String> {
    let value = value.trim();
    let Some((ip, prefix)) = value
        .split_once('/')
        .map(|(ip, prefix)| (ip, Some(prefix)))
        .or(Some((value, None)))
    else {
        return Err("invalid cidr rule".into());
    };
    let addr =
        IpAddr::from_str(ip).map_err(|err| format!("invalid ip {ip}: {err}"))?;
    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .map_err(|err| format!("invalid cidr prefix {prefix}: {err}"))?,
        None => max_prefix,
    };
    if prefix > max_prefix {
        return Err(format!("cidr prefix {prefix} exceeds {max_prefix}"));
    }
    Ok(CidrMatcher { addr, prefix })
}

fn matches_string_list(values: &[String], input: &str) -> bool {
    values.is_empty()
        || (!input.is_empty() && values.iter().any(|value| value == input))
}

fn matches_networks(networks: &[String], input: i32) -> bool {
    if networks.is_empty() {
        return true;
    }
    let network = match input {
        2 => "tcp",
        3 => "udp",
        4 => "unix",
        _ => return false,
    };
    networks.iter().any(|value| value == network)
}

fn decode_ip(input: &[u8]) -> Option<IpAddr> {
    match input {
        [a, b, c, d] => Some(IpAddr::from([*a, *b, *c, *d])),
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => Some(IpAddr::from([
            *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o, *p,
        ])),
        _ => None,
    }
}

impl CidrMatcher {
    fn matches(&self, input: IpAddr) -> bool {
        match (self.addr, input) {
            (IpAddr::V4(expected), IpAddr::V4(actual)) => {
                prefix_match(&expected.octets(), &actual.octets(), self.prefix)
            }
            (IpAddr::V6(expected), IpAddr::V6(actual)) => {
                prefix_match(&expected.octets(), &actual.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_match(expected: &[u8], actual: &[u8], prefix: u8) -> bool {
    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = prefix % 8;
    if expected[..full_bytes] != actual[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining_bits);
    (expected[full_bytes] & mask) == (actual[full_bytes] & mask)
}

fn matches_ports(ranges: &[PortRangeConfig], port: u32) -> bool {
    let port = port as u16;
    ranges.is_empty()
        || ranges
            .iter()
            .any(|range| port >= range.from && port <= range.to)
}

fn matches_domains(matchers: &[DomainMatcher], domain: &str) -> bool {
    if matchers.is_empty() {
        return true;
    }
    if domain.is_empty() {
        return false;
    }
    let domain = domain.to_ascii_lowercase();
    matchers.iter().any(|matcher| match matcher {
        DomainMatcher::Never => false,
        DomainMatcher::Plain(value) => domain.contains(value),
        DomainMatcher::Domain(value) => {
            domain == *value || domain.ends_with(&format!(".{value}"))
        }
        DomainMatcher::Full(value) => domain == *value,
        DomainMatcher::Regexp(value) => value.is_match(&domain),
    })
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::{
        config::rule::PortListConfig,
        geodata::{GeodataStore, proto as geodata_proto},
    };

    use super::*;

    fn outbound(tag: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.to_string(),
            protocol: "freedom".to_string(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    fn test_geodata() -> GeodataStore {
        let mut store = GeodataStore::default();
        store
            .load_geoip_bytes(
                &geodata_proto::GeoIpList {
                    entry: vec![
                        geodata_proto::GeoIp {
                            code: "TEST".into(),
                            cidr: vec![geodata_proto::Cidr {
                                ip: vec![203, 0, 113, 0],
                                prefix: 24,
                            }],
                            reverse_match: false,
                        },
                        geodata_proto::GeoIp {
                            code: "EMPTY".into(),
                            cidr: vec![],
                            reverse_match: false,
                        },
                    ],
                }
                .encode_to_vec(),
            )
            .expect("load routing geoip fixture");
        store
            .load_geosite_bytes(
                &geodata_proto::GeoSiteList {
                    entry: vec![
                        geodata_proto::GeoSite {
                            code: "TEST".into(),
                            domain: vec![
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Domain as i32,
                                    value: "example.com".into(),
                                    attribute: vec![geodata_proto::domain::Attribute {
                                        key: "ads".into(),
                                        typed_value: Some(
                                            geodata_proto::domain::attribute::TypedValue::BoolValue(
                                                true,
                                            ),
                                        ),
                                    }],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Full as i32,
                                    value: "only.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Regex as i32,
                                    value: r"^api[0-9]+\.example$".into(),
                                    attribute: vec![geodata_proto::domain::Attribute {
                                        key: "ads".into(),
                                        typed_value: None,
                                    }],
                                },
                            ],
                        },
                        geodata_proto::GeoSite {
                            code: "MIXED".into(),
                            domain: vec![
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Full as i32,
                                    value: "valid.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: 99,
                                    value: "unknown.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Domain as i32,
                                    value: "bad_name.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Regex as i32,
                                    value: "(".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Substr as i32,
                                    value: String::new(),
                                    attribute: vec![],
                                },
                            ],
                        },
                        geodata_proto::GeoSite {
                            code: "ALL_INVALID".into(),
                            domain: vec![
                                geodata_proto::Domain {
                                    r#type: 99,
                                    value: "unknown.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Domain as i32,
                                    value: "bad_name.example".into(),
                                    attribute: vec![],
                                },
                                geodata_proto::Domain {
                                    r#type: geodata_proto::domain::Type::Regex as i32,
                                    value: "(".into(),
                                    attribute: vec![],
                                },
                            ],
                        },
                    ],
                }
                .encode_to_vec(),
            )
            .expect("load routing geosite fixture");
        store
    }

    #[test]
    fn routing_state_matches_inbound_and_domain_rules() {
        let state = RoutingState::from_parts(
            vec![
                RuleConfig {
                    inbound_tag: vec!["api-in".into()],
                    outbound_tag: Some("api".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    domain: vec!["domain:example.com".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![],
        )
        .expect("routing state should build");

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "api-in".into(),
                    ..RoutingInput::default()
                },
                &[outbound("api"), outbound("direct")],
                &HashMap::new(),
            )
            .expect("api rule should match");
        assert_eq!(matched.outbound_tag, "api");

        let matched = state
            .route(
                &RoutingInput {
                    target_domain: "www.example.com".into(),
                    ..RoutingInput::default()
                },
                &[outbound("api"), outbound("direct")],
                &HashMap::new(),
            )
            .expect("domain rule should match");
        assert_eq!(matched.outbound_tag, "direct");
    }

    #[test]
    fn routing_state_supports_regexp_domain_rules() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec![r"regexp:^api[0-9]+\.example\.com$".into()],
                outbound_tag: Some("regexp".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("regexp routing rule should compile");

        let matched = state
            .route(
                &RoutingInput {
                    target_domain: "API42.EXAMPLE.COM".into(),
                    ..RoutingInput::default()
                },
                &[outbound("regexp")],
                &HashMap::new(),
            )
            .expect("regexp routing rule should match lowercased target domain");
        assert_eq!(matched.outbound_tag, "regexp");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "api.example.com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("regexp")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn invalid_regexp_domain_rule_is_rejected_during_compile() {
        let error = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec!["regexp:(unterminated".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect_err("invalid regexp routing rule must be rejected");

        assert!(error.contains("invalid regexp routing rule"));
    }

    #[test]
    fn non_regexp_domain_rules_are_ascii_case_insensitive() {
        for rule in [
            "keyword:EXAMPLE",
            "domain:EXAMPLE.COM",
            "full:WWW.EXAMPLE.COM",
        ] {
            let state = RoutingState::from_parts(
                vec![RuleConfig {
                    domain: vec![rule.into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
            )
            .expect("case-normalized routing rule should compile");

            assert!(
                state
                    .route(
                        &RoutingInput {
                            target_domain: "WWW.Example.Com".into(),
                            ..RoutingInput::default()
                        },
                        &[outbound("direct")],
                        &HashMap::new(),
                    )
                    .is_some(),
                "rule {rule} should match case-insensitively"
            );
        }
    }

    #[test]
    fn domain_rule_requires_label_boundary() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec!["domain:example.com".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("domain boundary routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "notexample.com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "sub.example.com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
    }

    #[test]
    fn regexp_pattern_remains_case_sensitive_after_domain_lowercasing() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec![r"regexp:^API\.example\.com$".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("case-sensitive regexp routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "API.EXAMPLE.COM".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    fn strategy_state(strategy: &str, rules: Vec<RuleConfig>) -> RoutingState {
        RoutingState::from_config(Some(&RoutingConfig {
            domain_strategy: Some(strategy.into()),
            rules,
            balancers: Vec::new(),
        }))
        .expect("domain strategy routing state should build")
    }

    fn domain_and_ip_rules() -> Vec<RuleConfig> {
        vec![
            RuleConfig {
                ip: vec!["203.0.113.7/32".into()],
                outbound_tag: Some("ip".into()),
                ..RuleConfig::default()
            },
            RuleConfig {
                domain: vec!["full:example.com".into()],
                outbound_tag: Some("domain".into()),
                ..RuleConfig::default()
            },
        ]
    }

    fn resolved_domain_input(domain: &str) -> RoutingInput {
        RoutingInput {
            target_domain: domain.into(),
            target_ips: vec![vec![203, 0, 113, 7]],
            ..RoutingInput::default()
        }
    }

    #[test]
    fn as_is_ignores_resolved_ips_for_domain_targets() {
        let state = strategy_state("AsIs", domain_and_ip_rules());
        let outbounds = [outbound("ip"), outbound("domain")];

        let matched = state
            .route(
                &resolved_domain_input("example.com"),
                &outbounds,
                &HashMap::new(),
            )
            .expect("AsIs domain rule should match");
        assert_eq!(matched.outbound_tag, "domain");

        assert!(
            state
                .route(
                    &resolved_domain_input("other.example"),
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none(),
            "AsIs must not fall through to resolved target IP rules"
        );
    }

    #[test]
    fn ip_if_non_match_retries_with_resolved_ips_only_after_domain_miss() {
        let state = strategy_state("IPIfNonMatch", domain_and_ip_rules());
        let outbounds = [outbound("ip"), outbound("domain")];

        let domain_match = state
            .route(
                &resolved_domain_input("example.com"),
                &outbounds,
                &HashMap::new(),
            )
            .expect("IPIfNonMatch domain rule should win first pass");
        assert_eq!(domain_match.outbound_tag, "domain");

        let ip_match = state
            .route(
                &resolved_domain_input("other.example"),
                &outbounds,
                &HashMap::new(),
            )
            .expect("IPIfNonMatch should retry target IP rules");
        assert_eq!(ip_match.outbound_tag, "ip");
    }

    #[test]
    fn ip_on_demand_allows_ip_rule_in_first_pass() {
        let state = strategy_state("IPOnDemand", domain_and_ip_rules());
        let matched = state
            .route(
                &resolved_domain_input("example.com"),
                &[outbound("ip"), outbound("domain")],
                &HashMap::new(),
            )
            .expect("IPOnDemand target IP rule should match");

        assert_eq!(matched.outbound_tag, "ip");
    }

    #[test]
    fn as_is_still_matches_ip_rules_for_literal_ip_targets() {
        let state = strategy_state("AsIs", domain_and_ip_rules());
        let matched = state
            .route(
                &RoutingInput {
                    target_ips: vec![vec![203, 0, 113, 7]],
                    ..RoutingInput::default()
                },
                &[outbound("ip"), outbound("domain")],
                &HashMap::new(),
            )
            .expect("literal IP target must remain eligible for IP rules");

        assert_eq!(matched.outbound_tag, "ip");
    }

    #[test]
    fn unknown_domain_strategy_defaults_to_as_is() {
        let state = strategy_state("unknown-future-value", domain_and_ip_rules());

        assert!(
            state
                .route(
                    &resolved_domain_input("other.example"),
                    &[outbound("ip"), outbound("domain")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn failed_strategy_merge_preserves_previous_strategy() {
        let mut state = strategy_state("IPOnDemand", domain_and_ip_rules());
        let error = state
            .merge_with_domain_strategy(
                vec![RuleConfig {
                    domain: vec!["regexp:(invalid".into()],
                    outbound_tag: Some("domain".into()),
                    ..RuleConfig::default()
                }],
                Vec::new(),
                false,
                Some(DomainStrategy::AsIs),
            )
            .expect_err("invalid strategy update must fail atomically");
        assert!(error.contains("invalid regexp routing rule"));

        let matched = state
            .route(
                &resolved_domain_input("example.com"),
                &[outbound("ip"), outbound("domain")],
                &HashMap::new(),
            )
            .expect("previous IPOnDemand strategy must survive failure");
        assert_eq!(matched.outbound_tag, "ip");
    }

    #[test]
    fn process_condition_matches_xray_name_path_folder_and_self_forms() {
        let state = RoutingState::from_parts(
            vec![
                RuleConfig {
                    process: vec!["curl.exe".into()],
                    outbound_tag: Some("name".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    process: vec!["/usr/bin/special".into()],
                    outbound_tag: Some("path".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    process: vec!["/opt/apps/".into()],
                    outbound_tag: Some("folder".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    process: vec!["self/".into()],
                    outbound_tag: Some("self".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![],
        )
        .expect("process routing rules should compile");
        assert!(state.requires_process_lookup());
        let outbounds = [
            outbound("name"),
            outbound("path"),
            outbound("folder"),
            outbound("self"),
        ];

        let cases = [
            (
                RoutingInput {
                    process_name: "curl".into(),
                    ..RoutingInput::default()
                },
                "name",
            ),
            (
                RoutingInput {
                    process_path: "/usr/bin/special".into(),
                    ..RoutingInput::default()
                },
                "path",
            ),
            (
                RoutingInput {
                    process_path: "/opt/apps/client".into(),
                    ..RoutingInput::default()
                },
                "folder",
            ),
            (
                RoutingInput {
                    process_id: std::process::id(),
                    ..RoutingInput::default()
                },
                "self",
            ),
        ];
        for (input, expected) in cases {
            let matched = state
                .route(&input, &outbounds, &HashMap::new())
                .expect("process condition should match");
            assert_eq!(matched.outbound_tag, expected);
        }

        assert!(
            state
                .route(&RoutingInput::default(), &outbounds, &HashMap::new(),)
                .is_none(),
            "configured process rules must reject missing process metadata"
        );
    }

    #[test]
    fn routing_without_process_rules_skips_process_lookup() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("routing state should compile");

        assert!(!state.requires_process_lookup());
    }

    #[test]
    fn matched_rule_fires_webhook_with_headers_and_user_deduplication() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind routing webhook listener");
        listener
            .set_nonblocking(true)
            .expect("set webhook listener nonblocking");
        let address = listener.local_addr().expect("webhook listener address");
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(
                                1,
                            )))
                            .expect("set webhook read timeout");
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            let read = stream.read(&mut chunk).unwrap_or_default();
                            if read == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..read]);
                            let Some(header_end) = request
                                .windows(4)
                                .position(|window| window == b"\r\n\r\n")
                                .map(|index| index + 4)
                            else {
                                continue;
                            };
                            let headers =
                                String::from_utf8_lossy(&request[..header_end]);
                            let content_length = headers
                                .lines()
                                .find_map(|line| {
                                    line.split_once(':').and_then(|(name, value)| {
                                        name.eq_ignore_ascii_case("content-length")
                                            .then(|| {
                                                value.trim().parse::<usize>().ok()
                                            })
                                            .flatten()
                                    })
                                })
                                .unwrap_or_default();
                            if request.len() >= header_end + content_length {
                                break;
                            }
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = request_tx.send(request);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["webhook-in".into()],
                outbound_tag: Some("direct".into()),
                webhook: Some(crate::config::rule::WebhookRuleConfig {
                    url: format!("http://{address}/route"),
                    deduplication: 60,
                    headers: HashMap::from([(
                        "X-Route-Key".into(),
                        "secret".into(),
                    )]),
                }),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("webhook routing rule should compile");
        let input = RoutingInput {
            inbound_tag: "webhook-in".into(),
            network: 2,
            source_ips: vec![vec![127, 0, 0, 1]],
            source_port: 12345,
            target_domain: "example.com".into(),
            target_port: 443,
            protocol: "tls".into(),
            user: "alice@example.com".into(),
            ..RoutingInput::default()
        };
        let outbounds = [outbound("direct")];

        for _ in 0..2 {
            let matched = state
                .route(&input, &outbounds, &HashMap::new())
                .expect("webhook rule should match");
            assert_eq!(matched.outbound_tag, "direct");
        }

        let request = request_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("webhook request missing");
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text.starts_with("POST /route HTTP/1.1"));
        assert!(
            request_text
                .to_ascii_lowercase()
                .contains("x-route-key: secret")
        );
        let body_offset = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("webhook header terminator")
            + 4;
        let body: serde_json::Value =
            serde_json::from_slice(&request[body_offset..])
                .expect("decode webhook body");
        assert_eq!(body["email"], "alice@example.com");
        assert_eq!(body["inboundTag"], "webhook-in");
        assert_eq!(body["outboundTag"], "direct");
        assert_eq!(body["destination"], "example.com:443");
        assert!(
            request_rx
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "duplicate user webhook should be suppressed"
        );
        server.join().expect("webhook server thread");
    }

    #[test]
    fn invalid_webhook_url_is_rejected_during_rule_compile() {
        let error = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["webhook-in".into()],
                outbound_tag: Some("direct".into()),
                webhook: Some(crate::config::rule::WebhookRuleConfig {
                    url: "unix:///tmp/router.sock".into(),
                    ..Default::default()
                }),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect_err("unsupported webhook scheme must fail at compile time");

        assert!(error.contains("webhook URL scheme unix is not supported"));
    }

    #[test]
    fn user_condition_supports_exact_and_regexp_values() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                user: vec![
                    "exact@example.com".into(),
                    r"regexp:^team-[0-9]+@example\.com$".into(),
                ],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("user routing rule should compile");
        let outbounds = [outbound("direct")];

        for user in ["exact@example.com", "team-42@example.com"] {
            assert!(
                state
                    .route(
                        &RoutingInput {
                            user: user.into(),
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                "user {user} should match"
            );
        }
        assert!(
            state
                .route(
                    &RoutingInput {
                        user: "other@example.com".into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn user_regexp_is_case_sensitive() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                user: vec![r"regexp:^Admin@Example\.Com$".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("case-sensitive user regexp should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        user: "Admin@Example.Com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
        assert!(
            state
                .route(
                    &RoutingInput {
                        user: "admin@example.com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn invalid_user_regexp_is_ignored_instead_of_rejecting_rule() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                user: vec!["regexp:(invalid".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("invalid user regexp should be ignored like xray-core");

        assert!(
            state
                .route(
                    &RoutingInput {
                        user: "anything".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none(),
            "rule with only invalid user regexp must never match"
        );
    }

    #[test]
    fn configured_user_condition_rejects_empty_user() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                user: vec!["exact@example.com".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("user routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput::default(),
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn internationalized_domain_rule_is_normalized_to_punycode() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec!["domain:bücher.example".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("internationalized domain routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "shop.xn--bcher-kva.example".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
    }

    #[test]
    fn non_regexp_domain_rule_rejects_non_ldh_characters_transactionally() {
        let mut state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![RuleConfig {
                    domain: vec!["domain:_service.example".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("non-LDH domain rule must be rejected");
        assert!(error.contains("does not conform to LDH subset"));

        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
    }

    #[test]
    fn regexp_domain_rule_may_use_non_ldh_characters() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec![r"regexp:^_service\.example$".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("regexp domain rule should not use LDH validation");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "_service.example".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
    }

    #[test]
    fn dotless_domain_rule_matches_only_single_label_domains() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec!["dotless:".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("dotless routing rule should compile");
        let outbounds = [outbound("direct")];

        for (domain, expected) in [
            ("localhost", true),
            ("printer-01", true),
            ("example.com", false),
        ] {
            assert_eq!(
                state
                    .route(
                        &RoutingInput {
                            target_domain: domain.into(),
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                expected,
                "domain {domain}"
            );
        }
    }

    #[test]
    fn dotless_substring_rule_and_invalid_dot_follow_xray_semantics() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec!["dotless:print".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("dotless substring routing rule should compile");
        let outbounds = [outbound("direct")];

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "office-printer".into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some()
        );
        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "print.example".into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none()
        );

        let error = RoutingState::from_parts(
            vec![RuleConfig {
                domain: vec!["dotless:bad.value".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect_err("dotless substring containing a dot must fail");
        assert!(error.contains("should not contain a dot"));
    }

    #[test]
    fn protocol_condition_uses_xray_prefix_matching() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                protocol: vec!["tls".into(), "http".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("protocol routing rule should compile");
        let outbounds = [outbound("direct")];

        for protocol in ["tls", "tls.http/1.1", "http2"] {
            assert!(
                state
                    .route(
                        &RoutingInput {
                            protocol: protocol.into(),
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                "protocol {protocol} should match by prefix"
            );
        }
        assert!(
            state
                .route(
                    &RoutingInput {
                        protocol: "quic".into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn configured_protocol_condition_rejects_empty_protocol() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                protocol: vec!["tls".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("protocol routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput::default(),
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn attribute_condition_uses_case_insensitive_keys_and_regexp_values() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                attrs: HashMap::from([
                    ("Host".into(), r"^api[0-9]+\.example\.com$".into()),
                    ("User-Agent".into(), r"^chimera/".into()),
                ]),
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("attribute routing rule should compile");

        let matched = state.route(
            &RoutingInput {
                attributes: HashMap::from([
                    ("HOST".into(), "api42.example.com".into()),
                    ("user-agent".into(), "chimera/1.0".into()),
                ]),
                ..RoutingInput::default()
            },
            &[outbound("direct")],
            &HashMap::new(),
        );
        assert!(matched.is_some());

        assert!(
            state
                .route(
                    &RoutingInput {
                        attributes: HashMap::from([
                            ("host".into(), "api42.example.com".into()),
                            ("user-agent".into(), "other/1.0".into()),
                        ]),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none(),
            "all configured attribute regexps must match"
        );
    }

    #[test]
    fn configured_attribute_condition_rejects_missing_attributes() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                attrs: HashMap::from([("host".into(), ".+".into())]),
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("attribute routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput::default(),
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn invalid_attribute_regexp_rejects_rule_transactionally() {
        let mut state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![RuleConfig {
                    attrs: HashMap::from([("host".into(), "(invalid".into())]),
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("invalid attribute regexp must reject rule");
        assert!(error.contains("invalid routing attribute regexp"));

        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some(),
            "failed attribute update must preserve existing state"
        );
    }

    #[test]
    fn multiple_geoip_reverse_prefixes_follow_xray_xor_semantics() {
        let outbounds = [outbound("direct")];
        for (rule, inside, outside) in [
            ("!!geoip:TEST", true, false),
            ("!geoip:!TEST", true, false),
            ("!!!geoip:TEST", false, true),
        ] {
            let state = RoutingState::from_parts_with_geodata(
                vec![RuleConfig {
                    ip: vec![rule.into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                test_geodata(),
            )
            .expect("multi-reverse geoip routing rule should compile");

            for (ip, expected) in [
                (vec![203, 0, 113, 42], inside),
                (vec![192, 0, 2, 42], outside),
            ] {
                assert_eq!(
                    state
                        .route(
                            &RoutingInput {
                                target_ips: vec![ip],
                                ..RoutingInput::default()
                            },
                            &outbounds,
                            &HashMap::new(),
                        )
                        .is_some(),
                    expected,
                    "rule {rule}"
                );
            }
        }
    }

    #[test]
    fn default_ext_aliases_expand_preloaded_geodata() {
        let geoip = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                ip: vec!["ext:geoip.dat:TEST".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("default ext geoip alias should compile");
        assert!(
            geoip
                .route(
                    &RoutingInput {
                        target_ips: vec![vec![203, 0, 113, 42]],
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );

        for rule in [
            "ext:geosite.dat:TEST@ads",
            "ext-domain:geosite.dat:TEST@ads",
            "ext-site:geosite.dat:TEST@ads",
        ] {
            let geosite = RoutingState::from_parts_with_geodata(
                vec![RuleConfig {
                    domain: vec![rule.into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                test_geodata(),
            )
            .expect("default ext geosite alias should compile");
            assert!(
                geosite
                    .route(
                        &RoutingInput {
                            target_domain: "sub.example.com".into(),
                            ..RoutingInput::default()
                        },
                        &[outbound("direct")],
                        &HashMap::new(),
                    )
                    .is_some(),
                "rule {rule}"
            );
        }
    }

    #[test]
    fn external_geodata_syntax_and_path_errors_are_transactional() {
        let invalid_rules = [
            "ext:missing-separator",
            "ext::TEST",
            "ext:../custom.dat:TEST",
            "ext:/tmp/custom.dat:TEST",
        ];
        for rule in invalid_rules {
            let mut state = RoutingState::from_parts_with_geodata(
                vec![RuleConfig {
                    inbound_tag: vec!["existing".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                test_geodata(),
            )
            .expect("existing routing state should build");

            state
                .merge(
                    vec![RuleConfig {
                        ip: vec![rule.into()],
                        outbound_tag: Some("direct".into()),
                        ..RuleConfig::default()
                    }],
                    vec![],
                    false,
                )
                .expect_err("invalid external geoip rule must fail");
            assert!(
                state
                    .route(
                        &RoutingInput {
                            inbound_tag: "existing".into(),
                            ..RoutingInput::default()
                        },
                        &[outbound("direct")],
                        &HashMap::new(),
                    )
                    .is_some(),
                "rule {rule} must not mutate previous state"
            );
        }
    }

    #[test]
    fn geosite_empty_attribute_syntax_is_rejected_transactionally() {
        for rule in ["geosite:TEST@", "geosite:TEST@@ads"] {
            let mut state = RoutingState::from_parts_with_geodata(
                vec![RuleConfig {
                    inbound_tag: vec!["existing".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                test_geodata(),
            )
            .expect("existing routing state should build");

            let error = state
                .merge(
                    vec![RuleConfig {
                        domain: vec![rule.into()],
                        outbound_tag: Some("direct".into()),
                        ..RuleConfig::default()
                    }],
                    vec![],
                    false,
                )
                .expect_err("empty geosite attr must fail");
            assert!(error.contains("empty attr"));
            assert!(
                state
                    .route(
                        &RoutingInput {
                            inbound_tag: "existing".into(),
                            ..RoutingInput::default()
                        },
                        &[outbound("direct")],
                        &HashMap::new(),
                    )
                    .is_some()
            );
        }
    }

    #[test]
    fn geoip_reference_expands_into_cidr_matchers() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                ip: vec!["geoip:test".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("geoip routing rule should compile");
        let outbounds = [outbound("direct")];

        for (ip, expected) in
            [(vec![203, 0, 113, 42], true), (vec![192, 0, 2, 42], false)]
        {
            assert_eq!(
                state
                    .route(
                        &RoutingInput {
                            target_ips: vec![ip],
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                expected
            );
        }
    }

    #[test]
    fn reversed_geoip_reference_excludes_the_named_set() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                ip: vec!["geoip:!TEST".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("reverse geoip routing rule should compile");
        let outbounds = [outbound("direct")];

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![vec![203, 0, 113, 42]],
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_none()
        );
        assert!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![vec![192, 0, 2, 42]],
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some()
        );
    }

    #[test]
    fn geosite_reference_expands_domain_types_and_attribute_filters() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                domain: vec!["geosite:test@ads".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("geosite routing rule should compile");
        let outbounds = [outbound("direct")];

        for (domain, expected) in [
            ("sub.example.com", true),
            ("api42.example", true),
            ("only.example", false),
            ("other.example", false),
        ] {
            assert_eq!(
                state
                    .route(
                        &RoutingInput {
                            target_domain: domain.into(),
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                expected,
                "domain {domain}"
            );
        }
    }

    #[test]
    fn malformed_geosite_entries_are_ignored_individually() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                domain: vec!["geosite:mixed".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("mixed geosite routing rule should compile");
        let outbounds = [outbound("direct")];

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "valid.example".into(),
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .is_some()
        );
        for domain in ["unknown.example", "bad_name.example", "other.example"] {
            assert!(
                state
                    .route(
                        &RoutingInput {
                            target_domain: domain.into(),
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_none(),
                "invalid geosite item must not match {domain}"
            );
        }
    }

    #[test]
    fn all_invalid_geosite_entry_remains_a_non_matching_condition() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                domain: vec!["geosite:all_invalid".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("all-invalid geosite routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "anything.example".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn empty_geoip_entry_remains_a_non_matching_condition() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                ip: vec!["geoip:empty".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("empty geoip routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![vec![203, 0, 113, 42]],
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none(),
            "an empty geoip set must not remove the IP condition"
        );
    }

    #[test]
    fn empty_geosite_attribute_filter_remains_a_non_matching_condition() {
        let state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                domain: vec!["geosite:test@missing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("empty geosite filter should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_domain: "example.com".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none(),
            "an empty geosite filter must not remove the domain condition"
        );
    }

    #[test]
    fn missing_geodata_code_rejects_update_transactionally() {
        let mut state = RoutingState::from_parts_with_geodata(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
            test_geodata(),
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![RuleConfig {
                    domain: vec!["geosite:missing".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("missing geosite code must reject update");
        assert!(error.contains("xray geosite entry not found: MISSING"));
        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some(),
            "failed geodata update must preserve previous routing state"
        );
    }

    #[test]
    fn cidr_conditions_match_source_target_and_local_addresses() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                source_ip: vec!["10.0.0.0/8".into()],
                ip: vec!["203.0.113.0/24".into()],
                local_ip: vec!["192.0.2.10/32".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("CIDR routing rule should compile");
        let input = RoutingInput {
            source_ips: vec![vec![198, 51, 100, 1], vec![10, 9, 8, 7]],
            target_ips: vec![vec![203, 0, 113, 42]],
            local_ips: vec![vec![192, 0, 2, 10]],
            ..RoutingInput::default()
        };

        assert!(
            state
                .route(&input, &[outbound("direct")], &HashMap::new())
                .is_some(),
            "each CIDR category should accept any matching candidate"
        );

        let mut wrong_local = input;
        wrong_local.local_ips = vec![vec![192, 0, 2, 11]];
        assert!(
            state
                .route(&wrong_local, &[outbound("direct")], &HashMap::new(),)
                .is_none(),
            "source, target, and local CIDR categories are combined with AND"
        );
    }

    #[test]
    fn ipv6_cidr_matches_prefix_boundary() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                ip: vec!["2001:db8:abcd:12::/64".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("IPv6 CIDR routing rule should compile");

        let matching: std::net::Ipv6Addr =
            "2001:db8:abcd:12::99".parse().expect("matching IPv6");
        let outside: std::net::Ipv6Addr =
            "2001:db8:abcd:13::1".parse().expect("outside IPv6");
        for (address, expected) in [(matching, true), (outside, false)] {
            let matched = state.route(
                &RoutingInput {
                    target_ips: vec![address.octets().to_vec()],
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            );
            assert_eq!(matched.is_some(), expected, "address {address}");
        }
    }

    #[test]
    fn malformed_ip_candidates_do_not_match_cidr_rules() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                ip: vec!["0.0.0.0/0".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("catch-all CIDR routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![vec![], vec![127, 0, 0]],
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none()
        );
    }

    #[test]
    fn reverse_cidr_matches_addresses_outside_the_excluded_set() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                ip: vec!["!8.8.8.8/32".into(), "!91.108.0.0/16".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("reverse CIDR routing rule should compile");
        let outbounds = [outbound("direct")];

        for (ip, expected) in [
            (vec![8, 8, 8, 8], false),
            (vec![91, 108, 4, 1], false),
            (vec![1, 1, 1, 1], true),
        ] {
            let matched = state.route(
                &RoutingInput {
                    target_ips: vec![ip],
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            );
            assert_eq!(matched.is_some(), expected);
        }
    }

    #[test]
    fn reverse_cidr_only_applies_to_configured_address_family() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                ip: vec!["!8.8.8.8/32".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("IPv4 reverse CIDR routing rule should compile");
        let ipv6: std::net::Ipv6Addr =
            "2001:db8::1".parse().expect("test IPv6 address");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![ipv6.octets().to_vec()],
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_none(),
            "IPv4-only reverse set must not match IPv6"
        );
    }

    #[test]
    fn positive_and_reverse_cidr_groups_are_combined_with_or() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                ip: vec!["203.0.113.0/24".into(), "!10.0.0.0/8".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("mixed CIDR routing rule should compile");
        let outbounds = [outbound("direct")];

        for (ip, expected) in [
            (vec![203, 0, 113, 9], true),
            (vec![192, 0, 2, 9], true),
            (vec![10, 1, 2, 3], false),
        ] {
            assert_eq!(
                state
                    .route(
                        &RoutingInput {
                            target_ips: vec![ip],
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some(),
                expected
            );
        }
    }

    #[test]
    fn reverse_cidr_uses_any_match_across_resolved_addresses() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                ip: vec!["!10.0.0.0/8".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("reverse CIDR routing rule should compile");

        assert!(
            state
                .route(
                    &RoutingInput {
                        target_ips: vec![vec![10, 1, 2, 3], vec![192, 0, 2, 9]],
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some(),
            "one allowed resolved address should satisfy AnyMatch"
        );
    }

    #[test]
    fn invalid_cidr_update_is_rejected_transactionally() {
        let mut state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![RuleConfig {
                    ip: vec!["192.0.2.0/33".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("invalid CIDR prefix must reject update");
        assert!(error.contains("prefix 33 exceeds 32"));
        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct")],
                    &HashMap::new(),
                )
                .is_some()
        );
    }

    #[test]
    fn port_conditions_use_closed_intervals_and_reject_unknown_zero() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                source_port: PortListConfig(vec![PortRangeConfig {
                    from: 1000,
                    to: 2000,
                }]),
                port: PortListConfig(vec![PortRangeConfig { from: 443, to: 443 }]),
                local_port: PortListConfig(vec![PortRangeConfig {
                    from: 1080,
                    to: 1081,
                }]),
                vless_route: PortListConfig(vec![PortRangeConfig {
                    from: 7,
                    to: 9,
                }]),
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("port routing rule should compile");
        let outbounds = [outbound("direct")];

        for source_port in [1000, 2000] {
            for local_port in [1080, 1081] {
                for vless_route in [7, 9] {
                    assert!(
                        state
                            .route(
                                &RoutingInput {
                                    source_port,
                                    target_port: 443,
                                    local_port,
                                    vless_route,
                                    ..RoutingInput::default()
                                },
                                &outbounds,
                                &HashMap::new(),
                            )
                            .is_some()
                    );
                }
            }
        }
        for input in [
            RoutingInput {
                source_port: 0,
                target_port: 443,
                local_port: 1080,
                vless_route: 7,
                ..RoutingInput::default()
            },
            RoutingInput {
                source_port: 1000,
                target_port: 444,
                local_port: 1080,
                vless_route: 7,
                ..RoutingInput::default()
            },
        ] {
            assert!(state.route(&input, &outbounds, &HashMap::new()).is_none());
        }
    }

    #[test]
    fn port_conditions_match_zero_and_wrap_test_route_values() {
        let state = RoutingState::from_parts(
            vec![
                RuleConfig {
                    port: PortListConfig(vec![PortRangeConfig { from: 0, to: 0 }]),
                    outbound_tag: Some("zero".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    port: PortListConfig(vec![PortRangeConfig { from: 1, to: 1 }]),
                    outbound_tag: Some("one".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![],
        )
        .expect("zero-port routing rules should compile");
        let outbounds = [outbound("zero"), outbound("one")];

        assert_eq!(
            state
                .route(
                    &RoutingInput {
                        target_port: 65_536,
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .expect("65536 should wrap to port zero")
                .outbound_tag,
            "zero"
        );
        assert_eq!(
            state
                .route(
                    &RoutingInput {
                        target_port: 65_537,
                        ..RoutingInput::default()
                    },
                    &outbounds,
                    &HashMap::new(),
                )
                .expect("65537 should wrap to port one")
                .outbound_tag,
            "one"
        );
    }

    #[test]
    fn network_condition_matches_xray_network_enum_values() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                network: NetworkListConfig(vec!["TCP".into(), "udp".into()]),
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("network routing rule should compile");
        let outbounds = [outbound("direct")];

        for network in [2, 3] {
            assert!(
                state
                    .route(
                        &RoutingInput {
                            network,
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_some()
            );
        }
        for network in [0, 1, 4, 99] {
            assert!(
                state
                    .route(
                        &RoutingInput {
                            network,
                            ..RoutingInput::default()
                        },
                        &outbounds,
                        &HashMap::new(),
                    )
                    .is_none()
            );
        }
    }

    #[test]
    fn xray_alias_fields_override_legacy_routing_fields() {
        let state = RoutingState::from_parts(
            vec![
                RuleConfig {
                    domain: vec!["regexp:(ignored-invalid".into()],
                    domains: vec!["full:new.example".into()],
                    outbound_tag: Some("domain".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    source: vec!["invalid-ignored-source".into()],
                    source_ip: vec!["192.0.2.7".into()],
                    outbound_tag: Some("source".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![],
        )
        .expect("Xray alias precedence should ignore shadowed values");
        let outbounds = [outbound("domain"), outbound("source")];

        let domain_match = state
            .route(
                &RoutingInput {
                    target_domain: "new.example".into(),
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .expect("domains should override domain");
        assert_eq!(domain_match.outbound_tag, "domain");

        let source_match = state
            .route(
                &RoutingInput {
                    source_ips: vec![vec![192, 0, 2, 7]],
                    ..RoutingInput::default()
                },
                &outbounds,
                &HashMap::new(),
            )
            .expect("sourceIP should override source");
        assert_eq!(source_match.outbound_tag, "source");
    }

    #[test]
    fn routing_rule_without_effective_fields_is_rejected() {
        let error = RoutingState::from_parts(
            vec![RuleConfig {
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect_err("unconditional Xray field rules must be rejected");

        assert_eq!(error, "routing rule has no effective fields");
    }

    #[test]
    fn routing_balancer_requires_an_outbound_selector() {
        let error = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("empty".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "empty".into(),
                outbound_selector: vec!["".into(), "   ".into()],
                strategy: Default::default(),
                fallback_tag: Some("direct".into()),
            }],
        )
        .expect_err("Xray balancers require at least one selector");

        assert_eq!(
            error,
            "routing balancer empty requires at least one outbound selector"
        );
    }

    #[test]
    fn matched_rule_with_missing_outbound_does_not_fall_through() {
        let state = RoutingState::from_parts(
            vec![
                RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("missing".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![],
        )
        .expect("missing outbound routing state should compile");

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .expect("first matched rule should be returned");
        assert_eq!(matched.outbound_tag, "missing");
    }

    #[test]
    fn failed_replace_merge_preserves_existing_routes() {
        let mut state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![RuleConfig {
                    domain: vec!["regexp:(invalid".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect_err("invalid replacement must fail atomically");
        assert!(error.contains("invalid regexp routing rule"));

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "existing".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct"), outbound("blocked")],
                &HashMap::new(),
            )
            .expect("existing route must survive failed replacement");
        assert_eq!(matched.outbound_tag, "direct");
    }

    #[test]
    fn failed_append_merge_does_not_keep_partial_rules_or_balancers() {
        let mut state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                rule_tag: Some("existing-rule".into()),
                ..RuleConfig::default()
            }],
            vec![],
        )
        .expect("existing routing state should build");

        let error = state
            .merge(
                vec![
                    RuleConfig {
                        inbound_tag: vec!["partial".into()],
                        outbound_tag: Some("blocked".into()),
                        rule_tag: Some("partial-rule".into()),
                        ..RuleConfig::default()
                    },
                    RuleConfig {
                        inbound_tag: vec!["duplicate".into()],
                        outbound_tag: Some("blocked".into()),
                        rule_tag: Some("existing-rule".into()),
                        ..RuleConfig::default()
                    },
                ],
                vec![BalancerConfig {
                    tag: "partial-balancer".into(),
                    outbound_selector: vec!["blocked".into()],
                    strategy: Default::default(),
                    fallback_tag: None,
                }],
                true,
            )
            .expect_err("invalid append must fail atomically");
        assert!(error.contains("duplicate routing ruleTag"));

        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "partial".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct"), outbound("blocked")],
                    &HashMap::new(),
                )
                .is_none(),
            "partial rule must not survive failed append"
        );
        assert!(
            state
                .balancer_targets("partial-balancer", &[outbound("blocked")])
                .is_empty(),
            "partial balancer must not survive failed append"
        );
        assert!(
            state
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &[outbound("direct"), outbound("blocked")],
                    &HashMap::new(),
                )
                .is_some(),
            "existing rule must survive failed append"
        );
    }

    #[test]
    fn empty_balancer_does_not_fall_through_to_later_rule() {
        let state = RoutingState::from_parts(
            vec![
                RuleConfig {
                    inbound_tag: vec!["test".into()],
                    balancer_tag: Some("empty".into()),
                    ..RuleConfig::default()
                },
                RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                },
            ],
            vec![BalancerConfig {
                tag: "empty".into(),
                outbound_selector: vec!["missing-prefix".into()],
                strategy: Default::default(),
                fallback_tag: None,
            }],
        )
        .expect("empty balancer routing state should compile");

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .expect("matched empty balancer should return an error route");

        assert_eq!(matched.outbound_tag, "");
        assert_eq!(matched.outbound_group_tags, vec!["empty"]);
        assert_eq!(
            matched.resolution_error.as_deref(),
            Some("routing balancer empty has no available outbound")
        );
    }

    #[test]
    fn balancer_fallback_is_used_when_selectors_match_nothing() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("auto".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "auto".into(),
                outbound_selector: vec!["missing-prefix".into()],
                strategy: Default::default(),
                fallback_tag: Some("direct".into()),
            }],
        )
        .expect("fallback balancer routing state should compile");

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .expect("fallback balancer should resolve");

        assert_eq!(matched.outbound_tag, "direct");
        assert_eq!(matched.outbound_group_tags, vec!["auto"]);
        assert_eq!(matched.resolution_error, None);
    }

    #[test]
    fn round_robin_balancer_rotates_in_candidate_order() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("round".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "round".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "roundRobin".into(),
                    settings: None,
                },
                fallback_tag: None,
            }],
        )
        .expect("round-robin routing state should build");
        let input = RoutingInput {
            inbound_tag: "test".into(),
            ..RoutingInput::default()
        };
        let outbounds = [outbound("direct"), outbound("backup")];

        let selected = (0..5)
            .map(|_| {
                state
                    .route(&input, &outbounds, &HashMap::new())
                    .expect("round-robin route should match")
                    .outbound_tag
            })
            .collect::<Vec<_>>();

        assert_eq!(
            selected,
            vec!["backup", "direct", "backup", "direct", "backup"]
        );
    }

    #[test]
    fn random_and_round_robin_fallback_filter_observed_dead_candidates() {
        for strategy in ["random", "roundRobin"] {
            let state = RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    balancer_tag: Some("auto".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "auto".into(),
                    outbound_selector: vec!["direct".into(), "backup".into()],
                    strategy: crate::config::rule::BalancerStrategyConfig {
                        kind: strategy.into(),
                        settings: None,
                    },
                    fallback_tag: Some("fallback".into()),
                }],
            )
            .expect("fallback-aware balancer should build");
            state.record_observation(
                "direct",
                OutboundObservation {
                    alive: false,
                    ..OutboundObservation::default()
                },
            );
            let input = RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            };
            let outbounds =
                [outbound("direct"), outbound("backup"), outbound("fallback")];

            for _ in 0..4 {
                let selected = state
                    .route(&input, &outbounds, &HashMap::new())
                    .expect("unobserved candidate should remain available");
                assert_eq!(selected.outbound_tag, "backup");
            }

            state.record_observation(
                "backup",
                OutboundObservation {
                    alive: false,
                    ..OutboundObservation::default()
                },
            );
            let fallback = state
                .route(&input, &outbounds, &HashMap::new())
                .expect("all dead candidates should use fallback");
            assert_eq!(fallback.outbound_tag, "fallback");
            assert_eq!(
                state.balancer_principle_targets("auto", &outbounds),
                vec!["backup", "direct"],
                "principle targets should remain selector candidates"
            );
        }
    }

    #[test]
    fn random_without_fallback_does_not_filter_dead_candidates() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("random".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "random".into(),
                outbound_selector: vec!["direct".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "random".into(),
                    settings: None,
                },
                fallback_tag: None,
            }],
        )
        .expect("random balancer should build");
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: false,
                ..OutboundObservation::default()
            },
        );

        let selected = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct")],
                &HashMap::new(),
            )
            .expect("random without fallback should ignore observation state");
        assert_eq!(selected.outbound_tag, "direct");
    }

    #[test]
    fn least_ping_balancer_selects_lowest_alive_observation() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("latency".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "latency".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "leastPing".into(),
                    settings: None,
                },
                fallback_tag: Some("fallback".into()),
            }],
        )
        .expect("leastPing routing state should build");
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: true,
                delay_ms: 80,
                ..OutboundObservation::default()
            },
        );
        state.record_observation(
            "backup",
            OutboundObservation {
                alive: true,
                delay_ms: 15,
                ..OutboundObservation::default()
            },
        );
        let input = RoutingInput {
            inbound_tag: "test".into(),
            ..RoutingInput::default()
        };
        let outbounds =
            [outbound("direct"), outbound("backup"), outbound("fallback")];

        let selected = state
            .route(&input, &outbounds, &HashMap::new())
            .expect("leastPing route should resolve");
        assert_eq!(selected.outbound_tag, "backup");

        state.record_observation(
            "direct",
            OutboundObservation {
                alive: false,
                delay_ms: 1,
                ..OutboundObservation::default()
            },
        );
        state.record_observation(
            "backup",
            OutboundObservation {
                alive: false,
                delay_ms: 1,
                ..OutboundObservation::default()
            },
        );
        let fallback = state
            .route(&input, &outbounds, &HashMap::new())
            .expect("leastPing fallback should resolve");
        assert_eq!(fallback.outbound_tag, "fallback");
        assert_eq!(
            state.balancer_principle_targets("latency", &outbounds),
            vec![String::new()],
            "leastPing principle target must not apply fallbackTag"
        );
    }

    #[test]
    fn connection_observation_preserves_active_health_window() {
        let state = RoutingState::default();
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: true,
                delay_ms: 20,
                last_seen_time: 100,
                last_try_time: 100,
                health_all: 10,
                health_fail: 2,
                health_deviation_ms: 4,
                health_average_ms: 18,
                health_max_ms: 30,
                health_min_ms: 10,
                ..OutboundObservation::default()
            },
        );
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: false,
                delay_ms: 50,
                last_error_reason: "connection refused".into(),
                last_try_time: 101,
                ..OutboundObservation::default()
            },
        );

        let status = &state.observations()["direct"];
        assert!(!status.alive);
        assert_eq!(status.delay_ms, 50);
        assert_eq!(status.last_seen_time, 100);
        assert_eq!(status.last_try_time, 101);
        assert_eq!(status.health_all, 10);
        assert_eq!(status.health_fail, 2);
        assert_eq!(status.health_average_ms, 18);
        assert_eq!(status.health_deviation_ms, 4);
    }

    #[test]
    fn routing_replace_preserves_outbound_observations() {
        let mut state = RoutingState::default();
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: true,
                delay_ms: 12,
                ..OutboundObservation::default()
            },
        );
        state
            .merge(
                vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("direct".into()),
                    ..RuleConfig::default()
                }],
                vec![],
                false,
            )
            .expect("routing replacement should compile");

        assert_eq!(state.observations()["direct"].delay_ms, 12);
    }

    #[test]
    fn least_load_balancer_applies_health_filters_costs_and_baselines() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("load".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "load".into(),
                outbound_selector: vec![
                    "fast".into(),
                    "premium".into(),
                    "flaky".into(),
                    "slow".into(),
                ],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "leastLoad".into(),
                    settings: Some(serde_json::json!({
                        "costs": [{"match": "premium", "value": 4}],
                        "baselines": ["20ms"],
                        "expected": 2,
                        "maxRTT": "100ms",
                        "tolerance": 0.5
                    })),
                },
                fallback_tag: Some("fallback".into()),
            }],
        )
        .expect("leastLoad routing state should build");
        for (tag, status) in [
            (
                "fast",
                OutboundObservation {
                    alive: true,
                    delay_ms: 12,
                    health_all: 10,
                    health_fail: 1,
                    health_average_ms: 12,
                    health_deviation_ms: 10,
                    ..OutboundObservation::default()
                },
            ),
            (
                "premium",
                OutboundObservation {
                    alive: true,
                    delay_ms: 8,
                    health_all: 10,
                    health_average_ms: 8,
                    health_deviation_ms: 6,
                    ..OutboundObservation::default()
                },
            ),
            (
                "flaky",
                OutboundObservation {
                    alive: true,
                    delay_ms: 4,
                    health_all: 10,
                    health_fail: 8,
                    health_average_ms: 4,
                    health_deviation_ms: 4,
                    ..OutboundObservation::default()
                },
            ),
            (
                "slow",
                OutboundObservation {
                    alive: true,
                    delay_ms: 150,
                    ..OutboundObservation::default()
                },
            ),
        ] {
            state.record_observation(tag, status);
        }
        let outbounds = [
            outbound("fast"),
            outbound("premium"),
            outbound("flaky"),
            outbound("slow"),
            outbound("fallback"),
        ];

        assert_eq!(
            state.balancer_principle_targets("load", &outbounds),
            vec!["fast", "premium"]
        );
    }

    #[test]
    fn least_load_filters_failed_node_even_with_zero_tolerance() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("load".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "load".into(),
                outbound_selector: vec!["direct".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "leastLoad".into(),
                    settings: Some(serde_json::json!({
                        "expected": 1,
                        "tolerance": 0
                    })),
                },
                fallback_tag: Some("fallback".into()),
            }],
        )
        .expect("leastLoad failed-node state should build");
        state.record_observation(
            "direct",
            OutboundObservation {
                alive: false,
                delay_ms: LEAST_PING_MAX_DELAY_MS,
                health_all: 3,
                health_fail: 3,
                ..OutboundObservation::default()
            },
        );

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct"), outbound("fallback")],
                &HashMap::new(),
            )
            .expect("failed measured node should use fallback");
        assert_eq!(matched.outbound_tag, "fallback");
    }

    #[test]
    fn least_load_balancer_uses_fallback_when_no_node_is_qualified() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("load".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "load".into(),
                outbound_selector: vec!["direct".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "leastLoad".into(),
                    settings: Some(serde_json::json!({"expected": 1})),
                },
                fallback_tag: Some("fallback".into()),
            }],
        )
        .expect("leastLoad fallback state should build");
        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct"), outbound("fallback")],
                &HashMap::new(),
            )
            .expect("leastLoad fallback should route");

        assert_eq!(matched.outbound_tag, "fallback");
        assert!(
            state
                .balancer_principle_targets(
                    "load",
                    &[outbound("direct"), outbound("fallback")],
                )
                .is_empty(),
            "leastLoad principle targets must not apply fallbackTag"
        );
    }

    #[test]
    fn least_load_ignores_invalid_or_empty_cost_matchers() {
        for cost in [
            serde_json::json!({"regexp": true, "match": "("}),
            serde_json::json!({"match": ""}),
        ] {
            let state = RoutingState::from_parts(
                vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    balancer_tag: Some("load".into()),
                    ..RuleConfig::default()
                }],
                vec![BalancerConfig {
                    tag: "load".into(),
                    outbound_selector: vec!["direct".into()],
                    strategy: crate::config::rule::BalancerStrategyConfig {
                        kind: "leastLoad".into(),
                        settings: Some(serde_json::json!({
                            "costs": [cost],
                            "expected": 1
                        })),
                    },
                    fallback_tag: None,
                }],
            )
            .expect("Xray ignores unusable leastLoad cost matchers");
            state.record_observation(
                "direct",
                OutboundObservation {
                    alive: true,
                    delay_ms: 10,
                    health_all: 1,
                    health_average_ms: 10,
                    health_deviation_ms: 10,
                    ..OutboundObservation::default()
                },
            );
            assert_eq!(
                state.balancer_principle_targets("load", &[outbound("direct")],),
                vec!["direct"]
            );
        }
    }

    #[test]
    fn least_load_rejects_invalid_duration() {
        let error = RoutingState::from_parts(
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("load".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "load".into(),
                outbound_selector: vec!["direct".into()],
                strategy: crate::config::rule::BalancerStrategyConfig {
                    kind: "leastLoad".into(),
                    settings: Some(serde_json::json!({
                        "maxRTT": "five parsecs"
                    })),
                },
                fallback_tag: None,
            }],
        )
        .expect_err("invalid leastLoad duration must fail");
        assert!(error.contains("invalid routing duration"));
    }

    #[test]
    fn routing_state_resolves_balancer_override() {
        let state = RoutingState::from_parts(
            vec![RuleConfig {
                balancer_tag: Some("auto".into()),
                inbound_tag: vec!["test".into()],
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "auto".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: Default::default(),
                fallback_tag: None,
            }],
        )
        .expect("routing state should build");

        let matched = state
            .route(
                &RoutingInput {
                    inbound_tag: "test".into(),
                    ..RoutingInput::default()
                },
                &[outbound("direct"), outbound("backup")],
                &HashMap::from([("auto".into(), "backup".into())]),
            )
            .expect("balancer rule should match");
        assert_eq!(matched.outbound_tag, "backup");
        assert_eq!(matched.outbound_group_tags, vec!["auto".to_string()]);
    }
}
