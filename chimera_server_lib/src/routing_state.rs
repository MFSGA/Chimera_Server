use std::{collections::HashMap, net::IpAddr, str::FromStr};

use crate::{
    config::rule::{
        BalancerConfig, NetworkListConfig, PortRangeConfig, RoutingConfig,
        RuleConfig,
    },
    runtime::OutboundSummary,
};

#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    balancers: HashMap<String, BalancerConfig>,
    rules: Vec<CompiledRule>,
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
    pub attributes: HashMap<String, String>,
    pub local_ips: Vec<Vec<u8>>,
    pub local_port: u32,
    pub vless_route: u32,
}

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub outbound_tag: String,
    pub outbound_group_tags: Vec<String>,
}

#[derive(Debug, Clone)]
enum RuleTarget {
    Outbound(String),
    Balancer(String),
}

#[derive(Debug, Clone)]
struct CompiledRule {
    attrs: HashMap<String, String>,
    inbound_tags: Vec<String>,
    local_ips: Vec<CidrMatcher>,
    local_ports: Vec<PortRangeConfig>,
    networks: Vec<String>,
    protocols: Vec<String>,
    rule_tag: String,
    source_ips: Vec<CidrMatcher>,
    source_ports: Vec<PortRangeConfig>,
    target: RuleTarget,
    target_domains: Vec<DomainMatcher>,
    target_ips: Vec<CidrMatcher>,
    target_ports: Vec<PortRangeConfig>,
    users: Vec<String>,
    vless_routes: Vec<PortRangeConfig>,
}

#[derive(Debug, Clone)]
enum DomainMatcher {
    Plain(String),
    Domain(String),
    Full(String),
}

#[derive(Debug, Clone)]
struct CidrMatcher {
    addr: IpAddr,
    prefix: u8,
}

impl RoutingState {
    pub fn from_config(config: Option<&RoutingConfig>) -> Result<Self, String> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        Self::from_parts(config.rules.clone(), config.balancers.clone())
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
        if !should_append {
            self.rules.clear();
            self.balancers.clear();
        }

        for balancer in balancers {
            if balancer.tag.trim().is_empty() {
                return Err("routing balancer tag is required".into());
            }
            if self.balancers.contains_key(&balancer.tag) {
                return Err(format!("duplicate routing balancer {}", balancer.tag));
            }
            self.balancers.insert(balancer.tag.clone(), balancer);
        }

        for rule in rules {
            let compiled = CompiledRule::try_from(rule)?;
            if !compiled.rule_tag.is_empty()
                && self
                    .rules
                    .iter()
                    .any(|item| item.rule_tag == compiled.rule_tag)
            {
                return Err(format!(
                    "duplicate routing ruleTag {}",
                    compiled.rule_tag
                ));
            }
            self.rules.push(compiled);
        }

        Ok(())
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
        for rule in &self.rules {
            if !rule.matches(input) {
                continue;
            }
            if let Some(resolved) =
                self.resolve_target(&rule.target, outbounds, balancer_overrides)
            {
                return Some(RouteMatch {
                    outbound_tag: resolved.0,
                    outbound_group_tags: resolved.1,
                });
            }
        }
        None
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

        let mut targets = Vec::new();
        for selector in &balancer.outbound_selector {
            for outbound in outbounds {
                if (outbound.tag == *selector || outbound.tag.starts_with(selector))
                    && !targets.iter().any(|target| target == &outbound.tag)
                {
                    targets.push(outbound.tag.clone());
                }
            }
        }
        if targets.is_empty() {
            if let Some(fallback_tag) = balancer.fallback_tag.as_ref() {
                if outbounds
                    .iter()
                    .any(|outbound| outbound.tag == *fallback_tag)
                {
                    targets.push(fallback_tag.clone());
                }
            }
        }
        targets
    }

    fn resolve_target(
        &self,
        target: &RuleTarget,
        outbounds: &[OutboundSummary],
        balancer_overrides: &HashMap<String, String>,
    ) -> Option<(String, Vec<String>)> {
        match target {
            RuleTarget::Outbound(tag) => outbounds
                .iter()
                .any(|outbound| outbound.tag == *tag)
                .then(|| (tag.clone(), Vec::new())),
            RuleTarget::Balancer(balancer_tag) => {
                if let Some(target) = balancer_overrides.get(balancer_tag) {
                    if outbounds.iter().any(|outbound| outbound.tag == *target) {
                        return Some((target.clone(), vec![balancer_tag.clone()]));
                    }
                }
                self.balancer_targets(balancer_tag, outbounds)
                    .into_iter()
                    .next()
                    .map(|target| (target, vec![balancer_tag.clone()]))
            }
        }
    }
}

impl TryFrom<RuleConfig> for CompiledRule {
    type Error = String;

    fn try_from(rule: RuleConfig) -> Result<Self, Self::Error> {
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
        for value in rule.domain.into_iter().chain(rule.domains) {
            target_domains.push(parse_domain_matcher(&value)?);
        }

        let mut target_ips = Vec::new();
        for value in rule.ip {
            target_ips.push(parse_cidr_matcher(&value)?);
        }

        let mut source_ips = Vec::new();
        for value in rule.source_ip.into_iter().chain(rule.source) {
            source_ips.push(parse_cidr_matcher(&value)?);
        }

        let mut local_ips = Vec::new();
        for value in rule.local_ip {
            local_ips.push(parse_cidr_matcher(&value)?);
        }

        Ok(Self {
            attrs: rule.attrs,
            inbound_tags: rule.inbound_tag,
            local_ips,
            local_ports: rule.local_port.0,
            networks: normalize_networks(rule.network),
            protocols: rule.protocol,
            rule_tag: rule.rule_tag.unwrap_or_default(),
            source_ips,
            source_ports: rule.source_port.0,
            target,
            target_domains,
            target_ips,
            target_ports: rule.port.0,
            users: rule.user,
            vless_routes: rule.vless_route.0,
        })
    }
}

impl CompiledRule {
    fn matches(&self, input: &RoutingInput) -> bool {
        matches_string_list(&self.inbound_tags, &input.inbound_tag)
            && matches_networks(&self.networks, input.network)
            && matches_ip_list(&self.source_ips, &input.source_ips)
            && matches_ip_list(&self.target_ips, &input.target_ips)
            && matches_ip_list(&self.local_ips, &input.local_ips)
            && matches_ports(&self.source_ports, input.source_port)
            && matches_ports(&self.target_ports, input.target_port)
            && matches_ports(&self.local_ports, input.local_port)
            && matches_ports(&self.vless_routes, input.vless_route)
            && matches_domains(&self.target_domains, &input.target_domain)
            && matches_string_list(&self.protocols, &input.protocol)
            && matches_string_list(&self.users, &input.user)
            && matches_attributes(&self.attrs, &input.attributes)
    }
}

fn normalize_networks(networks: NetworkListConfig) -> Vec<String> {
    networks
        .0
        .into_iter()
        .map(|network| network.trim().to_ascii_lowercase())
        .filter(|network| !network.is_empty())
        .collect()
}

fn parse_domain_matcher(value: &str) -> Result<DomainMatcher, String> {
    let value = value.trim();
    if let Some(value) = value.strip_prefix("domain:") {
        return Ok(DomainMatcher::Domain(value.to_string()));
    }
    if let Some(value) = value.strip_prefix("full:") {
        return Ok(DomainMatcher::Full(value.to_string()));
    }
    if value.starts_with("regexp:") {
        return Err("regexp routing rules are not supported yet".into());
    }
    let value = value.strip_prefix("keyword:").unwrap_or(value);
    Ok(DomainMatcher::Plain(value.to_string()))
}

fn parse_cidr_matcher(value: &str) -> Result<CidrMatcher, String> {
    let value = value.trim();
    let Some((ip, prefix)) = value
        .split_once('/')
        .map(|(ip, prefix)| (ip, Some(prefix)))
        .or_else(|| Some((value, None)))
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

fn matches_ip_list(matchers: &[CidrMatcher], inputs: &[Vec<u8>]) -> bool {
    if matchers.is_empty() {
        return true;
    }
    inputs.iter().any(|ip| {
        decode_ip(ip)
            .map(|ip| matchers.iter().any(|matcher| matcher.matches(ip)))
            .unwrap_or(false)
    })
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
    ranges.is_empty()
        || (port > 0
            && ranges
                .iter()
                .any(|range| port >= range.from as u32 && port <= range.to as u32))
}

fn matches_domains(matchers: &[DomainMatcher], domain: &str) -> bool {
    if matchers.is_empty() {
        return true;
    }
    if domain.is_empty() {
        return false;
    }
    matchers.iter().any(|matcher| match matcher {
        DomainMatcher::Plain(value) => domain.contains(value),
        DomainMatcher::Domain(value) => {
            domain == value || domain.ends_with(&format!(".{value}"))
        }
        DomainMatcher::Full(value) => domain == value,
    })
}

fn matches_attributes(
    expected: &HashMap<String, String>,
    actual: &HashMap<String, String>,
) -> bool {
    expected.is_empty()
        || expected
            .iter()
            .all(|(key, value)| actual.get(key) == Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbound(tag: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.to_string(),
            protocol: "freedom".to_string(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
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
