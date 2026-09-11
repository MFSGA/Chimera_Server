use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use regex::Regex;

use crate::{
    config::rule::{NetworkListConfig, PortRangeConfig, RuleConfig},
    geodata::GeodataStore,
    routing_webhook::RoutingWebhook,
};

use super::RoutingInput;

const INTERNAL_NEVER_IP_RULE: &str = "\0chimera:never-ip";
const INTERNAL_NEVER_DOMAIN_RULE: &str = "\0chimera:never-domain";

#[derive(Debug, Clone)]
pub(super) enum RuleTarget {
    Outbound(String),
    Balancer(String),
}

#[derive(Debug, Clone)]
pub(super) struct CompiledRule {
    attrs: AttributeMatcher,
    inbound_tags: Vec<String>,
    local_ips: IpMatcher,
    local_ports: Vec<PortRangeConfig>,
    networks: Vec<String>,
    pub(super) processes: ProcessMatcher,
    protocols: ProtocolMatcher,
    pub(super) rule_tag: String,
    source_ips: IpMatcher,
    source_ports: Vec<PortRangeConfig>,
    pub(super) target: RuleTarget,
    target_domains: Vec<DomainMatcher>,
    pub(super) target_ips: IpMatcher,
    target_ports: Vec<PortRangeConfig>,
    users: UserMatcher,
    vless_routes: Vec<PortRangeConfig>,
    pub(super) webhook: Option<Arc<RoutingWebhook>>,
}

#[derive(Debug, Clone)]
pub(super) enum DomainMatcher {
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
pub(super) struct IpMatcher {
    pub(super) configured: bool,
    positive: Vec<CidrMatcher>,
    negative: Vec<CidrMatcher>,
}

impl IpMatcher {
    pub(super) fn from_xray_values(values: Vec<String>) -> Result<Self, String> {
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

    pub(super) fn matches(&self, inputs: &[Vec<u8>]) -> bool {
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
    pub(super) configured: bool,
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
    pub(super) configured: bool,
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
pub(super) struct ProcessMatcher {
    pub(super) configured: bool,
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
    pub(super) configured: bool,
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

impl TryFrom<RuleConfig> for CompiledRule {
    type Error = String;

    fn try_from(rule: RuleConfig) -> Result<Self, Self::Error> {
        if !rule_has_effective_fields(&rule) {
            return Err("routing rule has no effective fields".into());
        }

        let outbound_tag = rule.outbound_tag.filter(|tag| !tag.trim().is_empty());
        let balancer_tag = rule.balancer_tag.filter(|tag| !tag.trim().is_empty());
        let target = if let Some(outbound_tag) = outbound_tag {
            RuleTarget::Outbound(outbound_tag)
        } else if let Some(balancer_tag) = balancer_tag {
            RuleTarget::Balancer(balancer_tag)
        } else {
            return Err(
                "neither outboundTag nor balancerTag is specified in routing rule"
                    .into(),
            );
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
        self.matches_with_target_ips(input, &input.target_ips)
    }

    pub(super) fn matches_before_target_ip(&self, input: &RoutingInput) -> bool {
        matches_string_list(&self.inbound_tags, &input.inbound_tag)
            && matches_networks(&self.networks, input.network)
            && self.protocols.matches(&input.protocol)
            && matches_ports(&self.target_ports, input.target_port)
            && matches_ports(&self.source_ports, input.source_port)
            && matches_ports(&self.local_ports, input.local_port)
            && matches_ports(&self.vless_routes, input.vless_route)
            && self.users.matches(&input.user)
            && self.attrs.matches(&input.attributes)
    }

    pub(super) fn matches_before_process(&self, input: &RoutingInput) -> bool {
        self.matches_before_target_ip(input)
            && self.target_ips.matches(&input.target_ips)
            && self.source_ips.matches(&input.source_ips)
            && self.local_ips.matches(&input.local_ips)
            && matches_domains(&self.target_domains, &input.target_domain)
    }

    pub(super) fn matches_with_target_ips(
        &self,
        input: &RoutingInput,
        target_ips: &[Vec<u8>],
    ) -> bool {
        matches_string_list(&self.inbound_tags, &input.inbound_tag)
            && matches_networks(&self.networks, input.network)
            && self.protocols.matches(&input.protocol)
            && matches_ports(&self.target_ports, input.target_port)
            && matches_ports(&self.source_ports, input.source_port)
            && matches_ports(&self.local_ports, input.local_port)
            && matches_ports(&self.vless_routes, input.vless_route)
            && self.users.matches(&input.user)
            && self.attrs.matches(&input.attributes)
            && self.target_ips.matches(target_ips)
            && self.source_ips.matches(&input.source_ips)
            && self.local_ips.matches(&input.local_ips)
            && matches_domains(&self.target_domains, &input.target_domain)
            && self.processes.matches(input)
    }
}

pub(super) fn normalize_rule_aliases(mut rule: RuleConfig) -> RuleConfig {
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

pub(super) fn rule_uses_geoip(rule: &RuleConfig) -> bool {
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

pub(super) fn rule_uses_geosite(rule: &RuleConfig) -> bool {
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

pub(super) fn expand_geoip_values(
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

pub(super) fn expand_geosite_values(
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

pub(super) fn parse_domain_matcher(value: &str) -> Result<DomainMatcher, String> {
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

pub(super) fn matches_domains(matchers: &[DomainMatcher], domain: &str) -> bool {
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
