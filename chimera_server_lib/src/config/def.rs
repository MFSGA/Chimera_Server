use std::{collections::HashMap, net::IpAddr, path::PathBuf, str::FromStr};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, log::LogConfig};

use super::{
    MkcpTransportConfig, Protocol, SettingObject, StreamSettings, Transport,
    rule::RoutingConfig,
};

#[derive(Deserialize, Debug)]
pub struct LiteralConfig {
    pub inbounds: Vec<InboudItem>,
    pub outbounds: Vec<OutboundItem>,
    pub log: Option<LogConfig>,
    #[serde(default)]
    pub stats: Option<StatsConfig>,
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default, rename = "userDomainAccess")]
    pub user_domain_access: Option<Value>,
    #[serde(default)]
    pub observatory: Option<ObservatoryConfig>,
    #[serde(default, rename = "burstObservatory")]
    pub burst_observatory: Option<BurstObservatoryConfig>,
    #[serde(default)]
    pub shutdown: Option<ShutdownConfig>,
    // mcp settings
    pub mcp: Option<McpConfig>,
}

/// The current Xray-compatible DNS slice. Static host mappings (including
/// response-code and plain UDP/TCP nameserver endpoints) are compiled into the
/// runtime resolver; unsupported per-server policies and encrypted transports
/// remain explicitly rejected.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    #[serde(default)]
    pub hosts: Option<HashMap<String, DnsHostValue>>,
    #[serde(default)]
    pub servers: Option<Value>,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub query_strategy: Option<String>,
    #[serde(default)]
    pub disable_cache: Option<bool>,
    #[serde(default)]
    pub serve_stale: Option<bool>,
    #[serde(default)]
    pub serve_expired_ttl: Option<u32>,
    #[serde(default)]
    pub disable_fallback: Option<bool>,
    #[serde(default)]
    pub disable_fallback_if_match: Option<bool>,
    #[serde(default)]
    pub enable_parallel_query: Option<bool>,
    #[serde(default)]
    pub use_system_hosts: Option<bool>,
}

/// Xray's DNS query-family selection for the supported plain UDP/TCP resolver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsQueryStrategy {
    #[default]
    UseIp,
    UseIpv4,
    UseIpv6,
    UseSystem,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsServerTransport {
    #[default]
    Udp,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDnsServer {
    pub address: std::net::SocketAddr,
    pub transport: DnsServerTransport,
    pub client_ip: Option<IpAddr>,
    pub query_strategy: Option<DnsQueryStrategy>,
    pub domains: Vec<String>,
    pub skip_fallback: bool,
    pub final_query: bool,
    pub timeout_ms: Option<u64>,
    pub expected_ips: Vec<String>,
    pub expected_ips_prefer: bool,
    pub unexpected_ips: Vec<String>,
    pub unexpected_ips_prefer: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum DnsHostValue {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDnsHost {
    pub rule: String,
    pub addresses: Vec<IpAddr>,
    pub proxied_domain: Option<String>,
    pub response_code: Option<u16>,
}

impl DnsConfig {
    /// Compiles Xray's textual query strategy. Xray treats unknown values as
    /// its default `UseIP`, so preserve that behavior for JSON compatibility.
    pub fn compile_query_strategy(&self) -> DnsQueryStrategy {
        compile_dns_query_strategy(self.query_strategy.as_deref())
    }

    /// Compiles the Xray DNS fallback switches. Omitted values use Xray's
    /// enabled-fallback defaults.
    pub fn compile_fallback_options(&self) -> (bool, bool) {
        (
            self.disable_fallback.unwrap_or(false),
            self.disable_fallback_if_match.unwrap_or(false),
        )
    }

    /// Compiles Xray's optional parallel nameserver query switch.
    pub fn compile_enable_parallel_query(&self) -> bool {
        self.enable_parallel_query.unwrap_or(false)
    }

    pub fn compile_servers(&self) -> Result<Vec<std::net::SocketAddr>, String> {
        Ok(self
            .compile_server_configs()?
            .into_iter()
            .map(|server| server.address)
            .collect())
    }

    /// Compiles Xray's optional EDNS Client Subnet address.
    pub fn compile_client_ip(&self) -> Result<Option<IpAddr>, String> {
        self.client_ip
            .as_deref()
            .map(str::parse::<IpAddr>)
            .transpose()
            .map_err(|_| {
                "dns.clientIp must be a valid IPv4 or IPv6 address".to_string()
            })
    }

    pub fn compile_server_configs(&self) -> Result<Vec<CompiledDnsServer>, String> {
        let Some(value) = self.servers.as_ref() else {
            return Ok(Vec::new());
        };
        if value.is_null() {
            return Ok(Vec::new());
        }
        let values = match value {
            Value::String(server) => {
                let (address, transport) = compile_dns_server_endpoint(server)?;
                vec![CompiledDnsServer {
                    address,
                    transport,
                    client_ip: None,
                    query_strategy: None,
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                }]
            }
            Value::Array(servers) => servers
                .iter()
                .map(compile_dns_server_value)
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(
                    "dns.servers currently accepts an endpoint string or an array of endpoint strings/objects"
                        .into(),
                );
            }
        };
        Ok(values)
    }
}

fn compile_dns_server_value(value: &Value) -> Result<CompiledDnsServer, String> {
    match value {
        Value::String(server) => {
            let (address, transport) = compile_dns_server_endpoint(server)?;
            Ok(CompiledDnsServer {
                address,
                transport,
                client_ip: None,
                query_strategy: None,
                domains: Vec::new(),
                skip_fallback: false,
                final_query: false,
                timeout_ms: None,
                expected_ips: Vec::new(),
                expected_ips_prefer: false,
                unexpected_ips: Vec::new(),
                unexpected_ips_prefer: false,
            })
        }
        Value::Object(object) => {
            const SUPPORTED_FIELDS: &[&str] = &[
                "address",
                "port",
                "clientIp",
                "domains",
                "skipFallback",
                "finalQuery",
                "timeoutMs",
                "expectedIPs",
                "expectIPs",
                "unexpectedIPs",
                "queryStrategy",
            ];
            if let Some(field) = object
                .keys()
                .find(|field| !SUPPORTED_FIELDS.contains(&field.as_str()))
            {
                return Err(format!(
                    "dns.servers object field {field} is recognized but not implemented; supported fields are address, port, clientIp, domains, skipFallback, finalQuery, timeoutMs, expectedIPs, expectIPs, unexpectedIPs and queryStrategy"
                ));
            }
            let address =
                object
                    .get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        "dns.servers object requires a string IP address".to_string()
                    })?;
            let address = address.parse::<IpAddr>().map_err(|_| {
                format!(
                    "dns.servers object address {address} is not an IP; domain names are not supported for nameserver endpoints"
                )
            })?;
            let port = match object.get("port") {
                None | Some(Value::Null) => 53,
                Some(value) => value
                    .as_u64()
                    .filter(|port| *port <= u16::MAX as u64)
                    .map(|port| if port == 0 { 53 } else { port as u16 })
                    .ok_or_else(|| {
                        "dns.servers object port must be an integer between 0 and 65535"
                            .to_string()
                    })?,
            };
            let query_strategy = match object.get("queryStrategy") {
                None | Some(Value::Null) => None,
                Some(Value::String(strategy)) => {
                    Some(compile_dns_query_strategy(Some(strategy)))
                }
                Some(_) => {
                    return Err(
                        "dns.servers object queryStrategy must be a string".into()
                    );
                }
            };
            let client_ip = compile_dns_client_ip(object.get("clientIp"))?;
            let domains = compile_dns_server_domains(object.get("domains"))?;
            let skip_fallback =
                compile_dns_bool(object.get("skipFallback"), "skipFallback")?;
            let final_query =
                compile_dns_bool(object.get("finalQuery"), "finalQuery")?;
            let timeout_ms = compile_dns_timeout_ms(object.get("timeoutMs"))?;
            let expected_value = object
                .get("expectedIPs")
                .filter(|value| !dns_value_is_empty_list(value))
                .or_else(|| object.get("expectIPs"));
            let (expected_ips, expected_ips_prefer) =
                compile_dns_ip_rules(expected_value, "expectedIPs")?;
            let (unexpected_ips, unexpected_ips_prefer) =
                compile_dns_ip_rules(object.get("unexpectedIPs"), "unexpectedIPs")?;
            Ok(CompiledDnsServer {
                address: std::net::SocketAddr::new(address, port),
                transport: DnsServerTransport::Udp,
                client_ip,
                query_strategy,
                domains,
                skip_fallback,
                final_query,
                timeout_ms,
                expected_ips,
                expected_ips_prefer,
                unexpected_ips,
                unexpected_ips_prefer,
            })
        }
        _ => Err("dns.servers entries must be endpoint strings or objects".into()),
    }
}

fn compile_dns_client_ip(value: Option<&Value>) -> Result<Option<IpAddr>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            value.parse::<IpAddr>().map(Some).map_err(|_| {
                "dns.servers object clientIp must be a valid IPv4 or IPv6 address"
                    .to_string()
            })
        }
        Some(_) => Err(
            "dns.servers object clientIp must be a string containing an IP address"
                .into(),
        ),
    }
}

fn compile_dns_server_domains(value: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = match value {
        Value::String(value) => {
            value.split(',').map(str::trim).map(str::to_owned).collect()
        }
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    "dns.servers object domains must contain only strings"
                        .to_string()
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(
                "dns.servers object domains must be a string or an array of strings"
                    .into(),
            );
        }
    };
    values
        .into_iter()
        .map(|rule| normalize_dns_server_domain_rule(&rule))
        .collect()
}

fn compile_dns_bool(value: Option<&Value>, field: &str) -> Result<bool, String> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("dns.servers object {field} must be a boolean")),
    }
}

fn compile_dns_timeout_ms(value: Option<&Value>) -> Result<Option<u64>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            "dns.servers object timeoutMs must be a non-negative integer".into()
        }),
    }
}

fn dns_value_is_empty_list(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.trim().is_empty(),
        Value::Array(values) => values.is_empty(),
        _ => false,
    }
}

fn compile_dns_ip_rules(
    value: Option<&Value>,
    field: &str,
) -> Result<(Vec<String>, bool), String> {
    let Some(value) = value else {
        return Ok((Vec::new(), false));
    };
    if value.is_null() {
        return Ok((Vec::new(), false));
    }
    let values = match value {
        Value::String(value) => {
            value.split(',').map(str::trim).map(str::to_owned).collect()
        }
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    format!("dns.servers object {field} must contain only strings")
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(format!(
                "dns.servers object {field} must be a string or an array of strings"
            ));
        }
    };
    let mut rules = Vec::new();
    let mut prefer = false;
    for rule in values {
        let rule = rule.trim();
        if rule.is_empty() {
            return Err(format!(
                "dns.servers object {field} contains an empty rule"
            ));
        }
        if rule == "*" {
            prefer = true;
            continue;
        }
        let candidate = rule.trim_start_matches('!');
        if candidate.starts_with("geoip:") || candidate.starts_with("ext:") {
            return Err(format!(
                "dns.servers object {field} rule {rule} uses unsupported GeoIP/ext data"
            ));
        }
        compile_dns_ip_rule(candidate).map_err(|error| {
            format!("dns.servers object {field} rule {rule} is invalid: {error}")
        })?;
        rules.push(rule.to_owned());
    }
    Ok((rules, prefer))
}

fn compile_dns_ip_rule(rule: &str) -> Result<(), String> {
    let (address, prefix) = rule
        .split_once('/')
        .map_or((rule, None), |(address, prefix)| (address, Some(prefix)));
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| "expected an IP address or CIDR".to_string())?;
    let max_prefix: u8 = if address.is_ipv4() { 32 } else { 128 };
    if let Some(prefix) = prefix {
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| "CIDR prefix is not an integer".to_string())?;
        if prefix > max_prefix {
            return Err(format!("CIDR prefix exceeds {max_prefix}"));
        }
    }
    Ok(())
}

fn normalize_dns_server_domain_rule(rule: &str) -> Result<String, String> {
    let rule = rule.trim();
    if rule.is_empty() {
        return Err("dns.servers object domains contains an empty rule".into());
    }
    if rule.starts_with("geosite:")
        || rule.starts_with("ext:")
        || rule.starts_with("ext-domain:")
        || rule.starts_with("ext-site:")
    {
        return Err(format!(
            "dns.servers object domain rule {rule} uses unsupported geosite/ext data"
        ));
    }
    if let Some(pattern) = rule.strip_prefix("regexp:") {
        regex::Regex::new(pattern).map_err(|error| {
            format!("invalid dns.servers object domain regexp {pattern}: {error}")
        })?;
        return Ok(format!("regexp:{pattern}"));
    }
    if let Some(pattern) = rule.strip_prefix("dotless:") {
        if pattern.contains('.') {
            return Err(format!(
                "dns.servers object dotless rule {rule} must not contain a dot"
            ));
        }
        return Ok(if pattern.is_empty() {
            "regexp:^[^.]*$".into()
        } else {
            format!("regexp:^[^.]*{pattern}[^.]*$")
        });
    }
    let (prefix, pattern) = if let Some(pattern) = rule.strip_prefix("domain:") {
        ("domain:", pattern)
    } else if let Some(pattern) = rule.strip_prefix("full:") {
        ("full:", pattern)
    } else if let Some(pattern) = rule.strip_prefix("keyword:") {
        ("keyword:", pattern)
    } else {
        ("keyword:", rule)
    };
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(format!(
            "dns.servers object domain rule {rule} contains an empty pattern"
        ));
    }
    if matches!(prefix, "domain:" | "full:") {
        let pattern = normalize_dns_host(pattern)?;
        return Ok(format!("{prefix}{pattern}"));
    }
    Ok(format!("{prefix}{}", pattern.to_ascii_lowercase()))
}

fn compile_dns_query_strategy(value: Option<&str>) -> DnsQueryStrategy {
    let value = value
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    match value.as_str() {
        "useip" | "use_ip" | "use-ip" => DnsQueryStrategy::UseIp,
        "useip4" | "useipv4" | "use_ip4" | "use_ipv4" | "use_ip_v4" | "use-ip4"
        | "use-ipv4" | "use-ip-v4" => DnsQueryStrategy::UseIpv4,
        "useip6" | "useipv6" | "use_ip6" | "use_ipv6" | "use_ip_v6" | "use-ip6"
        | "use-ipv6" | "use-ip-v6" => DnsQueryStrategy::UseIpv6,
        "usesys" | "usesystem" | "use_sys" | "use_system" | "use-sys"
        | "use-system" => DnsQueryStrategy::UseSystem,
        _ => DnsQueryStrategy::UseIp,
    }
}

fn compile_dns_server_endpoint(
    server: &str,
) -> Result<(std::net::SocketAddr, DnsServerTransport), String> {
    let server = server.trim();
    if server.is_empty() {
        return Err("dns.servers contains an empty endpoint".into());
    }
    let (transport, endpoint) = match server.split_once("://") {
        Some((scheme, endpoint)) if scheme.eq_ignore_ascii_case("tcp") => {
            (DnsServerTransport::Tcp, endpoint)
        }
        Some(_) => {
            return Err(format!(
                "dns.servers endpoint {server} uses an unsupported URL scheme; only UDP IP endpoints and tcp:// endpoints are supported"
            ));
        }
        None => (DnsServerTransport::Udp, server),
    };
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(format!(
            "dns.servers endpoint {server} has no nameserver address"
        ));
    }
    if let Ok(endpoint) = endpoint.parse::<std::net::SocketAddr>() {
        return Ok((endpoint, transport));
    }
    if let Ok(address) = endpoint.parse::<std::net::IpAddr>() {
        return Ok((std::net::SocketAddr::new(address, 53), transport));
    }
    Err(format!(
        "dns.servers endpoint {server} is not an IP or IP:port endpoint"
    ))
}

impl DnsConfig {
    pub fn compile_hosts(&self) -> Result<Vec<CompiledDnsHost>, String> {
        self.reject_unsupported_fields()?;
        let mut hosts = Vec::new();
        for (domain, value) in self.hosts.as_ref().into_iter().flatten() {
            let rule = normalize_dns_host_rule(domain)?;
            let values = match value {
                DnsHostValue::Single(address) => vec![address.clone()],
                DnsHostValue::Multiple(addresses) => addresses.clone(),
            };
            if values.is_empty() {
                return Err(format!("dns.hosts entry {rule} has no addresses"));
            }
            let mut addresses = Vec::new();
            let mut proxied_domain = None;
            let mut response_code = None;
            let mut has_non_ip_value = false;
            for address in values {
                if has_non_ip_value {
                    // Xray's HostAddress returns on the first domain-valued
                    // entry, so values after a proxied domain or response
                    // code do not affect the compiled mapping.
                    continue;
                }
                match address.parse::<IpAddr>() {
                    Ok(address) => addresses.push(address),
                    Err(_) => {
                        has_non_ip_value = true;
                        if let Some(value) = address.strip_prefix('#') {
                            let code = value.parse::<u16>().map_err(|_| {
                                format!(
                                    "dns.hosts entry {rule} contains an invalid response code {address}"
                                )
                            })?;
                            response_code = Some(code);
                        } else {
                            let domain = normalize_dns_host(&address).map_err(|error| {
                                format!(
                                    "dns.hosts entry {rule} contains an unsupported address {address}: {error}"
                                )
                            })?;
                            proxied_domain = Some(domain);
                        }
                    }
                }
            }
            if response_code.is_some() || proxied_domain.is_some() {
                // Xray's JSON host wrapper treats a domain-valued host as a
                // proxied-domain response rather than mixing it with IPs.
                addresses.clear();
            }
            if addresses.is_empty()
                && proxied_domain.is_none()
                && response_code.is_none()
            {
                return Err(format!(
                    "dns.hosts entry {rule} has no usable IP or proxied domain"
                ));
            }
            hosts.push(CompiledDnsHost {
                rule,
                addresses,
                proxied_domain,
                response_code,
            });
        }
        Ok(hosts)
    }

    fn reject_unsupported_fields(&self) -> Result<(), String> {
        let unsupported = [
            self.tag.as_ref().map(|_| "tag"),
            self.serve_stale.map(|_| "serveStale"),
            self.serve_expired_ttl.map(|_| "serveExpiredTTL"),
            self.use_system_hosts.map(|_| "useSystemHosts"),
        ];
        if let Some(field) = unsupported.into_iter().flatten().next() {
            return Err(format!(
                "dns.{field} is recognized but not implemented; supported DNS settings are dns.hosts, plain UDP/TCP dns.servers IP endpoints/basic objects and fallback controls"
            ));
        }
        Ok(())
    }
}

fn normalize_dns_host(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        return Err("dns.hosts contains an empty domain".into());
    }
    idna::domain_to_ascii(value)
        .map(|domain| domain.to_ascii_lowercase())
        .map_err(|error| format!("invalid dns.hosts domain {value}: {error}"))
}

fn normalize_dns_host_rule(value: &str) -> Result<String, String> {
    let value = value.trim();
    if let Some(pattern) = value.strip_prefix("regexp:") {
        Regex::new(pattern).map_err(|error| {
            format!("invalid dns.hosts regexp {pattern}: {error}")
        })?;
        return Ok(format!("regexp:{pattern}"));
    }
    if let Some(substr) = value.strip_prefix("dotless:") {
        if substr.contains('.') {
            return Err("dns.hosts dotless rule must not contain a dot".into());
        }
        let pattern = if substr.is_empty() {
            "^[^.]*$".to_string()
        } else {
            format!("^[^.]*{substr}[^.]*$")
        };
        Regex::new(&pattern).map_err(|error| {
            format!("invalid dns.hosts dotless rule {substr}: {error}")
        })?;
        return Ok(format!("regexp:{pattern}"));
    }
    if let Some(keyword) = value.strip_prefix("keyword:") {
        return Ok(format!("keyword:{}", keyword.to_ascii_lowercase()));
    }

    let (prefix, domain) = if let Some(domain) = value.strip_prefix("domain:") {
        ("domain", domain)
    } else if let Some(domain) = value.strip_prefix("full:") {
        ("full", domain)
    } else {
        ("full", value)
    };
    if domain.contains(':') {
        return Err(format!(
            "unsupported dns.hosts rule {value}; supported rules are full, domain, keyword, regexp and dotless"
        ));
    }
    Ok(format!("{prefix}:{}", normalize_dns_host(domain)?))
}

impl TryFrom<PathBuf> for LiteralConfig {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(&value)?;

        let config = match value.extension() {
            Some(ext) => match ext.to_str() {
                Some("json") => LiteralConfig::from_str(&content)?,
                Some("json5") => json5::from_str(&content).map_err(|e| {
                    Error::InvalidConfig(format!("Could not parse JSON5: {}", e))
                })?,
                Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                    .map_err(|e| {
                        Error::InvalidConfig(format!("Could not parse YAML: {e}"))
                    })?,
                Some("toml") => {
                    return Err(Error::InvalidConfig(
                        "TOML config format is not yet supported".into(),
                    ));
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "unsupported file type: {:?}",
                        value.extension()
                    )));
                }
            },
            None => {
                return Err(Error::InvalidConfig(format!(
                    "unknown file type {:?}",
                    value.extension()
                )));
            }
        };

        Ok(config)
    }
}

impl FromStr for LiteralConfig {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|x| {
            Error::InvalidConfig(format!(
                "cound not parse config content {}: {}",
                s, x
            ))
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InboudItem {
    pub allocate: Option<Value>,
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub protocol: Protocol,
    pub settings: Option<SettingObject>,
    pub sniffing: Option<Value>,
    #[serde(alias = "streamSettings")]
    pub stream_settings: Option<StreamSettings>,
    pub tag: String,
}

impl InboudItem {
    pub fn get_transport_type(&self) -> Transport {
        let Some(settings) = &self.stream_settings else {
            return Transport::Tcp;
        };

        match settings.network.to_ascii_lowercase().as_str() {
            "" | "tcp" => Transport::Tcp,
            "quic" => Transport::Quic,
            "kcp" | "mkcp" => {
                Transport::Mkcp(MkcpTransportConfig::from_kcp_settings(
                    settings.kcp_settings.as_ref(),
                ))
            }
            "udp" => Transport::Udp,
            _ => Transport::Tcp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundItem {
    pub protocol: String,
    pub tag: String,
    #[serde(default)]
    pub settings: Option<SettingObject>,
    #[serde(default, alias = "streamSettings")]
    pub stream_settings: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatsConfig {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    pub tag: Option<String>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObservatoryConfig {
    #[serde(default)]
    pub subject_selector: Vec<String>,
    #[serde(default)]
    pub probe_url: String,
    #[serde(default)]
    pub probe_interval: Option<Value>,
    #[serde(default)]
    pub enable_concurrency: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BurstObservatoryConfig {
    #[serde(default)]
    pub subject_selector: Vec<String>,
    #[serde(default)]
    pub ping_config: Option<HealthPingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HealthPingConfig {
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub connectivity: String,
    #[serde(default)]
    pub interval: Option<Value>,
    #[serde(default, alias = "samplingCount")]
    pub sampling: Option<usize>,
    #[serde(default)]
    pub timeout: Option<Value>,
    #[serde(default)]
    pub http_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyConfig {
    #[serde(default, deserialize_with = "deserialize_policy_levels")]
    pub levels: HashMap<u32, Option<PolicyLevelConfig>>,
    #[serde(default)]
    pub system: Option<SystemPolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PolicyLevelConfig {
    #[serde(default)]
    pub handshake: Option<u32>,
    #[serde(default, rename = "connIdle")]
    pub connection_idle: Option<u32>,
    #[serde(default)]
    pub uplink_only: Option<u32>,
    #[serde(default)]
    pub downlink_only: Option<u32>,
    #[serde(default)]
    pub stats_user_uplink: bool,
    #[serde(default)]
    pub stats_user_downlink: bool,
    #[serde(default)]
    pub stats_user_online: bool,
    #[serde(default)]
    pub buffer_size: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SystemPolicyConfig {
    #[serde(default)]
    pub stats_inbound_uplink: bool,
    #[serde(default)]
    pub stats_inbound_downlink: bool,
    #[serde(default)]
    pub stats_outbound_uplink: bool,
    #[serde(default)]
    pub stats_outbound_downlink: bool,
}

fn deserialize_policy_levels<'de, D>(
    deserializer: D,
) -> Result<HashMap<u32, Option<PolicyLevelConfig>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PolicyLevelsVisitor;

    impl<'de> serde::de::Visitor<'de> for PolicyLevelsVisitor {
        type Value = HashMap<u32, Option<PolicyLevelConfig>>;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter<'_>,
        ) -> std::fmt::Result {
            formatter.write_str("an Xray policy level map or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(HashMap::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(HashMap::new())
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_map(self)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut levels = HashMap::new();
            while let Some((level, policy)) =
                map.next_entry::<String, Option<PolicyLevelConfig>>()?
            {
                if level.is_empty()
                    || !level.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(serde::de::Error::custom(format!(
                        "invalid policy level key {level:?}: expected uint32 decimal"
                    )));
                }
                let level = level.parse::<u32>().map_err(|_| {
                    serde::de::Error::custom(format!(
                        "invalid policy level key {level:?}: expected uint32 decimal"
                    ))
                })?;
                // Match encoding/json map assignment: numerically equivalent keys
                // such as "7" and "07" target the same uint32 entry, and the
                // later JSON member wins.
                levels.insert(level, policy);
            }
            Ok(levels)
        }
    }

    deserializer.deserialize_option(PolicyLevelsVisitor)
}

pub const DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS: u64 = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShutdownConfig {
    #[serde(default = "default_shutdown_grace_period_seconds")]
    pub grace_period_seconds: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace_period_seconds: DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS,
        }
    }
}

fn default_shutdown_grace_period_seconds() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default = "default_mcp_path")]
    pub path: String,
    #[serde(default = "default_mcp_update_interval_ms")]
    pub update_interval_ms: u64,
}

fn default_mcp_path() -> String {
    "/mcp".to_string()
}

fn default_mcp_update_interval_ms() -> u64 {
    1000
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::IpAddr};

    use super::{
        CompiledDnsServer, DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS, DnsConfig,
        DnsQueryStrategy, DnsServerTransport, LiteralConfig, PolicyConfig, Protocol,
    };

    #[test]
    fn policy_levels_match_xray_uint32_json_semantics() {
        let policy: PolicyConfig = serde_json::from_str(
            r#"{
                "levels": {
                    "07": {"handshake": 5, "connIdle": 9},
                    "8": {"handshake": 0},
                    "9": null
                },
                "system": null
            }"#,
        )
        .expect("parse Xray policy levels");

        let level_seven = policy.levels[&7].as_ref().expect("level 7 policy");
        assert_eq!(level_seven.handshake, Some(5));
        assert_eq!(level_seven.connection_idle, Some(9));
        assert_eq!(
            policy.levels[&8]
                .as_ref()
                .expect("level 8 policy")
                .handshake,
            Some(0)
        );
        assert!(policy.levels[&9].is_none());
        assert!(policy.system.is_none());

        let null_levels: PolicyConfig =
            serde_json::from_str(r#"{"levels":null}"#).expect("accept null levels");
        assert!(null_levels.levels.is_empty());

        let duplicate_level: PolicyConfig = serde_json::from_str(
            r#"{"levels":{"7":{"handshake":1},"07":{"handshake":2}}}"#,
        )
        .expect("parse numerically duplicate Xray levels");
        assert_eq!(
            duplicate_level.levels[&7]
                .as_ref()
                .expect("merged level 7")
                .handshake,
            Some(2)
        );
    }

    #[test]
    fn policy_levels_reject_values_xray_rejects() {
        for level in ["+7", "-1", "4294967296", "x", ""] {
            let json = format!(r#"{{"levels":{{"{level}":{{"handshake":5}}}}}}"#);
            assert!(
                serde_json::from_str::<PolicyConfig>(&json).is_err(),
                "unexpectedly accepted policy level key {level:?}"
            );
        }
        for handshake in ["-1", "4294967296", "1.5"] {
            let json =
                [r#"{"levels":{"7":{"handshake":"#, handshake, "}}}"].concat();
            assert!(
                serde_json::from_str::<PolicyConfig>(&json).is_err(),
                "unexpectedly accepted handshake value {handshake}"
            );
        }
    }

    #[test]
    fn parse_simple() {
        let cfg = r#"
        {
  "inbounds":      [
    {
      "allocate": null,
      "listen": "127.0.0.1",
      "port": 62789,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "sniffing": null,
      "streamSettings": null,
      "tag": "api"
    }],
    "outbounds": [
    {
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIP"
      },
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ]
        }
        "#;
        let c = cfg.parse::<LiteralConfig>().expect("should parse");
        println!("{:?}", c);
    }

    #[test]
    fn parses_shutdown_grace_period_extension() {
        let explicit: LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [],
                "outbounds": [],
                "shutdown": {"gracePeriodSeconds": 3}
            }"#,
        )
        .expect("shutdown config should parse");
        assert_eq!(
            explicit
                .shutdown
                .expect("shutdown config missing")
                .grace_period_seconds,
            3
        );

        let defaulted: LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [],
                "outbounds": [],
                "shutdown": {}
            }"#,
        )
        .expect("default shutdown config should parse");
        assert_eq!(
            defaulted
                .shutdown
                .expect("shutdown config missing")
                .grace_period_seconds,
            DEFAULT_SHUTDOWN_GRACE_PERIOD_SECONDS
        );
    }

    #[test]
    fn parses_user_domain_access_config() {
        let config: LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [],
                "outbounds": [],
                "userDomainAccess": {
                    "version": 1,
                    "defaultAction": "allow",
                    "users": []
                }
            }"#,
        )
        .expect("userDomainAccess should parse");

        assert_eq!(
            config
                .user_domain_access
                .as_ref()
                .and_then(|value| value.get("version"))
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn parse_xray_internal_tunnel_protocol() {
        let config: LiteralConfig = serde_json::from_str(
            r#"{
                "inbounds": [{
                    "listen": "@chimera-api",
                    "protocol": "tunnel",
                    "tag": "api"
                }],
                "outbounds": []
            }"#,
        )
        .expect("parse Xray internal tunnel inbound");

        let inbound = config.inbounds.first().expect("tunnel inbound");
        assert!(matches!(inbound.protocol, Protocol::Tunnel));
        assert_eq!(inbound.listen.as_deref(), Some("@chimera-api"));
        assert_eq!(inbound.port, None);
    }

    #[test]
    fn parses_burst_observatory_ping_config() {
        let config = r#"
        {
          "inbounds": [],
          "outbounds": [{
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
          }],
          "burstObservatory": {
            "subjectSelector": ["direct"],
            "pingConfig": {
              "destination": "http://127.0.0.1:8080/generate_204",
              "connectivity": "http://127.0.0.1:8080/connectivity",
              "interval": "15s",
              "sampling": 6,
              "timeout": "2s",
              "httpMethod": "GET"
            }
          }
        }
        "#
        .parse::<LiteralConfig>()
        .expect("burstObservatory should parse");

        let burst = config.burst_observatory.expect("burstObservatory missing");
        assert_eq!(burst.subject_selector, vec!["direct"]);
        let ping = burst.ping_config.expect("pingConfig missing");
        assert_eq!(ping.destination, "http://127.0.0.1:8080/generate_204");
        assert_eq!(ping.connectivity, "http://127.0.0.1:8080/connectivity");
        assert_eq!(ping.sampling, Some(6));
        assert_eq!(ping.http_method, "GET");
    }

    #[test]
    fn compiles_xray_dns_hosts_with_normalized_ip_mappings() {
        let config: DnsConfig = serde_json::from_str(
            r#"{
                "hosts": {
                    "Example.COM.": "192.0.2.10",
                    "bücher.example": ["2001:db8::10", "192.0.2.11"]
                }
            }"#,
        )
        .expect("parse dns hosts");

        let hosts = config.compile_hosts().expect("compile dns hosts");
        let hosts = hosts
            .into_iter()
            .map(|host| (host.rule, host.addresses))
            .collect::<HashMap<_, _>>();
        assert_eq!(
            hosts["full:example.com"],
            vec!["192.0.2.10".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(
            hosts["full:xn--bcher-kva.example"],
            vec![
                "2001:db8::10".parse::<std::net::IpAddr>().unwrap(),
                "192.0.2.11".parse::<std::net::IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn compiles_xray_dns_hosts_domain_rule_forms() {
        let config: DnsConfig = serde_json::from_str(
            r#"{
                "hosts": {
                    "domain:Example.COM.": "192.0.2.10",
                    "keyword:Service": "192.0.2.11",
                    "regexp:^api\\.example\\.com$": "192.0.2.12",
                    "dotless:printer": "192.0.2.13"
                }
            }"#,
        )
        .expect("parse dns hosts rules");

        let mut rules = config
            .compile_hosts()
            .expect("compile dns hosts rules")
            .into_iter()
            .map(|host| host.rule)
            .collect::<Vec<_>>();
        rules.sort();
        assert_eq!(
            rules,
            vec![
                "domain:example.com",
                "keyword:service",
                "regexp:^[^.]*printer[^.]*$",
                "regexp:^api\\.example\\.com$",
            ]
        );
    }

    #[test]
    fn compiles_xray_dns_hosts_proxied_domain() {
        let config: DnsConfig = serde_json::from_str(
            r#"{
                "hosts": {
                    "alias.example": "Target.EXAMPLE.",
                    "mixed.example": ["192.0.2.10", "target.example"]
                }
            }"#,
        )
        .expect("parse proxied dns hosts");

        let hosts = config.compile_hosts().expect("compile proxied dns hosts");
        assert_eq!(
            hosts
                .iter()
                .find(|host| host.rule == "full:alias.example")
                .and_then(|host| host.proxied_domain.as_deref()),
            Some("target.example")
        );
        let mixed = hosts
            .iter()
            .find(|host| host.rule == "full:mixed.example")
            .expect("mixed host entry");
        assert_eq!(mixed.addresses, Vec::<std::net::IpAddr>::new());
        assert_eq!(mixed.proxied_domain.as_deref(), Some("target.example"));
    }

    #[test]
    fn compiles_xray_dns_hosts_response_codes() {
        let config: DnsConfig = serde_json::from_str(
            r##"{"hosts": {"blocked.example": "#3", "empty.example": "#0"}}"##,
        )
        .expect("parse response-code hosts");

        let hosts = config.compile_hosts().expect("compile response-code hosts");
        let blocked = hosts
            .iter()
            .find(|host| host.rule == "full:blocked.example")
            .expect("blocked response-code host");
        assert_eq!(blocked.addresses, Vec::<IpAddr>::new());
        assert_eq!(blocked.proxied_domain, None);
        assert_eq!(blocked.response_code, Some(3));

        let empty = hosts
            .iter()
            .find(|host| host.rule == "full:empty.example")
            .expect("empty response-code host");
        assert_eq!(empty.response_code, Some(0));
    }

    #[test]
    fn rejects_invalid_xray_dns_hosts_response_code() {
        for value in ["#", "#not-a-code", "#65536"] {
            let config: DnsConfig = serde_json::from_value(serde_json::json!({
                "hosts": {"blocked.example": value},
            }))
            .expect("parse response-code host");
            let error = config
                .compile_hosts()
                .expect_err("invalid response code must be rejected");
            assert!(error.contains("response code"), "{error}");
        }
    }

    #[test]
    fn compiles_xray_dns_server_fallback_controls() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"disableFallback": true, "disableFallbackIfMatch": true, "servers": [{"address": "8.8.8.8", "skipFallback": true, "finalQuery": true}]}"#,
        )
        .expect("parse DNS fallback controls");

        let server = config
            .compile_servers()
            .expect("compile DNS fallback controls");
        let configs = config
            .compile_server_configs()
            .expect("compile DNS fallback controls");
        assert_eq!(server, vec!["8.8.8.8:53".parse().unwrap()]);
        assert_eq!(config.compile_fallback_options(), (true, true));
        config.compile_hosts().expect("compile fallback settings");
        assert!(configs[0].skip_fallback);
        assert!(configs[0].final_query);
    }

    #[test]
    fn rejects_invalid_xray_dns_server_timeout() {
        for timeout in [serde_json::json!("1500"), serde_json::json!(-1)] {
            let config: DnsConfig = serde_json::from_value(serde_json::json!({
                "servers": [{"address": "8.8.8.8", "timeoutMs": timeout}]
            }))
            .expect("parse invalid DNS timeout value");

            let error = config
                .compile_server_configs()
                .expect_err("timeoutMs must be a non-negative integer");
            assert!(error.contains("timeoutMs"));
        }
    }

    #[test]
    fn rejects_invalid_xray_dns_server_fallback_controls() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": [{"address": "8.8.8.8", "skipFallback": "true"}]}"#,
        )
        .expect("parse invalid DNS fallback control");

        let error = config
            .compile_server_configs()
            .expect_err("fallback controls must be booleans");
        assert!(error.contains("skipFallback"));
        assert!(error.contains("boolean"));
    }

    #[test]
    fn compiles_plain_xray_dns_server_endpoints() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": ["8.8.8.8", "[2001:4860:4860::8888]:5353"]}"#,
        )
        .expect("parse dns servers");

        assert_eq!(
            config.compile_servers().expect("compile dns servers"),
            vec![
                "8.8.8.8:53".parse().unwrap(),
                "[2001:4860:4860::8888]:5353".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn compiles_xray_dns_tcp_server_endpoint() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": ["TCP://127.0.0.1:5353", "8.8.8.8"]}"#,
        )
        .expect("parse DNS over TCP server");

        let servers = config
            .compile_server_configs()
            .expect("compile DNS over TCP server");
        assert_eq!(servers[0].address, "127.0.0.1:5353".parse().unwrap());
        assert_eq!(servers[0].transport, DnsServerTransport::Tcp);
        assert_eq!(servers[1].transport, DnsServerTransport::Udp);
    }

    #[test]
    fn accepts_xray_enable_parallel_query() {
        let enabled: DnsConfig =
            serde_json::from_str(r#"{"enableParallelQuery": true}"#)
                .expect("parse enableParallelQuery");
        assert!(enabled.compile_enable_parallel_query());

        let omitted: DnsConfig =
            serde_json::from_str("{}").expect("parse empty DNS config");
        assert!(!omitted.compile_enable_parallel_query());
    }

    #[test]
    fn compiles_basic_xray_dns_server_objects() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": [
                {"address": "8.8.8.8", "clientIp": "192.0.2.44", "domains": ["domain:Example.COM.", "keyword:Internal"], "timeoutMs": 1500},
                {"address": "2001:4860:4860::8888", "port": 5353, "queryStrategy": "UseIPv6", "timeoutMs": 0},
                {"address": "1.1.1.1", "port": 0, "queryStrategy": "unknown"}
            ]}"#,
        )
        .expect("parse DNS server objects");

        assert_eq!(
            config
                .compile_server_configs()
                .expect("compile DNS server objects"),
            vec![
                CompiledDnsServer {
                    address: "8.8.8.8:53".parse().unwrap(),
                    transport: DnsServerTransport::Udp,
                    client_ip: Some("192.0.2.44".parse().unwrap()),
                    query_strategy: None,
                    domains: vec![
                        "domain:example.com".into(),
                        "keyword:internal".into(),
                    ],
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: Some(1500),
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
                CompiledDnsServer {
                    address: "[2001:4860:4860::8888]:5353".parse().unwrap(),
                    transport: DnsServerTransport::Udp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIpv6),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: Some(0),
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
                CompiledDnsServer {
                    address: "1.1.1.1:53".parse().unwrap(),
                    transport: DnsServerTransport::Udp,
                    client_ip: None,
                    query_strategy: Some(DnsQueryStrategy::UseIp),
                    domains: Vec::new(),
                    skip_fallback: false,
                    final_query: false,
                    timeout_ms: None,
                    expected_ips: Vec::new(),
                    expected_ips_prefer: false,
                    unexpected_ips: Vec::new(),
                    unexpected_ips_prefer: false,
                },
            ]
        );
    }

    #[test]
    fn compiles_xray_dns_client_ip_and_rejects_invalid_values() {
        let config: DnsConfig = serde_json::from_value(serde_json::json!({
            "clientIp": "2001:db8::44",
            "servers": [{"address": "8.8.8.8", "clientIp": "192.0.2.44"}],
        }))
        .expect("parse DNS client IP settings");
        assert_eq!(
            config.compile_client_ip().unwrap(),
            Some("2001:db8::44".parse().unwrap())
        );
        assert_eq!(
            config.compile_server_configs().unwrap()[0].client_ip,
            Some("192.0.2.44".parse().unwrap())
        );

        let invalid_top_level: DnsConfig =
            serde_json::from_value(serde_json::json!({
                "clientIp": "not-an-ip",
            }))
            .expect("parse invalid top-level client IP");
        assert!(
            invalid_top_level
                .compile_client_ip()
                .expect_err("invalid top-level client IP must fail")
                .contains("clientIp")
        );

        let invalid_server: DnsConfig = serde_json::from_value(serde_json::json!({
            "servers": [{"address": "8.8.8.8", "clientIp": 1}],
        }))
        .expect("parse invalid per-server client IP");
        assert!(
            invalid_server
                .compile_server_configs()
                .expect_err("invalid per-server client IP must fail")
                .contains("clientIp")
        );
    }

    #[test]
    fn accepts_xray_top_level_dns_disable_cache() {
        let config: DnsConfig = serde_json::from_value(serde_json::json!({
            "disableCache": true,
        }))
        .expect("parse DNS disableCache");

        assert_eq!(config.disable_cache, Some(true));
        config.compile_hosts().expect("compile DNS cache settings");
    }

    #[test]
    fn compiles_xray_dns_server_domain_rules() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": [{
                "address": "8.8.8.8",
                "domains": [
                    "Example.COM",
                    "full:API.Example.COM.",
                    "regexp:^cdn\\.",
                    "dotless:lan"
                ]
            }]}"#,
        )
        .expect("parse DNS server domain rules");

        assert_eq!(
            config.compile_server_configs().unwrap()[0].domains,
            vec![
                "keyword:example.com",
                "full:api.example.com",
                "regexp:^cdn\\.",
                "regexp:^[^.]*lan[^.]*$",
            ]
        );
    }

    #[test]
    fn rejects_xray_dns_server_geosite_domain_rules() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": [{"address": "8.8.8.8", "domains": "geosite:cn"}]}"#,
        )
        .expect("parse DNS server geosite rule");

        let error = config
            .compile_server_configs()
            .expect_err("geosite data is not available in this slice");
        assert!(error.contains("geosite/ext"));
    }

    #[test]
    fn compiles_xray_dns_server_ip_filters_and_aliases() {
        let config: DnsConfig = serde_json::from_str(
            r#"{"servers": [
                {
                    "address": "8.8.8.8",
                    "expectedIPs": ["203.0.113.0/24", "*"],
                    "unexpectedIPs": "!192.0.2.0/24"
                },
                {
                    "address": "1.1.1.1",
                    "expectedIPs": [],
                    "expectIPs": "2001:db8::/32"
                }
            ]}"#,
        )
        .expect("parse DNS server IP filters");

        let servers = config
            .compile_server_configs()
            .expect("compile DNS server IP filters");
        assert_eq!(servers[0].expected_ips, vec!["203.0.113.0/24".to_string()]);
        assert!(servers[0].expected_ips_prefer);
        assert_eq!(servers[0].unexpected_ips, vec!["!192.0.2.0/24".to_string()]);
        assert!(!servers[0].unexpected_ips_prefer);
        assert_eq!(servers[1].expected_ips, vec!["2001:db8::/32".to_string()]);
    }

    #[test]
    fn compiles_xray_dns_query_strategy_aliases() {
        let cases = [
            ("UseIP", DnsQueryStrategy::UseIp),
            ("use_ipv4", DnsQueryStrategy::UseIpv4),
            ("UseIPv6", DnsQueryStrategy::UseIpv6),
            ("use-system", DnsQueryStrategy::UseSystem),
            ("unknown-value", DnsQueryStrategy::UseIp),
        ];
        for (value, expected) in cases {
            let config: DnsConfig = serde_json::from_value(serde_json::json!({
                "queryStrategy": value,
            }))
            .expect("parse query strategy");
            assert_eq!(config.compile_query_strategy(), expected);
        }
        let default_config: DnsConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            default_config.compile_query_strategy(),
            DnsQueryStrategy::UseIp
        );
    }

    #[test]
    fn compiles_domain_proxy_values_in_xray_dns_hosts_slice() {
        let config: DnsConfig =
            serde_json::from_str(r#"{"hosts": {"example.com": "proxy.example"}}"#)
                .expect("parse dns hosts");

        let hosts = config.compile_hosts().expect("compile proxied dns hosts");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].addresses, Vec::<std::net::IpAddr>::new());
        assert_eq!(hosts[0].proxied_domain.as_deref(), Some("proxy.example"));
    }
}
