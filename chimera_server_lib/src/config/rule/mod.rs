use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    #[serde(default)]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub balancers: Vec<BalancerConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuleConfig {
    #[serde(default)]
    pub rule_tag: Option<String>,
    #[serde(default)]
    pub inbound_tag: Vec<String>,
    #[serde(default)]
    pub outbound_tag: Option<String>,
    #[serde(default)]
    pub balancer_tag: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub domain: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub domains: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub ip: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub source_ip: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub source: Vec<String>,
    #[serde(default)]
    pub port: PortListConfig,
    #[serde(default)]
    pub network: NetworkListConfig,
    #[serde(default)]
    pub source_port: PortListConfig,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub user: Vec<String>,
    #[serde(default)]
    pub vless_route: PortListConfig,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub local_ip: Vec<String>,
    #[serde(default)]
    pub local_port: PortListConfig,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub process: Vec<String>,
    #[serde(default)]
    pub webhook: Option<WebhookRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WebhookRuleConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub deduplication: u32,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BalancerConfig {
    pub tag: String,
    #[serde(
        default,
        alias = "selector",
        deserialize_with = "deserialize_string_list"
    )]
    pub outbound_selector: Vec<String>,
    #[serde(default)]
    pub strategy: BalancerStrategyConfig,
    #[serde(default)]
    pub fallback_tag: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BalancerStrategyConfig {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkListConfig(pub Vec<String>);

impl<'de> Deserialize<'de> for NetworkListConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_string_list(deserializer).map(Self)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PortListConfig(pub Vec<PortRangeConfig>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRangeConfig {
    pub from: u16,
    pub to: u16,
}

impl PortRangeConfig {
    fn new(from: u16, to: u16) -> Self {
        if from <= to {
            Self { from, to }
        } else {
            Self { from: to, to: from }
        }
    }
}

impl<'de> Deserialize<'de> for PortListConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawPortList {
            Number(u16),
            Text(String),
            Numbers(Vec<u16>),
            Texts(Vec<String>),
        }

        let raw = Option::<RawPortList>::deserialize(deserializer)?;
        let mut ranges = Vec::new();
        match raw {
            None => {}
            Some(RawPortList::Number(value)) => {
                ranges.push(PortRangeConfig::new(value, value));
            }
            Some(RawPortList::Text(value)) => {
                ranges.push(
                    parse_port_range(&value).map_err(serde::de::Error::custom)?,
                );
            }
            Some(RawPortList::Numbers(values)) => {
                for value in values {
                    ranges.push(PortRangeConfig::new(value, value));
                }
            }
            Some(RawPortList::Texts(values)) => {
                for value in values {
                    ranges.push(
                        parse_port_range(&value)
                            .map_err(serde::de::Error::custom)?,
                    );
                }
            }
        }
        Ok(Self(ranges))
    }
}

fn parse_port_range(value: &str) -> Result<PortRangeConfig, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("port value cannot be empty".into());
    }
    if let Some(name) = value.strip_prefix("env:") {
        if name.is_empty() {
            return Err(
                "routing port environment variable name cannot be empty".into()
            );
        }
        let resolved = std::env::var(name).map_err(|error| {
            format!(
                "routing port environment variable {name} is unavailable: {error}"
            )
        })?;
        return parse_port_range(&resolved);
    }
    let Some((from, to)) = value.split_once('-') else {
        let port = value
            .parse::<u16>()
            .map_err(|err| format!("invalid port {value}: {err}"))?;
        return Ok(PortRangeConfig::new(port, port));
    };

    let from = from
        .trim()
        .parse::<u16>()
        .map_err(|err| format!("invalid port range start {from}: {err}"))?;
    let to = to
        .trim()
        .parse::<u16>()
        .map_err(|err| format!("invalid port range end {to}: {err}"))?;
    Ok(PortRangeConfig::new(from, to))
}

fn deserialize_string_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrManyStrings {
        One(String),
        Many(Vec<String>),
    }

    match Option::<OneOrManyStrings>::deserialize(deserializer)? {
        None => Ok(Vec::new()),
        Some(OneOrManyStrings::One(value)) => Ok(split_csv_values(&value)),
        Some(OneOrManyStrings::Many(values)) => Ok(values
            .into_iter()
            .flat_map(|value| split_csv_values(&value))
            .collect()),
    }
}

fn split_csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_balancer_selector_and_strategy_fields_are_deserialized() {
        let config: RoutingConfig = serde_json::from_value(serde_json::json!({
            "balancers": [{
                "tag": "round",
                "selector": ["direct", "backup"],
                "strategy": {
                    "type": "roundRobin",
                    "settings": {"ignored": true}
                },
                "fallbackTag": "direct"
            }]
        }))
        .expect("Xray balancer JSON should deserialize");

        let balancer = config.balancers.first().expect("balancer missing");
        assert_eq!(balancer.tag, "round");
        assert_eq!(balancer.outbound_selector, vec!["direct", "backup"]);
        assert_eq!(balancer.strategy.kind, "roundRobin");
        assert_eq!(
            balancer.strategy.settings,
            Some(serde_json::json!({"ignored": true}))
        );
        assert_eq!(balancer.fallback_tag.as_deref(), Some("direct"));
    }

    #[test]
    fn xray_env_port_rule_is_deserialized() {
        const NAME: &str = "CHIMERA_ROUTING_PORT_TEST_8F2A";
        // Safety: this test uses a unique process-local variable name and no
        // production thread depends on it.
        unsafe {
            std::env::set_var(NAME, "8443-8445");
        }
        let config: RoutingConfig = serde_json::from_value(serde_json::json!({
            "rules": [{
                "port": format!("env:{NAME}"),
                "outboundTag": "direct"
            }]
        }))
        .expect("Xray env port should deserialize");
        unsafe {
            std::env::remove_var(NAME);
        }

        assert_eq!(
            config.rules[0].port.0,
            vec![PortRangeConfig {
                from: 8443,
                to: 8445,
            }]
        );
    }
}
