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
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BalancerConfig {
    pub tag: String,
    #[serde(default, deserialize_with = "deserialize_string_list")]
    pub outbound_selector: Vec<String>,
    #[serde(default)]
    pub fallback_tag: Option<String>,
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
