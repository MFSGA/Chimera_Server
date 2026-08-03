use std::{path::PathBuf, str::FromStr};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, log::LogConfig};

use super::{
    Protocol, SettingObject, StreamSettings, Transport, rule::RoutingConfig,
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
    pub observatory: Option<ObservatoryConfig>,
    #[serde(default, rename = "burstObservatory")]
    pub burst_observatory: Option<BurstObservatoryConfig>,
    // mcp settings
    pub mcp: Option<McpConfig>,
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
    pub port: u16,
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
            "quic" | "kcp" => Transport::Quic,
            "udp" => Transport::Udp,
            _ => Transport::Tcp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundItem {
    pub protocol: String,
    pub tag: String,
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
    #[serde(default)]
    pub levels: HashMap<String, Value>,
    #[serde(default)]
    pub system: HashMap<String, Value>,
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
    use super::LiteralConfig;

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
}
