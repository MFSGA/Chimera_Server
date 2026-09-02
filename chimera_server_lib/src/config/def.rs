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
    #[serde(default, rename = "userDomainAccess")]
    pub user_domain_access: Option<Value>,
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
    use super::{LiteralConfig, PolicyConfig, Protocol};

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
                    "listen": "127.0.0.1",
                    "port": 62789,
                    "protocol": "tunnel",
                    "settings": {"rewriteAddress": "127.0.0.1"},
                    "tag": "api"
                }],
                "outbounds": []
            }"#,
        )
        .expect("parse Xray internal tunnel inbound");

        assert!(matches!(
            config.inbounds.first().map(|inbound| &inbound.protocol),
            Some(Protocol::Tunnel)
        ));
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
