use std::{collections::HashMap, path::PathBuf, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{log::LogConfig, Error};

use super::{Protocol, SettingObject, StreamSettings, SupportedFileType, Transport};

#[derive(Deserialize, Debug)]
pub struct LiteralConfig {
    pub inbounds: Vec<InboudItem>,
    pub outbounds: Vec<OutboundItem>,
    pub log: Option<LogConfig>,
    pub api: Option<ApiConfig>,
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
                Some("json5") => json5::from_str(&content)
                    .map_err(|e| Error::InvalidConfig(format!("Could not parse JSON5: {}", e)))?,
                Some("yaml") => {
                    todo!()
                }
                Some("toml") => {
                    todo!()
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "unsupported file type: {:?}",
                        value.extension()
                    )))
                }
            },
            None => {
                return Err(Error::InvalidConfig(format!(
                    "unknown file type {:?}",
                    value.extension()
                )))
            }
        };

        Ok(config)
    }
}

impl FromStr for LiteralConfig {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|x| {
            Error::InvalidConfig(format!("cound not parse config content {}: {}", s, x))
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
        if self.stream_settings.is_none() {
            return Transport::Tcp;
        } else {
        }

        todo!()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundItem {
    pub protocol: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApiConfig {
    pub tag: Option<String>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub listen: Option<String>,
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

    use crate::config::internal::InternalConfig;

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
}
