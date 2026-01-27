use serde::{Deserialize, Serialize};

use crate::util::bandwidth::BandwidthValue;

pub mod internal;

pub mod def;

pub mod server_config;

pub mod rule;

pub enum SupportedFileType {
    Yaml,
    Json,
    Json5,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]

pub enum Transport {
    Tcp,
    Quic,
    Udp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    Vless,
    Vmess,
    #[cfg(feature = "hysteria")]
    #[serde(alias = "hysteria")]
    Hysteria2,
    #[serde(alias = "dokodemo-door")]
    DokodemoDoor,
    #[cfg(feature = "trojan")]
    Trojan,
    Xhttp,
    Socks,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings {
    network: String,
    security: Option<String>,
    tls_settings: Option<TlsSettings>,
    #[cfg(feature = "ws")]
    ws_settings: Option<WsSettings>,
    #[serde(alias = "hysteriaSettings")]
    hysteria_settings: Option<HysteriaSettings>,
    #[cfg(feature = "reality")]
    #[serde(alias = "realitySettings")]
    reality_settings: Option<RealitySettings>,
}

#[cfg(feature = "ws")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WsSettings {
    host: String,
    path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HysteriaSettings {
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub congestion: Option<String>,
    #[serde(default)]
    pub up: Option<BandwidthValue>,
    #[serde(default)]
    pub down: Option<BandwidthValue>,
    #[serde(default)]
    pub ignore_client_bandwidth: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct SettingObject(pub serde_json::Value);

impl SettingObject {
    pub fn clients(&self) -> Option<Vec<ClientSetting>> {
        self.0
            .get("clients")
            .map(|value| serde_json::from_value::<Vec<ClientSetting>>(value.clone()))
            .transpose()
            .unwrap_or(None)
    }

    #[cfg(feature = "trojan")]
    pub fn trojan_clients(&self) -> Option<Vec<TrojanClientSetting>> {
        self.0
            .get("clients")
            .map(|value| serde_json::from_value::<Vec<TrojanClientSetting>>(value.clone()))
            .transpose()
            .unwrap_or(None)
    }

    pub fn deserialize<T>(&self) -> Result<T, serde_json::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_value(self.0.clone())
    }
}

impl Default for SettingObject {
    fn default() -> Self {
        SettingObject(serde_json::Value::Null)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientSetting {
    email: String,
    flow: String,
    id: String,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrojanClientSetting {
    #[serde(default)]
    email: Option<String>,
    password: String,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TlsSettings {
    alpn: Vec<String>,
    certificates: Vec<Certificate>,
    cipher_suites: Option<String>,
    disable_system_root: Option<bool>,
    enable_session_resumption: Option<bool>,
    max_version: String,
    min_version: String,
    reject_unknown_sni: Option<bool>,
    server_name: String,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Certificate {
    build_chain: Option<bool>,
    certificate_file: String,
    key_file: String,
    // reload the certificate every n seconds
    ocsp_stapling: Option<u64>,
    one_time_loading: Option<bool>,
    // set Certificate type
    usage: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealitySettings {
    #[serde(default)]
    pub server_names: Vec<String>,
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub dest: String,
    #[serde(default)]
    pub max_time_diff: Option<u64>,
    #[serde(default)]
    pub min_client_ver: Option<String>,
    #[serde(default)]
    pub max_client_ver: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
    #[serde(default)]
    pub show: Option<bool>,
    #[serde(default)]
    pub xver: Option<i64>,
}
