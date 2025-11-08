use serde::{Deserialize, Serialize};

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
    Hysteria2,
    #[serde(alias = "dokodemo-door")]
    DokodemoDoor,
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
    ws_settings: Option<WsSettings>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WsSettings {
    host: String,
    path: Option<String>,
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
    cipher_suites: String,
    disable_system_root: bool,
    enable_session_resumption: bool,
    max_version: String,
    min_version: String,
    reject_unknown_sni: bool,
    server_name: String,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Certificate {
    build_chain: bool,
    certificate_file: String,
    key_file: String,
    ocsp_stapling: u64,
    one_time_loading: bool,
    usage: String,
}
