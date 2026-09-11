use std::collections::HashMap;

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticSocksClientConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    pass: String,
    #[serde(default)]
    servers: Vec<StaticSocksServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticSocksServerConfig {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<StaticSocksUserConfig>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticSocksUserConfig {
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    pass: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticVlessClientConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    encryption: String,
    #[serde(default)]
    vnext: Vec<StaticVlessServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticVlessServerConfig {
    address: String,
    port: u16,
    #[serde(default)]
    users: Vec<StaticVlessUserConfig>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticVlessUserConfig {
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    id: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    encryption: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct StaticTrojanClientConfig {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    servers: Vec<StaticTrojanServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticTrojanServerConfig {
    address: String,
    port: u16,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    password: String,
    #[serde(default)]
    flow: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundStreamSettings {
    #[serde(default)]
    network: String,
    #[serde(default)]
    security: String,
    #[serde(default)]
    tls_settings: Option<StaticOutboundTlsSettings>,
    #[serde(default, alias = "wsSettings")]
    ws_settings: Option<StaticOutboundWebsocketSettings>,
    #[serde(default, alias = "httpUpgradeSettings")]
    http_upgrade_settings: Option<StaticOutboundHttpUpgradeSettings>,
    #[cfg(feature = "grpc_transport")]
    #[serde(default, alias = "grpcSettings")]
    grpc_settings: Option<StaticOutboundGrpcSettings>,
    #[serde(default, alias = "realitySettings")]
    reality_settings: Option<StaticOutboundRealitySettings>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundWebsocketSettings {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
    #[serde(default)]
    heartbeat_period: u32,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundHttpUpgradeSettings {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct StaticOutboundGrpcSettings {
    #[serde(default)]
    pub(super) authority: String,
    #[serde(default)]
    pub(super) service_name: String,
    #[serde(default)]
    pub(super) multi_mode: bool,
    #[serde(default, alias = "idle_timeout")]
    pub(super) idle_timeout: i32,
    #[serde(default, alias = "health_check_timeout")]
    pub(super) health_check_timeout: i32,
    #[serde(default, alias = "permit_without_stream")]
    pub(super) permit_without_stream: bool,
    #[serde(default, alias = "initial_windows_size")]
    pub(super) initial_windows_size: i32,
    #[serde(default, alias = "user_agent")]
    pub(super) user_agent: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundRealitySettings {
    #[serde(default)]
    show: bool,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    short_id: String,
    #[serde(default)]
    mldsa65_verify: String,
    #[serde(default)]
    spider_x: String,
    #[serde(default)]
    master_key_log: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundTlsSettings {
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default)]
    certificates: Vec<StaticOutboundTlsCertificate>,
    #[serde(default)]
    enable_session_resumption: bool,
    #[serde(default)]
    disable_system_root: bool,
    #[serde(default)]
    min_version: String,
    #[serde(default)]
    max_version: String,
    #[serde(default)]
    cipher_suites: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    reject_unknown_sni: bool,
    #[serde(default)]
    master_key_log: String,
    #[serde(default)]
    curve_preferences: Vec<String>,
    #[serde(default)]
    verify_peer_cert_by_name: String,
    #[serde(default)]
    pinned_peer_cert_sha256: String,
    #[serde(default)]
    ech_server_keys: String,
    #[serde(default)]
    ech_config_list: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticOutboundTlsCertificate {
    #[serde(default)]
    certificate_file: String,
    #[serde(default)]
    certificate: Vec<String>,
    #[serde(default)]
    key_file: String,
    #[serde(default)]
    key: Vec<String>,
    #[serde(default)]
    usage: String,
}

mod compile;

#[cfg(all(test, feature = "grpc_transport"))]
pub(super) use compile::encode_static_grpc_config;
pub(crate) use compile::{compile_static_outbound, parse_xray_uuid};
