use std::collections::HashMap;

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StaticFreedomConfig {
    #[serde(default)]
    proxy_protocol: u32,
}

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
    reverse: Option<StaticVlessReverseConfig>,
    #[serde(default)]
    vnext: Vec<StaticVlessServerConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct StaticVlessReverseConfig {
    #[serde(default)]
    tag: String,
    #[serde(default)]
    sniffing: Option<StaticVlessReverseSniffingConfig>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticVlessReverseSniffingConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    dest_override: Vec<String>,
    #[serde(default)]
    domains_excluded: Vec<String>,
    #[serde(default)]
    ips_excluded: Vec<String>,
    #[serde(default)]
    metadata_only: bool,
    #[serde(default)]
    route_only: bool,
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
    #[serde(default)]
    reverse: Option<serde_json::Value>,
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
    #[serde(default, alias = "xhttpSettings")]
    xhttp_settings: Option<StaticOutboundXhttpSettings>,
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

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticOutboundXhttpSettings {
    #[serde(default)]
    host: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    x_padding_bytes: Option<StaticOutboundXhttpRange>,
    #[serde(default, rename = "noGRPCHeader")]
    no_grpc_header: bool,
    #[serde(default, rename = "noSSEHeader")]
    no_sse_header: bool,
    #[serde(default, rename = "uplinkHTTPMethod")]
    uplink_http_method: String,
    #[serde(default, rename = "sessionIDPlacement", alias = "sessionPlacement")]
    session_id_placement: String,
    #[serde(default, rename = "sessionIDKey", alias = "sessionKey")]
    session_id_key: String,
    #[serde(default, rename = "sessionIDTable")]
    session_id_table: String,
    #[serde(default, rename = "sessionIDLength")]
    session_id_length: Option<StaticOutboundXhttpRange>,
    #[serde(default)]
    x_padding_obfs_mode: bool,
    #[serde(default)]
    download_settings: Option<serde_json::Value>,
    #[serde(default)]
    xmux: Option<serde_json::Value>,
    #[serde(default)]
    seq_placement: String,
    #[serde(default)]
    seq_key: String,
    #[serde(default)]
    uplink_data_placement: String,
    #[serde(default)]
    uplink_data_key: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct StaticOutboundXhttpRange {
    from: i32,
    to: i32,
}

impl<'de> serde::Deserialize<'de> for StaticOutboundXhttpRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Integer(i32),
            String(String),
            Object { from: i32, to: i32 },
        }

        let (mut from, mut to) = match Repr::deserialize(deserializer)? {
            Repr::Integer(value) => (value, value),
            Repr::String(value) => {
                if let Some((from, to)) = value.split_once('-') {
                    (
                        from.parse::<i32>().map_err(serde::de::Error::custom)?,
                        to.parse::<i32>().map_err(serde::de::Error::custom)?,
                    )
                } else {
                    let value =
                        value.parse::<i32>().map_err(serde::de::Error::custom)?;
                    (value, value)
                }
            }
            Repr::Object { from, to } => (from, to),
        };
        if from > to {
            std::mem::swap(&mut from, &mut to);
        }
        Ok(Self { from, to })
    }
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
