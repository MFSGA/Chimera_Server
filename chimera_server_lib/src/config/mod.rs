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
    TcpAndUdp,
    Quic,
    Udp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    #[cfg(feature = "vless")]
    Vless,
    #[cfg(feature = "vmess")]
    Vmess,
    #[cfg(feature = "hysteria")]
    #[serde(alias = "hysteria")]
    Hysteria2,
    #[serde(alias = "dokodemo-door")]
    DokodemoDoor,
    #[cfg(feature = "trojan")]
    Trojan,
    #[cfg(feature = "tuic")]
    #[serde(alias = "tuic")]
    TuicV5,
    Xhttp,
    Socks,
    Http,
    Mixed,
    Shadowsocks,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamSettings {
    #[serde(default)]
    network: String,
    security: Option<String>,
    tls_settings: Option<TlsSettings>,
    #[serde(default)]
    sockopt: Option<SocketSettings>,
    #[serde(alias = "tcpSettings", alias = "rawSettings")]
    tcp_settings: Option<TcpSettings>,
    #[serde(alias = "xhttpSettings")]
    xhttp_settings: Option<XhttpSettings>,
    #[cfg(feature = "ws")]
    ws_settings: Option<WsSettings>,
    #[cfg(feature = "httpupgrade")]
    #[serde(alias = "httpupgradeSettings")]
    httpupgrade_settings: Option<HttpUpgradeSettings>,
    #[cfg(feature = "grpc_transport")]
    #[serde(alias = "grpcSettings")]
    grpc_settings: Option<GrpcSettings>,
    #[serde(alias = "hysteriaSettings")]
    hysteria_settings: Option<HysteriaSettings>,
    #[cfg(feature = "reality")]
    #[serde(alias = "realitySettings")]
    reality_settings: Option<RealitySettings>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum TcpFastOpenValue {
    Bool(bool),
    Number(f64),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomSockoptConfig {
    #[serde(default)]
    pub system: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub opt: String,
    #[serde(default)]
    pub value: String,
    #[serde(default, rename = "type")]
    pub value_type: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SocketSettings {
    #[serde(default)]
    accept_proxy_protocol: bool,
    #[serde(default)]
    tcp_fast_open: Option<TcpFastOpenValue>,
    #[serde(default)]
    tcp_keep_alive_interval: i32,
    #[serde(default)]
    tcp_keep_alive_idle: i32,
    #[serde(default)]
    tcp_user_timeout: i32,
    #[serde(default)]
    tcp_congestion: String,
    #[serde(default)]
    tcp_window_clamp: i32,
    #[serde(default)]
    tcp_max_seg: i32,
    #[serde(default)]
    tcp_mptcp: bool,
    #[serde(default)]
    v6only: bool,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    mark: i32,
    #[serde(default)]
    custom_sockopt: Vec<CustomSockoptConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TcpSettings {
    #[serde(default)]
    accept_proxy_protocol: bool,
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcSettings {
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    multi_mode: bool,
    #[serde(default)]
    authority: Option<String>,
    #[serde(default)]
    idle_timeout: u32,
    #[serde(default)]
    health_check_timeout: u32,
    #[serde(default)]
    permit_without_stream: bool,
    #[serde(default)]
    initial_windows_size: u32,
}

#[cfg(feature = "httpupgrade")]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpUpgradeSettings {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    header: std::collections::HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
    #[serde(default)]
    ed: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XhttpSettings {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    x_padding_bytes: Option<XhttpRange>,
    #[serde(default)]
    sc_max_each_post_bytes: Option<XhttpRange>,
    #[serde(default)]
    sc_max_buffered_posts: Option<i64>,
    #[serde(default)]
    sc_stream_up_server_secs: Option<XhttpRange>,
    #[serde(default)]
    extra: Option<serde_json::Value>,
    #[serde(default)]
    download_settings: Option<serde_json::Value>,
    #[serde(default)]
    xmux: Option<serde_json::Value>,
    #[serde(default, rename = "noGRPCHeader")]
    no_grpc_header: Option<bool>,
    #[serde(default, rename = "noSSEHeader")]
    no_sse_header: Option<bool>,
    #[serde(default)]
    server_max_header_bytes: Option<i32>,
    #[serde(default, rename = "uplinkHTTPMethod")]
    uplink_http_method: Option<String>,
    #[serde(default, rename = "sessionIDPlacement", alias = "sessionPlacement")]
    session_placement: Option<String>,
    #[serde(default, rename = "sessionIDKey", alias = "sessionKey")]
    session_key: Option<String>,
    #[serde(default, rename = "sessionIDTable")]
    session_id_table: Option<String>,
    #[serde(default, rename = "sessionIDLength")]
    session_id_length: Option<XhttpRange>,
    #[serde(default)]
    seq_placement: Option<String>,
    #[serde(default)]
    seq_key: Option<String>,
    #[serde(default)]
    uplink_data_placement: Option<String>,
    #[serde(default)]
    uplink_data_key: Option<String>,
    #[serde(default)]
    uplink_chunk_size: Option<serde_json::Value>,
    #[serde(default)]
    sc_min_posts_interval_ms: Option<XhttpRange>,
    #[serde(default)]
    x_padding_key: Option<String>,
    #[serde(default)]
    x_padding_header: Option<String>,
    #[serde(default)]
    x_padding_placement: Option<String>,
    #[serde(default)]
    x_padding_method: Option<String>,
    #[serde(default)]
    x_padding_obfs_mode: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct XhttpRange {
    #[serde(default)]
    from: i32,
    #[serde(default)]
    to: i32,
}

#[cfg(feature = "ws")]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsSettings {
    #[serde(default)]
    host: Option<String>,
    path: Option<String>,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    accept_proxy_protocol: bool,
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
            .map(|value| {
                serde_json::from_value::<Vec<TrojanClientSetting>>(value.clone())
            })
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
    #[serde(default)]
    email: String,
    #[serde(default)]
    flow: String,
    id: String,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    security: Option<String>,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrojanClientSetting {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    level: u32,
    password: String,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TlsSettings {
    #[serde(default)]
    alpn: Vec<String>,
    certificates: Vec<Certificate>,
    #[serde(default)]
    cipher_suites: Option<String>,
    #[serde(default)]
    disable_system_root: Option<bool>,
    #[serde(default)]
    enable_session_resumption: Option<bool>,
    #[serde(default)]
    max_version: Option<String>,
    #[serde(default)]
    min_version: Option<String>,
    #[serde(default)]
    reject_unknown_sni: Option<bool>,
    #[serde(default)]
    server_name: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Certificate {
    #[serde(default)]
    build_chain: Option<bool>,
    #[serde(default)]
    certificate: Vec<String>,
    #[serde(default)]
    certificate_file: Option<String>,
    #[serde(default)]
    key: Vec<String>,
    #[serde(default)]
    key_file: Option<String>,
    // reload the certificate every n seconds
    #[serde(default)]
    ocsp_stapling: Option<u64>,
    #[serde(default)]
    one_time_loading: Option<bool>,
    // set Certificate type
    #[serde(default)]
    usage: Option<String>,
}

#[cfg(feature = "reality")]
#[derive(Deserialize, Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealitySettings {
    #[serde(default)]
    pub server_names: Vec<String>,
    pub private_key: String,
    #[serde(default)]
    pub short_ids: Vec<String>,
    #[serde(alias = "target")]
    pub dest: String,
    #[serde(default, alias = "cipher_suite")]
    pub cipher_suites: Vec<crate::reality::CipherSuite>,
    #[serde(default, alias = "maxTimediff", alias = "maxTimeDiff")]
    pub max_time_diff: Option<u64>,
    #[serde(default, alias = "minClient", alias = "minClientVer")]
    pub min_client_ver: Option<String>,
    #[serde(default, alias = "maxClient", alias = "maxClientVer")]
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
