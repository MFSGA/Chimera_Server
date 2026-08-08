use std::{
    net::IpAddr,
    sync::{Arc, RwLock},
};

use serde::Deserialize;

use crate::{
    address::{BindLocation, NetLocation},
    config::Transport,
};

#[cfg(feature = "reality")]
use crate::reality::CipherSuite;
#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;

use super::quic::ServerQuicConfig;
#[cfg(feature = "ws")]
use super::ws::WebsocketServerConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub tag: String,
    #[serde(flatten)]
    pub bind_location: BindLocation,
    pub protocol: ServerProxyConfig,
    #[serde(alias = "transport")]
    pub transport: Transport,
    #[serde(default)]
    pub quic_settings: Option<ServerQuicConfig>,
}

#[cfg(feature = "hysteria")]
#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2Client {
    pub password: String,
    pub email: Option<String>,
    #[serde(default)]
    pub user_level: u32,
}

#[cfg(feature = "hysteria")]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2BandwidthConfig {
    #[serde(default, alias = "up")]
    pub max_tx: u64,
    #[serde(default, alias = "down")]
    pub max_rx: u64,
}

#[cfg(feature = "hysteria")]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2QuicParams {
    #[serde(default)]
    pub congestion: String,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub max_idle_timeout: u64,
    #[serde(default)]
    pub keep_alive_period: u64,
    #[serde(default)]
    pub disable_path_mtu_discovery: bool,
    #[serde(default)]
    pub max_incoming_streams: u64,
    // Quinn exposes a static receive window rather than quic-go's separate
    // initial/max auto-tuned windows. Preserve Xray's initial values for config
    // parity while runtime applies the corresponding max/static window values.
    #[serde(default)]
    pub init_stream_receive_window: u64,
    #[serde(default)]
    pub max_stream_receive_window: u64,
    #[serde(default)]
    pub init_connection_receive_window: u64,
    #[serde(default)]
    pub max_connection_receive_window: u64,
    #[serde(default)]
    pub brutal_up: u64,
    #[serde(default)]
    pub brutal_down: u64,
    #[serde(skip)]
    pub from_finalmask: bool,
}

#[cfg(feature = "hysteria")]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2MasqueradeConfig {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub status_code: u16,
}

#[cfg(feature = "hysteria")]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2ServerConfig {
    pub clients: Vec<Hysteria2Client>,
    #[serde(default)]
    pub fallback_auth: Option<String>,
    #[serde(default)]
    pub bandwidth: Hysteria2BandwidthConfig,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
    #[serde(default)]
    pub udp_idle_timeout: u64,
    #[serde(default)]
    pub quic_params: Hysteria2QuicParams,
    #[serde(default)]
    pub masquerade: Hysteria2MasqueradeConfig,
}

#[cfg(feature = "tuic")]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
/// TUIC v5 inbound settings after config parsing and validation.
pub struct TuicServerConfig {
    pub uuid: String,
    pub password: String,
    #[serde(default, alias = "zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanUser {
    pub password: String,
    pub email: Option<String>,
    #[serde(default)]
    pub user_level: u32,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanFallback {
    pub name: String,
    pub alpn: String,
    pub path: String,
    pub dest: NetLocation,
    pub xver: u8,
}

#[cfg(feature = "http")]
#[derive(Debug, Clone, Deserialize)]
pub struct HttpUser {
    pub username: String,
    pub password: String,
}

#[cfg(feature = "shadowsocks")]
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksUser {
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub user_level: u32,
}

#[cfg(feature = "shadowsocks")]
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowsocksServerIdentity {
    pub method: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SocksUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct SocksUserStore {
    users: Arc<RwLock<Vec<SocksUser>>>,
    auth_required: Arc<RwLock<bool>>,
}

impl SocksUserStore {
    pub fn new(users: Vec<SocksUser>) -> Self {
        let auth_required = !users.is_empty();
        Self::with_auth_required(users, auth_required)
    }

    pub fn with_auth_required(users: Vec<SocksUser>, auth_required: bool) -> Self {
        Self {
            users: Arc::new(RwLock::new(users)),
            auth_required: Arc::new(RwLock::new(auth_required)),
        }
    }

    pub fn snapshot(&self) -> Vec<SocksUser> {
        self.users
            .read()
            .expect("socks users lock poisoned")
            .clone()
    }

    pub fn auth_required(&self) -> bool {
        *self
            .auth_required
            .read()
            .expect("socks auth mode lock poisoned")
    }

    pub fn upsert(&self, user: SocksUser) {
        *self
            .auth_required
            .write()
            .expect("socks auth mode lock poisoned") = true;
        let mut users = self.users.write().expect("socks users lock poisoned");
        if let Some(existing) = users
            .iter_mut()
            .find(|existing| existing.username == user.username)
        {
            existing.password = user.password;
        } else {
            users.push(user);
        }
    }

    pub fn remove(&self, username: &str) -> bool {
        let mut users = self.users.write().expect("socks users lock poisoned");
        let before = users.len();
        users.retain(|user| user.username != username);
        before != users.len()
    }
}

impl From<Vec<SocksUser>> for SocksUserStore {
    fn from(users: Vec<SocksUser>) -> Self {
        Self::new(users)
    }
}

impl<'de> Deserialize<'de> for SocksUserStore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<SocksUser>::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(feature = "vless")]
#[derive(Debug, Clone, Deserialize)]
pub struct VlessFallback {
    pub name: String,
    pub alpn: String,
    pub path: String,
    pub dest: NetLocation,
    pub xver: u8,
}

#[cfg(feature = "vless")]
#[derive(Debug, Clone, Deserialize)]
pub struct VlessUser {
    pub user_id: String,
    pub user_label: String,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default)]
    pub flow: String,
}

#[cfg(feature = "vmess")]
#[derive(Debug, Clone, Deserialize)]
pub struct VmessUser {
    pub user_id: String,
    #[serde(default)]
    pub user_label: String,
    #[serde(default)]
    pub user_level: u32,
    #[serde(default)]
    pub cipher: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RangeConfig {
    #[serde(default)]
    pub from: i32,
    #[serde(default)]
    pub to: i32,
}

impl RangeConfig {
    pub fn clamp_with_defaults(
        &self,
        default_from: i32,
        default_to: i32,
    ) -> (usize, usize) {
        let mut from = if self.from <= 0 {
            default_from
        } else {
            self.from
        };
        let mut to = if self.to <= 0 { default_to } else { self.to };
        if from > to {
            std::mem::swap(&mut from, &mut to);
        }
        (from.max(0) as usize, to.max(0) as usize)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum XhttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum XhttpPlacement {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum XhttpDataPlacement {
    Auto,
    Body,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum XhttpPaddingPlacement {
    Cookie,
    Header,
    Query,
    QueryInHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum XhttpPaddingMethod {
    RepeatX,
    Tokenish,
}

#[cfg(feature = "grpc_transport")]
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcServerConfig {
    pub service_name: String,
    pub inner: Box<ServerProxyConfig>,
}

#[cfg(feature = "httpupgrade")]
#[derive(Debug, Clone, Deserialize)]
pub struct HttpUpgradeServerConfig {
    pub host: Option<String>,
    pub path: String,
    pub inner: Box<ServerProxyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct XhttpServerConfig {
    pub mode: XhttpMode,
    pub host: Option<String>,
    pub path: String,
    pub min_padding: usize,
    pub max_padding: usize,
    pub max_each_post_bytes: usize,
    pub max_buffered_posts: usize,
    pub session_ttl_secs: u64,
    pub stream_up_server_secs: (usize, usize),
    pub server_max_header_bytes: usize,
    pub padding_obfs_mode: bool,
    pub padding_key: String,
    pub padding_header: String,
    pub padding_placement: XhttpPaddingPlacement,
    pub padding_method: XhttpPaddingMethod,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub uplink_http_method: String,
    pub min_posts_interval_ms: (usize, usize),
    pub session_placement: XhttpPlacement,
    pub session_key: String,
    pub seq_placement: XhttpPlacement,
    pub seq_key: String,
    pub uplink_data_placement: XhttpDataPlacement,
    pub uplink_data_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DokodemoDoorConfig {
    pub target: NetLocation,
    #[serde(default)]
    pub follow_redirect: bool,
    #[serde(default)]
    pub user_level: u32,
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone, Deserialize)]
pub enum TlsCertificateUsage {
    Encipherment,
    Verify,
    Issue,
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone, Deserialize)]
pub struct TlsCertificateConfig {
    pub certificate_path: Option<String>,
    pub certificate_pem: Vec<u8>,
    pub key_path: Option<String>,
    pub key_pem: Option<Vec<u8>>,
    pub usage: TlsCertificateUsage,
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone, Deserialize)]
pub struct TlsServerConfig {
    pub certificates: Vec<TlsCertificateConfig>,
    pub alpn_protocols: Vec<String>,
    pub enable_session_resumption: bool,
    pub reject_unknown_sni: bool,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub server_name: Option<String>,
    pub inner: Box<ServerProxyConfig>,
}

#[cfg(feature = "reality")]
#[derive(Debug, Clone, Deserialize)]
pub struct RealityTransportConfig {
    pub dest: NetLocation,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    #[serde(default, alias = "cipher_suite")]
    pub cipher_suites: Vec<CipherSuite>,
    #[serde(default)]
    pub max_time_diff: Option<u64>,
    #[serde(default)]
    pub min_client_version: Option<[u8; 3]>,
    #[serde(default)]
    pub max_client_version: Option<[u8; 3]>,
    #[serde(default)]
    pub server_names: Vec<String>,
    pub inner: Box<ServerProxyConfig>,
}

#[cfg(feature = "reality")]
impl RealityTransportConfig {
    pub fn to_reality_server_config(&self) -> crate::reality::RealityServerConfig {
        crate::reality::RealityServerConfig {
            private_key: self.private_key,
            short_ids: self.short_ids.clone(),
            dest: self.dest.clone(),
            server_names: self.server_names.clone(),
            max_time_diff: self.max_time_diff,
            min_client_version: self.min_client_version,
            max_client_version: self.max_client_version,
            cipher_suites: self.cipher_suites.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum ServerProxyConfig {
    #[cfg(feature = "vless")]
    Vless {
        users: Vec<VlessUser>,
        #[serde(default)]
        fallbacks: Vec<VlessFallback>,
    },
    #[cfg(feature = "vmess")]
    Vmess {
        users: Vec<VmessUser>,
    },
    #[cfg(feature = "ws")]
    #[serde(alias = "ws")]
    Websocket {
        #[serde(alias = "target")]
        targets: Box<OneOrSome<WebsocketServerConfig>>,
    },
    #[cfg(feature = "hysteria")]
    Hysteria2 {
        config: Hysteria2ServerConfig,
    },
    #[cfg(feature = "tuic")]
    TuicV5 {
        config: TuicServerConfig,
    },
    #[cfg(feature = "trojan")]
    Trojan {
        users: Vec<TrojanUser>,
        #[serde(default)]
        fallbacks: Vec<TrojanFallback>,
    },
    ProxyProtocol {
        inner: Box<ServerProxyConfig>,
    },
    TcpKeepAlive {
        idle_secs: i32,
        interval_secs: i32,
        inner: Box<ServerProxyConfig>,
    },
    TcpUserTimeout {
        timeout_ms: i32,
        inner: Box<ServerProxyConfig>,
    },
    TcpCongestion {
        algorithm: String,
        inner: Box<ServerProxyConfig>,
    },
    TcpWindowClamp {
        value: i32,
        inner: Box<ServerProxyConfig>,
    },
    TcpMaxSeg {
        value: i32,
        inner: Box<ServerProxyConfig>,
    },
    TcpMultipath {
        inner: Box<ServerProxyConfig>,
    },
    TransparentSocket {
        inner: Box<ServerProxyConfig>,
    },
    ReceiveOriginalDestination {
        inner: Box<ServerProxyConfig>,
    },
    TrustedForwardedHeaders {
        names: Vec<String>,
        inner: Box<ServerProxyConfig>,
    },
    Ipv6Only {
        inner: Box<ServerProxyConfig>,
    },
    TcpFastOpen {
        value: i32,
        inner: Box<ServerProxyConfig>,
    },
    BindInterface {
        name: String,
        inner: Box<ServerProxyConfig>,
    },
    BindMark {
        value: i32,
        inner: Box<ServerProxyConfig>,
    },
    CustomSockopt {
        options: Vec<crate::config::CustomSockoptConfig>,
        inner: Box<ServerProxyConfig>,
    },
    #[cfg(feature = "tls")]
    Tls(TlsServerConfig),
    #[cfg(feature = "reality")]
    Reality(RealityTransportConfig),
    Xhttp {
        config: XhttpServerConfig,
        inner: Box<ServerProxyConfig>,
    },
    #[cfg(feature = "httpupgrade")]
    HttpUpgrade(HttpUpgradeServerConfig),
    #[cfg(feature = "grpc_transport")]
    Grpc(GrpcServerConfig),
    #[cfg(feature = "http")]
    Http {
        accounts: Vec<HttpUser>,
        #[serde(default)]
        allow_transparent: bool,
        #[serde(default)]
        user_level: u32,
    },
    #[cfg(feature = "mixed")]
    Mixed {
        accounts: SocksUserStore,
        #[serde(default)]
        udp_enabled: bool,
    },
    #[cfg(feature = "shadowsocks")]
    Shadowsocks {
        users: Vec<ShadowsocksUser>,
        identity: Option<ShadowsocksServerIdentity>,
    },
    Socks {
        accounts: SocksUserStore,
        #[serde(default)]
        udp_enabled: bool,
        #[serde(default)]
        udp_bind_ip: Option<IpAddr>,
        #[serde(default)]
        user_level: u32,
    },
    DokodemoDoor {
        config: DokodemoDoorConfig,
    },
}

impl std::fmt::Display for ServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                #[cfg(feature = "vless")]
                Self::Vless { .. } => "Vless",
                #[cfg(feature = "vmess")]
                Self::Vmess { .. } => "Vmess",
                #[cfg(feature = "ws")]
                Self::Websocket { .. } => "Websocket",
                #[cfg(feature = "hysteria")]
                Self::Hysteria2 { .. } => "Hysteria2",
                #[cfg(feature = "tuic")]
                Self::TuicV5 { .. } => "TuicV5",
                #[cfg(feature = "trojan")]
                Self::Trojan { .. } => "Trojan",
                Self::ProxyProtocol { .. } => "ProxyProtocol",
                Self::TcpKeepAlive { .. } => "TcpKeepAlive",
                Self::TcpUserTimeout { .. } => "TcpUserTimeout",
                Self::TcpCongestion { .. } => "TcpCongestion",
                Self::TcpWindowClamp { .. } => "TcpWindowClamp",
                Self::TcpMaxSeg { .. } => "TcpMaxSeg",
                Self::TcpMultipath { .. } => "TcpMultipath",
                Self::TransparentSocket { .. } => "TransparentSocket",
                Self::ReceiveOriginalDestination { .. } => {
                    "ReceiveOriginalDestination"
                }
                Self::TrustedForwardedHeaders { .. } => "TrustedForwardedHeaders",
                Self::Ipv6Only { .. } => "Ipv6Only",
                Self::TcpFastOpen { .. } => "TcpFastOpen",
                Self::BindInterface { .. } => "BindInterface",
                Self::BindMark { .. } => "BindMark",
                Self::CustomSockopt { .. } => "CustomSockopt",
                #[cfg(feature = "reality")]
                Self::Reality(_) => "Reality",
                #[cfg(feature = "tls")]
                Self::Tls(_) => "Tls",
                Self::Xhttp { .. } => "Xhttp",
                #[cfg(feature = "httpupgrade")]
                Self::HttpUpgrade(_) => "HttpUpgrade",
                #[cfg(feature = "grpc_transport")]
                Self::Grpc(_) => "Grpc",
                #[cfg(feature = "http")]
                Self::Http { .. } => "Http",
                #[cfg(feature = "mixed")]
                Self::Mixed { .. } => "Mixed",
                #[cfg(feature = "shadowsocks")]
                Self::Shadowsocks { .. } => "Shadowsocks",
                Self::Socks { .. } => "Socks",
                Self::DokodemoDoor { .. } => "DokodemoDoor",
            }
        )
    }
}
