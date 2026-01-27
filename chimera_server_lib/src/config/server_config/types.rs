use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    address::{BindLocation, NetLocation},
    config::Transport,
};

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
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2ServerConfig {
    pub clients: Vec<Hysteria2Client>,
    #[serde(default)]
    pub bandwidth: Hysteria2BandwidthConfig,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanUser {
    pub password: String,
    pub email: Option<String>,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, Deserialize)]
pub struct TrojanFallback {
    pub dest: NetLocation,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SocksUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RangeConfig {
    #[serde(default)]
    pub from: i32,
    #[serde(default)]
    pub to: i32,
}

impl RangeConfig {
    pub fn clamp_with_defaults(&self, default_from: i32, default_to: i32) -> (usize, usize) {
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

#[derive(Debug, Clone, Deserialize)]
pub struct XhttpServerConfig {
    pub upstream: String,
    pub host: Option<String>,
    pub path: String,
    pub min_padding: usize,
    pub max_padding: usize,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsServerConfig {
    pub certificate_path: String,
    pub private_key_path: String,
    pub alpn_protocols: Vec<String>,
    pub inner: Box<ServerProxyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RealityTransportConfig {
    pub dest: NetLocation,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
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

impl RealityTransportConfig {
    pub fn to_reality_server_config(&self) -> crate::reality::RealityServerConfig {
        crate::reality::RealityServerConfig {
            private_key: self.private_key,
            short_ids: self.short_ids.clone(),
            dest: self.dest.clone(),
            max_time_diff: self.max_time_diff,
            min_client_version: self.min_client_version,
            max_client_version: self.max_client_version,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum ServerProxyConfig {
    Vless {
        user_id: String,
        user_label: String,
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
    #[cfg(feature = "trojan")]
    Trojan {
        users: Vec<TrojanUser>,
        #[serde(default)]
        fallbacks: Vec<TrojanFallback>,
    },
    Tls(TlsServerConfig),
    Reality(RealityTransportConfig),
    Xhttp {
        config: XhttpServerConfig,
    },
    Socks {
        accounts: Vec<SocksUser>,
    },
}

impl std::fmt::Display for ServerProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Vless { .. } => "Vless",
                #[cfg(feature = "ws")]
                Self::Websocket { .. } => "Websocket",
                #[cfg(feature = "hysteria")]
                Self::Hysteria2 { .. } => "Hysteria2",
                #[cfg(feature = "trojan")]
                Self::Trojan { .. } => "Trojan",
                Self::Tls(_) => "Tls",
                Self::Reality(_) => "Reality",
                Self::Xhttp { .. } => "Xhttp",
                Self::Socks { .. } => "Socks",
            }
        )
    }
}
