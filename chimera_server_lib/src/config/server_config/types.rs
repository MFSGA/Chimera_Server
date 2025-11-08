use std::collections::HashMap;

use serde::Deserialize;

use crate::{address::BindLocation, config::Transport, util::option::OneOrSome};

use super::{quic::ServerQuicConfig, ws::WebsocketServerConfig};

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(flatten)]
    pub bind_location: BindLocation,
    pub protocol: ServerProxyConfig,
    #[serde(alias = "transport")]
    pub transport: Transport,
    #[serde(default)]
    pub quic_settings: Option<ServerQuicConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Hysteria2Client {
    pub password: String,
    pub email: Option<String>,
    pub flow: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrojanUser {
    pub password: String,
    pub email: Option<String>,
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
pub enum ServerProxyConfig {
    Vless {
        user_id: String,
    },
    #[serde(alias = "ws")]
    Websocket {
        #[serde(alias = "target")]
        targets: Box<OneOrSome<WebsocketServerConfig>>,
    },
    Hysteria2 {
        clients: Vec<Hysteria2Client>,
    },
    Trojan {
        users: Vec<TrojanUser>,
    },
    Tls(TlsServerConfig),
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
                Self::Websocket { .. } => "Websocket",
                Self::Hysteria2 { .. } => "Hysteria2",
                Self::Trojan { .. } => "Trojan",
                Self::Tls(_) => "Tls",
                Self::Xhttp { .. } => "Xhttp",
                Self::Socks { .. } => "Socks",
            }
        )
    }
}
