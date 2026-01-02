use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    config::{ClientSetting, SettingObject},
    util::bandwidth::{parse_bandwidth, BandwidthValue},
    Error,
};

use super::super::types::{
    Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig, RangeConfig, SocksUser,
    TrojanUser, XhttpServerConfig,
};

pub(super) fn collect_hysteria2_settings(
    settings: SettingObject,
) -> Result<Hysteria2ServerConfig, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2InboundSettings {
        #[serde(default)]
        clients: Vec<ClientSetting>,
        #[serde(default)]
        bandwidth: Option<Hysteria2BandwidthSetting>,
        #[serde(default)]
        ignore_client_bandwidth: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2BandwidthSetting {
        #[serde(default)]
        up: Option<BandwidthValue>,
        #[serde(default)]
        down: Option<BandwidthValue>,
    }

    let raw: Hysteria2InboundSettings = settings
        .deserialize()
        .map_err(|e| Error::InvalidConfig(format!("failed to parse hysteria2 settings: {}", e)))?;

    let clients = raw
        .clients
        .into_iter()
        .map(|client| Hysteria2Client {
            password: client.id,
            email: if client.email.is_empty() {
                None
            } else {
                Some(client.email)
            },
            flow: if client.flow.is_empty() {
                None
            } else {
                Some(client.flow)
            },
        })
        .collect();

    let mut bandwidth = Hysteria2BandwidthConfig::default();
    if let Some(config) = raw.bandwidth {
        if let Some(up) = config.up {
            bandwidth.max_tx = parse_bandwidth(up).map_err(|err| {
                Error::InvalidConfig(format!("invalid hysteria2 bandwidth.up: {}", err))
            })?;
        }
        if let Some(down) = config.down {
            bandwidth.max_rx = parse_bandwidth(down).map_err(|err| {
                Error::InvalidConfig(format!("invalid hysteria2 bandwidth.down: {}", err))
            })?;
        }
    }

    if bandwidth.max_tx != 0 && bandwidth.max_tx < 65_536 {
        return Err(Error::InvalidConfig(
            "hysteria2 bandwidth.up must be at least 65536 bytes/s".into(),
        ));
    }
    if bandwidth.max_rx != 0 && bandwidth.max_rx < 65_536 {
        return Err(Error::InvalidConfig(
            "hysteria2 bandwidth.down must be at least 65536 bytes/s".into(),
        ));
    }

    Ok(Hysteria2ServerConfig {
        clients,
        bandwidth,
        ignore_client_bandwidth: raw.ignore_client_bandwidth,
    })
}

pub(super) fn collect_trojan_clients(settings: SettingObject) -> Result<Vec<TrojanUser>, Error> {
    let clients = settings.trojan_clients().unwrap_or_default();
    if clients.is_empty() {
        return Err(Error::InvalidConfig(
            "trojan inbound requires at least one client".into(),
        ));
    }

    clients
        .into_iter()
        .map(|client| {
            if client.password.is_empty() {
                return Err(Error::InvalidConfig(
                    "trojan client password cannot be empty".into(),
                ));
            }
            Ok(TrojanUser {
                password: client.password,
                email: client
                    .email
                    .and_then(|value| if value.is_empty() { None } else { Some(value) }),
            })
        })
        .collect()
}

pub(super) fn collect_socks_accounts(settings: SettingObject) -> Result<Vec<SocksUser>, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SocksInboundSettings {
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        accounts: Vec<SocksAccountSetting>,
    }

    #[derive(Deserialize)]
    struct SocksAccountSetting {
        user: String,
        pass: String,
    }

    let socks_settings: SocksInboundSettings = settings
        .deserialize()
        .map_err(|e| Error::InvalidConfig(format!("failed to parse socks settings: {}", e)))?;

    let auth_mode = socks_settings
        .auth
        .as_deref()
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| {
            if socks_settings.accounts.is_empty() {
                "noauth".to_string()
            } else {
                "password".to_string()
            }
        });

    match auth_mode.as_str() {
        "noauth" | "none" => Ok(vec![]),
        "password" => {
            if socks_settings.accounts.is_empty() {
                return Err(Error::InvalidConfig(
                    "socks inbound with password auth requires accounts".into(),
                ));
            }
            Ok(socks_settings
                .accounts
                .into_iter()
                .map(|account| SocksUser {
                    username: account.user,
                    password: account.pass,
                })
                .collect())
        }
        other => Err(Error::InvalidConfig(format!(
            "unsupported socks auth mode: {}",
            other
        ))),
    }
}

pub(super) fn collect_xhttp_settings(settings: SettingObject) -> Result<XhttpServerConfig, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawXhttpSettings {
        upstream: String,
        host: Option<String>,
        path: Option<String>,
        headers: Option<HashMap<String, String>>,
        x_padding_bytes: Option<RangeConfig>,
    }

    let raw: RawXhttpSettings = settings
        .deserialize()
        .map_err(|e| Error::InvalidConfig(format!("failed to parse xhttp settings: {}", e)))?;

    if raw.upstream.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "xhttp settings require a non-empty upstream address".into(),
        ));
    }

    let normalized_path = normalize_path(raw.path);
    let (min_padding, max_padding) = raw
        .x_padding_bytes
        .unwrap_or_else(|| RangeConfig {
            from: 100,
            to: 1000,
        })
        .clamp_with_defaults(100, 1000);

    Ok(XhttpServerConfig {
        upstream: raw.upstream,
        host: raw.host.map(|h| h.to_ascii_lowercase()),
        path: normalized_path,
        min_padding,
        max_padding,
        headers: raw.headers.unwrap_or_default(),
    })
}

pub(super) fn normalize_path(path: Option<String>) -> String {
    let mut normalized = path.unwrap_or_else(|| "/".to_string());
    if normalized.is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if normalized.len() > 1 {
        normalized = normalized.trim_end_matches('/').to_string();
    }
    normalized
}
