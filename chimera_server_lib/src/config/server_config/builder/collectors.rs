use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    config::{HysteriaSettings, SettingObject},
    util::bandwidth::{parse_bandwidth, BandwidthValue},
    Error,
};

#[cfg(feature = "tuic")]
use super::super::types::TuicServerConfig;
#[cfg(feature = "hysteria")]
use super::super::types::{Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig};
use super::super::types::{RangeConfig, SocksUser, XhttpServerConfig};

#[cfg(feature = "trojan")]
use crate::address::NetLocation;

#[cfg(feature = "trojan")]
use super::super::types::{TrojanFallback, TrojanUser};

#[cfg(feature = "hysteria")]
pub(super) fn collect_hysteria2_settings(
    settings: SettingObject,
    hysteria_settings: Option<&HysteriaSettings>,
) -> Result<Hysteria2ServerConfig, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2InboundSettings {
        #[serde(default)]
        clients: Vec<Hysteria2ClientSetting>,
        #[serde(default)]
        bandwidth: Option<Hysteria2BandwidthSetting>,
        #[serde(default)]
        ignore_client_bandwidth: Option<bool>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2ClientSetting {
        id: String,
        #[serde(default)]
        email: String,
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
        })
        .collect();

    let mut bandwidth = Hysteria2BandwidthConfig::default();
    let mut saw_up = false;
    let mut saw_down = false;
    if let Some(config) = raw.bandwidth {
        if let Some(up) = config.up {
            bandwidth.max_tx = parse_bandwidth(up).map_err(|err| {
                Error::InvalidConfig(format!("invalid hysteria2 bandwidth.up: {}", err))
            })?;
            saw_up = true;
        }
        if let Some(down) = config.down {
            bandwidth.max_rx = parse_bandwidth(down).map_err(|err| {
                Error::InvalidConfig(format!("invalid hysteria2 bandwidth.down: {}", err))
            })?;
            saw_down = true;
        }
    }

    if let Some(hysteria_settings) = hysteria_settings {
        if let Some(version) = hysteria_settings.version {
            if version != 2 {
                return Err(Error::InvalidConfig(format!(
                    "hysteriaSettings.version must be 2 for hysteria2 inbound (got {version})"
                )));
            }
        }

        if !saw_up {
            if let Some(up) = hysteria_settings.up.clone() {
                bandwidth.max_tx = parse_bandwidth(up).map_err(|err| {
                    Error::InvalidConfig(format!("invalid hysteriaSettings.up value: {}", err))
                })?;
            }
        }
        if !saw_down {
            if let Some(down) = hysteria_settings.down.clone() {
                bandwidth.max_rx = parse_bandwidth(down).map_err(|err| {
                    Error::InvalidConfig(format!("invalid hysteriaSettings.down value: {}", err))
                })?;
            }
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

    let ignore_client_bandwidth = raw.ignore_client_bandwidth.unwrap_or_else(|| {
        hysteria_settings
            .and_then(|settings| settings.ignore_client_bandwidth)
            .unwrap_or(false)
    });

    Ok(Hysteria2ServerConfig {
        clients,
        bandwidth,
        ignore_client_bandwidth,
    })
}

#[cfg(feature = "trojan")]
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

#[cfg(feature = "trojan")]
pub(super) fn collect_trojan_fallbacks(
    settings: &SettingObject,
) -> Result<Vec<TrojanFallback>, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TrojanInboundSettings {
        #[serde(default)]
        fallbacks: Vec<TrojanInboundFallback>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TrojanInboundFallback {
        dest: String,
    }

    let trojan_settings: TrojanInboundSettings = settings
        .deserialize()
        .map_err(|e| Error::InvalidConfig(format!("failed to parse trojan settings: {e}")))?;

    let mut fallbacks = Vec::new();
    for fallback in trojan_settings.fallbacks {
        let dest = fallback.dest.trim();
        if dest.is_empty() {
            return Err(Error::InvalidConfig(
                "trojan fallback dest cannot be empty".into(),
            ));
        }

        // dest-only mode: require explicit host:port (no port-only, no unix)
        if dest.find(':').is_none() {
            return Err(Error::InvalidConfig(
                "trojan fallback dest must be host:port".into(),
            ));
        }

        let net_location = NetLocation::from_str(dest, None).map_err(|e| {
            Error::InvalidConfig(format!("invalid trojan fallback dest {dest}: {e}"))
        })?;

        fallbacks.push(TrojanFallback { dest: net_location });
    }

    Ok(fallbacks)
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

#[cfg(feature = "tuic")]
pub(super) fn collect_tuic_settings(settings: SettingObject) -> Result<TuicServerConfig, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TuicInboundSettings {
        uuid: String,
        password: String,
        #[serde(default, alias = "zero_rtt_handshake")]
        zero_rtt_handshake: bool,
    }

    let raw: TuicInboundSettings = settings
        .deserialize()
        .map_err(|e| Error::InvalidConfig(format!("failed to parse tuic settings: {e}")))?;

    if raw.uuid.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "tuic settings require a non-empty uuid".into(),
        ));
    }
    if raw.password.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "tuic settings require a non-empty password".into(),
        ));
    }

    uuid::Uuid::parse_str(raw.uuid.trim())
        .map_err(|e| Error::InvalidConfig(format!("invalid tuic uuid {}: {e}", raw.uuid)))?;

    Ok(TuicServerConfig {
        uuid: raw.uuid,
        password: raw.password,
        zero_rtt_handshake: raw.zero_rtt_handshake,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tuic")]
    #[test]
    fn collect_tuic_settings_accepts_valid_config() {
        let settings = SettingObject(serde_json::json!({
            "uuid": "550e8400-e29b-41d4-a716-446655440000",
            "password": "tuic-password",
            "zeroRttHandshake": true
        }));

        let config = collect_tuic_settings(settings).expect("valid tuic settings");
        assert_eq!(config.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(config.password, "tuic-password");
        assert!(config.zero_rtt_handshake);
    }

    #[cfg(feature = "tuic")]
    #[test]
    fn collect_tuic_settings_rejects_invalid_uuid() {
        let settings = SettingObject(serde_json::json!({
            "uuid": "not-a-uuid",
            "password": "tuic-password"
        }));

        let err = collect_tuic_settings(settings).expect_err("invalid uuid");
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "expected InvalidConfig"
        );
    }
}
