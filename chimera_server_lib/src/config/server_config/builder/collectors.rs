use std::collections::HashMap;

use serde::Deserialize;

use crate::{
    config::{HysteriaSettings, SettingObject},
    util::bandwidth::{parse_bandwidth, BandwidthValue},
    Error,
};

use super::super::types::SocksUser;
#[cfg(feature = "tuic")]
use super::super::types::TuicServerConfig;
#[cfg(feature = "hysteria")]
use super::super::types::{Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig};
#[cfg(feature = "xhttp")]
use super::super::types::{RangeConfig, XhttpMode, XhttpServerConfig};
#[cfg(feature = "xhttp")]
use crate::config::StreamSettings;

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

#[cfg(feature = "xhttp")]
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawXhttpTransportSettings {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    x_padding_bytes: Option<RangeConfig>,
}

#[cfg(feature = "xhttp")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawXhttpInboundSettings {
    upstream: String,
    #[serde(flatten)]
    transport: RawXhttpTransportSettings,
}

#[cfg(feature = "xhttp")]
pub(super) fn collect_xhttp_settings(settings: SettingObject) -> Result<XhttpServerConfig, Error> {
    let raw: RawXhttpInboundSettings = settings
        .deserialize()
        .map_err(|e| Error::InvalidConfig(format!("failed to parse xhttp settings: {}", e)))?;

    if raw.upstream.trim().is_empty() {
        return Err(Error::InvalidConfig(
            "xhttp settings require a non-empty upstream address".into(),
        ));
    }

    build_xhttp_settings(
        raw.transport,
        Some(raw.upstream.trim().to_string()),
        "xhttp settings",
    )
}

#[cfg(feature = "xhttp")]
pub(super) fn collect_xhttp_transport_settings(
    stream_settings: &StreamSettings,
) -> Result<XhttpServerConfig, Error> {
    let raw = if let Some(value) = stream_settings.xhttp_settings.as_ref() {
        value
            .deserialize::<RawXhttpTransportSettings>()
            .map_err(|e| {
                Error::InvalidConfig(format!(
                    "failed to parse streamSettings.xhttpSettings: {}",
                    e
                ))
            })?
    } else if let Some(value) = stream_settings.splithttp_settings.as_ref() {
        value
            .deserialize::<RawXhttpTransportSettings>()
            .map_err(|e| {
                Error::InvalidConfig(format!(
                    "failed to parse streamSettings.splithttpSettings: {}",
                    e
                ))
            })?
    } else {
        RawXhttpTransportSettings::default()
    };

    build_xhttp_settings(raw, None, "streamSettings.xhttpSettings")
}

#[cfg(feature = "xhttp")]
fn build_xhttp_settings(
    raw: RawXhttpTransportSettings,
    upstream: Option<String>,
    source_name: &str,
) -> Result<XhttpServerConfig, Error> {
    let mode = parse_xhttp_mode(raw.mode.as_deref(), source_name)?;

    if matches!(mode, XhttpMode::StreamOne | XhttpMode::StreamUp) {
        return Err(Error::InvalidConfig(format!(
            "{} mode {:?} is not supported yet (supported: auto, packet-up)",
            source_name, mode
        )));
    }

    if let Some(headers) = raw.headers.as_ref() {
        for key in headers.keys() {
            if key.eq_ignore_ascii_case("host") {
                return Err(Error::InvalidConfig(format!(
                    "{}.headers cannot include host",
                    source_name
                )));
            }
        }
    }

    let (min_padding, max_padding) = parse_padding_range(raw.x_padding_bytes, source_name)?;

    Ok(XhttpServerConfig {
        upstream,
        host: raw
            .host
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty()),
        path: normalize_xhttp_path(raw.path),
        mode,
        min_padding,
        max_padding,
        headers: raw.headers.unwrap_or_default(),
    })
}

#[cfg(feature = "xhttp")]
fn parse_xhttp_mode(value: Option<&str>, source_name: &str) -> Result<XhttpMode, Error> {
    match value
        .map(|text| text.trim().to_ascii_lowercase())
        .as_deref()
        .unwrap_or("auto")
    {
        "auto" => Ok(XhttpMode::Auto),
        "packet-up" => Ok(XhttpMode::PacketUp),
        "stream-up" => Ok(XhttpMode::StreamUp),
        "stream-one" => Ok(XhttpMode::StreamOne),
        other => Err(Error::InvalidConfig(format!(
            "{}.mode has unsupported value: {}",
            source_name, other
        ))),
    }
}

#[cfg(feature = "xhttp")]
fn parse_padding_range(
    value: Option<RangeConfig>,
    source_name: &str,
) -> Result<(usize, usize), Error> {
    let Some(range) = value else {
        return Ok((100, 1000));
    };

    if range.from <= 0 || range.to <= 0 {
        return Err(Error::InvalidConfig(format!(
            "{}.xPaddingBytes cannot be disabled",
            source_name
        )));
    }

    let mut from = range.from as usize;
    let mut to = range.to as usize;
    if from > to {
        std::mem::swap(&mut from, &mut to);
    }

    Ok((from, to))
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

#[cfg(feature = "xhttp")]
pub(super) fn normalize_xhttp_path(path: Option<String>) -> String {
    let raw = path.unwrap_or_else(|| "/".to_string());
    let mut normalized = raw.split('?').next().unwrap_or_default().to_string();
    if normalized.trim().is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if !normalized.ends_with('/') {
        normalized.push('/');
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

    #[cfg(feature = "xhttp")]
    #[test]
    fn collect_xhttp_transport_settings_defaults_and_path_normalization() {
        let stream_settings = serde_json::from_value::<StreamSettings>(serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "api",
                "headers": {
                    "x-test": "ok"
                }
            }
        }))
        .expect("stream settings");

        let config =
            collect_xhttp_transport_settings(&stream_settings).expect("valid xhttp transport");

        assert_eq!(config.path, "/api/");
        assert_eq!(config.mode, XhttpMode::Auto);
        assert_eq!(config.min_padding, 100);
        assert_eq!(config.max_padding, 1000);
        assert_eq!(config.upstream, None);
    }

    #[cfg(feature = "xhttp")]
    #[test]
    fn collect_xhttp_transport_settings_accepts_splithttp_alias() {
        let stream_settings = serde_json::from_value::<StreamSettings>(serde_json::json!({
            "network": "splithttp",
            "splithttpSettings": {
                "host": "Example.COM",
                "xPaddingBytes": {
                    "from": 120,
                    "to": 180
                }
            }
        }))
        .expect("stream settings");

        let config =
            collect_xhttp_transport_settings(&stream_settings).expect("valid xhttp transport");

        assert_eq!(config.host.as_deref(), Some("example.com"));
        assert_eq!(config.min_padding, 120);
        assert_eq!(config.max_padding, 180);
    }

    #[cfg(feature = "xhttp")]
    #[test]
    fn collect_xhttp_transport_settings_rejects_host_header() {
        let stream_settings = serde_json::from_value::<StreamSettings>(serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "headers": {
                    "Host": "example.com"
                }
            }
        }))
        .expect("stream settings");

        let err =
            collect_xhttp_transport_settings(&stream_settings).expect_err("host header rejected");
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[cfg(feature = "xhttp")]
    #[test]
    fn collect_xhttp_transport_settings_rejects_disabled_padding() {
        let stream_settings = serde_json::from_value::<StreamSettings>(serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "xPaddingBytes": {
                    "from": 0,
                    "to": 10
                }
            }
        }))
        .expect("stream settings");

        let err = collect_xhttp_transport_settings(&stream_settings)
            .expect_err("zero padding range must be rejected");
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
