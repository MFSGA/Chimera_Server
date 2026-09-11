use serde::Deserialize;

use crate::{Error, address::Address, config::SettingObject};

#[cfg(feature = "hysteria")]
use crate::{
    config::HysteriaSettings,
    util::bandwidth::{BandwidthValue, parse_bandwidth},
};

#[cfg(feature = "tuic")]
use super::super::types::TuicServerConfig;
#[cfg(feature = "hysteria")]
use super::super::types::{
    Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2MasqueradeFileConfig,
    Hysteria2MasqueradeProxyConfig, Hysteria2MasqueradeStringConfig,
    Hysteria2ServerConfig,
};
use super::super::types::{SocksUser, SocksUserStore};

#[cfg(feature = "trojan")]
use crate::address::NetLocation;

#[cfg(feature = "trojan")]
use super::super::types::{TrojanFallback, TrojanUser};

mod xhttp;

pub(super) use xhttp::collect_xhttp_settings;
#[cfg(test)]
use xhttp::parse_xhttp_placement;

#[cfg(feature = "hysteria")]
pub(super) fn collect_hysteria2_settings(
    settings: SettingObject,
    hysteria_settings: Option<&HysteriaSettings>,
) -> Result<Hysteria2ServerConfig, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2InboundSettings {
        #[serde(default)]
        version: Option<u8>,
        #[serde(default)]
        users: Option<Vec<Hysteria2ClientSetting>>,
        #[serde(default)]
        clients: Option<Vec<Hysteria2ClientSetting>>,
        #[serde(default)]
        bandwidth: Option<Hysteria2BandwidthSetting>,
        #[serde(default)]
        ignore_client_bandwidth: Option<bool>,
        #[serde(default, alias = "udp_enabled")]
        udp_enabled: Option<bool>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2ClientSetting {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        email: String,
        #[serde(default)]
        level: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Hysteria2BandwidthSetting {
        #[serde(default)]
        up: Option<BandwidthValue>,
        #[serde(default)]
        down: Option<BandwidthValue>,
    }

    let raw: Hysteria2InboundSettings = settings.deserialize().map_err(|e| {
        Error::InvalidConfig(format!("failed to parse hysteria2 settings: {}", e))
    })?;

    let xray_compat = raw.version == Some(2)
        && hysteria_settings.and_then(|settings| settings.version) == Some(2);

    // Xray keeps both names for Hysteria2 inbound users. If `clients` is
    // present it replaces `users`, including when it is an explicit empty
    // array; otherwise the legacy `users` field is used.
    let mut clients = raw
        .clients
        .or(raw.users)
        .unwrap_or_default()
        .into_iter()
        .map(|client| {
            let xray_uuid_route = client.auth.is_some();
            let password = match client.auth {
                Some(auth) if xray_compat || !auth.is_empty() => auth,
                Some(_) => {
                    return Err(Error::InvalidConfig(
                        "hysteria client requires non-empty auth or id".into(),
                    ));
                }
                None => {
                    client.id.filter(|value| !value.is_empty()).ok_or_else(|| {
                        Error::InvalidConfig(
                            "hysteria client requires auth or id".into(),
                        )
                    })?
                }
            };

            Ok(Hysteria2Client {
                password,
                email: if client.email.is_empty() {
                    None
                } else {
                    Some(client.email)
                },
                level: client.level,
                xray_uuid_route,
                xray_transport_auth_fallback: false,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    // Xray's transport-level hysteriaSettings.auth is a fallback credential:
    // it is consulted only when the inbound validator has no configured users.
    // Keep it latent even when Xray starts with users so a later gRPC removal
    // of the last user can re-enable the fallback exactly like Xray. Preserve
    // the previous non-Xray behavior by promoting it only when no users exist.
    if (clients.is_empty() || xray_compat)
        && let Some(auth) = hysteria_settings
            .map(|settings| settings.auth.as_str())
            .filter(|auth| !auth.is_empty())
    {
        clients.push(Hysteria2Client {
            password: auth.to_string(),
            email: None,
            level: 0,
            xray_uuid_route: false,
            xray_transport_auth_fallback: true,
        });
    }

    let mut bandwidth = Hysteria2BandwidthConfig::default();
    let mut saw_up = false;
    let mut saw_down = false;
    if let Some(config) = raw.bandwidth {
        if let Some(up) = config.up {
            bandwidth.max_tx = parse_bandwidth(up).map_err(|err| {
                Error::InvalidConfig(format!(
                    "invalid hysteria2 bandwidth.up: {}",
                    err
                ))
            })?;
            saw_up = true;
        }
        if let Some(down) = config.down {
            bandwidth.max_rx = parse_bandwidth(down).map_err(|err| {
                Error::InvalidConfig(format!(
                    "invalid hysteria2 bandwidth.down: {}",
                    err
                ))
            })?;
            saw_down = true;
        }
    }

    if let Some(version) = raw.version
        && version != 2
    {
        return Err(Error::InvalidConfig(format!(
            "hysteria settings.version must be 2 for hysteria2 inbound (got {version})"
        )));
    }

    if let Some(hysteria_settings) = hysteria_settings {
        if let Some(version) = hysteria_settings.version
            && version != 2
        {
            return Err(Error::InvalidConfig(format!(
                "hysteriaSettings.version must be 2 for hysteria2 inbound (got {version})"
            )));
        }
        if let (Some(settings_version), Some(stream_version)) =
            (raw.version, hysteria_settings.version)
            && settings_version != stream_version
        {
            return Err(Error::InvalidConfig(format!(
                "hysteria settings.version ({settings_version}) conflicts with hysteriaSettings.version ({stream_version})"
            )));
        }

        if xray_compat && let Some(masquerade) = &hysteria_settings.masquerade {
            match masquerade.kind.to_ascii_lowercase().as_str() {
                "" | "404" | "file" | "proxy" | "string" => {}
                kind => {
                    return Err(Error::InvalidConfig(format!(
                        "hysteriaSettings.masquerade.type {kind:?} is not supported; Chimera currently supports Xray 404, file, proxy, and string masquerades"
                    )));
                }
            }
        }

        if !xray_compat {
            if !saw_up && let Some(up) = hysteria_settings.up.clone() {
                bandwidth.max_tx = parse_bandwidth(up).map_err(|err| {
                    Error::InvalidConfig(format!(
                        "invalid hysteriaSettings.up value: {}",
                        err
                    ))
                })?;
            }
            if !saw_down && let Some(down) = hysteria_settings.down.clone() {
                bandwidth.max_rx = parse_bandwidth(down).map_err(|err| {
                    Error::InvalidConfig(format!(
                        "invalid hysteriaSettings.down value: {}",
                        err
                    ))
                })?;
            }
        }
    }

    let xray_udp_idle_timeout_secs = Some(match hysteria_settings {
        Some(settings) => {
            let timeout = settings.udp_idle_timeout;
            if timeout != 0 && !(2..=600).contains(&timeout) {
                return Err(Error::InvalidConfig(format!(
                    "hysteriaSettings.udpIdleTimeout must be 0 or between 2 and 600 seconds (got {timeout})"
                )));
            }
            if timeout == 0 { 60 } else { timeout as u64 }
        }
        None => 60,
    });

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

    let xray_masquerade_file = if xray_compat {
        hysteria_settings
            .and_then(|settings| settings.masquerade.as_ref())
            .filter(|masquerade| masquerade.kind.eq_ignore_ascii_case("file"))
            .map(|masquerade| Hysteria2MasqueradeFileConfig {
                dir: masquerade.dir.clone(),
            })
    } else {
        None
    };

    let xray_masquerade_proxy = if xray_compat {
        hysteria_settings
            .and_then(|settings| settings.masquerade.as_ref())
            .filter(|masquerade| masquerade.kind.eq_ignore_ascii_case("proxy"))
            .map(|masquerade| Hysteria2MasqueradeProxyConfig {
                url: masquerade.url.clone(),
                rewrite_host: masquerade.rewrite_host,
                insecure: masquerade.insecure,
            })
    } else {
        None
    };

    let xray_masquerade_string = if xray_compat {
        hysteria_settings
            .and_then(|settings| settings.masquerade.as_ref())
            .filter(|masquerade| masquerade.kind.eq_ignore_ascii_case("string"))
            .map(|masquerade| Hysteria2MasqueradeStringConfig {
                content: masquerade.content.clone(),
                headers: masquerade.headers.clone(),
                status_code: masquerade.status_code,
            })
    } else {
        None
    };

    let ignore_client_bandwidth = raw.ignore_client_bandwidth.unwrap_or_else(|| {
        hysteria_settings
            .and_then(|settings| settings.ignore_client_bandwidth)
            .unwrap_or(false)
    });
    // Xray Hysteria always advertises/enables UDP through its inbound
    // validator. Shoes exposes an explicit udp_enabled switch, default true.
    let udp_enabled = if xray_compat {
        true
    } else {
        raw.udp_enabled.unwrap_or(true)
    };

    Ok(Hysteria2ServerConfig {
        clients,
        bandwidth,
        ignore_client_bandwidth,
        udp_enabled,
        xray_compat,
        xray_masquerade_string,
        xray_masquerade_file,
        xray_masquerade_proxy,
        xray_congestion: None,
        xray_bbr_profile: None,
        xray_brutal_up: None,
        xray_brutal_down: None,
        xray_max_idle_timeout_secs: None,
        xray_keep_alive_period_secs: None,
        xray_udp_idle_timeout_secs,
        xray_max_incoming_streams: None,
        xray_init_stream_receive_window: None,
        xray_max_stream_receive_window: None,
        xray_init_connection_receive_window: None,
        xray_max_connection_receive_window: None,
        xray_disable_path_mtu_discovery: None,
        udp_finalmask: None,
    })
}

#[cfg(feature = "trojan")]
pub(super) fn collect_trojan_clients(
    settings: SettingObject,
) -> Result<Vec<TrojanUser>, Error> {
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
                email: client.email.filter(|value| !value.is_empty()),
                user_level: client.level,
            })
        })
        .collect()
}

#[cfg(feature = "trojan")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrojanInboundSettings {
    #[serde(default)]
    fallbacks: Vec<TrojanInboundFallback>,
}

#[cfg(feature = "trojan")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrojanInboundFallback {
    dest: serde_json::Value,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    alpn: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    xver: Option<u8>,
}

#[cfg(feature = "trojan")]
pub(super) fn collect_trojan_fallbacks(
    settings: &SettingObject,
) -> Result<Vec<TrojanFallback>, Error> {
    let trojan_settings: TrojanInboundSettings =
        settings.deserialize().map_err(|e| {
            Error::InvalidConfig(format!("failed to parse trojan settings: {e}"))
        })?;

    let mut fallbacks = Vec::new();
    for fallback in trojan_settings.fallbacks {
        let fallback_type = fallback
            .r#type
            .as_deref()
            .unwrap_or("tcp")
            .trim()
            .to_ascii_lowercase();
        if !matches!(fallback_type.as_str(), "" | "tcp") {
            return Err(Error::InvalidConfig(format!(
                "trojan fallback type={fallback_type} is not supported yet"
            )));
        }
        let name = fallback
            .name
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let alpn = fallback
            .alpn
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let path = fallback.path.unwrap_or_default().trim().to_string();
        if !path.is_empty() && !path.starts_with('/') {
            return Err(Error::InvalidConfig(
                "trojan fallback path must be empty or start with /".into(),
            ));
        }
        let xver = fallback.xver.unwrap_or(0);
        if xver > 2 {
            return Err(Error::InvalidConfig(format!(
                "trojan fallback xver must be 0, 1, or 2; got {xver}"
            )));
        }
        let dest = parse_trojan_fallback_dest(fallback.dest)?;
        fallbacks.push(TrojanFallback {
            name,
            alpn,
            path,
            dest,
            xver,
        });
    }

    Ok(fallbacks)
}

#[cfg(feature = "trojan")]
fn parse_trojan_fallback_dest(
    value: serde_json::Value,
) -> Result<NetLocation, Error> {
    let local_port = |port: u16| {
        NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), port)
    };
    match value {
        serde_json::Value::Number(number) => {
            let port = number
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "trojan fallback numeric dest must be a port from 1 to 65535"
                            .into(),
                    )
                })?;
            Ok(local_port(port))
        }
        serde_json::Value::String(value) => {
            let dest = value.trim();
            if dest.is_empty() {
                return Err(Error::InvalidConfig(
                    "trojan fallback dest cannot be empty".into(),
                ));
            }
            if let Ok(port) = dest.parse::<u16>()
                && port != 0
            {
                return Ok(local_port(port));
            }
            if dest.starts_with('/') || dest.starts_with('@') {
                return Err(Error::InvalidConfig(
                    "trojan fallback Unix socket destinations are not supported yet"
                        .into(),
                ));
            }
            NetLocation::from_str(dest, None).map_err(|error| {
                Error::InvalidConfig(format!(
                    "invalid trojan fallback dest {dest}: {error}"
                ))
            })
        }
        _ => Err(Error::InvalidConfig(
            "trojan fallback dest must be a port number or host:port string".into(),
        )),
    }
}

pub(super) fn collect_socks_settings(
    settings: SettingObject,
) -> Result<(SocksUserStore, bool, Option<String>, u32), Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SocksInboundSettings {
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        users: Option<Vec<SocksAccountSetting>>,
        #[serde(default)]
        accounts: Option<Vec<SocksAccountSetting>>,
        #[serde(default)]
        udp: Option<bool>,
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        user_level: Option<u32>,
    }

    #[derive(Deserialize)]
    struct SocksAccountSetting {
        user: String,
        pass: String,
    }

    let socks_settings: SocksInboundSettings =
        settings.deserialize().map_err(|e| {
            Error::InvalidConfig(format!("failed to parse socks settings: {}", e))
        })?;

    // Xray treats a present `accounts` field as an alias that overrides
    // `users`, including when it is explicitly an empty list.
    let raw_accounts = socks_settings
        .accounts
        .or(socks_settings.users)
        .unwrap_or_default();

    // SOCKS UDP is implemented through UDP ASSOCIATE on the TCP control stream.
    let udp_enabled = socks_settings.udp.unwrap_or(false);
    let udp_response_ip = socks_settings
        .ip
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            Address::from(value)
                .map(|_| value.to_string())
                .map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid socks settings.ip address: {error}"
                    ))
                })
        })
        .transpose()?;
    let user_level = socks_settings.user_level.unwrap_or(0);

    let auth_mode = socks_settings
        .auth
        .as_deref()
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| {
            if raw_accounts.is_empty() {
                "noauth".to_string()
            } else {
                "password".to_string()
            }
        });

    let accounts = raw_accounts
        .into_iter()
        .map(|account| SocksUser {
            username: account.user,
            password: account.pass,
        })
        .collect::<Vec<_>>();

    match auth_mode.as_str() {
        "noauth" | "none" => Ok((
            SocksUserStore::with_auth_required(accounts, false),
            udp_enabled,
            udp_response_ip,
            user_level,
        )),
        "password" => Ok((
            SocksUserStore::with_auth_required(accounts, true),
            udp_enabled,
            udp_response_ip,
            user_level,
        )),
        _ => Ok((
            SocksUserStore::with_auth_required(accounts, false),
            udp_enabled,
            udp_response_ip,
            user_level,
        )),
    }
}

#[cfg(feature = "tuic")]
pub(super) fn collect_tuic_settings(
    settings: SettingObject,
) -> Result<TuicServerConfig, Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TuicInboundSettings {
        uuid: String,
        password: String,
        #[serde(default, alias = "zero_rtt_handshake")]
        zero_rtt_handshake: bool,
    }

    let raw: TuicInboundSettings = settings.deserialize().map_err(|e| {
        Error::InvalidConfig(format!("failed to parse tuic settings: {e}"))
    })?;

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

    uuid::Uuid::parse_str(raw.uuid.trim()).map_err(|e| {
        Error::InvalidConfig(format!("invalid tuic uuid {}: {e}", raw.uuid))
    })?;

    Ok(TuicServerConfig {
        uuid: raw.uuid,
        password: raw.password,
        zero_rtt_handshake: raw.zero_rtt_handshake,
    })
}

pub(super) fn normalize_path(
    path: Option<String>,
    require_trailing_slash: bool,
) -> String {
    let configured = path.unwrap_or_else(|| "/".to_string());
    let mut normalized = configured
        .split_once('?')
        .map_or(configured.clone(), |(path, _)| path.to_string());
    if normalized.is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if require_trailing_slash && !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

#[cfg(test)]
mod tests;
