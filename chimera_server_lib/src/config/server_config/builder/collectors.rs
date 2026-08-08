use serde::Deserialize;

use crate::{
    Error,
    config::{SettingObject, XhttpRange, XhttpSettings},
};

#[cfg(feature = "hysteria")]
use crate::{
    config::{HysteriaSettings, QuicParamsConfig, UdpHopConfig},
    util::bandwidth::{BandwidthValue, parse_bandwidth},
};

#[cfg(feature = "tuic")]
use super::super::types::TuicServerConfig;
#[cfg(feature = "hysteria")]
use super::super::types::{
    Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2MasqueradeConfig,
    Hysteria2QuicParams, Hysteria2ServerConfig,
};
use super::super::types::{
    RangeConfig, SocksUser, SocksUserStore, XhttpDataPlacement, XhttpMode,
    XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement, XhttpServerConfig,
};

#[cfg(feature = "trojan")]
use crate::address::{Address, NetLocation};

#[cfg(feature = "trojan")]
use super::super::types::{TrojanFallback, TrojanUser};

#[cfg(feature = "hysteria")]
fn collect_hysteria2_masquerade(
    settings: Option<&HysteriaSettings>,
) -> Result<Hysteria2MasqueradeConfig, Error> {
    let Some(settings) = settings else {
        return Ok(Hysteria2MasqueradeConfig::default());
    };
    let masquerade = &settings.masquerade;
    let mode = masquerade.kind.trim().to_ascii_lowercase();
    match mode.as_str() {
        "" | "404" => Ok(Hysteria2MasqueradeConfig::default()),
        "string" => {
            let status_code = if masquerade.status_code == 0 {
                200
            } else if (100..=999).contains(&masquerade.status_code) {
                masquerade.status_code as u16
            } else {
                return Err(Error::InvalidConfig(
                    "hysteria2 masquerade.statusCode must be between 100 and 999"
                        .into(),
                ));
            };
            Ok(Hysteria2MasqueradeConfig {
                mode,
                content: masquerade.content.clone(),
                headers: masquerade.headers.clone(),
                status_code,
            })
        }
        "file" | "proxy" => Err(Error::InvalidConfig(format!(
            "hysteria2 masquerade type {mode} is not yet supported"
        ))),
        _ => Err(Error::InvalidConfig(format!(
            "unknown hysteria2 masquerade type: {}",
            masquerade.kind
        ))),
    }
}

#[cfg(feature = "hysteria")]
fn validate_xray_udp_hop_ports(value: &serde_json::Value) -> Result<(), String> {
    fn parse_port(value: &str) -> Result<u16, String> {
        let value = value
            .parse::<u32>()
            .map_err(|_| format!("invalid port: {value}"))?;
        u16::try_from(value).map_err(|_| format!("invalid port: {value}"))
    }

    fn parse_port_range(value: &str) -> Result<(), String> {
        let value = if let Some(name) = value.strip_prefix("env:") {
            std::env::var(name).unwrap_or_default()
        } else {
            value.to_string()
        };
        let mut parts = value.splitn(2, '-');
        let from = parts.next().unwrap_or_default();
        let Some(to) = parts.next() else {
            parse_port(from)?;
            return Ok(());
        };
        parse_port(from)?;
        parse_port(to)?;
        Ok(())
    }

    match value {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::Number(number) => {
            let value = number
                .as_u64()
                .ok_or_else(|| "invalid udpHop ports number".to_string())?;
            u16::try_from(value)
                .map(|_| ())
                .map_err(|_| format!("invalid port: {value}"))
        }
        serde_json::Value::String(value) => {
            for item in value.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                if item.contains('-') || item.starts_with("env:") {
                    parse_port_range(item)?;
                } else {
                    parse_port(item)?;
                }
            }
            Ok(())
        }
        _ => Err("udpHop.ports must be a number or string".to_string()),
    }
}

#[cfg(feature = "hysteria")]
fn parse_xray_i32_range(value: &serde_json::Value) -> Result<(i32, i32), String> {
    let (left, right) = match value {
        serde_json::Value::Null => (0, 0),
        serde_json::Value::Number(number) => {
            let raw = number
                .as_i64()
                .ok_or_else(|| "invalid udpHop interval number".to_string())?;
            let value = i32::try_from(raw)
                .map_err(|_| format!("invalid udpHop interval: {raw}"))?;
            (value, value)
        }
        serde_json::Value::String(value) => {
            if value.is_empty() {
                (0, 0)
            } else if let Ok(single) = value.parse::<i32>() {
                (single, single)
            } else {
                let split = if let Some(rest) = value.strip_prefix('-') {
                    let index =
                        rest.find('-').map(|index| index + 1).ok_or_else(|| {
                            format!("invalid udpHop interval: {value}")
                        })?;
                    (&value[..index], &value[index + 1..])
                } else {
                    value
                        .split_once('-')
                        .ok_or_else(|| format!("invalid udpHop interval: {value}"))?
                };
                let left = split
                    .0
                    .parse::<i32>()
                    .map_err(|_| format!("invalid udpHop interval: {value}"))?;
                let right = split
                    .1
                    .parse::<i32>()
                    .map_err(|_| format!("invalid udpHop interval: {value}"))?;
                (left, right)
            }
        }
        _ => {
            return Err(
                "udpHop.interval must be an integer or range string".to_string()
            );
        }
    };
    Ok(if left <= right {
        (left, right)
    } else {
        (right, left)
    })
}

#[cfg(feature = "hysteria")]
fn validate_xray_udp_hop(udp_hop: &UdpHopConfig) -> Result<(), Error> {
    validate_xray_udp_hop_ports(&udp_hop.ports).map_err(|err| {
        Error::InvalidConfig(format!(
            "invalid hysteria2 finalmask.quicParams.udpHop.ports: {err}"
        ))
    })?;
    let (from, to) = parse_xray_i32_range(&udp_hop.interval).map_err(|err| {
        Error::InvalidConfig(format!(
            "invalid hysteria2 finalmask.quicParams.udpHop.interval: {err}"
        ))
    })?;
    if (from != 0 && from < 5) || (to != 0 && to < 5) {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.udpHop.interval must be at least 5"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "hysteria")]
fn parse_xray_quic_bandwidth(value: &str) -> Result<u64, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(0);
    }

    let split = value
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit() && *ch != '.')
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number = number
        .parse::<f64>()
        .map_err(|_| "invalid bandwidth value".to_string())?;
    let multiplier = match unit.trim() {
        "" | "b" | "bps" => 1u64,
        "k" | "kb" | "kbps" => 1024,
        "m" | "mb" | "mbps" => 1024 * 1024,
        "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
        "t" | "tb" | "tbps" => 1024 * 1024 * 1024 * 1024,
        unit => return Err(format!("unsupported bandwidth unit: {unit}")),
    };
    let scaled = number * multiplier as f64;
    if !scaled.is_finite() || scaled < 0.0 || scaled > u64::MAX as f64 {
        return Err("bandwidth value out of range".to_string());
    }
    Ok((scaled as u64) / 8)
}

#[cfg(feature = "hysteria")]
pub(super) fn collect_hysteria2_quic_params(
    params: Option<&QuicParamsConfig>,
) -> Result<Hysteria2QuicParams, Error> {
    let Some(params) = params else {
        return Ok(Hysteria2QuicParams::default());
    };

    validate_xray_udp_hop(&params.udp_hop)?;

    let brutal_up = parse_xray_quic_bandwidth(&params.brutal_up).map_err(|err| {
        Error::InvalidConfig(format!(
            "invalid hysteria2 finalmask.quicParams.brutalUp: {err}"
        ))
    })?;
    let brutal_down =
        parse_xray_quic_bandwidth(&params.brutal_down).map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid hysteria2 finalmask.quicParams.brutalDown: {err}"
            ))
        })?;
    if brutal_up != 0 && brutal_up < 65_536 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.brutalUp must be at least 65536 bytes per second"
                .into(),
        ));
    }
    if brutal_down != 0 && brutal_down < 65_536 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.brutalDown must be at least 65536 bytes per second"
                .into(),
        ));
    }

    let congestion = params.congestion.trim().to_ascii_lowercase();
    match congestion.as_str() {
        "" | "reno" | "bbr" | "brutal" => {}
        "force-brutal" if brutal_up != 0 => {}
        "force-brutal" => {
            return Err(Error::InvalidConfig(
                "hysteria2 finalmask.quicParams force-brutal requires brutalUp"
                    .into(),
            ));
        }
        _ => {
            return Err(Error::InvalidConfig(format!(
                "unknown hysteria2 finalmask.quicParams congestion control: {}",
                params.congestion
            )));
        }
    }

    if params.max_idle_timeout != 0 && !(4..=120).contains(&params.max_idle_timeout)
    {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.maxIdleTimeout must be between 4 and 120"
                .into(),
        ));
    }
    if params.keep_alive_period != 0 && !(2..=60).contains(&params.keep_alive_period)
    {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.keepAlivePeriod must be between 2 and 60"
                .into(),
        ));
    }
    if params.max_incoming_streams != 0 && params.max_incoming_streams < 8 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.maxIncomingStreams must be at least 8"
                .into(),
        ));
    }
    if params.init_stream_receive_window != 0
        && params.init_stream_receive_window < 16_384
    {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.initStreamReceiveWindow must be at least 16384"
                .into(),
        ));
    }
    if params.max_stream_receive_window != 0
        && params.max_stream_receive_window < 16_384
    {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.maxStreamReceiveWindow must be at least 16384"
                .into(),
        ));
    }
    if params.init_connection_receive_window != 0
        && params.init_connection_receive_window < 16_384
    {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.initConnectionReceiveWindow must be at least 16384"
                .into(),
        ));
    }
    if params.max_connection_receive_window != 0
        && params.max_connection_receive_window < 16_384
    {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.quicParams.maxConnectionReceiveWindow must be at least 16384"
                .into(),
        ));
    }

    Ok(Hysteria2QuicParams {
        congestion,
        debug: params.debug,
        max_idle_timeout: params.max_idle_timeout as u64,
        keep_alive_period: params.keep_alive_period as u64,
        disable_path_mtu_discovery: params.disable_path_mtu_discovery,
        max_incoming_streams: params.max_incoming_streams as u64,
        init_stream_receive_window: params.init_stream_receive_window,
        max_stream_receive_window: params.max_stream_receive_window,
        init_connection_receive_window: params.init_connection_receive_window,
        max_connection_receive_window: params.max_connection_receive_window,
        brutal_up,
        brutal_down,
        from_finalmask: true,
    })
}

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

    let clients = raw
        .clients
        .or(raw.users)
        .unwrap_or_default()
        .into_iter()
        .map(|client| {
            let password = client
                .auth
                .or(client.id)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "hysteria client requires auth or id".into(),
                    )
                })?;

            Ok(Hysteria2Client {
                password,
                email: if client.email.is_empty() {
                    None
                } else {
                    Some(client.email)
                },
                user_level: client.level,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

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
    let fallback_auth = hysteria_settings
        .map(|settings| settings.auth.clone())
        .filter(|auth| !auth.is_empty());
    let udp_idle_timeout = hysteria_settings
        .and_then(|settings| settings.udp_idle_timeout)
        .unwrap_or(0);
    if udp_idle_timeout != 0 && !(2..=600).contains(&udp_idle_timeout) {
        return Err(Error::InvalidConfig(
            "hysteriaSettings.udpIdleTimeout must be between 2 and 600".into(),
        ));
    }
    let udp_idle_timeout = if udp_idle_timeout == 0 {
        60
    } else {
        udp_idle_timeout
    };
    let masquerade = collect_hysteria2_masquerade(hysteria_settings)?;

    Ok(Hysteria2ServerConfig {
        clients,
        fallback_auth,
        bandwidth,
        ignore_client_bandwidth,
        udp_idle_timeout,
        quic_params: Hysteria2QuicParams::default(),
        masquerade,
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

#[derive(Debug)]
pub(super) struct CollectedSocksSettings {
    pub accounts: SocksUserStore,
    pub udp_enabled: bool,
    pub udp_bind_ip: Option<std::net::IpAddr>,
    pub user_level: u32,
}

pub(super) fn collect_socks_settings(
    settings: SettingObject,
    allow_user_level: bool,
) -> Result<CollectedSocksSettings, Error> {
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
    let accounts = socks_settings
        .accounts
        .or(socks_settings.users)
        .unwrap_or_default();

    // SOCKS UDP is implemented through UDP ASSOCIATE on the TCP control stream.
    let udp_enabled = socks_settings.udp.unwrap_or(false);
    let udp_bind_ip = socks_settings
        .ip
        .map(|value| {
            value.parse::<std::net::IpAddr>().map_err(|_| {
                Error::InvalidConfig(format!(
                    "socks settings.ip must be an IP address: {value}"
                ))
            })
        })
        .transpose()?;
    if socks_settings.user_level.is_some() && !allow_user_level {
        return Err(Error::InvalidConfig(
            "mixed settings.userLevel is not supported".into(),
        ));
    }
    let user_level = socks_settings.user_level.unwrap_or_default();

    // Match xray-core: an omitted `auth` field falls through to NO_AUTH,
    // even when `users` / `accounts` are present.
    let auth_mode = socks_settings
        .auth
        .as_deref()
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| "noauth".to_string());

    let users = accounts
        .into_iter()
        .map(|account| SocksUser {
            username: account.user,
            password: account.pass,
        })
        .collect();
    let auth_required = auth_mode == "password";

    Ok(CollectedSocksSettings {
        accounts: SocksUserStore::with_auth_required(users, auth_required),
        udp_enabled,
        udp_bind_ip,
        user_level,
    })
}

pub(super) fn collect_xhttp_settings(
    raw: XhttpSettings,
) -> Result<XhttpServerConfig, Error> {
    let raw = apply_xhttp_extra(raw)?;
    let mode = parse_xhttp_mode(raw.mode.as_deref())?;
    validate_xhttp_client_fields(&raw, mode)?;
    let uplink_http_method =
        normalize_xhttp_uplink_method(raw.uplink_http_method.as_deref(), mode)?;
    let min_posts_interval_ms = clamp_xhttp_range(
        raw.sc_min_posts_interval_ms
            .clone()
            .unwrap_or(XhttpRange { from: 30, to: 30 }),
        30,
        30,
    );
    let session_placement =
        parse_xhttp_placement(raw.session_placement.as_deref(), "sessionPlacement")?;
    let seq_placement =
        parse_xhttp_placement(raw.seq_placement.as_deref(), "seqPlacement")?;
    let session_key = normalize_xhttp_meta_key(
        raw.session_key.as_deref(),
        session_placement,
        "X-Session",
        "x_session",
        "sessionKey",
    )?;
    let seq_key = normalize_xhttp_meta_key(
        raw.seq_key.as_deref(),
        seq_placement,
        "X-Seq",
        "x_seq",
        "seqKey",
    )?;
    let uplink_data_placement =
        parse_xhttp_data_placement(raw.uplink_data_placement.as_deref(), mode)?;
    let uplink_data_key = normalize_xhttp_data_key(
        raw.uplink_data_key.as_deref(),
        uplink_data_placement,
    );
    if raw
        .headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("host"))
    {
        return Err(Error::InvalidConfig(
            "xhttpSettings.headers cannot contain host; use xhttpSettings.host instead"
                .into(),
        ));
    }
    if raw
        .x_padding_bytes
        .as_ref()
        .is_some_and(|range| range.from <= 0 || range.to <= 0)
    {
        return Err(Error::InvalidConfig(
            "xhttpSettings.xPaddingBytes cannot be disabled".into(),
        ));
    }
    let normalized_path = normalize_path(
        raw.path,
        session_placement == XhttpPlacement::Path
            || seq_placement == XhttpPlacement::Path,
    );
    let (min_padding, max_padding) = clamp_xhttp_range(
        raw.x_padding_bytes.unwrap_or(XhttpRange {
            from: 100,
            to: 1000,
        }),
        100,
        1000,
    );
    let padding_obfs_mode = raw.x_padding_obfs_mode.unwrap_or(false);
    let padding_key = raw
        .x_padding_key
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "x_padding".to_string());
    let padding_header = raw
        .x_padding_header
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "X-Padding".to_string());
    let padding_placement =
        parse_xhttp_padding_placement(raw.x_padding_placement.as_deref())?;
    let padding_method =
        parse_xhttp_padding_method(raw.x_padding_method.as_deref())?;
    if matches!(
        padding_placement,
        XhttpPaddingPlacement::Header | XhttpPaddingPlacement::QueryInHeader
    ) && http::header::HeaderName::from_bytes(padding_header.as_bytes()).is_err()
    {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttpSettings.xPaddingHeader: {padding_header}"
        )));
    }
    let server_max_header_bytes = match raw.server_max_header_bytes.unwrap_or(0) {
        value if value < 0 => {
            return Err(Error::InvalidConfig(
                "xhttpSettings.serverMaxHeaderBytes cannot be negative".into(),
            ));
        }
        0 => 8192,
        value => value as usize,
    };
    let (_, max_each_post_bytes) = clamp_xhttp_range(
        raw.sc_max_each_post_bytes.unwrap_or(XhttpRange {
            from: 1_000_000,
            to: 1_000_000,
        }),
        1_000_000,
        1_000_000,
    );
    let stream_up_server_secs = clamp_xhttp_range(
        raw.sc_stream_up_server_secs
            .unwrap_or(XhttpRange { from: 20, to: 80 }),
        20,
        80,
    );

    Ok(XhttpServerConfig {
        mode,
        host: raw.host.map(|h| h.to_ascii_lowercase()),
        path: normalized_path,
        min_padding,
        max_padding,
        max_each_post_bytes,
        max_buffered_posts: raw.sc_max_buffered_posts.unwrap_or(30).max(1) as usize,
        session_ttl_secs: 30,
        stream_up_server_secs,
        server_max_header_bytes,
        padding_obfs_mode,
        padding_key,
        padding_header,
        padding_placement,
        padding_method,
        no_grpc_header: raw.no_grpc_header.unwrap_or(false),
        no_sse_header: raw.no_sse_header.unwrap_or(false),
        uplink_http_method,
        min_posts_interval_ms,
        session_placement,
        session_key,
        seq_placement,
        seq_key,
        uplink_data_placement,
        uplink_data_key,
    })
}

fn apply_xhttp_extra(mut raw: XhttpSettings) -> Result<XhttpSettings, Error> {
    let Some(extra_value) = raw.extra.take() else {
        return Ok(raw);
    };

    let outer_host = raw.host.take();
    let outer_path = raw.path.take();
    let outer_mode = raw.mode.take();
    let mut extra =
        serde_json::from_value::<XhttpSettings>(extra_value).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to parse xhttpSettings.extra: {error}"
            ))
        })?;
    extra.host = outer_host;
    extra.path = outer_path;
    extra.mode = outer_mode;
    extra.extra = None;
    Ok(extra)
}

fn validate_xhttp_client_fields(
    raw: &XhttpSettings,
    mode: XhttpMode,
) -> Result<(), Error> {
    if raw.download_settings.is_some() && mode == XhttpMode::StreamOne {
        return Err(Error::InvalidConfig(
            "xhttpSettings.downloadSettings cannot be used with mode=stream-one"
                .into(),
        ));
    }

    if let Some(value) = raw.uplink_chunk_size.as_ref() {
        serde_json::from_value::<XhttpRange>(value.clone()).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid xhttpSettings.uplinkChunkSize: {error}"
            ))
        })?;
    }

    if let Some(value) = raw.xmux.as_ref() {
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct XmuxInput {
            #[serde(default)]
            max_concurrency: Option<XhttpRange>,
            #[serde(default)]
            max_connections: Option<XhttpRange>,
        }

        let xmux =
            serde_json::from_value::<XmuxInput>(value.clone()).map_err(|error| {
                Error::InvalidConfig(format!("invalid xhttpSettings.xmux: {error}"))
            })?;
        if xmux
            .max_connections
            .as_ref()
            .is_some_and(|range| range.to > 0)
            && xmux
                .max_concurrency
                .as_ref()
                .is_some_and(|range| range.to > 0)
        {
            return Err(Error::InvalidConfig(
                "xhttpSettings.xmux.maxConnections cannot be specified together with maxConcurrency"
                    .into(),
            ));
        }
    }

    validate_xhttp_session_id(raw)
}

fn validate_xhttp_session_id(raw: &XhttpSettings) -> Result<(), Error> {
    let Some(configured_table) = raw
        .session_id_table
        .as_deref()
        .filter(|table| !table.is_empty())
    else {
        return Ok(());
    };
    let table =
        predefined_session_id_table(configured_table).unwrap_or(configured_table);
    if !table.is_ascii() {
        return Err(Error::InvalidConfig(
            "xhttpSettings.sessionIDTable must contain only ASCII characters".into(),
        ));
    }

    let length = raw
        .session_id_length
        .clone()
        .unwrap_or(XhttpRange { from: 0, to: 0 });
    let room = xhttp_session_id_room(table.len(), length.from, length.to);
    if room < 2_147_483_648 {
        return Err(Error::InvalidConfig(
            "xhttpSettings.sessionIDTable or sessionIDLength is too small".into(),
        ));
    }
    if length.from <= 0 {
        return Err(Error::InvalidConfig(
            "xhttpSettings.sessionIDLength.from must be greater than 0".into(),
        ));
    }
    Ok(())
}

fn predefined_session_id_table(name: &str) -> Option<&'static str> {
    match name {
        "ALPHABET" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Alphabet" => Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
        "BASE36" => Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "Base62" => {
            Some("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        }
        "HEX" => Some("0123456789ABCDEF"),
        "alphabet" => Some("abcdefghijklmnopqrstuvwxyz"),
        "base36" => Some("0123456789abcdefghijklmnopqrstuvwxyz"),
        "hex" => Some("0123456789abcdef"),
        "number" => Some("0123456789"),
        _ => None,
    }
}

fn xhttp_session_id_room(table_size: usize, from: i32, to: i32) -> u128 {
    const REQUIRED_ROOM: u128 = 2_147_483_648;
    if table_size == 0 || from <= 0 || to < from {
        return 0;
    }

    let base = table_size as u128;
    let mut total = 0u128;
    for length in from..=to {
        let mut term = 1u128;
        for _ in 0..length {
            term = term.saturating_mul(base).min(REQUIRED_ROOM);
        }
        total = total.saturating_add(term).min(REQUIRED_ROOM);
        if total >= REQUIRED_ROOM {
            return REQUIRED_ROOM;
        }
    }
    total
}

fn parse_xhttp_data_placement(
    placement: Option<&str>,
    mode: XhttpMode,
) -> Result<XhttpDataPlacement, Error> {
    let placement = match placement
        .unwrap_or("auto")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "auto" => XhttpDataPlacement::Auto,
        "body" => XhttpDataPlacement::Body,
        "header" => XhttpDataPlacement::Header,
        "cookie" => XhttpDataPlacement::Cookie,
        unsupported => {
            return Err(Error::InvalidConfig(format!(
                "unsupported xhttpSettings.uplinkDataPlacement: {unsupported}"
            )));
        }
    };
    if matches!(
        placement,
        XhttpDataPlacement::Header | XhttpDataPlacement::Cookie
    ) && mode != XhttpMode::PacketUp
    {
        let value = match placement {
            XhttpDataPlacement::Header => "header",
            XhttpDataPlacement::Cookie => "cookie",
            _ => unreachable!(),
        };
        return Err(Error::InvalidConfig(format!(
            "xhttpSettings.uplinkDataPlacement={value} requires mode=packet-up"
        )));
    }
    Ok(placement)
}

fn normalize_xhttp_data_key(
    key: Option<&str>,
    placement: XhttpDataPlacement,
) -> String {
    let key = key.unwrap_or("").trim();
    if !key.is_empty() {
        return key.to_string();
    }
    match placement {
        XhttpDataPlacement::Body => String::new(),
        XhttpDataPlacement::Cookie => "x_data".to_string(),
        XhttpDataPlacement::Auto | XhttpDataPlacement::Header => {
            "X-Data".to_string()
        }
    }
}

fn parse_xhttp_padding_placement(
    placement: Option<&str>,
) -> Result<XhttpPaddingPlacement, Error> {
    match placement
        .unwrap_or("queryInHeader")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "cookie" => Ok(XhttpPaddingPlacement::Cookie),
        "header" => Ok(XhttpPaddingPlacement::Header),
        "query" => Ok(XhttpPaddingPlacement::Query),
        "" | "queryinheader" => Ok(XhttpPaddingPlacement::QueryInHeader),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.xPaddingPlacement: {unsupported}"
        ))),
    }
}

fn parse_xhttp_padding_method(
    method: Option<&str>,
) -> Result<XhttpPaddingMethod, Error> {
    match method
        .unwrap_or("repeat-x")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "repeat-x" => Ok(XhttpPaddingMethod::RepeatX),
        "tokenish" => Ok(XhttpPaddingMethod::Tokenish),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.xPaddingMethod: {unsupported}"
        ))),
    }
}

fn parse_xhttp_placement(
    placement: Option<&str>,
    field: &str,
) -> Result<XhttpPlacement, Error> {
    match placement
        .unwrap_or("path")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "path" => Ok(XhttpPlacement::Path),
        "query" => Ok(XhttpPlacement::Query),
        "header" => Ok(XhttpPlacement::Header),
        "cookie" => Ok(XhttpPlacement::Cookie),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.{field}: {unsupported}"
        ))),
    }
}

fn normalize_xhttp_meta_key(
    key: Option<&str>,
    placement: XhttpPlacement,
    default_header: &str,
    default_query_cookie: &str,
    field: &str,
) -> Result<String, Error> {
    let key = key.unwrap_or("").trim();
    let normalized = if key.is_empty() {
        match placement {
            XhttpPlacement::Path => String::new(),
            XhttpPlacement::Header => default_header.to_string(),
            XhttpPlacement::Query | XhttpPlacement::Cookie => {
                default_query_cookie.to_string()
            }
        }
    } else {
        key.to_string()
    };
    if placement == XhttpPlacement::Header
        && http::header::HeaderName::from_bytes(normalized.as_bytes()).is_err()
    {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttpSettings.{field} header name: {normalized}"
        )));
    }
    Ok(normalized)
}

fn normalize_xhttp_uplink_method(
    method: Option<&str>,
    mode: XhttpMode,
) -> Result<String, Error> {
    let method = method.unwrap_or("").trim();
    let method = if method.is_empty() {
        "POST".to_string()
    } else {
        method.to_ascii_uppercase()
    };
    if http::Method::from_bytes(method.as_bytes()).is_err() {
        return Err(Error::InvalidConfig(format!(
            "invalid xhttpSettings.uplinkHTTPMethod: {method}"
        )));
    }
    if method == "GET" && mode != XhttpMode::PacketUp {
        return Err(Error::InvalidConfig(
            "xhttpSettings.uplinkHTTPMethod=GET requires mode=packet-up".into(),
        ));
    }
    Ok(method)
}

fn parse_xhttp_mode(mode: Option<&str>) -> Result<XhttpMode, Error> {
    match mode.unwrap_or("auto").trim() {
        "" | "auto" => Ok(XhttpMode::Auto),
        "packet-up" => Ok(XhttpMode::PacketUp),
        "stream-up" => Ok(XhttpMode::StreamUp),
        "stream-one" => Ok(XhttpMode::StreamOne),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.mode: {unsupported}"
        ))),
    }
}

fn clamp_xhttp_range(
    range: XhttpRange,
    default_from: i32,
    default_to: i32,
) -> (usize, usize) {
    RangeConfig {
        from: range.from,
        to: range.to,
    }
    .clamp_with_defaults(default_from, default_to)
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
mod tests {
    use super::*;

    #[cfg(feature = "tuic")]
    #[test]
    fn collect_tuic_settings_accepts_valid_config() {
        let settings = SettingObject(serde_json::json!({
            "uuid": "dd206ca8-f026-47a3-8861-733c738a6242",
            "password": "tuic-password",
            "zeroRttHandshake": true
        }));

        let config = collect_tuic_settings(settings).expect("valid tuic settings");
        assert_eq!(config.uuid, "dd206ca8-f026-47a3-8861-733c738a6242");
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

    #[test]
    fn collect_socks_settings_accepts_udp_true() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "udp": true
        }));

        let collected = collect_socks_settings(settings, true)
            .expect("socks udp should be accepted");
        assert!(!collected.accounts.auth_required());
        assert!(collected.udp_enabled);
        assert_eq!(collected.user_level, 0);
    }

    #[test]
    fn collect_socks_unknown_auth_defaults_to_noauth() {
        let settings = SettingObject(serde_json::json!({
            "auth": "future-auth",
            "accounts": [{"user": "alice", "pass": "secret"}],
            "udp": true,
            "userLevel": 7
        }));

        let collected = collect_socks_settings(settings, true)
            .expect("unknown socks auth should match Xray noauth fallback");
        assert!(!collected.accounts.auth_required());
        assert_eq!(collected.accounts.snapshot()[0].username, "alice");
        assert!(collected.udp_enabled);
        assert_eq!(collected.user_level, 7);
    }

    #[test]
    fn collect_socks_omitted_auth_defaults_to_noauth_even_with_accounts() {
        let settings = SettingObject(serde_json::json!({
            "accounts": [{"user": "alice", "pass": "secret"}]
        }));

        let collected = collect_socks_settings(settings, true)
            .expect("omitted socks auth should match Xray noauth fallback");
        assert!(!collected.accounts.auth_required());
        assert_eq!(collected.accounts.snapshot()[0].username, "alice");
    }

    #[test]
    fn collect_socks_users_alias_and_accounts_override_match_xray() {
        let users_only = SettingObject(serde_json::json!({
            "auth": "password",
            "users": [{"user": "legacy", "pass": "secret"}]
        }));
        let collected = collect_socks_settings(users_only, true)
            .expect("legacy socks users should be accepted");
        assert!(collected.accounts.auth_required());
        assert_eq!(collected.accounts.snapshot()[0].username, "legacy");

        let accounts_override = SettingObject(serde_json::json!({
            "users": [{"user": "legacy", "pass": "secret"}],
            "accounts": []
        }));
        let collected = collect_socks_settings(accounts_override, true)
            .expect("explicit accounts should override legacy users");
        assert!(!collected.accounts.auth_required());
        assert!(collected.accounts.snapshot().is_empty());
    }

    #[test]
    fn collect_socks_settings_preserves_udp_bind_ip() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "ip": "127.0.0.1"
        }));

        let collected = collect_socks_settings(settings, true)
            .expect("socks ip should be accepted");
        assert_eq!(
            collected.udp_bind_ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn collect_socks_settings_preserves_global_user_level() {
        let settings = SettingObject(serde_json::json!({
            "auth": "password",
            "accounts": [{"user": "alice", "pass": "secret"}],
            "userLevel": 7
        }));

        let collected = collect_socks_settings(settings, true)
            .expect("socks userLevel should be accepted");
        assert_eq!(collected.user_level, 7);
        assert!(collected.accounts.auth_required());
        assert_eq!(collected.accounts.snapshot().len(), 1);
    }

    #[test]
    fn collect_mixed_settings_rejects_socks_user_level() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "userLevel": 7
        }));

        let error = collect_socks_settings(settings, false)
            .expect_err("mixed userLevel must remain unsupported");
        assert!(error.to_string().contains("mixed settings.userLevel"));
    }

    #[test]
    fn collect_socks_accounts_accepts_explicit_udp_false() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "udp": false
        }));

        let collected =
            collect_socks_settings(settings, true).expect("udp false is a no-op");
        assert!(!collected.accounts.auth_required());
        assert!(!collected.udp_enabled);
    }

    #[cfg(feature = "trojan")]
    #[test]
    fn collect_trojan_fallbacks_preserves_xray_fields() {
        let settings = SettingObject(serde_json::json!({
            "fallbacks": [{
                "name": "EXAMPLE.COM",
                "alpn": "H2",
                "dest": 8080,
                "path": "/ws",
                "type": "tcp",
                "xver": 2
            }]
        }));

        let fallbacks = collect_trojan_fallbacks(&settings)
            .expect("Trojan fallback fields should build");
        assert_eq!(fallbacks.len(), 1);
        assert_eq!(fallbacks[0].name, "example.com");
        assert_eq!(fallbacks[0].alpn, "h2");
        assert_eq!(fallbacks[0].path, "/ws");
        assert_eq!(fallbacks[0].dest.to_string(), "127.0.0.1:8080");
        assert_eq!(fallbacks[0].xver, 2);
    }

    #[cfg(feature = "trojan")]
    #[test]
    fn collect_trojan_fallbacks_rejects_invalid_type_path_and_xver() {
        for (field, value, expected) in [
            (
                "type",
                serde_json::json!("unix"),
                "trojan fallback type=unix is not supported yet",
            ),
            (
                "path",
                serde_json::json!("ws"),
                "trojan fallback path must be empty or start with /",
            ),
            (
                "xver",
                serde_json::json!(3),
                "trojan fallback xver must be 0, 1, or 2; got 3",
            ),
        ] {
            let mut fallback = serde_json::json!({"dest": 8080});
            fallback[field] = value;
            let settings = SettingObject(serde_json::json!({
                "fallbacks": [fallback]
            }));
            let error = collect_trojan_fallbacks(&settings)
                .expect_err("invalid Trojan fallback field must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn collect_xhttp_settings_applies_reference_defaults() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp/?ed=2048"
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.mode, XhttpMode::Auto);
        assert_eq!(config.path, "/xhttp/");
        assert_eq!(config.max_each_post_bytes, 1_000_000);
        assert_eq!(config.max_buffered_posts, 30);
        assert_eq!(config.session_ttl_secs, 30);
        assert_eq!(config.stream_up_server_secs, (20, 80));
        assert_eq!(config.server_max_header_bytes, 8192);
        assert!(!config.padding_obfs_mode);
        assert_eq!(config.padding_key, "x_padding");
        assert_eq!(config.padding_header, "X-Padding");
        assert_eq!(
            config.padding_placement,
            XhttpPaddingPlacement::QueryInHeader
        );
        assert_eq!(config.padding_method, XhttpPaddingMethod::RepeatX);
        assert!(!config.no_grpc_header);
        assert!(!config.no_sse_header);
        assert_eq!(config.uplink_http_method, "POST");
        assert_eq!(config.min_posts_interval_ms, (30, 30));
        assert_eq!(config.session_placement, XhttpPlacement::Path);
        assert!(config.session_key.is_empty());
        assert_eq!(config.seq_placement, XhttpPlacement::Path);
        assert!(config.seq_key.is_empty());
        assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Auto);
        assert_eq!(config.uplink_data_key, "X-Data");
    }

    #[test]
    fn collect_xhttp_settings_accepts_padding_obfuscation_and_header_limit() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "xPaddingObfsMode": true,
            "xPaddingKey": "pad",
            "xPaddingHeader": "X-Custom-Pad",
            "xPaddingPlacement": "cookie",
            "xPaddingMethod": "tokenish",
            "xPaddingBytes": {"from": 64, "to": 128},
            "serverMaxHeaderBytes": 32768,
            "scStreamUpServerSecs": {"from": 5, "to": 10}
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("custom XHTTP padding settings should be supported");
        assert!(config.padding_obfs_mode);
        assert_eq!(config.padding_key, "pad");
        assert_eq!(config.padding_header, "X-Custom-Pad");
        assert_eq!(config.padding_placement, XhttpPaddingPlacement::Cookie);
        assert_eq!(config.padding_method, XhttpPaddingMethod::Tokenish);
        assert_eq!((config.min_padding, config.max_padding), (64, 128));
        assert_eq!(config.server_max_header_bytes, 32768);
        assert_eq!(config.stream_up_server_secs, (5, 10));
    }

    #[test]
    fn collect_xhttp_settings_rejects_invalid_padding_configuration() {
        for (field, field_value, expected) in [
            (
                "xPaddingBytes",
                serde_json::json!({"from": 0, "to": 100}),
                "xPaddingBytes cannot be disabled",
            ),
            (
                "xPaddingPlacement",
                serde_json::json!("fragment"),
                "unsupported xhttpSettings.xPaddingPlacement",
            ),
            (
                "xPaddingMethod",
                serde_json::json!("random"),
                "unsupported xhttpSettings.xPaddingMethod",
            ),
            (
                "serverMaxHeaderBytes",
                serde_json::json!(-1),
                "serverMaxHeaderBytes cannot be negative",
            ),
        ] {
            let mut settings_value = serde_json::json!({"path": "/xhttp"});
            settings_value[field] = field_value;
            let settings = serde_json::from_value::<XhttpSettings>(settings_value)
                .expect("xhttp settings should deserialize");
            let error = collect_xhttp_settings(settings)
                .expect_err("invalid XHTTP padding setting must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn collect_xhttp_settings_accepts_reference_modes() {
        for (mode, expected) in [
            ("auto", XhttpMode::Auto),
            ("packet-up", XhttpMode::PacketUp),
            ("stream-up", XhttpMode::StreamUp),
            ("stream-one", XhttpMode::StreamOne),
        ] {
            let settings =
                serde_json::from_value::<XhttpSettings>(serde_json::json!({
                    "path": "/xhttp",
                    "mode": mode
                }))
                .expect("xhttp settings");

            let config = collect_xhttp_settings(settings).unwrap_or_else(|err| {
                panic!("mode {mode} should be accepted: {err}")
            });
            assert_eq!(config.mode, expected);
        }
    }

    #[test]
    fn collect_xhttp_settings_accepts_reference_header_and_method_options() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "stream-one",
            "noGRPCHeader": true,
            "noSSEHeader": true,
            "uplinkHTTPMethod": "patch",
            "scMinPostsIntervalMs": {"from": 40, "to": 60},
            "sessionPlacement": "header",
            "seqPlacement": "query"
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("supported XHTTP header and method options");
        assert!(config.no_grpc_header);
        assert!(config.no_sse_header);
        assert_eq!(config.uplink_http_method, "PATCH");
        assert_eq!(config.min_posts_interval_ms, (40, 60));
        assert_eq!(config.session_placement, XhttpPlacement::Header);
        assert_eq!(config.session_key, "X-Session");
        assert_eq!(config.seq_placement, XhttpPlacement::Query);
        assert_eq!(config.seq_key, "x_seq");
    }

    #[test]
    fn collect_xhttp_settings_accepts_packet_up_header_data() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "packet-up",
            "uplinkDataPlacement": "header"
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("packet-up header data should be supported");
        assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Header);
        assert_eq!(config.uplink_data_key, "X-Data");
    }

    #[test]
    fn collect_xhttp_settings_accepts_packet_up_cookie_data() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "packet-up",
            "uplinkDataPlacement": "cookie"
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("packet-up cookie data should be supported");
        assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Cookie);
        assert_eq!(config.uplink_data_key, "x_data");
    }

    #[test]
    fn collect_xhttp_settings_rejects_header_data_outside_packet_up() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "stream-up",
            "uplinkDataPlacement": "header"
        }))
        .expect("xhttp settings");

        let error = collect_xhttp_settings(settings)
            .expect_err("header data must require packet-up");
        assert!(error.to_string().contains(
            "xhttpSettings.uplinkDataPlacement=header requires mode=packet-up"
        ));
    }

    #[test]
    fn collect_xhttp_settings_rejects_unknown_meta_placement() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "sessionPlacement": "fragment"
        }))
        .expect("xhttp settings");

        let error = collect_xhttp_settings(settings)
            .expect_err("unknown session placement must fail");
        assert!(
            error
                .to_string()
                .contains("unsupported xhttpSettings.sessionPlacement: fragment")
        );
    }

    #[test]
    fn collect_xhttp_settings_rejects_get_outside_packet_up() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "stream-one",
            "uplinkHTTPMethod": "GET"
        }))
        .expect("xhttp settings");

        let error = collect_xhttp_settings(settings)
            .expect_err("GET uplink must be packet-up only");
        assert!(
            error.to_string().contains(
                "xhttpSettings.uplinkHTTPMethod=GET requires mode=packet-up"
            )
        );
    }

    #[test]
    fn collect_xhttp_settings_rejects_unsupported_mode() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "grpc"
        }))
        .expect("xhttp settings");

        let err = collect_xhttp_settings(settings).expect_err("unsupported mode");
        assert!(
            err.to_string()
                .contains("unsupported xhttpSettings.mode: grpc")
        );
    }

    #[test]
    fn collect_xhttp_settings_rejects_host_header() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "headers": {
                "Host": "edge.example.com"
            }
        }))
        .expect("xhttp settings");

        let err = collect_xhttp_settings(settings).expect_err("host header");
        assert!(
            err.to_string()
                .contains("xhttpSettings.headers cannot contain host")
        );
    }

    #[test]
    fn collect_xhttp_settings_accepts_client_request_headers() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "headers": {
                "X-Test": "ok"
            }
        }))
        .expect("xhttp settings");

        collect_xhttp_settings(settings)
            .expect("server should accept client-side XHTTP request headers");
    }

    #[test]
    fn collect_xhttp_settings_accepts_shared_client_only_fields() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "packet-up",
            "downloadSettings": {"network": "xhttp"},
            "xmux": {
                "maxConnections": {"from": 2, "to": 3},
                "hMaxRequestTimes": {"from": 100, "to": 200}
            },
            "uplinkChunkSize": {"from": 1024, "to": 2048},
            "sessionIDTable": "Base62",
            "sessionIDLength": {"from": 6, "to": 8}
        }))
        .expect("xhttp settings");

        collect_xhttp_settings(settings).expect(
            "server should accept valid XHTTP fields consumed by the client",
        );
    }

    #[test]
    fn collect_xhttp_settings_applies_extra_with_outer_identity_fields() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "host": "outer.example",
            "path": "/outer",
            "mode": "packet-up",
            "extra": {
                "host": "ignored.example",
                "path": "/ignored",
                "mode": "stream-one",
                "uplinkDataPlacement": "cookie",
                "xPaddingObfsMode": true,
                "xPaddingPlacement": "header",
                "xPaddingMethod": "tokenish"
            }
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("xhttpSettings.extra should overlay non-identity fields");
        assert_eq!(config.host.as_deref(), Some("outer.example"));
        assert_eq!(config.path, "/outer/");
        assert_eq!(config.mode, XhttpMode::PacketUp);
        assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Cookie);
        assert!(config.padding_obfs_mode);
        assert_eq!(config.padding_placement, XhttpPaddingPlacement::Header);
        assert_eq!(config.padding_method, XhttpPaddingMethod::Tokenish);
    }

    #[test]
    fn collect_xhttp_settings_rejects_invalid_shared_client_fields() {
        for (settings_value, expected) in [
            (
                serde_json::json!({
                    "path": "/xhttp",
                    "mode": "stream-one",
                    "downloadSettings": {"network": "xhttp"}
                }),
                "downloadSettings cannot be used with mode=stream-one",
            ),
            (
                serde_json::json!({
                    "path": "/xhttp",
                    "xmux": {
                        "maxConnections": {"from": 1, "to": 1},
                        "maxConcurrency": {"from": 1, "to": 1}
                    }
                }),
                "maxConnections cannot be specified together with maxConcurrency",
            ),
            (
                serde_json::json!({
                    "path": "/xhttp",
                    "sessionIDTable": "number",
                    "sessionIDLength": {"from": 1, "to": 8}
                }),
                "sessionIDTable or sessionIDLength is too small",
            ),
            (
                serde_json::json!({
                    "path": "/xhttp",
                    "sessionIDTable": "表格",
                    "sessionIDLength": {"from": 10, "to": 10}
                }),
                "sessionIDTable must contain only ASCII characters",
            ),
        ] {
            let settings = serde_json::from_value::<XhttpSettings>(settings_value)
                .expect("xhttp settings should deserialize");
            let error = collect_xhttp_settings(settings)
                .expect_err("invalid shared XHTTP field must fail");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_quic_params_accepts_xray_initial_receive_windows() {
        let params: QuicParamsConfig = serde_json::from_value(serde_json::json!({
            "initStreamReceiveWindow": 32768,
            "initConnectionReceiveWindow": 65536
        }))
        .expect("Xray quicParams should deserialize");

        let config = collect_hysteria2_quic_params(Some(&params))
            .expect("valid initial receive windows should pass");
        assert_eq!(config.init_stream_receive_window, 32_768);
        assert_eq!(config.init_connection_receive_window, 65_536);
        assert!(config.from_finalmask);
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_quic_params_rejects_small_initial_receive_windows() {
        for (params, expected) in [
            (
                QuicParamsConfig {
                    init_stream_receive_window: 16_383,
                    ..QuicParamsConfig::default()
                },
                "initStreamReceiveWindow",
            ),
            (
                QuicParamsConfig {
                    init_connection_receive_window: 16_383,
                    ..QuicParamsConfig::default()
                },
                "initConnectionReceiveWindow",
            ),
        ] {
            let error = collect_hysteria2_quic_params(Some(&params))
                .expect_err("Xray minimum receive window should be enforced");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_xray_client_auth() {
        let settings = SettingObject(serde_json::json!({
            "clients": [{
                "auth": "xray-auth-token",
                "email": "hy@example.com",
                "level": 7
            }]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("hysteria auth should map to password");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "xray-auth-token");
        assert_eq!(config.clients[0].email.as_deref(), Some("hy@example.com"));
        assert_eq!(config.clients[0].user_level, 7);
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_users_alias_and_clients_override_match_xray() {
        let users_only = SettingObject(serde_json::json!({
            "users": [{"auth": "users-auth"}]
        }));
        let config = collect_hysteria2_settings(users_only, None)
            .expect("hysteria users alias should be accepted");
        assert_eq!(config.clients[0].password, "users-auth");

        let both = SettingObject(serde_json::json!({
            "users": [{"auth": "users-auth"}],
            "clients": [{"auth": "clients-auth"}]
        }));
        let config = collect_hysteria2_settings(both, None)
            .expect("clients should override users like Xray");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "clients-auth");

        let explicit_empty_clients = SettingObject(serde_json::json!({
            "users": [{"auth": "users-auth"}],
            "clients": []
        }));
        let config = collect_hysteria2_settings(explicit_empty_clients, None)
            .expect("explicit clients list should override users");
        assert!(config.clients.is_empty());
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_xray_settings_version() {
        let settings = SettingObject(serde_json::json!({
            "version": 2,
            "clients": [{
                "auth": "xray-auth-token",
                "email": "hy@example.com"
            }]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("hysteria settings.version should be accepted");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "xray-auth-token");
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_rejects_non_v2_settings_version() {
        let settings = SettingObject(serde_json::json!({
            "version": 1,
            "clients": [{
                "auth": "xray-auth-token"
            }]
        }));

        let err = collect_hysteria2_settings(settings, None)
            .expect_err("hysteria settings.version other than 2 should fail");
        assert!(
            err.to_string()
                .contains("hysteria settings.version must be 2")
        );
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_udp_idle_timeout_matches_xray_bounds_and_default() {
        let settings = || {
            SettingObject(serde_json::json!({
                "clients": [{"auth": "xray-auth-token"}]
            }))
        };

        let default_stream = serde_json::from_value::<HysteriaSettings>(
            serde_json::json!({"version": 2}),
        )
        .unwrap();
        let config =
            collect_hysteria2_settings(settings(), Some(&default_stream)).unwrap();
        assert_eq!(config.udp_idle_timeout, 60);

        for value in [2, 600] {
            let stream =
                serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                    "version": 2,
                    "udpIdleTimeout": value
                }))
                .unwrap();
            let config =
                collect_hysteria2_settings(settings(), Some(&stream)).unwrap();
            assert_eq!(config.udp_idle_timeout, value);
        }

        for value in [1, 601] {
            let stream =
                serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                    "version": 2,
                    "udpIdleTimeout": value
                }))
                .unwrap();
            let error = collect_hysteria2_settings(settings(), Some(&stream))
                .expect_err("out-of-range udpIdleTimeout must fail");
            assert!(error.to_string().contains("between 2 and 600"));
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_string_masquerade_matches_xray() {
        let settings = || {
            SettingObject(serde_json::json!({
                "clients": [{"auth": "xray-auth-token"}]
            }))
        };
        let stream = serde_json::from_value::<HysteriaSettings>(serde_json::json!({
            "version": 2,
            "masquerade": {
                "type": "STRING",
                "content": "hello from hysteria",
                "headers": {"x-hysteria-test": "yes"},
                "statusCode": 201
            }
        }))
        .expect("Xray string masquerade should deserialize");
        let config = collect_hysteria2_settings(settings(), Some(&stream))
            .expect("Xray string masquerade should build");
        assert_eq!(config.masquerade.mode, "string");
        assert_eq!(config.masquerade.status_code, 201);
        assert_eq!(config.masquerade.content, "hello from hysteria");
        assert_eq!(config.masquerade.headers["x-hysteria-test"], "yes");

        for masquerade in [
            serde_json::json!({"type": "file", "dir": "/tmp"}),
            serde_json::json!({"type": "proxy", "url": "https://example.com"}),
            serde_json::json!({"type": "unknown"}),
            serde_json::json!({"type": "string", "statusCode": 99}),
        ] {
            let stream =
                serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                    "version": 2,
                    "masquerade": masquerade
                }))
                .expect("Xray masquerade shape should deserialize");
            assert!(collect_hysteria2_settings(settings(), Some(&stream)).is_err());
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_rejects_conflicting_versions() {
        let settings = SettingObject(serde_json::json!({
            "version": 2,
            "clients": [{
                "auth": "xray-auth-token"
            }]
        }));
        let stream_settings = HysteriaSettings {
            version: Some(3),
            auth: String::new(),
            congestion: None,
            up: None,
            down: None,
            ignore_client_bandwidth: None,
            udp_idle_timeout: None,
            masquerade: Default::default(),
        };

        let err = collect_hysteria2_settings(settings, Some(&stream_settings))
            .expect_err("conflicting versions should fail");
        assert!(
            err.to_string()
                .contains("hysteriaSettings.version must be 2")
        );
    }
}
