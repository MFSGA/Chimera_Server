use serde::Deserialize;

use crate::{
    Error,
    address::Address,
    config::{SettingObject, XhttpRange, XhttpSettings},
};

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
use super::super::types::{
    RangeConfig, SocksUser, SocksUserStore, XhttpDataPlacement, XhttpMode,
    XhttpPaddingMethod, XhttpPaddingPlacement, XhttpPlacement, XhttpServerConfig,
};

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
        xray_udp_idle_timeout_secs,
        xray_max_incoming_streams: None,
        xray_init_stream_receive_window: None,
        xray_max_stream_receive_window: None,
        xray_init_connection_receive_window: None,
        xray_max_connection_receive_window: None,
        xray_disable_path_mtu_discovery: None,
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
        "password" => {
            if accounts.is_empty() {
                return Err(Error::InvalidConfig(
                    "socks inbound with password auth requires accounts".into(),
                ));
            }
            Ok((
                SocksUserStore::with_auth_required(accounts, true),
                udp_enabled,
                udp_response_ip,
                user_level,
            ))
        }
        _ => Ok((
            SocksUserStore::with_auth_required(accounts, false),
            udp_enabled,
            udp_response_ip,
            user_level,
        )),
    }
}

pub(super) fn collect_xhttp_settings(
    raw: XhttpSettings,
) -> Result<XhttpServerConfig, Error> {
    let raw = apply_xhttp_extra(raw)?;
    let mode = parse_xhttp_mode(raw.mode.as_deref())?;
    validate_xhttp_client_fields(&raw, mode)?;
    let uplink_http_method =
        normalize_xhttp_uplink_method(raw.uplink_http_method.as_deref(), mode)?;
    let min_posts_interval_ms =
        normalize_xhttp_min_posts_interval_ms(raw.sc_min_posts_interval_ms.clone());
    let session_placement =
        parse_xhttp_placement(raw.session_placement.as_deref(), "sessionPlacement")?;
    let seq_placement =
        parse_xhttp_placement(raw.seq_placement.as_deref(), "seqPlacement")?;
    let session_key = normalize_xhttp_meta_key(
        raw.session_key.as_deref(),
        session_placement,
        "X-Session",
        "x_session",
    );
    let seq_key = normalize_xhttp_meta_key(
        raw.seq_key.as_deref(),
        seq_placement,
        "X-Seq",
        "x_seq",
    );
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
    if raw.x_padding_bytes.as_ref().is_some_and(|range| {
        (range.from != 0 || range.to != 0) && (range.from <= 0 || range.to <= 0)
    }) {
        return Err(Error::InvalidConfig(
            "xhttpSettings.xPaddingBytes cannot be disabled".into(),
        ));
    }
    // Current Xray only requires a trailing slash when session or sequence
    // metadata is encoded in the path. Preserve file-like paths otherwise.
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
    let max_each_post_bytes = match raw.sc_max_each_post_bytes {
        None => 1_000_000,
        Some(range) if range.to == 0 => 1_000_000,
        Some(range) => i64::from(range.to),
    };
    let stream_up_server_secs =
        normalize_xhttp_stream_up_server_secs(raw.sc_stream_up_server_secs);

    Ok(XhttpServerConfig {
        mode,
        host: raw.host.map(|h| h.to_ascii_lowercase()),
        path: normalized_path,
        trusted_x_forwarded_for: Vec::new(),
        min_padding,
        max_padding,
        max_each_post_bytes,
        max_buffered_posts: match raw.sc_max_buffered_posts.unwrap_or(0) {
            value if value < 0 => {
                return Err(Error::InvalidConfig(
                    "xhttpSettings.scMaxBufferedPosts cannot be negative".into(),
                ));
            }
            0 => 30,
            value => value as usize,
        },
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

    Ok(())
}

fn parse_xhttp_data_placement(
    placement: Option<&str>,
    mode: XhttpMode,
) -> Result<XhttpDataPlacement, Error> {
    let placement = match placement.unwrap_or("") {
        "" | "body" => XhttpDataPlacement::Body,
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
    let key = key.unwrap_or("");
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
    match placement.unwrap_or("queryInHeader") {
        "cookie" => Ok(XhttpPaddingPlacement::Cookie),
        "header" => Ok(XhttpPaddingPlacement::Header),
        "query" => Ok(XhttpPaddingPlacement::Query),
        "" | "queryInHeader" => Ok(XhttpPaddingPlacement::QueryInHeader),
        unsupported => Err(Error::InvalidConfig(format!(
            "unsupported xhttpSettings.xPaddingPlacement: {unsupported}"
        ))),
    }
}

fn parse_xhttp_padding_method(
    method: Option<&str>,
) -> Result<XhttpPaddingMethod, Error> {
    match method.unwrap_or("repeat-x") {
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
    match placement.unwrap_or("path") {
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
) -> String {
    let key = key.unwrap_or("");
    if !key.is_empty() {
        return key.to_string();
    }
    match placement {
        XhttpPlacement::Path => String::new(),
        XhttpPlacement::Header => default_header.to_string(),
        XhttpPlacement::Query | XhttpPlacement::Cookie => {
            default_query_cookie.to_string()
        }
    }
}

fn normalize_xhttp_uplink_method(
    method: Option<&str>,
    mode: XhttpMode,
) -> Result<String, Error> {
    let method = method.unwrap_or("");
    let method = if method.is_empty() {
        "POST".to_string()
    } else {
        // Xray v26.2.6 applies strings.ToUpper without trimming or validating
        // the value as an HTTP token. Preserve that exact config semantics;
        // odd values simply never match a real request method at runtime.
        method.to_ascii_uppercase()
    };
    if method == "GET" && mode != XhttpMode::PacketUp {
        return Err(Error::InvalidConfig(
            "xhttpSettings.uplinkHTTPMethod=GET requires mode=packet-up".into(),
        ));
    }
    Ok(method)
}

fn parse_xhttp_mode(mode: Option<&str>) -> Result<XhttpMode, Error> {
    match mode.unwrap_or("auto") {
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

fn normalize_xhttp_min_posts_interval_ms(
    range: Option<XhttpRange>,
) -> (usize, usize) {
    let range = range.unwrap_or(XhttpRange { from: 30, to: 30 });
    if range.to == 0 {
        return (30, 30);
    }
    if range.to < 0 {
        // Xray v26.2.6 preserves negative sentinels here. Its client-side
        // scheduler only sleeps when From > 0, so represent that disabled
        // state explicitly in the unsigned server config.
        return (0, 0);
    }
    (range.from.max(0) as usize, range.to as usize)
}

fn normalize_xhttp_stream_up_server_secs(
    range: Option<XhttpRange>,
) -> (usize, usize) {
    let range = range.unwrap_or(XhttpRange { from: 20, to: 80 });
    if range.to == 0 {
        return (20, 80);
    }
    if range.to < 0 {
        // Xray v26.2.6 preserves a negative range here and then gates the
        // stream-up padding writer on To > 0. Represent that disabled state
        // explicitly because the runtime duration type is unsigned.
        return (0, 0);
    }
    (range.from.max(0) as usize, range.to as usize)
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

        let (users, udp_enabled, udp_response_ip, _) =
            collect_socks_settings(settings).expect("socks udp should be accepted");
        assert!(!users.auth_required());
        assert!(udp_enabled);
        assert!(udp_response_ip.is_none());
    }

    #[test]
    fn collect_socks_unknown_auth_defaults_to_noauth() {
        let settings = SettingObject(serde_json::json!({
            "auth": "future-auth",
            "accounts": [{"user": "alice", "pass": "secret"}],
            "udp": true,
            "ip": "127.0.0.1"
        }));

        let (users, udp_enabled, udp_response_ip, _) =
            collect_socks_settings(settings)
                .expect("unknown socks auth should match Xray noauth fallback");
        assert!(!users.auth_required());
        assert_eq!(users.snapshot()[0].username, "alice");
        assert!(udp_enabled);
        assert_eq!(udp_response_ip.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn collect_socks_users_alias_and_accounts_override_match_xray() {
        let users_only = SettingObject(serde_json::json!({
            "auth": "password",
            "users": [{"user": "legacy", "pass": "secret"}]
        }));
        let (users, _, _, _) = collect_socks_settings(users_only)
            .expect("legacy socks users should be accepted");
        assert!(users.auth_required());
        assert_eq!(users.snapshot()[0].username, "legacy");

        let accounts_override = SettingObject(serde_json::json!({
            "users": [{"user": "legacy", "pass": "secret"}],
            "accounts": []
        }));
        let (users, _, _, _) = collect_socks_settings(accounts_override)
            .expect("explicit accounts should override legacy users");
        assert!(!users.auth_required());
        assert!(users.snapshot().is_empty());
    }

    #[test]
    fn collect_socks_settings_preserves_xray_user_level() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "userLevel": 7
        }));

        let (_, _, _, user_level) = collect_socks_settings(settings)
            .expect("Xray userLevel should be accepted");
        assert_eq!(user_level, 7);
    }

    #[test]
    fn collect_socks_settings_preserves_udp_response_ip() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "udp": true,
            "ip": "127.0.0.1"
        }));

        let (_, udp_enabled, udp_response_ip, _) =
            collect_socks_settings(settings).expect("socks ip should be accepted");
        assert!(udp_enabled);
        assert_eq!(udp_response_ip.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn collect_socks_settings_accepts_domain_udp_response_address() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "udp": true,
            "ip": "localhost"
        }));

        let (_, udp_enabled, udp_response_ip, _) = collect_socks_settings(settings)
            .expect("Xray accepts domain settings.ip");
        assert!(udp_enabled);
        assert_eq!(udp_response_ip.as_deref(), Some("localhost"));
    }

    #[test]
    fn collect_socks_accounts_accepts_explicit_udp_false() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "udp": false
        }));

        let (users, udp_enabled, udp_response_ip, _) =
            collect_socks_settings(settings).expect("udp false is a no-op");
        assert!(!users.auth_required());
        assert!(!udp_enabled);
        assert!(udp_response_ip.is_none());
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
        assert_eq!(config.uplink_data_placement, XhttpDataPlacement::Body);
        assert!(config.uplink_data_key.is_empty());
    }

    #[test]
    fn collect_xhttp_settings_preserves_negative_post_limit_like_xray_v26_2_6() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "scMaxEachPostBytes": -1
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.max_each_post_bytes, -1);
    }

    #[test]
    fn collect_xhttp_settings_disables_min_post_delay_for_negative_range_like_xray_v26_2_6()
     {
        for value in [serde_json::json!(-1), serde_json::json!("-5--1")] {
            let settings =
                serde_json::from_value::<XhttpSettings>(serde_json::json!({
                    "scMinPostsIntervalMs": value
                }))
                .expect("xhttp settings");

            let config =
                collect_xhttp_settings(settings).expect("valid xhttp settings");
            assert_eq!(config.min_posts_interval_ms, (0, 0));
        }

        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "scMinPostsIntervalMs": 0
        }))
        .expect("xhttp settings");
        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.min_posts_interval_ms, (30, 30));
    }

    #[test]
    fn collect_xhttp_settings_disables_stream_up_padding_for_negative_range_like_xray_v26_2_6()
     {
        for value in [serde_json::json!(-1), serde_json::json!("-5--1")] {
            let settings =
                serde_json::from_value::<XhttpSettings>(serde_json::json!({
                    "scStreamUpServerSecs": value
                }))
                .expect("xhttp settings");

            let config =
                collect_xhttp_settings(settings).expect("valid xhttp settings");
            assert_eq!(config.stream_up_server_secs, (0, 0));
        }
    }

    #[test]
    fn collect_xhttp_settings_normalizes_zero_buffered_posts_like_xray_v26_2_6() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "scMaxBufferedPosts": 0
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.max_buffered_posts, 30);
    }

    #[test]
    fn collect_xhttp_settings_rejects_negative_buffered_posts_like_xray_v26_2_6() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "scMaxBufferedPosts": -1
        }))
        .expect("xhttp settings");

        let error = collect_xhttp_settings(settings)
            .expect_err("negative scMaxBufferedPosts must be rejected");
        assert!(
            error
                .to_string()
                .contains("xhttpSettings.scMaxBufferedPosts cannot be negative"),
            "{error}"
        );
    }

    #[test]
    fn collect_xhttp_settings_treats_zero_padding_range_as_xray_default() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "xPaddingBytes": 0
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("Xray v26.2.6 accepts zero xPaddingBytes as the default range");
        assert_eq!((config.min_padding, config.max_padding), (100, 1000));
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
    fn collect_xhttp_settings_accepts_mixed_metadata_placements_like_current_xray() {
        for (session_placement, seq_placement) in [
            ("path", "query"),
            ("query", "path"),
            ("path", "header"),
            ("cookie", "path"),
        ] {
            let settings =
                serde_json::from_value::<XhttpSettings>(serde_json::json!({
                    "mode": "packet-up",
                    "sessionIDPlacement": session_placement,
                    "seqPlacement": seq_placement
                }))
                .expect("xhttp settings");

            let config = collect_xhttp_settings(settings).unwrap_or_else(|err| {
                panic!(
                    "current Xray accepts mixed metadata placements {session_placement}/{seq_placement}: {err}"
                )
            });
            assert_eq!(
                config.session_placement,
                parse_xhttp_placement(Some(session_placement), "sessionIDPlacement")
                    .unwrap()
            );
            assert_eq!(
                config.seq_placement,
                parse_xhttp_placement(Some(seq_placement), "seqPlacement").unwrap()
            );
        }
    }

    #[test]
    fn collect_xhttp_settings_accepts_xray_server_side_session_id_fields() {
        for settings_value in [
            serde_json::json!({
                "path": "/xhttp",
                "sessionIDTable": "number",
                "sessionIDLength": 1
            }),
            serde_json::json!({
                "path": "/xhttp",
                "sessionIDTable": "表格",
                "sessionIDLength": 0
            }),
        ] {
            let settings = serde_json::from_value::<XhttpSettings>(settings_value)
                .expect("xhttp settings should deserialize");
            collect_xhttp_settings(settings).expect(
                "Xray v26.2.6 accepts inbound session ID generator settings without client-side validation",
            );
        }
    }

    #[test]
    fn collect_xhttp_settings_matches_current_xray_path_normalization() {
        for (settings_value, expected_path) in [
            (
                serde_json::json!({
                    "path": "/stream",
                    "sessionIDPlacement": "query",
                    "seqPlacement": "query"
                }),
                "/stream",
            ),
            (
                serde_json::json!({
                    "path": "/stream/filename.extension",
                    "sessionIDPlacement": "query",
                    "seqPlacement": "header"
                }),
                "/stream/filename.extension",
            ),
            (
                serde_json::json!({
                    "path": "/stream",
                    "sessionIDPlacement": "query",
                    "seqPlacement": "path"
                }),
                "/stream/",
            ),
            (
                serde_json::json!({
                    "path": "/stream"
                }),
                "/stream/",
            ),
        ] {
            let settings = serde_json::from_value::<XhttpSettings>(settings_value)
                .expect("xhttp settings");
            let config = collect_xhttp_settings(settings)
                .expect("current Xray path placement should be accepted");
            assert_eq!(config.path, expected_path);
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
    fn collect_xhttp_settings_preserves_xray_uplink_method_text_semantics() {
        for (raw_method, expected) in
            [("FOO BAR", "FOO BAR"), (":", ":"), (" get ", " GET ")]
        {
            let settings =
                serde_json::from_value::<XhttpSettings>(serde_json::json!({
                    "path": "/xhttp",
                    "mode": "stream-one",
                    "uplinkHTTPMethod": raw_method
                }))
                .expect("xhttp settings");

            let config = collect_xhttp_settings(settings)
                .expect("Xray v26.2.6 accepts arbitrary uplink method text");
            assert_eq!(config.uplink_http_method, expected);
        }

        let exact_get = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "stream-one",
            "uplinkHTTPMethod": "get"
        }))
        .expect("xhttp settings");
        assert!(collect_xhttp_settings(exact_get).is_err());
    }

    #[test]
    fn collect_xhttp_settings_rejects_explicit_auto_data_placement_like_xray_v26_2_6()
     {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "packet-up",
            "uplinkDataPlacement": "auto"
        }))
        .expect("xhttp settings");

        let error = collect_xhttp_settings(settings)
            .expect_err("Xray v26.2.6 rejects explicit auto uplink data placement");
        assert!(
            error
                .to_string()
                .contains("unsupported xhttpSettings.uplinkDataPlacement: auto"),
            "unexpected error: {error}"
        );
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
    fn collect_xhttp_settings_preserves_path_without_path_metadata() {
        let settings: XhttpSettings = serde_json::from_value(serde_json::json!({
            "path": "/x",
            "mode": "packet-up",
            "sessionIDPlacement": "query",
            "seqPlacement": "query"
        }))
        .expect("valid xhttp settings");

        let config =
            collect_xhttp_settings(settings).expect("xhttp settings should parse");
        assert_eq!(config.path, "/x");
    }

    #[test]
    fn collect_xhttp_settings_preserves_key_text_like_xray_v26_2_6() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "mode": "packet-up",
            "sessionPlacement": "query",
            "sessionKey": " x_session ",
            "seqPlacement": "query",
            "seqKey": " x_seq ",
            "uplinkDataPlacement": "header",
            "uplinkDataKey": " X-Data "
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings)
            .expect("Xray v26.2.6 preserves non-empty key text verbatim");
        assert_eq!(config.session_key, " x_session ");
        assert_eq!(config.seq_key, " x_seq ");
        assert_eq!(config.uplink_data_key, " X-Data ");
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
    fn collect_xhttp_settings_rejects_noncanonical_selector_text_like_xray_v26_2_6()
    {
        let cases = [
            ("mode", "Packet-Up"),
            ("mode", " packet-up "),
            ("sessionPlacement", "Query"),
            ("sessionPlacement", " query "),
            ("seqPlacement", "Header"),
            ("seqPlacement", " header "),
            ("uplinkDataPlacement", "Header"),
            ("uplinkDataPlacement", " header "),
            ("xPaddingPlacement", "Header"),
            ("xPaddingPlacement", " header "),
            ("xPaddingMethod", "Tokenish"),
            ("xPaddingMethod", " tokenish "),
        ];

        for (field, value) in cases {
            let mut object = serde_json::json!({
                "path": "/xhttp",
                "mode": "packet-up",
                "sessionPlacement": "query"
            });
            object.as_object_mut().expect("xhttp object").insert(
                field.to_string(),
                serde_json::Value::String(value.to_string()),
            );
            let settings = serde_json::from_value::<XhttpSettings>(object)
                .expect("xhttp settings should deserialize before validation");

            let error = collect_xhttp_settings(settings).expect_err(
                "Xray v26.2.6 treats selector values as exact case-sensitive text",
            );
            assert!(
                error.to_string().contains("unsupported xhttpSettings"),
                "{field}={value:?} returned unexpected error: {error}"
            );
        }
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
            "uplinkChunkSize": 2048,
            "sessionIDTable": "Base62",
            "sessionIDLength": {"from": 6, "to": 8}
        }))
        .expect("xhttp settings");

        collect_xhttp_settings(settings).expect(
            "server should accept valid XHTTP fields consumed by the client",
        );
    }

    #[test]
    fn xhttp_uplink_chunk_size_matches_xray_uint32_schema() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "mode": "packet-up",
            "uplinkChunkSize": 63
        }))
        .expect("Xray accepts uint32 uplinkChunkSize values");
        collect_xhttp_settings(settings)
            .expect("uint32 uplinkChunkSize should be accepted");

        let range = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "mode": "packet-up",
            "uplinkChunkSize": {"from": 1024, "to": 2048}
        }));
        assert!(
            range.is_err(),
            "Xray rejects range objects for uplinkChunkSize"
        );

        let negative = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "mode": "packet-up",
            "uplinkChunkSize": -1
        }));
        assert!(
            negative.is_err(),
            "Xray rejects negative uplinkChunkSize values"
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
        assert_eq!(config.clients[0].level, 7);
        assert!(config.clients[0].xray_uuid_route);
        assert_eq!(config.xray_udp_idle_timeout_secs, Some(60));
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_empty_auth_only_for_xray_users() {
        let xray_settings = SettingObject(serde_json::json!({
            "version": 2,
            "clients": [{"auth": "", "email": "empty@example.com"}]
        }));
        let xray_stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2
            }))
            .expect("valid Xray hysteriaSettings");
        let config =
            collect_hysteria2_settings(xray_settings, Some(&xray_stream_settings))
                .expect("Xray validator accepts an empty auth key");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "");
        assert!(config.clients[0].xray_uuid_route);

        let shoes_settings = SettingObject(serde_json::json!({
            "clients": [{"auth": "", "email": "empty@example.com"}]
        }));
        let err = collect_hysteria2_settings(shoes_settings, None)
            .expect_err("non-Xray empty auth must stay invalid");
        assert!(err.to_string().contains("non-empty auth or id"), "{err}");
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_xray_transport_auth_fallback() {
        let settings = SettingObject(serde_json::json!({
            "version": 2
        }));
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "auth": "transport-auth-token",
                "up": "1 kbps",
                "down": "2 kbps"
            }))
            .expect("valid hysteriaSettings auth");

        let config = collect_hysteria2_settings(settings, Some(&stream_settings))
            .expect("Xray transport auth fallback should be accepted");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "transport-auth-token");
        assert_eq!(config.clients[0].email, None);
        assert!(!config.clients[0].xray_uuid_route);
        assert!(config.clients[0].xray_transport_auth_fallback);
        assert!(config.xray_compat);
        assert_eq!(config.bandwidth.max_tx, 0);
        assert_eq!(config.bandwidth.max_rx, 0);
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_supported_xray_masquerade() {
        let settings = || {
            SettingObject(serde_json::json!({
                "version": 2,
                "clients": [{"auth": "xray-auth-token"}]
            }))
        };

        for kind in ["", "404"] {
            let stream_settings =
                serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                    "version": 2,
                    "masquerade": {"type": kind}
                }))
                .expect("valid Xray masquerade shape");
            let config =
                collect_hysteria2_settings(settings(), Some(&stream_settings))
                    .expect("Xray default 404 masquerade should be accepted");
            assert!(config.xray_masquerade_string.is_none());
            assert!(config.xray_masquerade_file.is_none());
        }

        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "masquerade": {
                    "type": "FILE",
                    "dir": "/srv/hysteria-site"
                }
            }))
            .expect("valid Xray file masquerade shape");
        let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect("Xray file masquerade should be accepted case-insensitively");
        assert_eq!(
            config
                .xray_masquerade_file
                .expect("file masquerade should reach runtime config")
                .dir,
            "/srv/hysteria-site"
        );

        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "masquerade": {
                    "type": "string",
                    "content": "hello",
                    "headers": {"X-Test": "yes"},
                    "statusCode": 201
                }
            }))
            .expect("valid Xray string masquerade shape");
        let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect("Xray string masquerade should be accepted");
        let masquerade = config
            .xray_masquerade_string
            .expect("string masquerade should reach runtime config");
        assert_eq!(masquerade.content, "hello");
        assert_eq!(
            masquerade.headers.get("X-Test").map(String::as_str),
            Some("yes")
        );
        assert_eq!(masquerade.status_code, 201);

        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "masquerade": {
                    "type": "PrOxY",
                    "url": "https://example.test/base",
                    "rewriteHost": true,
                    "insecure": true
                }
            }))
            .expect("valid Xray proxy masquerade shape");
        let config = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect("Xray proxy masquerade should be accepted case-insensitively");
        let masquerade = config
            .xray_masquerade_proxy
            .expect("proxy masquerade should reach runtime config");
        assert_eq!(masquerade.url, "https://example.test/base");
        assert!(masquerade.rewrite_host);
        assert!(masquerade.insecure);

        let kind = "unknown";
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "masquerade": {"type": kind}
            }))
            .expect("valid Xray masquerade shape");
        let err = collect_hysteria2_settings(settings(), Some(&stream_settings))
            .expect_err("unsupported Xray masquerade must fail explicitly");
        assert!(
            err.to_string()
                .contains("supports Xray 404, file, proxy, and string masquerades"),
            "unexpected masquerade error for {kind}: {err}"
        );
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_keeps_shoes_id_exact() {
        let settings = SettingObject(serde_json::json!({
            "clients": [{"id": "00112233-4455-6677-8899-aabbccddeeff"}]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("shoes-style Hysteria id should be accepted");
        assert_eq!(
            config.clients[0].password,
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        assert!(!config.clients[0].xray_uuid_route);
        assert!(!config.clients[0].xray_transport_auth_fallback);
        assert!(!config.xray_compat);
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_matches_shoes_udp_switch_and_xray_udp_default() {
        let shoes = SettingObject(serde_json::json!({
            "clients": [{"id": "secret"}],
            "udp_enabled": false
        }));
        let shoes_config = collect_hysteria2_settings(shoes, None)
            .expect("shoes-style Hysteria UDP switch should parse");
        assert!(!shoes_config.xray_compat);
        assert!(!shoes_config.udp_enabled);

        let xray = SettingObject(serde_json::json!({
            "version": 2,
            "clients": [{"auth": "secret"}],
            "udpEnabled": false
        }));
        let xray_transport = serde_json::from_value::<HysteriaSettings>(
            serde_json::json!({"version": 2}),
        )
        .expect("valid Xray Hysteria transport");
        let xray_config = collect_hysteria2_settings(xray, Some(&xray_transport))
            .expect("Xray Hysteria config should parse");
        assert!(xray_config.xray_compat);
        assert!(xray_config.udp_enabled);
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_users_override_transport_auth_fallback() {
        let settings = SettingObject(serde_json::json!({
            "clients": [{"auth": "user-auth-token"}]
        }));
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "auth": "transport-auth-token"
            }))
            .expect("valid hysteriaSettings auth");

        let config = collect_hysteria2_settings(settings, Some(&stream_settings))
            .expect("configured users should take precedence over transport auth");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "user-auth-token");
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_keeps_xray_transport_auth_latent_with_users() {
        let settings = SettingObject(serde_json::json!({
            "version": 2,
            "clients": [{
                "auth": "user-auth-token",
                "email": "user@example.com"
            }]
        }));
        let stream_settings =
            serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                "version": 2,
                "auth": "transport-auth-token"
            }))
            .expect("valid Xray hysteriaSettings auth");

        let config = collect_hysteria2_settings(settings, Some(&stream_settings))
            .expect("valid Xray users plus transport auth should parse");
        assert!(config.xray_compat);
        assert_eq!(config.clients.len(), 2);
        assert_eq!(config.clients[0].password, "user-auth-token");
        assert!(!config.clients[0].xray_transport_auth_fallback);
        assert_eq!(config.clients[1].password, "transport-auth-token");
        assert!(config.clients[1].xray_transport_auth_fallback);
        assert_eq!(
            config
                .clients
                .iter()
                .filter(|client| client.email.is_some())
                .count(),
            1,
            "transport fallback must stay hidden from Xray user-manager listings"
        );
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_preserves_xray_auth_whitespace() {
        let settings = SettingObject(serde_json::json!({
            "clients": [{"auth": " spaced-secret "}]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("Xray Hysteria auth should be preserved exactly");
        assert_eq!(config.clients[0].password, " spaced-secret ");
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_xray_users_alias() {
        let settings = SettingObject(serde_json::json!({
            "users": [{
                "auth": "legacy-xray-auth",
                "email": "legacy@example.com"
            }]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("Xray users alias should be accepted");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "legacy-xray-auth");
        assert_eq!(
            config.clients[0].email.as_deref(),
            Some("legacy@example.com")
        );
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_clients_override_xray_users() {
        let settings = SettingObject(serde_json::json!({
            "users": [{"auth": "legacy-xray-auth"}],
            "clients": [{"auth": "current-xray-auth"}]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("Xray clients should replace users when present");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "current-xray-auth");
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
            udp_idle_timeout: 0,
            masquerade: None,
        };

        let err = collect_hysteria2_settings(settings, Some(&stream_settings))
            .expect_err("conflicting versions should fail");
        assert!(
            err.to_string()
                .contains("hysteriaSettings.version must be 2")
        );
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_matches_xray_udp_idle_timeout() {
        let settings = || {
            SettingObject(serde_json::json!({
                "clients": [{"auth": "xray-auth-token"}]
            }))
        };

        for (configured, expected) in [(0, 60), (2, 2), (600, 600)] {
            let stream_settings =
                serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                    "version": 2,
                    "udpIdleTimeout": configured
                }))
                .expect("valid hysteriaSettings");
            let config =
                collect_hysteria2_settings(settings(), Some(&stream_settings))
                    .expect("Xray UDP idle timeout should be accepted");
            assert_eq!(config.xray_udp_idle_timeout_secs, Some(expected));
        }

        for configured in [1, 601] {
            let stream_settings =
                serde_json::from_value::<HysteriaSettings>(serde_json::json!({
                    "version": 2,
                    "udpIdleTimeout": configured
                }))
                .expect("hysteriaSettings should deserialize");
            let error =
                collect_hysteria2_settings(settings(), Some(&stream_settings))
                    .expect_err("Xray rejects out-of-range UDP idle timeout");
            assert!(error.to_string().contains("udpIdleTimeout"), "{error}");
        }
    }
}
