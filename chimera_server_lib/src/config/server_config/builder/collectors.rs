use serde::Deserialize;

use crate::{
    Error,
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
    Hysteria2BandwidthConfig, Hysteria2Client, Hysteria2ServerConfig,
};
use super::super::types::{
    RangeConfig, SocksUser, SocksUserStore, XhttpServerConfig,
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
        clients: Vec<Hysteria2ClientSetting>,
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

    Ok(Hysteria2ServerConfig {
        clients,
        bandwidth,
        ignore_client_bandwidth,
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
                email: client.email.and_then(|value| {
                    if value.is_empty() { None } else { Some(value) }
                }),
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
    dest: String,
    #[serde(default)]
    alpn: Option<serde_json::Value>,
    #[serde(default)]
    path: Option<serde_json::Value>,
    #[serde(default)]
    r#type: Option<serde_json::Value>,
    #[serde(default)]
    xver: Option<serde_json::Value>,
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
        reject_unsupported_trojan_fallback_fields(&fallback)?;
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

#[cfg(feature = "trojan")]
fn reject_unsupported_trojan_fallback_fields(
    fallback: &TrojanInboundFallback,
) -> Result<(), Error> {
    let unsupported_fields = [
        ("alpn", fallback.alpn.as_ref()),
        ("path", fallback.path.as_ref()),
        ("type", fallback.r#type.as_ref()),
        ("xver", fallback.xver.as_ref()),
    ];

    if let Some((field, _)) = unsupported_fields
        .into_iter()
        .find(|(_, value)| value.is_some())
    {
        return Err(Error::InvalidConfig(format!(
            "trojan fallback field {field} is not supported yet"
        )));
    }

    Ok(())
}

pub(super) fn collect_socks_settings(
    settings: SettingObject,
) -> Result<(SocksUserStore, bool), Error> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SocksInboundSettings {
        #[serde(default)]
        auth: Option<String>,
        #[serde(default)]
        accounts: Vec<SocksAccountSetting>,
        #[serde(default)]
        udp: Option<bool>,
        #[serde(default)]
        ip: Option<serde_json::Value>,
        #[serde(default)]
        user_level: Option<serde_json::Value>,
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

    // SOCKS UDP is implemented through UDP ASSOCIATE on the TCP control stream.
    let udp_enabled = socks_settings.udp.unwrap_or(false);
    if socks_settings.ip.is_some() {
        return Err(Error::InvalidConfig(
            "socks settings.ip is not supported yet".into(),
        ));
    }
    if socks_settings.user_level.is_some() {
        return Err(Error::InvalidConfig(
            "socks settings.userLevel is not supported yet".into(),
        ));
    }

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
        "noauth" | "none" => Ok((
            SocksUserStore::with_auth_required(Vec::new(), false),
            udp_enabled,
        )),
        "password" => {
            if socks_settings.accounts.is_empty() {
                return Err(Error::InvalidConfig(
                    "socks inbound with password auth requires accounts".into(),
                ));
            }
            Ok((
                SocksUserStore::with_auth_required(
                    socks_settings
                        .accounts
                        .into_iter()
                        .map(|account| SocksUser {
                            username: account.user,
                            password: account.pass,
                        })
                        .collect(),
                    true,
                ),
                udp_enabled,
            ))
        }
        other => Err(Error::InvalidConfig(format!(
            "unsupported socks auth mode: {}",
            other
        ))),
    }
}

pub(super) fn collect_xhttp_settings(
    raw: XhttpSettings,
) -> Result<XhttpServerConfig, Error> {
    reject_unsupported_xhttp_fields(&raw)?;
    validate_xhttp_mode(raw.mode.as_deref())?;
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
    if !raw.headers.is_empty() {
        return Err(Error::InvalidConfig(
            "xhttpSettings.headers is not supported yet".into(),
        ));
    }

    let normalized_path = normalize_path(raw.path);
    let (min_padding, max_padding) = clamp_xhttp_range(
        raw.x_padding_bytes.unwrap_or(XhttpRange {
            from: 100,
            to: 1000,
        }),
        100,
        1000,
    );
    let (_, max_each_post_bytes) = clamp_xhttp_range(
        raw.sc_max_each_post_bytes.unwrap_or(XhttpRange {
            from: 1_000_000,
            to: 1_000_000,
        }),
        1_000_000,
        1_000_000,
    );
    let (_, session_ttl_secs) = clamp_xhttp_range(
        raw.sc_stream_up_server_secs
            .unwrap_or(XhttpRange { from: 30, to: 30 }),
        30,
        30,
    );

    Ok(XhttpServerConfig {
        host: raw.host.map(|h| h.to_ascii_lowercase()),
        path: normalized_path,
        min_padding,
        max_padding,
        max_each_post_bytes,
        max_buffered_posts: raw.sc_max_buffered_posts.unwrap_or(30).max(1) as usize,
        session_ttl_secs: session_ttl_secs as u64,
    })
}

fn reject_unsupported_xhttp_fields(raw: &XhttpSettings) -> Result<(), Error> {
    let unsupported_fields = [
        ("extra", raw.extra.as_ref()),
        ("downloadSettings", raw.download_settings.as_ref()),
        ("xmux", raw.xmux.as_ref()),
        ("noGRPCHeader", raw.no_grpc_header.as_ref()),
        ("noSSEHeader", raw.no_sse_header.as_ref()),
        ("serverMaxHeaderBytes", raw.server_max_header_bytes.as_ref()),
        ("uplinkHTTPMethod", raw.uplink_http_method.as_ref()),
        ("sessionPlacement", raw.session_placement.as_ref()),
        ("sessionKey", raw.session_key.as_ref()),
        ("seqPlacement", raw.seq_placement.as_ref()),
        ("seqKey", raw.seq_key.as_ref()),
        ("uplinkDataPlacement", raw.uplink_data_placement.as_ref()),
        ("uplinkDataKey", raw.uplink_data_key.as_ref()),
        ("uplinkChunkSize", raw.uplink_chunk_size.as_ref()),
        (
            "scMinPostsIntervalMs",
            raw.sc_min_posts_interval_ms.as_ref(),
        ),
        ("xPaddingKey", raw.x_padding_key.as_ref()),
        ("xPaddingHeader", raw.x_padding_header.as_ref()),
        ("xPaddingPlacement", raw.x_padding_placement.as_ref()),
        ("xPaddingMethod", raw.x_padding_method.as_ref()),
        ("xPaddingObfsMode", raw.x_padding_obfs_mode.as_ref()),
    ];

    if let Some((field, _)) = unsupported_fields
        .into_iter()
        .find(|(_, value)| value.is_some())
    {
        return Err(Error::InvalidConfig(format!(
            "xhttpSettings.{field} is not supported yet"
        )));
    }

    Ok(())
}

fn validate_xhttp_mode(mode: Option<&str>) -> Result<(), Error> {
    match mode.unwrap_or("auto").trim() {
        "" | "auto" | "packet-up" | "stream-up" | "stream-one" => Ok(()),
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

        let (users, udp_enabled) =
            collect_socks_settings(settings).expect("socks udp should be accepted");
        assert!(!users.auth_required());
        assert!(udp_enabled);
    }

    #[test]
    fn collect_socks_accounts_rejects_ip_until_supported() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "ip": "127.0.0.1"
        }));

        let err =
            collect_socks_settings(settings).expect_err("socks ip unsupported");
        assert!(
            err.to_string()
                .contains("socks settings.ip is not supported yet")
        );
    }

    #[test]
    fn collect_socks_accounts_accepts_explicit_udp_false() {
        let settings = SettingObject(serde_json::json!({
            "auth": "noauth",
            "udp": false
        }));

        let (users, udp_enabled) =
            collect_socks_settings(settings).expect("udp false is a no-op");
        assert!(!users.auth_required());
        assert!(!udp_enabled);
    }

    #[cfg(feature = "trojan")]
    #[test]
    fn collect_trojan_fallbacks_rejects_unsupported_xray_fields() {
        let settings = SettingObject(serde_json::json!({
            "fallbacks": [{
                "dest": "127.0.0.1:8080",
                "path": "/ws"
            }]
        }));

        let err = collect_trojan_fallbacks(&settings)
            .expect_err("trojan fallback path unsupported");
        assert!(
            err.to_string()
                .contains("trojan fallback field path is not supported yet")
        );
    }

    #[test]
    fn collect_xhttp_settings_applies_reference_defaults() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp/"
        }))
        .expect("xhttp settings");

        let config = collect_xhttp_settings(settings).expect("valid xhttp settings");
        assert_eq!(config.path, "/xhttp");
        assert_eq!(config.max_each_post_bytes, 1_000_000);
        assert_eq!(config.max_buffered_posts, 30);
        assert_eq!(config.session_ttl_secs, 30);
    }

    #[test]
    fn collect_xhttp_settings_accepts_reference_modes() {
        for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
            let settings =
                serde_json::from_value::<XhttpSettings>(serde_json::json!({
                    "path": "/xhttp",
                    "mode": mode
                }))
                .expect("xhttp settings");

            collect_xhttp_settings(settings).unwrap_or_else(|err| {
                panic!("mode {mode} should be accepted: {err}")
            });
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
    fn collect_xhttp_settings_rejects_unsupported_headers() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "headers": {
                "X-Test": "ok"
            }
        }))
        .expect("xhttp settings");

        let err = collect_xhttp_settings(settings).expect_err("headers unsupported");
        assert!(
            err.to_string()
                .contains("xhttpSettings.headers is not supported yet")
        );
    }

    #[test]
    fn collect_xhttp_settings_rejects_known_unsupported_fields() {
        let settings = serde_json::from_value::<XhttpSettings>(serde_json::json!({
            "path": "/xhttp",
            "downloadSettings": {
                "network": "xhttp"
            }
        }))
        .expect("xhttp settings");

        let err = collect_xhttp_settings(settings).expect_err("unsupported field");
        assert!(
            err.to_string()
                .contains("xhttpSettings.downloadSettings is not supported yet")
        );
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn collect_hysteria2_settings_accepts_xray_client_auth() {
        let settings = SettingObject(serde_json::json!({
            "clients": [{
                "auth": "xray-auth-token",
                "email": "hy@example.com"
            }]
        }));

        let config = collect_hysteria2_settings(settings, None)
            .expect("hysteria auth should map to password");
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.clients[0].password, "xray-auth-token");
        assert_eq!(config.clients[0].email.as_deref(), Some("hy@example.com"));
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
            congestion: None,
            up: None,
            down: None,
            ignore_client_bandwidth: None,
        };

        let err = collect_hysteria2_settings(settings, Some(&stream_settings))
            .expect_err("conflicting versions should fail");
        assert!(
            err.to_string()
                .contains("hysteriaSettings.version must be 2")
        );
    }
}
