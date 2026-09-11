use crate::{
    Error,
    config::server_config::types::{
        ServerProxyConfig, TcpBrutalConfig, TcpSocketPolicy,
    },
    util::bandwidth::parse_bandwidth,
};

#[cfg(feature = "grpc_transport")]
use crate::config::server_config::types::GrpcServerConfig;
#[cfg(feature = "httpupgrade")]
use crate::config::server_config::types::HttpUpgradeServerConfig;
#[cfg(feature = "ws")]
use crate::{
    config::server_config::ws::WebsocketServerConfig, util::option::OneOrSome,
};

use super::tls::apply_security_layers;

#[cfg(feature = "ws")]
pub(super) fn normalize_xray_websocket_path(path: Option<String>) -> String {
    let path = path.map(strip_xray_websocket_early_data_query);
    match path {
        Some(path) if path.starts_with('/') => path,
        Some(path) if !path.is_empty() => format!("/{path}"),
        _ => "/".to_string(),
    }
}

pub(super) fn strip_xray_websocket_early_data_query(path: String) -> String {
    let Some(query_start) = path.find('?') else {
        return path;
    };
    let query_end = path[query_start + 1..]
        .find('#')
        .map(|offset| query_start + 1 + offset)
        .unwrap_or(path.len());
    let query = &path[query_start + 1..query_end];

    let has_early_data = query.split('&').any(|pair| {
        parse_xray_websocket_query_pair(pair)
            .is_some_and(|(key, value)| key == "ed" && !value.is_empty())
    });
    if !has_early_data {
        return path;
    }

    let remaining = query
        .split('&')
        .filter(|pair| {
            parse_xray_websocket_query_pair(pair).is_some_and(|(key, _)| key != "ed")
        })
        .collect::<Vec<_>>()
        .join("&");
    let suffix = &path[query_end..];
    if remaining.is_empty() {
        format!("{}{}", &path[..query_start], suffix)
    } else {
        format!("{}?{}{}", &path[..query_start], remaining, suffix)
    }
}

pub(super) fn parse_xray_websocket_query_pair(
    pair: &str,
) -> Option<(String, String)> {
    if pair.contains(';') {
        return None;
    }
    let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
    Some((
        decode_xray_websocket_query_component(key)?,
        decode_xray_websocket_query_component(value)?,
    ))
}

pub(super) fn decode_xray_websocket_query_component(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'+' => {
                decoded.push(b' ');
                offset += 1;
            }
            b'%' if offset + 2 < bytes.len() => {
                let high = (bytes[offset + 1] as char).to_digit(16)? as u8;
                let low = (bytes[offset + 2] as char).to_digit(16)? as u8;
                decoded.push((high << 4) | low);
                offset += 3;
            }
            b'%' => return None,
            byte => {
                decoded.push(byte);
                offset += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

pub(super) fn xray_trusted_x_forwarded_for(
    stream_settings: &crate::config::StreamSettings,
) -> Vec<String> {
    stream_settings
        .sockopt
        .as_ref()
        .map(|settings| settings.trusted_x_forwarded_for.clone())
        .unwrap_or_default()
}

#[cfg(feature = "ws")]
pub(super) fn websocket_server_config(
    ws_setting: crate::config::WsSettings,
    stream_settings: &crate::config::StreamSettings,
    protocol: ServerProxyConfig,
) -> WebsocketServerConfig {
    let accept_proxy_protocol = ws_setting.accept_proxy_protocol
        || stream_settings
            .sockopt
            .as_ref()
            .is_some_and(|settings| settings.accept_proxy_protocol);
    let trusted_x_forwarded_for = xray_trusted_x_forwarded_for(stream_settings);
    let mut host = ws_setting.host.filter(|value| !value.is_empty());

    if host.is_none() {
        for (key, value) in ws_setting.headers {
            if key.eq_ignore_ascii_case("host") {
                if !value.is_empty() {
                    host = Some(value);
                }
                break;
            }
        }
    }

    let matching_headers = host
        .map(|host| std::collections::HashMap::from([("host".to_string(), host)]));

    WebsocketServerConfig {
        matching_path: Some(normalize_xray_websocket_path(ws_setting.path)),
        matching_headers,
        xray_mismatch_404: true,
        trusted_x_forwarded_for,
        accept_proxy_protocol,
        heartbeat_period: ws_setting.heartbeat_period,
        protocol,
    }
}

#[cfg(feature = "grpc_transport")]
pub(super) fn apply_grpc_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    if !stream_settings.network.eq_ignore_ascii_case("grpc") {
        return Ok(protocol);
    }
    let settings = stream_settings.grpc_settings.clone().unwrap_or_default();
    let service_name = settings.service_name.unwrap_or_default();
    let _ = (
        settings.authority,
        settings.permit_without_stream,
        settings.initial_windows_size,
    );
    Ok(ServerProxyConfig::Grpc(GrpcServerConfig {
        service_name,
        multi_mode: settings.multi_mode,
        idle_timeout: settings.idle_timeout,
        health_check_timeout: settings.health_check_timeout,
        trusted_x_forwarded_for: xray_trusted_x_forwarded_for(stream_settings),
        inner: Box::new(protocol),
    }))
}

#[cfg(not(feature = "grpc_transport"))]
pub(super) fn apply_grpc_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    if stream_settings.network.eq_ignore_ascii_case("grpc") {
        return Err(Error::InvalidConfig(
            "grpc transport requires the grpc_transport feature".into(),
        ));
    }
    Ok(protocol)
}

#[cfg(feature = "httpupgrade")]
pub(super) fn apply_httpupgrade_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    if !stream_settings.network.eq_ignore_ascii_case("httpupgrade") {
        return Ok(protocol);
    }
    let settings = stream_settings
        .httpupgrade_settings
        .clone()
        .unwrap_or_default();
    // Xray's HTTPUpgrade server does not consume `ed`; the field only changes
    // whether the client waits for the 101 response before sending protocol data.
    // Accept it on inbound configs so early protocol bytes can already be queued
    // behind the HTTP headers and consumed by the inner handler after upgrade.
    let _ = settings.ed;
    let path = settings.path.unwrap_or_default();
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };
    let host = settings
        .host
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    // Xray's server uses host/path for validation. Custom headers are a
    // client-side request construction option and do not alter inbound matching.
    let _ = settings.header;
    Ok(ServerProxyConfig::HttpUpgrade(HttpUpgradeServerConfig {
        host,
        path,
        accept_proxy_protocol: settings.accept_proxy_protocol,
        trusted_x_forwarded_for: xray_trusted_x_forwarded_for(stream_settings),
        inner: Box::new(protocol),
    }))
}

#[cfg(not(feature = "httpupgrade"))]
pub(super) fn apply_httpupgrade_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    if stream_settings.network.eq_ignore_ascii_case("httpupgrade") {
        return Err(Error::InvalidConfig(
            "httpupgrade transport requires the httpupgrade feature".into(),
        ));
    }
    Ok(protocol)
}

#[cfg(feature = "ws")]
pub(super) fn apply_websocket_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> ServerProxyConfig {
    let network = stream_settings.network.trim();
    if !network.eq_ignore_ascii_case("ws")
        && !network.eq_ignore_ascii_case("websocket")
    {
        return protocol;
    }
    ServerProxyConfig::Websocket {
        targets: Box::new(OneOrSome::One(websocket_server_config(
            stream_settings.ws_settings.clone().unwrap_or_default(),
            stream_settings,
            protocol,
        ))),
    }
}

#[cfg(not(feature = "ws"))]
pub(super) fn apply_websocket_layer(
    protocol: ServerProxyConfig,
    _stream_settings: &crate::config::StreamSettings,
) -> ServerProxyConfig {
    protocol
}

pub(super) fn apply_standard_stream_layers(
    protocol: ServerProxyConfig,
    stream_settings: Option<&crate::config::StreamSettings>,
) -> Result<ServerProxyConfig, Error> {
    let Some(stream_settings) = stream_settings else {
        return Ok(protocol);
    };

    let protocol = apply_websocket_layer(protocol, stream_settings);
    let protocol = apply_httpupgrade_layer(protocol, stream_settings)?;
    let protocol = apply_grpc_layer(protocol, stream_settings)?;
    apply_security_layers(protocol, stream_settings)
}

pub(super) fn validate_standard_tcp_network(
    stream_settings: Option<&crate::config::StreamSettings>,
    inbound_protocol: &str,
) -> Result<(), Error> {
    let Some(stream_settings) = stream_settings else {
        return Ok(());
    };
    let network = stream_settings.network.trim().to_ascii_lowercase();
    if matches!(
        network.as_str(),
        "" | "raw" | "tcp" | "ws" | "websocket" | "httpupgrade" | "grpc"
    ) {
        Ok(())
    } else {
        Err(Error::InvalidConfig(format!(
            "{inbound_protocol} inbound streamSettings.network={network} is not supported"
        )))
    }
}

const TCP_BRUTAL_MIN_RATE_BYTES_PER_SEC: u64 = 62_500;
const TCP_BRUTAL_MAX_RATE_BYTES_PER_SEC: u64 = 125_000_000_000;
const TCP_BRUTAL_DEFAULT_CWND_GAIN: u32 = 20;
const TCP_BRUTAL_MIN_CWND_GAIN: u32 = 5;
const TCP_BRUTAL_MAX_CWND_GAIN: u32 = 80;

pub(super) fn collect_tcp_congestion_policy(
    stream_settings: Option<&crate::config::StreamSettings>,
) -> Result<Option<TcpSocketPolicy>, Error> {
    let Some(sockopt) =
        stream_settings.and_then(|settings| settings.sockopt.as_ref())
    else {
        return Ok(None);
    };
    let congestion = sockopt
        .tcp_congestion
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let brutal_rate = sockopt
        .tcp_brutal_rate
        .clone()
        .map(parse_bandwidth)
        .transpose()
        .map_err(|error| {
            Error::InvalidConfig(format!("invalid sockopt.tcpBrutalRate: {error}"))
        })?;
    let brutal_cwnd_gain = sockopt.tcp_brutal_cwnd_gain;

    let Some(congestion) = congestion else {
        if brutal_rate.is_some() || brutal_cwnd_gain.is_some() {
            return Err(Error::InvalidConfig(
                "sockopt.tcpBrutalRate/tcpBrutalCwndGain require tcpCongestion=brutal".into(),
            ));
        }
        return Ok(None);
    };

    if !congestion.eq_ignore_ascii_case("brutal") {
        if brutal_rate.is_some() || brutal_cwnd_gain.is_some() {
            return Err(Error::InvalidConfig(format!(
                "sockopt.tcpBrutalRate/tcpBrutalCwndGain require tcpCongestion=brutal, got {congestion}"
            )));
        }
        return Ok(Some(TcpSocketPolicy {
            congestion,
            brutal: None,
            ..TcpSocketPolicy::default()
        }));
    }

    let rate_bytes_per_sec = brutal_rate.ok_or_else(|| {
        Error::InvalidConfig(
            "sockopt.tcpCongestion=brutal requires tcpBrutalRate; TCP Brutal defaults to 1 Mbps without an explicit rate".into(),
        )
    })?;
    if !(TCP_BRUTAL_MIN_RATE_BYTES_PER_SEC..=TCP_BRUTAL_MAX_RATE_BYTES_PER_SEC)
        .contains(&rate_bytes_per_sec)
    {
        return Err(Error::InvalidConfig(format!(
            "sockopt.tcpBrutalRate must be between 500kbps and 1tbps (got {rate_bytes_per_sec} bytes/s)"
        )));
    }
    let cwnd_gain = brutal_cwnd_gain.unwrap_or(TCP_BRUTAL_DEFAULT_CWND_GAIN);
    if !(TCP_BRUTAL_MIN_CWND_GAIN..=TCP_BRUTAL_MAX_CWND_GAIN).contains(&cwnd_gain) {
        return Err(Error::InvalidConfig(format!(
            "sockopt.tcpBrutalCwndGain must be between {TCP_BRUTAL_MIN_CWND_GAIN} and {TCP_BRUTAL_MAX_CWND_GAIN} (got {cwnd_gain})"
        )));
    }

    Ok(Some(TcpSocketPolicy {
        congestion: "brutal".to_string(),
        brutal: Some(TcpBrutalConfig {
            rate_bytes_per_sec,
            cwnd_gain,
        }),
        ..TcpSocketPolicy::default()
    }))
}

pub(super) fn collect_tcp_socket_policy(
    stream_settings: Option<&crate::config::StreamSettings>,
) -> Result<Option<TcpSocketPolicy>, Error> {
    use crate::config::TcpFastOpenValue;
    use crate::config::server_config::types::CustomSocketOption;

    let Some(stream_settings) = stream_settings else {
        return Ok(None);
    };
    let Some(sockopt) = stream_settings.sockopt.as_ref() else {
        return Ok(None);
    };

    let mut policy =
        collect_tcp_congestion_policy(Some(stream_settings))?.unwrap_or_default();

    policy.fast_open = match sockopt.tcp_fast_open.as_ref() {
        None => None,
        Some(TcpFastOpenValue::Bool(true)) => Some(256),
        Some(TcpFastOpenValue::Bool(false)) => Some(0),
        Some(TcpFastOpenValue::Number(value)) => {
            if !value.is_finite() {
                return Err(Error::InvalidConfig(
                    "tcpFastOpen must be a finite number".into(),
                ));
            }
            let value = value.min(i32::MAX as f64) as i32;
            match value.cmp(&0) {
                std::cmp::Ordering::Equal => None,
                std::cmp::Ordering::Less => Some(0),
                std::cmp::Ordering::Greater => Some(value),
            }
        }
    };
    policy.keep_alive_idle = sockopt.tcp_keep_alive_idle;
    policy.keep_alive_interval = sockopt.tcp_keep_alive_interval;
    policy.user_timeout_ms =
        (sockopt.tcp_user_timeout > 0).then_some(sockopt.tcp_user_timeout);
    policy.window_clamp =
        (sockopt.tcp_window_clamp > 0).then_some(sockopt.tcp_window_clamp);
    policy.max_seg = (sockopt.tcp_max_seg > 0).then_some(sockopt.tcp_max_seg);
    policy.multipath = sockopt.tcp_mptcp;
    policy.ipv6_only = sockopt.v6only;
    policy.bind_interface =
        (!sockopt.interface.is_empty()).then(|| sockopt.interface.clone());
    policy.mark = (sockopt.mark != 0).then_some(sockopt.mark);
    policy.transparent = matches!(
        sockopt.tproxy.to_ascii_lowercase().as_str(),
        "tproxy" | "redirect"
    );
    policy.receive_original_destination = sockopt.receive_original_dest_address;
    policy.custom_sockopt = sockopt
        .custom_sockopt
        .iter()
        .cloned()
        .map(|option| CustomSocketOption {
            system: option.system,
            network: option.network,
            level: option.level,
            opt: option.opt,
            value: option.value,
            value_type: option.value_type,
        })
        .collect();

    if policy
        .bind_interface
        .as_deref()
        .is_some_and(|value| value.contains('\0'))
    {
        return Err(Error::InvalidConfig(
            "sockopt.interface must not contain NUL bytes".into(),
        ));
    }

    let configured = !policy.congestion.is_empty()
        || policy.brutal.is_some()
        || policy.fast_open.is_some()
        || policy.keep_alive_idle != 0
        || policy.keep_alive_interval != 0
        || policy.user_timeout_ms.is_some()
        || policy.window_clamp.is_some()
        || policy.max_seg.is_some()
        || policy.multipath
        || policy.ipv6_only
        || policy.bind_interface.is_some()
        || policy.mark.is_some()
        || policy.transparent
        || policy.receive_original_destination
        || !policy.custom_sockopt.is_empty();
    if !configured {
        return Ok(None);
    }

    let network = stream_settings.network.trim().to_ascii_lowercase();
    if policy.receive_original_destination
        && !matches!(network.as_str(), "udp" | "quic" | "hysteria2")
    {
        return Err(Error::InvalidConfig(
            "receiveOriginalDestAddress is supported only for UDP/QUIC listeners"
                .into(),
        ));
    }
    if !matches!(
        network.as_str(),
        "" | "raw"
            | "tcp"
            | "ws"
            | "websocket"
            | "httpupgrade"
            | "grpc"
            | "xhttp"
            | "splithttp"
    ) {
        let has_tcp_only = !policy.congestion.is_empty()
            || policy.brutal.is_some()
            || policy.fast_open.is_some()
            || policy.keep_alive_idle != 0
            || policy.keep_alive_interval != 0
            || policy.user_timeout_ms.is_some()
            || policy.window_clamp.is_some()
            || policy.max_seg.is_some()
            || policy.multipath;
        if has_tcp_only {
            return Err(Error::InvalidConfig(format!(
                "TCP socket options are not supported for {network} transport"
            )));
        }
        // Listener-generic options are retained for UDP/QUIC listeners by the
        // same runtime policy and are ignored by TCP-only connection setup.
    }

    Ok(Some(policy))
}
