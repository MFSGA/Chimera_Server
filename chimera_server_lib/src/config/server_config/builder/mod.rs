mod collectors;
mod tls;

use serde::Deserialize;

use crate::{
    Error,
    address::{Address, BindLocation, NetLocation},
    config::{Protocol, Transport, def::InboudItem},
    util::bandwidth::parse_bandwidth,
};

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use crate::util::option::NoneOrSome;

#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;

#[cfg(feature = "ws")]
use super::ws::WebsocketServerConfig;

#[cfg(feature = "hysteria")]
fn finalmask_udp_hop_is_inert(udp_hop: &crate::config::FinalMaskUdpHop) -> bool {
    fn value_is_zero(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => true,
            serde_json::Value::Number(number) => {
                number.as_i64() == Some(0) || number.as_u64() == Some(0)
            }
            serde_json::Value::String(value) => {
                matches!(value.as_str(), "" | "0" | "0-0")
            }
            _ => false,
        }
    }

    value_is_zero(&udp_hop.ports) && value_is_zero(&udp_hop.interval)
}

fn parse_xray_finalmask_bandwidth(input: &str) -> Result<u64, Error> {
    let value = input.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(0);
    }
    let split = value
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
        .map(|(idx, _)| idx)
        .unwrap_or(value.len());
    let number = value[..split].parse::<f64>().map_err(|_| {
        Error::InvalidConfig(format!(
            "invalid finalmask.quicParams bandwidth value: {input}"
        ))
    })?;
    let multiplier = match value[split..].trim() {
        "" | "b" | "bps" => 1_u64,
        "k" | "kb" | "kbps" => 1024,
        "m" | "mb" | "mbps" => 1024 * 1024,
        "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
        "t" | "tb" | "tbps" => 1024_u64.pow(4),
        unit => {
            return Err(Error::InvalidConfig(format!(
                "unsupported finalmask.quicParams bandwidth unit: {unit}"
            )));
        }
    };
    let bits_per_second = number * multiplier as f64;
    if !bits_per_second.is_finite()
        || bits_per_second < 0.0
        || bits_per_second > u64::MAX as f64
    {
        return Err(Error::InvalidConfig(format!(
            "invalid finalmask.quicParams bandwidth value: {input}"
        )));
    }
    Ok(bits_per_second as u64 / 8)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedFinalMaskQuicParams {
    congestion: String,
    bbr_profile: String,
    brutal_up: u64,
    brutal_down: Option<u64>,
    max_idle_timeout: u64,
    keep_alive_period: u64,
    max_incoming_streams: u64,
    receive_windows: (u64, u64, u64, u64),
}

fn validate_xray_finalmask_quic_params(
    params: &crate::config::FinalMaskQuicParams,
    validate_brutal_down: bool,
) -> Result<ValidatedFinalMaskQuicParams, Error> {
    let congestion = params.congestion.to_ascii_lowercase();
    if !matches!(
        congestion.as_str(),
        "" | "brutal" | "reno" | "bbr" | "force-brutal"
    ) {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.congestion must be one of reno, bbr, brutal, force-brutal (got {})",
            params.congestion
        )));
    }

    let bbr_profile = match params.bbr_profile.to_ascii_lowercase() {
        profile if profile.is_empty() => "standard".to_string(),
        profile
            if matches!(
                profile.as_str(),
                "conservative" | "standard" | "aggressive"
            ) =>
        {
            profile
        }
        _ => {
            return Err(Error::InvalidConfig(format!(
                "finalmask.quicParams.bbrProfile must be one of conservative, standard, aggressive (got {})",
                params.bbr_profile
            )));
        }
    };
    if matches!(bbr_profile.as_str(), "conservative" | "aggressive")
        && !matches!(congestion.as_str(), "reno" | "force-brutal")
    {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.bbrProfile conservative/aggressive is not supported when Xray may use BBR"
                .into(),
        ));
    }

    let brutal_up = parse_xray_finalmask_bandwidth(&params.brutal_up)?;
    if brutal_up != 0 && brutal_up < 65_536 {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.brutalUp must be at least 65536 bytes per second"
                .into(),
        ));
    }
    let brutal_down = validate_brutal_down
        .then(|| {
            let value = parse_xray_finalmask_bandwidth(&params.brutal_down)?;
            if value != 0 && value < 65_536 {
                return Err(Error::InvalidConfig(
                    "finalmask.quicParams.brutalDown must be at least 65536 bytes per second"
                        .into(),
                ));
            }
            Ok(value)
        })
        .transpose()?;
    if congestion == "force-brutal" && brutal_up == 0 {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.force-brutal requires brutalUp".into(),
        ));
    }

    let max_idle_timeout = params.max_idle_timeout;
    if max_idle_timeout != 0 && !(4..=120).contains(&max_idle_timeout) {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.maxIdleTimeout must be 0 or between 4 and 120 seconds (got {max_idle_timeout})"
        )));
    }
    let keep_alive_period = params.keep_alive_period;
    if keep_alive_period != 0 && !(2..=60).contains(&keep_alive_period) {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.keepAlivePeriod must be 0 or between 2 and 60 seconds (got {keep_alive_period})"
        )));
    }
    let max_incoming_streams = params.max_incoming_streams;
    if max_incoming_streams != 0 && max_incoming_streams < 8 {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.maxIncomingStreams must be 0 or at least 8 (got {max_incoming_streams})"
        )));
    }

    for (field, value) in [
        ("initStreamReceiveWindow", params.init_stream_receive_window),
        ("maxStreamReceiveWindow", params.max_stream_receive_window),
        (
            "initConnectionReceiveWindow",
            params.init_connection_receive_window,
        ),
        (
            "maxConnectionReceiveWindow",
            params.max_connection_receive_window,
        ),
    ] {
        if value != 0 && value < 16_384 {
            return Err(Error::InvalidConfig(format!(
                "finalmask.quicParams.{field} must be 0 or at least 16384 (got {value})"
            )));
        }
    }

    Ok(ValidatedFinalMaskQuicParams {
        congestion,
        bbr_profile,
        brutal_up,
        brutal_down,
        max_idle_timeout: max_idle_timeout as u64,
        keep_alive_period: keep_alive_period as u64,
        max_incoming_streams: if max_incoming_streams == 0 {
            0
        } else {
            (max_incoming_streams as u64).min(1_u64 << 60)
        },
        receive_windows: (
            params.init_stream_receive_window,
            params.max_stream_receive_window,
            params.init_connection_receive_window,
            params.max_connection_receive_window,
        ),
    })
}

#[cfg(feature = "ws")]
fn normalize_xray_websocket_path(path: Option<String>) -> String {
    let path = path.map(strip_xray_websocket_early_data_query);
    match path {
        Some(path) if path.starts_with('/') => path,
        Some(path) if !path.is_empty() => format!("/{path}"),
        _ => "/".to_string(),
    }
}

fn strip_xray_websocket_early_data_query(path: String) -> String {
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

fn parse_xray_websocket_query_pair(pair: &str) -> Option<(String, String)> {
    if pair.contains(';') {
        return None;
    }
    let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
    Some((
        decode_xray_websocket_query_component(key)?,
        decode_xray_websocket_query_component(value)?,
    ))
}

fn decode_xray_websocket_query_component(value: &str) -> Option<String> {
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

#[cfg(any(feature = "ws", feature = "httpupgrade", feature = "grpc_transport"))]
fn xray_trusted_x_forwarded_for(
    stream_settings: &crate::config::StreamSettings,
) -> Vec<String> {
    stream_settings
        .sockopt
        .as_ref()
        .map(|settings| settings.trusted_x_forwarded_for.clone())
        .unwrap_or_default()
}

#[cfg(feature = "ws")]
fn websocket_server_config(
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
fn apply_grpc_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    if !stream_settings.network.eq_ignore_ascii_case("grpc") {
        return Ok(protocol);
    }
    let settings = stream_settings.grpc_settings.clone().ok_or_else(|| {
        Error::InvalidConfig("grpc inbound requires grpcSettings".into())
    })?;
    let service_name = settings
        .service_name
        .unwrap_or_else(|| "GunService".to_string());
    let _ = (
        settings.authority,
        settings.permit_without_stream,
        settings.initial_windows_size,
    );
    Ok(ServerProxyConfig::Grpc(super::types::GrpcServerConfig {
        service_name,
        multi_mode: settings.multi_mode,
        idle_timeout: settings.idle_timeout,
        health_check_timeout: settings.health_check_timeout,
        trusted_x_forwarded_for: xray_trusted_x_forwarded_for(stream_settings),
        inner: Box::new(protocol),
    }))
}

#[cfg(not(feature = "grpc_transport"))]
fn apply_grpc_layer(
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
fn apply_httpupgrade_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    if !stream_settings.network.eq_ignore_ascii_case("httpupgrade") {
        return Ok(protocol);
    }
    let settings =
        stream_settings
            .httpupgrade_settings
            .clone()
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "httpupgrade inbound requires httpupgradeSettings".into(),
                )
            })?;
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
fn apply_httpupgrade_layer(
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
fn apply_websocket_layer(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
) -> ServerProxyConfig {
    match stream_settings.ws_settings.clone() {
        Some(ws_setting) => ServerProxyConfig::Websocket {
            targets: Box::new(OneOrSome::One(websocket_server_config(
                ws_setting,
                stream_settings,
                protocol,
            ))),
        },
        None => protocol,
    }
}

#[cfg(not(feature = "ws"))]
fn apply_websocket_layer(
    protocol: ServerProxyConfig,
    _stream_settings: &crate::config::StreamSettings,
) -> ServerProxyConfig {
    protocol
}

fn apply_standard_stream_layers(
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

fn validate_standard_tcp_network(
    stream_settings: Option<&crate::config::StreamSettings>,
    inbound_protocol: &str,
) -> Result<(), Error> {
    let Some(stream_settings) = stream_settings else {
        return Ok(());
    };
    let network = stream_settings.network.trim().to_ascii_lowercase();
    if matches!(
        network.as_str(),
        "" | "tcp" | "ws" | "websocket" | "httpupgrade" | "grpc"
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

fn collect_tcp_congestion_policy(
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

fn collect_tcp_socket_policy(
    stream_settings: Option<&crate::config::StreamSettings>,
) -> Result<Option<TcpSocketPolicy>, Error> {
    use super::types::CustomSocketOption;
    use crate::config::TcpFastOpenValue;

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

struct InboundBuildContext {
    tag: String,
    port: u16,
    bind_location: BindLocation,
    stream_settings: Option<crate::config::StreamSettings>,
    sniffing: Option<InboundSniffingConfig>,
    tcp_socket_policy: Option<TcpSocketPolicy>,
}

impl InboundBuildContext {
    fn stream_settings(&self) -> Option<&crate::config::StreamSettings> {
        self.stream_settings.as_ref()
    }

    fn finish(
        self,
        protocol: ServerProxyConfig,
        transport: Transport,
        quic_settings: Option<super::quic::ServerQuicConfig>,
    ) -> ServerConfig {
        ServerConfig {
            tag: self.tag,
            bind_location: self.bind_location,
            protocol,
            transport,
            quic_settings,
            sniffing: self.sniffing,
            tcp_socket_policy: self.tcp_socket_policy,
        }
    }

    fn finish_tcp(self, protocol: ServerProxyConfig) -> ServerConfig {
        self.finish(protocol, Transport::Tcp, None)
    }
}

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use super::quic::ServerQuicConfig;
#[cfg(feature = "httpupgrade")]
use super::types::HttpUpgradeServerConfig;
use super::types::{
    InboundSniffingConfig, ServerConfig, ServerProxyConfig, TcpBrutalConfig,
    TcpSocketPolicy, XhttpServerConfig,
};
use crate::routing_state::SniffExclusionMatcher;

pub(crate) fn collect_xhttp_settings_from_json(
    value: serde_json::Value,
) -> Result<XhttpServerConfig, Error> {
    let settings = serde_json::from_value::<crate::config::XhttpSettings>(value)
        .map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid xhttp transport settings: {error}"
            ))
        })?;
    collectors::collect_xhttp_settings(settings)
}

#[cfg(feature = "hysteria")]
use collectors::collect_hysteria2_settings;
use collectors::collect_socks_settings;
#[cfg(feature = "vless")]
use collectors::collect_xhttp_settings;

#[cfg(feature = "tuic")]
use collectors::collect_tuic_settings;
#[cfg(feature = "trojan")]
use collectors::{collect_trojan_clients, collect_trojan_fallbacks};
use tls::apply_security_layers;

#[cfg(feature = "shadowsocks")]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShadowsocksInboundSettings {
    #[serde(default)]
    method: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    level: u32,
    #[serde(default)]
    users: Option<Vec<ShadowsocksAccountSetting>>,
    #[serde(default)]
    clients: Option<Vec<ShadowsocksAccountSetting>>,
    #[serde(default)]
    network: Option<serde_json::Value>,
}

#[cfg(feature = "shadowsocks")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShadowsocksAccountSetting {
    #[serde(default)]
    method: String,
    password: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    level: u32,
}

#[cfg(feature = "http")]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpInboundSettings {
    #[serde(default)]
    users: Option<Vec<HttpAccountSetting>>,
    #[serde(default)]
    accounts: Option<Vec<HttpAccountSetting>>,
    #[serde(default)]
    allow_transparent: bool,
    #[serde(default)]
    user_level: u32,
}

#[cfg(feature = "http")]
#[derive(Debug, Deserialize)]
struct HttpAccountSetting {
    user: String,
    pass: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DokodemoDoorSettings {
    #[serde(default, alias = "rewriteAddress")]
    address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    follow_redirect: bool,
    #[serde(default)]
    user_level: u32,
}

#[cfg(feature = "vless")]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VlessInboundSettings {
    #[serde(default)]
    decryption: Option<String>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    fallbacks: Vec<serde_json::Value>,
}

#[cfg(feature = "vless")]
#[derive(Debug, Deserialize)]
struct VlessInboundFallback {
    dest: serde_json::Value,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    alpn: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default, rename = "type")]
    fallback_type: Option<String>,
    #[serde(default)]
    xver: Option<u8>,
}

#[cfg(feature = "vless")]
fn collect_vless_fallbacks(
    values: Vec<serde_json::Value>,
) -> Result<Vec<crate::config::server_config::VlessFallback>, Error> {
    values
        .into_iter()
        .map(|value| {
            let fallback: VlessInboundFallback = serde_json::from_value(value)
                .map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid vless fallback settings: {error}"
                    ))
                })?;
            let fallback_type = fallback
                .fallback_type
                .as_deref()
                .unwrap_or("tcp")
                .trim()
                .to_ascii_lowercase();
            if !matches!(fallback_type.as_str(), "" | "tcp") {
                return Err(Error::InvalidConfig(format!(
                    "vless fallback type={fallback_type} is not supported yet"
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
                    "vless fallback path must be empty or start with /".into(),
                ));
            }

            let xver = fallback.xver.unwrap_or(0);
            if xver > 2 {
                return Err(Error::InvalidConfig(format!(
                    "vless fallback xver must be 0, 1, or 2; got {xver}"
                )));
            }
            let dest = parse_vless_fallback_dest(fallback.dest)?;
            Ok(crate::config::server_config::VlessFallback {
                name,
                alpn,
                path,
                dest,
                xver,
            })
        })
        .collect()
}

#[cfg(feature = "vless")]
fn parse_vless_fallback_dest(
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
                        "vless fallback numeric dest must be a port from 1 to 65535"
                            .into(),
                    )
                })?;
            Ok(local_port(port))
        }
        serde_json::Value::String(value) => {
            let dest = value.trim();
            if dest.is_empty() {
                return Err(Error::InvalidConfig(
                    "vless fallback dest cannot be empty".into(),
                ));
            }
            if let Ok(port) = dest.parse::<u16>()
                && port != 0
            {
                return Ok(local_port(port));
            }
            if dest.starts_with('/') || dest.starts_with('@') {
                return Err(Error::InvalidConfig(
                    "vless fallback Unix socket destinations are not supported yet"
                        .into(),
                ));
            }
            NetLocation::from_str(dest, None).map_err(|error| {
                Error::InvalidConfig(format!(
                    "invalid vless fallback dest {dest}: {error}"
                ))
            })
        }
        _ => Err(Error::InvalidConfig(
            "vless fallback dest must be a port number or host:port string".into(),
        )),
    }
}

#[cfg(feature = "vless")]
fn validate_vless_flow(flow: &str) -> Result<(), Error> {
    match flow {
        "" | "xtls-rprx-vision" => Ok(()),
        unsupported => Err(Error::InvalidConfig(format!(
            "vless clients.flow doesn't support {unsupported}"
        ))),
    }
}

#[cfg(feature = "vless")]
fn has_vless_vision_flow(users: &[crate::config::server_config::VlessUser]) -> bool {
    users.iter().any(|user| user.flow == "xtls-rprx-vision")
}

#[cfg(feature = "vless")]
struct VlessCorePlan {
    protocol: ServerProxyConfig,
    uses_vision: bool,
}

#[cfg(feature = "vless")]
fn plan_vless_core(
    settings: Option<&crate::config::SettingObject>,
) -> Result<VlessCorePlan, Error> {
    let vless_settings = settings
        .map(|value| value.deserialize::<VlessInboundSettings>())
        .transpose()
        .map_err(|err| {
            Error::InvalidConfig(format!("invalid vless settings: {err}"))
        })?
        .unwrap_or_default();
    let decryption = vless_settings
        .decryption
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::InvalidConfig(
                "vless settings.decryption must be explicitly set to none".into(),
            )
        })?
        .to_ascii_lowercase();
    if decryption != "none" {
        return Err(Error::InvalidConfig(format!(
            "vless settings.decryption must be none, got {decryption}"
        )));
    }

    let settings_flow = vless_settings.flow.as_deref().map(str::trim).unwrap_or("");
    validate_vless_flow(settings_flow)?;
    let users = settings
        .and_then(crate::config::SettingObject::clients)
        .map(|clients| {
            clients
                .into_iter()
                .map(|client| {
                    let flow = if client.flow.trim().is_empty() {
                        settings_flow.to_string()
                    } else {
                        client.flow
                    };
                    validate_vless_flow(&flow)?;
                    Ok(crate::config::server_config::VlessUser {
                        user_id: client.id.clone(),
                        user_label: if client.email.is_empty() {
                            client.id
                        } else {
                            client.email
                        },
                        user_level: client.level,
                        flow,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()
        })
        .transpose()?
        .ok_or_else(|| {
            Error::InvalidConfig("vless inbound requires at least one client".into())
        })?;
    let uses_vision = has_vless_vision_flow(&users);
    let fallbacks = collect_vless_fallbacks(vless_settings.fallbacks)?;

    Ok(VlessCorePlan {
        protocol: ServerProxyConfig::Vless { users, fallbacks },
        uses_vision,
    })
}

#[cfg(feature = "vless")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VlessTransportKind {
    Xhttp,
    Standard,
}

#[cfg(feature = "vless")]
struct VlessTransportPlan {
    kind: VlessTransportKind,
    security: String,
}

#[cfg(feature = "vless")]
fn plan_vless_transport(
    stream_settings: Option<&crate::config::StreamSettings>,
    uses_vision: bool,
) -> Result<VlessTransportPlan, Error> {
    let uses_xhttp = stream_settings
        .map(|settings| settings.network.eq_ignore_ascii_case("xhttp"))
        .unwrap_or(false);
    let security = stream_settings
        .and_then(|settings| settings.security.as_deref())
        .unwrap_or("none")
        .to_ascii_lowercase();

    if uses_vision {
        if uses_xhttp {
            return Err(Error::InvalidConfig(
                "xtls-rprx-vision does not support xhttp transport".into(),
            ));
        }
        if security != "tls" && security != "reality" {
            return Err(Error::InvalidConfig(
                "xtls-rprx-vision requires streamSettings.security=tls or reality"
                    .into(),
            ));
        }
        #[cfg(feature = "ws")]
        if stream_settings.is_some_and(|settings| settings.ws_settings.is_some()) {
            return Err(Error::InvalidConfig(
                "xtls-rprx-vision does not support websocket transport".into(),
            ));
        }
        if stream_settings.is_some_and(|settings| {
            matches!(
                settings.network.to_ascii_lowercase().as_str(),
                "httpupgrade" | "grpc"
            )
        }) {
            return Err(Error::InvalidConfig(
                "xtls-rprx-vision does not support httpupgrade or grpc transport"
                    .into(),
            ));
        }
    }

    Ok(VlessTransportPlan {
        kind: if uses_xhttp {
            VlessTransportKind::Xhttp
        } else {
            VlessTransportKind::Standard
        },
        security,
    })
}

#[cfg(feature = "vless")]
fn apply_vless_xhttp_transport(
    protocol: ServerProxyConfig,
    stream_settings: &crate::config::StreamSettings,
    security: &str,
) -> Result<ServerProxyConfig, Error> {
    let xhttp_settings =
        stream_settings.xhttp_settings.clone().ok_or_else(|| {
            Error::InvalidConfig("xhttp inbound requires xhttpSettings".into())
        })?;
    let mut xhttp_config = collect_xhttp_settings(xhttp_settings)?;
    xhttp_config.trusted_x_forwarded_for =
        xray_trusted_x_forwarded_for(stream_settings);
    if let Some(quic_params) = stream_settings
        .final_mask
        .as_ref()
        .and_then(|final_mask| final_mask.quic_params.as_ref())
    {
        if quic_params.congestion.eq_ignore_ascii_case("brutal") {
            return Err(Error::InvalidConfig(format!(
                "finalmask.quicParams.congestion={} is not supported for XHTTP",
                quic_params.congestion
            )));
        }
        let validated = validate_xray_finalmask_quic_params(quic_params, false)?;
        xhttp_config.xray_congestion = Some(validated.congestion);
        xhttp_config.xray_brutal_up =
            (validated.brutal_up != 0).then_some(validated.brutal_up);
        xhttp_config.xray_max_idle_timeout_secs =
            (validated.max_idle_timeout != 0).then_some(validated.max_idle_timeout);
        xhttp_config.xray_max_incoming_streams = (validated.max_incoming_streams
            != 0)
            .then_some(validated.max_incoming_streams);
        let (init_stream, max_stream, init_connection, max_connection) =
            validated.receive_windows;
        xhttp_config.xray_init_stream_receive_window = Some(init_stream);
        xhttp_config.xray_max_stream_receive_window = Some(max_stream);
        xhttp_config.xray_init_connection_receive_window = Some(init_connection);
        xhttp_config.xray_max_connection_receive_window = Some(max_connection);
        xhttp_config.xray_disable_path_mtu_discovery =
            Some(quic_params.disable_path_mtu_discovery);
    }
    let protocol = ServerProxyConfig::Xhttp {
        config: xhttp_config,
        inner: Box::new(protocol),
    };

    match security {
        "none" => Ok(protocol),
        "tls" | "reality" => apply_security_layers(protocol, stream_settings),
        unsupported => Err(Error::InvalidConfig(format!(
            "xhttp inbound currently supports only security=none, tls, or reality, got {unsupported}"
        ))),
    }
}

#[cfg(feature = "vless")]
fn apply_vless_transport_plan(
    mut protocol: ServerProxyConfig,
    stream_settings: Option<&crate::config::StreamSettings>,
    plan: &VlessTransportPlan,
) -> Result<ServerProxyConfig, Error> {
    #[cfg(feature = "ws")]
    if plan.kind == VlessTransportKind::Standard
        && let Some(stream_settings) = stream_settings
        && let Some(ws_settings) = stream_settings.ws_settings.clone()
    {
        tracing::info!("use websocket");
        protocol = ServerProxyConfig::Websocket {
            targets: Box::new(OneOrSome::One(websocket_server_config(
                ws_settings,
                stream_settings,
                protocol,
            ))),
        };
    }

    let Some(stream_settings) = stream_settings else {
        return Ok(protocol);
    };
    match plan.kind {
        VlessTransportKind::Xhttp => {
            apply_vless_xhttp_transport(protocol, stream_settings, &plan.security)
        }
        VlessTransportKind::Standard => {
            let protocol = apply_httpupgrade_layer(protocol, stream_settings)?;
            let protocol = apply_grpc_layer(protocol, stream_settings)?;
            apply_security_layers(protocol, stream_settings)
        }
    }
}

#[cfg(feature = "vless")]
fn build_vless_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let VlessCorePlan {
        protocol,
        uses_vision,
    } = plan_vless_core(settings.as_ref())?;
    let transport_plan =
        plan_vless_transport(context.stream_settings(), uses_vision)?;
    let protocol = apply_vless_transport_plan(
        protocol,
        context.stream_settings(),
        &transport_plan,
    )?;
    Ok(context.finish_tcp(protocol))
}

#[cfg(feature = "shadowsocks")]
fn collect_shadowsocks_users(
    settings: Option<crate::config::SettingObject>,
) -> Result<
    (
        Vec<crate::config::server_config::ShadowsocksUser>,
        Option<crate::config::server_config::ShadowsocksServerIdentity>,
        Transport,
    ),
    Error,
> {
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("shadowsocks inbound requires settings".into())
    })?;
    let raw = settings
        .deserialize::<ShadowsocksInboundSettings>()
        .map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid shadowsocks inbound settings: {error}"
            ))
        })?;
    let transport = shadowsocks_transport(raw.network.as_ref())?;
    let accounts = raw.clients.or(raw.users);
    let is_aead2022_multi =
        accounts.is_some() && raw.method.starts_with("2022-blake3-");

    let (users, identity) = if let Some(accounts) = accounts {
        if accounts.is_empty() {
            return Err(Error::InvalidConfig(
                "shadowsocks users cannot be empty".into(),
            ));
        }
        if is_aead2022_multi {
            if !matches!(
                raw.method.as_str(),
                "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"
            ) {
                return Err(Error::InvalidConfig(
                    "Shadowsocks 2022 multi-user EIH supports only AES-128-GCM and AES-256-GCM"
                        .into(),
                ));
            }
            let identity = crate::config::server_config::ShadowsocksServerIdentity {
                method: raw.method.clone(),
                password: raw.password.clone(),
            };
            crate::handler::shadowsocks::validate_user(
                &crate::config::server_config::ShadowsocksUser {
                    method: identity.method.clone(),
                    password: identity.password.clone(),
                    email: String::new(),
                    user_level: raw.level,
                },
            )
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
            let users = accounts
                .into_iter()
                .map(|user| {
                    if !user.method.trim().is_empty() {
                        return Err(Error::InvalidConfig(
                            "Shadowsocks 2022 EIH users must omit method".into(),
                        ));
                    }
                    Ok(crate::config::server_config::ShadowsocksUser {
                        method: raw.method.clone(),
                        password: user.password,
                        email: user.email,
                        user_level: user.level,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            (users, Some(identity))
        } else {
            let users = accounts
                .into_iter()
                .map(|user| {
                    Ok(crate::config::server_config::ShadowsocksUser {
                        method: user.method,
                        password: user.password,
                        email: user.email,
                        user_level: user.level,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            (users, None)
        }
    } else {
        (
            vec![crate::config::server_config::ShadowsocksUser {
                method: raw.method,
                password: raw.password,
                email: raw.email,
                user_level: raw.level,
            }],
            None,
        )
    };

    for user in &users {
        crate::handler::shadowsocks::validate_user(user)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    }
    Ok((users, identity, transport))
}

#[cfg(feature = "shadowsocks")]
fn shadowsocks_transport(
    network: Option<&serde_json::Value>,
) -> Result<Transport, Error> {
    let Some(network) = network else {
        return Ok(Transport::Tcp);
    };
    let values = match network {
        serde_json::Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>(),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    Error::InvalidConfig(
                        "shadowsocks settings.network must contain strings".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(Error::InvalidConfig(
                "shadowsocks settings.network must be a string or string array"
                    .into(),
            ));
        }
    };
    let tcp = values.iter().any(|value| value.eq_ignore_ascii_case("tcp"));
    let udp = values.iter().any(|value| value.eq_ignore_ascii_case("udp"));
    if values.is_empty() || (tcp && !udp && values.len() == 1) {
        return Ok(Transport::Tcp);
    }
    if udp && !tcp && values.len() == 1 {
        return Ok(Transport::Udp);
    }
    if tcp && udp && values.len() == 2 {
        return Ok(Transport::TcpAndUdp);
    }
    Err(Error::InvalidConfig(format!(
        "unsupported shadowsocks network list: {}",
        values.join(",")
    )))
}

#[cfg(feature = "http")]
fn collect_http_settings(
    settings: Option<crate::config::SettingObject>,
) -> Result<(Vec<crate::config::server_config::HttpUser>, bool, u32), Error> {
    let raw = settings
        .map(|settings| settings.deserialize::<HttpInboundSettings>())
        .transpose()
        .map_err(|error| {
            Error::InvalidConfig(format!("invalid http inbound settings: {error}"))
        })?
        .unwrap_or_default();

    let accounts = raw.accounts.or(raw.users).unwrap_or_default();
    Ok((
        accounts
            .into_iter()
            .map(|account| crate::config::server_config::HttpUser {
                username: account.user,
                password: account.pass,
            })
            .collect(),
        raw.allow_transparent,
        raw.user_level,
    ))
}

fn planned_unsupported_protocol_error(protocol: &str) -> Error {
    Error::InvalidConfig(format!(
        "protocol={protocol} is recognized but not supported in this stage"
    ))
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSniffingConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    dest_override: Vec<String>,
    #[serde(default)]
    domains_excluded: Vec<String>,
    #[serde(default)]
    ips_excluded: Vec<String>,
    #[serde(default)]
    metadata_only: bool,
    #[serde(default)]
    route_only: bool,
}

fn collect_sniffing_config(
    tag: &str,
    value: Option<serde_json::Value>,
) -> Result<Option<InboundSniffingConfig>, Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    let raw =
        serde_json::from_value::<RawSniffingConfig>(value).map_err(|error| {
            Error::InvalidConfig(format!(
                "invalid inbound {tag} sniffing settings: {error}"
            ))
        })?;
    if raw.metadata_only {
        return Err(Error::InvalidConfig(format!(
            "inbound {tag} sniffing metadataOnly is not implemented yet"
        )));
    }

    let mut dest_override_http = false;
    let mut dest_override_tls = false;
    for protocol in &raw.dest_override {
        match protocol.trim().to_ascii_lowercase().as_str() {
            "http" => dest_override_http = true,
            "tls" | "https" | "ssl" => dest_override_tls = true,
            // Xray accepts QUIC as a sniffing destination override, but this
            // server does not implement QUIC destination replacement. Keep
            // the option as a compatibility no-op so existing Xray-shaped
            // configs remain loadable while HTTP/TLS overrides still work.
            "quic" => {}
            "fakedns" | "fakedns+others" => {
                return Err(Error::InvalidConfig(format!(
                    "inbound {tag} sniffing destOverride={protocol:?} is recognized by Xray but not implemented yet"
                )));
            }
            _ => {
                return Err(Error::InvalidConfig(format!(
                    "inbound {tag} sniffing has unknown destOverride protocol {protocol:?}"
                )));
            }
        }
    }

    let has_exclusions =
        !raw.domains_excluded.is_empty() || !raw.ips_excluded.is_empty();
    let exclusions =
        SniffExclusionMatcher::compile(raw.domains_excluded, raw.ips_excluded)
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "invalid inbound {tag} sniffing exclusions: {error}"
                ))
            })?;
    let config = InboundSniffingConfig {
        enabled: raw.enabled,
        dest_override_http,
        dest_override_tls,
        route_only: raw.route_only,
        exclusions: std::sync::Arc::new(exclusions),
    };
    Ok((raw.enabled
        || raw.route_only
        || !raw.dest_override.is_empty()
        || has_exclusions)
        .then_some(config))
}

fn build_dokodemo_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let settings = settings
        .map(|value| value.deserialize::<DokodemoDoorSettings>())
        .transpose()
        .map_err(|err| {
            Error::InvalidConfig(format!("invalid dokodemo-door settings: {err}"))
        })?
        .unwrap_or_default();

    let address = match settings.address.as_deref() {
        Some(value) => Address::from(value)?,
        None => match &context.bind_location {
            BindLocation::Address(addr) => addr.address().clone(),
        },
    };
    let remote_location =
        NetLocation::new(address, settings.port.unwrap_or(context.port));
    let protocol = ServerProxyConfig::DokodemoDoor {
        config: super::types::DokodemoDoorConfig {
            target: remote_location,
            follow_redirect: settings.follow_redirect,
            user_level: settings.user_level,
        },
    };

    let (protocol, transport) = match context.stream_settings() {
        Some(stream_settings)
            if stream_settings.network.trim().eq_ignore_ascii_case("udp") =>
        {
            if stream_settings.security.as_deref().unwrap_or("none") != "none" {
                return Err(Error::InvalidConfig(
                    "dokodemo-door udp transport does not support streamSettings.security"
                        .into(),
                ));
            }
            (protocol, Transport::Udp)
        }
        Some(stream_settings)
            if matches!(
                stream_settings.network.trim().to_ascii_lowercase().as_str(),
                "" | "tcp" | "httpupgrade" | "grpc"
            ) =>
        {
            let protocol = apply_httpupgrade_layer(protocol, stream_settings)?;
            let protocol = apply_grpc_layer(protocol, stream_settings)?;
            (
                apply_security_layers(protocol, stream_settings)?,
                Transport::Tcp,
            )
        }
        Some(stream_settings) => {
            let network = stream_settings.network.trim().to_ascii_lowercase();
            return Err(Error::InvalidConfig(format!(
                "dokodemo-door streamSettings.network={network} is not supported"
            )));
        }
        None => (protocol, Transport::Tcp),
    };

    Ok(context.finish(protocol, transport, None))
}

#[cfg(feature = "vmess")]
fn build_vmess_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("vmess inbound requires clients".into())
    })?;
    let clients = settings.clients().ok_or_else(|| {
        Error::InvalidConfig("vmess inbound settings.clients is required".into())
    })?;
    let users = clients
        .into_iter()
        .map(|client| {
            let user_id = super::normalize_vmess_user_id(&client.id)
                .map_err(Error::InvalidConfig)?;
            let user_label = if client.email.is_empty() {
                user_id.clone()
            } else {
                client.email
            };
            Ok(crate::config::server_config::VmessUser {
                user_id,
                user_label,
                user_level: client.level,
                cipher: client
                    .security
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "auto".to_string()),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    #[cfg(feature = "ws")]
    if context
        .stream_settings()
        .is_some_and(|settings| settings.ws_settings.is_some())
    {
        tracing::info!("use websocket");
    }
    let protocol = apply_standard_stream_layers(
        ServerProxyConfig::Vmess { users },
        context.stream_settings(),
    )?;
    Ok(context.finish_tcp(protocol))
}

#[cfg(feature = "trojan")]
fn build_trojan_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("trojan inbound requires clients".into())
    })?;
    let fallbacks = collect_trojan_fallbacks(&settings)?;
    let users = collect_trojan_clients(settings)?;
    #[cfg(feature = "ws")]
    if context
        .stream_settings()
        .is_some_and(|settings| settings.ws_settings.is_some())
    {
        tracing::info!("use websocket");
    }
    let protocol = apply_standard_stream_layers(
        ServerProxyConfig::Trojan { users, fallbacks },
        context.stream_settings(),
    )?;
    Ok(context.finish_tcp(protocol))
}

#[cfg(feature = "http")]
fn build_http_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let (accounts, allow_transparent, user_level) = collect_http_settings(settings)?;
    validate_standard_tcp_network(context.stream_settings(), "http")?;
    let protocol = apply_standard_stream_layers(
        ServerProxyConfig::Http {
            accounts,
            allow_transparent,
            user_level,
        },
        context.stream_settings(),
    )?;
    Ok(context.finish_tcp(protocol))
}

#[cfg(feature = "mixed")]
fn build_mixed_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let settings = settings
        .unwrap_or_else(|| crate::config::SettingObject(serde_json::json!({})));
    let (accounts, udp_enabled, udp_response_ip, user_level) =
        collect_socks_settings(settings)?;
    if udp_response_ip.is_some() {
        return Err(Error::InvalidConfig(
            "mixed settings.ip is not supported".into(),
        ));
    }
    if user_level != 0 {
        return Err(Error::InvalidConfig(
            "mixed settings.userLevel is not supported".into(),
        ));
    }
    validate_standard_tcp_network(context.stream_settings(), "mixed")?;
    let protocol = apply_standard_stream_layers(
        ServerProxyConfig::Mixed {
            accounts,
            udp_enabled,
        },
        context.stream_settings(),
    )?;
    Ok(context.finish_tcp(protocol))
}

#[cfg(feature = "shadowsocks")]
fn build_shadowsocks_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let (users, identity, transport) = collect_shadowsocks_users(settings)?;
    if !matches!(transport, Transport::Tcp) && context.stream_settings.is_some() {
        return Err(Error::InvalidConfig(
            "shadowsocks UDP listeners do not support streamSettings".into(),
        ));
    }
    validate_standard_tcp_network(context.stream_settings(), "shadowsocks")?;
    let protocol = apply_standard_stream_layers(
        ServerProxyConfig::Shadowsocks { users, identity },
        context.stream_settings(),
    )?;
    Ok(context.finish(protocol, transport, None))
}

fn build_socks_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("socks inbound requires settings".into())
    })?;
    let (accounts, udp_enabled, udp_response_ip, user_level) =
        collect_socks_settings(settings)?;
    #[cfg(feature = "ws")]
    if context
        .stream_settings()
        .is_some_and(|settings| settings.ws_settings.is_some())
    {
        tracing::info!("use websocket");
    }
    let protocol = apply_standard_stream_layers(
        ServerProxyConfig::Socks {
            accounts,
            udp_enabled,
            udp_response_ip,
            user_level,
        },
        context.stream_settings(),
    )?;
    Ok(context.finish_tcp(protocol))
}

#[cfg(feature = "hysteria")]
fn parse_hysteria2_finalmask_packet_size(
    value: &serde_json::Value,
) -> Result<(i32, i32), Error> {
    let (left, right) = if let Some(value) = value.as_i64() {
        let value = i32::try_from(value).map_err(|_| {
            Error::InvalidConfig(
                "hysteria2 finalmask packetSize is out of int32 range".into(),
            )
        })?;
        (value, value)
    } else if let Some(value) = value.as_str() {
        if value.is_empty() {
            (0, 0)
        } else if let Ok(value) = value.parse::<i32>() {
            (value, value)
        } else {
            let split_index = if let Some(value) = value.strip_prefix('-') {
                value.find('-').map(|index| index + 1)
            } else {
                value.find('-')
            }
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "invalid hysteria2 finalmask packetSize range {value:?}"
                ))
            })?;
            let (left, right) = value.split_at(split_index);
            let right = &right[1..];
            (
                left.parse::<i32>().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid hysteria2 finalmask packetSize range {value:?}"
                    ))
                })?,
                right.parse::<i32>().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid hysteria2 finalmask packetSize range {value:?}"
                    ))
                })?,
            )
        }
    } else {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask packetSize must be an integer or range string"
                .into(),
        ));
    };
    Ok(if left <= right {
        (left, right)
    } else {
        (right, left)
    })
}

#[cfg(feature = "hysteria")]
fn collect_hysteria2_udp_finalmask(
    masks: &[serde_json::Value],
) -> Result<Option<crate::config::server_config::Hysteria2UdpFinalMask>, Error> {
    use crate::config::server_config::Hysteria2UdpFinalMask;

    if masks.is_empty() {
        return Ok(None);
    }
    if masks.len() != 1 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.udp currently supports exactly one salamander mask"
                .into(),
        ));
    }

    let mask = masks[0].as_object().ok_or_else(|| {
        Error::InvalidConfig("hysteria2 finalmask.udp mask must be an object".into())
    })?;
    let mask_type = mask
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::InvalidConfig(
                "hysteria2 finalmask.udp mask requires a string type".into(),
            )
        })?;
    if !mask_type.eq_ignore_ascii_case("salamander") {
        return Err(Error::InvalidConfig(format!(
            "hysteria2 finalmask.udp mask type {mask_type:?} is not implemented yet"
        )));
    }

    let settings = mask.get("settings").and_then(serde_json::Value::as_object);
    let packet_size = settings
        .and_then(|settings| settings.get("packetSize"))
        .map(parse_hysteria2_finalmask_packet_size)
        .transpose()?;
    let password = settings
        .and_then(|settings| settings.get("password"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if password.len() < 4 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.udp salamander password must be at least 4 bytes"
                .into(),
        ));
    }

    if let Some((min_packet_size, max_packet_size)) = packet_size
        && max_packet_size > 0
    {
        if min_packet_size <= 0 || max_packet_size > 2048 {
            return Err(Error::InvalidConfig(
                "gecko: invalid min/max packet size".into(),
            ));
        }
        return Ok(Some(Hysteria2UdpFinalMask::Gecko {
            password,
            min_packet_size: min_packet_size as usize,
            max_packet_size: max_packet_size as usize,
        }));
    }

    Ok(Some(Hysteria2UdpFinalMask::Salamander { password }))
}

#[cfg(feature = "hysteria")]
#[derive(Default)]
struct Hysteria2XrayQuicPlan {
    enabled: bool,
    congestion: Option<String>,
    bbr_profile: Option<String>,
    brutal_up: Option<u64>,
    brutal_down: Option<u64>,
    max_idle_timeout_secs: Option<u64>,
    keep_alive_period_secs: Option<u64>,
    max_incoming_streams: Option<u64>,
    receive_windows: Option<(u64, u64, u64, u64)>,
    disable_path_mtu_discovery: Option<bool>,
    udp_finalmask: Option<crate::config::server_config::Hysteria2UdpFinalMask>,
}

#[cfg(feature = "hysteria")]
fn plan_hysteria2_xray_quic(
    final_mask: Option<&crate::config::FinalMaskSettings>,
) -> Result<Hysteria2XrayQuicPlan, Error> {
    let Some(final_mask) = final_mask else {
        return Ok(Hysteria2XrayQuicPlan::default());
    };
    if !final_mask.tcp.is_empty() {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.tcp mask chains are not supported".into(),
        ));
    }
    let udp_finalmask = collect_hysteria2_udp_finalmask(&final_mask.udp)?;

    let Some(quic_params) = final_mask.quic_params.as_ref() else {
        return Ok(Hysteria2XrayQuicPlan {
            enabled: udp_finalmask.is_some(),
            udp_finalmask,
            ..Hysteria2XrayQuicPlan::default()
        });
    };
    if quic_params
        .udp_hop
        .as_ref()
        .is_some_and(|udp_hop| !finalmask_udp_hop_is_inert(udp_hop))
    {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.udpHop is not supported unless it is empty/inert"
                .into(),
        ));
    }

    let validated = validate_xray_finalmask_quic_params(quic_params, true)?;
    Ok(Hysteria2XrayQuicPlan {
        enabled: true,
        congestion: Some(validated.congestion),
        bbr_profile: Some(validated.bbr_profile),
        brutal_up: Some(validated.brutal_up),
        brutal_down: validated.brutal_down,
        max_idle_timeout_secs: Some(if validated.max_idle_timeout == 0 {
            30
        } else {
            validated.max_idle_timeout
        }),
        keep_alive_period_secs: Some(validated.keep_alive_period),
        max_incoming_streams: Some(if validated.max_incoming_streams == 0 {
            1024
        } else {
            validated.max_incoming_streams
        }),
        receive_windows: Some(validated.receive_windows),
        disable_path_mtu_discovery: Some(quic_params.disable_path_mtu_discovery),
        udp_finalmask,
    })
}

#[cfg(feature = "hysteria")]
fn apply_hysteria2_xray_quic_plan(
    mut config: crate::config::server_config::Hysteria2ServerConfig,
    plan: Hysteria2XrayQuicPlan,
) -> crate::config::server_config::Hysteria2ServerConfig {
    config.xray_compat |= plan.enabled;
    config.xray_congestion = plan.congestion;
    config.xray_bbr_profile = plan.bbr_profile;
    config.xray_brutal_up = plan.brutal_up;
    config.xray_brutal_down = plan.brutal_down;
    config.xray_max_idle_timeout_secs = plan.max_idle_timeout_secs;
    config.xray_keep_alive_period_secs = plan.keep_alive_period_secs;
    config.xray_max_incoming_streams = plan.max_incoming_streams;
    config.xray_disable_path_mtu_discovery = plan.disable_path_mtu_discovery;
    config.udp_finalmask = plan.udp_finalmask;
    if let Some((init_stream, max_stream, init_connection, max_connection)) =
        plan.receive_windows
    {
        config.xray_init_stream_receive_window = Some(init_stream);
        config.xray_max_stream_receive_window = Some(max_stream);
        config.xray_init_connection_receive_window = Some(init_connection);
        config.xray_max_connection_receive_window = Some(max_connection);
    }
    config
}

#[cfg(feature = "hysteria")]
fn plan_hysteria2_quic_settings(
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerQuicConfig, Error> {
    let tls_settings = stream_settings.tls_settings.as_ref().ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound requires tlsSettings".into())
    })?;
    let item = tls_settings.certificates[0].clone();
    let cert = item.certificate_file.ok_or_else(|| {
        Error::InvalidConfig(
            "hysteria2 inbound currently requires certificateFile".into(),
        )
    })?;
    let key = item.key_file.ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound currently requires keyFile".into())
    })?;
    Ok(ServerQuicConfig {
        cert,
        key,
        alpn_protocols: NoneOrSome::Some(tls_settings.alpn.clone()),
        client_fingerprints: NoneOrSome::None,
    })
}

#[cfg(feature = "hysteria")]
fn build_hysteria2_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let stream_settings = context.stream_settings().ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound missing streamSettings".into())
    })?;
    let xray_quic_plan =
        plan_hysteria2_xray_quic(stream_settings.final_mask.as_ref())?;
    let quic_settings = plan_hysteria2_quic_settings(stream_settings)?;
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound requires clients".into())
    })?;
    let config = collect_hysteria2_settings(
        settings,
        stream_settings.hysteria_settings.as_ref(),
    )?;
    let config = apply_hysteria2_xray_quic_plan(config, xray_quic_plan);
    if config.clients.is_empty() {
        return Err(Error::InvalidConfig(
            "hysteria2 inbound requires at least one client".into(),
        ));
    }
    Ok(context.finish(
        ServerProxyConfig::Hysteria2 { config },
        Transport::Quic,
        Some(quic_settings),
    ))
}

#[cfg(feature = "tuic")]
fn build_tuic_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let InboundBuildContext {
        tag,
        bind_location,
        stream_settings,
        sniffing,
        ..
    } = context;
    let stream_settings = stream_settings.ok_or_else(|| {
        Error::InvalidConfig("tuic inbound missing streamSettings".into())
    })?;
    let tls_settings = stream_settings.tls_settings.ok_or_else(|| {
        Error::InvalidConfig("tuic inbound requires tlsSettings".into())
    })?;
    let certificate = tls_settings
        .certificates
        .first()
        .ok_or_else(|| {
            Error::InvalidConfig(
                "tuic inbound requires at least one certificate".into(),
            )
        })?
        .clone();
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("tuic inbound requires settings".into())
    })?;
    let config = collect_tuic_settings(settings)?;
    let quic_settings = Some(ServerQuicConfig {
        cert: certificate.certificate_file.ok_or_else(|| {
            Error::InvalidConfig("tuic inbound requires certificateFile".into())
        })?,
        key: certificate.key_file.ok_or_else(|| {
            Error::InvalidConfig("tuic inbound requires keyFile".into())
        })?,
        alpn_protocols: NoneOrSome::Some(tls_settings.alpn),
        client_fingerprints: NoneOrSome::None,
    });

    Ok(ServerConfig {
        tag,
        bind_location,
        protocol: ServerProxyConfig::TuicV5 { config },
        transport: Transport::Quic,
        quic_settings,
        sniffing,
        tcp_socket_policy: None,
    })
}

impl TryFrom<InboudItem> for ServerConfig {
    type Error = Error;

    fn try_from(value: InboudItem) -> Result<Self, Self::Error> {
        tracing::info!("try from inbound item {:?}", &value);

        let InboudItem {
            listen,
            port,
            protocol,
            settings,
            stream_settings,
            tag,
            sniffing,
            ..
        } = value;
        let sniffing = collect_sniffing_config(&tag, sniffing)?;
        let tcp_socket_policy = collect_tcp_socket_policy(stream_settings.as_ref())?;

        let listen = listen.unwrap_or_else(|| "0.0.0.0".to_string());
        let address = Address::from(&listen).map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid inbound listen for tag {}: {} ({})",
                tag, listen, err
            ))
        })?;
        let bind_location = BindLocation::Address(NetLocation::new(address, port));
        let context = InboundBuildContext {
            tag,
            port,
            bind_location,
            stream_settings,
            sniffing,
            tcp_socket_policy,
        };

        match protocol {
            Protocol::DokodemoDoor | Protocol::Tunnel => {
                build_dokodemo_server(context, settings)
            }
            #[cfg(feature = "hysteria")]
            Protocol::Hysteria2 => build_hysteria2_server(context, settings),
            #[cfg(feature = "vless")]
            Protocol::Vless => build_vless_server(context, settings),
            #[cfg(feature = "vmess")]
            Protocol::Vmess => build_vmess_server(context, settings),

            #[cfg(feature = "trojan")]
            Protocol::Trojan => build_trojan_server(context, settings),

            #[cfg(feature = "tuic")]
            Protocol::TuicV5 => build_tuic_server(context, settings),

            Protocol::Xhttp => {
                Err(Error::InvalidConfig(
                    "protocol=xhttp is no longer supported; use protocol=vless with streamSettings.network=xhttp"
                        .into(),
                ))
            }

            #[cfg(feature = "http")]
            Protocol::Http => build_http_server(context, settings),
            #[cfg(not(feature = "http"))]
            Protocol::Http => Err(Error::InvalidConfig(
                "http inbound requires the http feature".into(),
            )),
            #[cfg(feature = "mixed")]
            Protocol::Mixed => build_mixed_server(context, settings),
            #[cfg(not(feature = "mixed"))]
            Protocol::Mixed => Err(Error::InvalidConfig(
                "mixed inbound requires the mixed feature".into(),
            )),
            #[cfg(feature = "shadowsocks")]
            Protocol::Shadowsocks => build_shadowsocks_server(context, settings),
            #[cfg(not(feature = "shadowsocks"))]
            Protocol::Shadowsocks => Err(Error::InvalidConfig(
                "shadowsocks inbound requires the shadowsocks feature".into(),
            )),

            Protocol::Socks => build_socks_server(context, settings),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inbound_for_protocol(protocol: &str) -> InboudItem {
        serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": protocol,
            "tag": format!("{protocol}-planned")
        }))
        .expect("valid inbound item")
    }

    #[test]
    fn tcp_sockopt_preserves_xray_congestion_and_validates_brutal_v2() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "socks",
            "tag": "socks-brutal",
            "settings": {},
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpCongestion": "brutal",
                    "tcpBrutalRate": "150mbps",
                    "tcpBrutalCwndGain": 20
                }
            }
        }))
        .expect("valid TCP Brutal inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("TCP Brutal socket policy should build");
        let policy = config
            .tcp_socket_policy
            .expect("TCP socket policy should be retained");
        assert_eq!(policy.congestion, "brutal");
        let brutal = policy.brutal.expect("Brutal settings should be retained");
        assert_eq!(brutal.rate_bytes_per_sec, 18_750_000);
        assert_eq!(brutal.cwnd_gain, 20);

        let bbr: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10001,
            "protocol": "socks",
            "tag": "socks-bbr",
            "settings": {},
            "streamSettings": {
                "network": "tcp",
                "sockopt": { "tcpCongestion": "bbr" }
            }
        }))
        .expect("valid BBR inbound");
        let bbr =
            ServerConfig::try_from(bbr).expect("Xray tcpCongestion should build");
        let policy = bbr
            .tcp_socket_policy
            .expect("BBR policy should be retained");
        assert_eq!(policy.congestion, "bbr");
        assert!(policy.brutal.is_none());
    }

    #[test]
    fn tcp_sockopt_preserves_xray_listener_and_connection_options() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::1",
            "port": 10002,
            "protocol": "socks",
            "tag": "socks-sockopt",
            "settings": {},
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpKeepAliveIdle": 11,
                    "tcpKeepAliveInterval": 7,
                    "tcpUserTimeout": 12345,
                    "tcpWindowClamp": 32768,
                    "tcpMaxSeg": 1200,
                    "tcpMptcp": true,
                    "v6only": true,
                    "interface": "lo",
                    "mark": 17,
                    "tproxy": "redirect",
                    "customSockopt": [{
                        "system": "linux",
                        "network": "tcp",
                        "level": "1",
                        "opt": "2",
                        "value": "1",
                        "type": "int"
                    }]
                }
            }
        }))
        .expect("Xray TCP socket options should deserialize");
        let config = ServerConfig::try_from(inbound)
            .expect("Xray TCP socket options should build");
        let policy = config
            .tcp_socket_policy
            .expect("TCP socket policy should be retained");
        assert_eq!(policy.fast_open, Some(256));
        assert_eq!(policy.keep_alive_idle, 11);
        assert_eq!(policy.keep_alive_interval, 7);
        assert_eq!(policy.user_timeout_ms, Some(12345));
        assert_eq!(policy.window_clamp, Some(32768));
        assert_eq!(policy.max_seg, Some(1200));
        assert!(policy.multipath);
        assert!(policy.ipv6_only);
        assert_eq!(policy.bind_interface.as_deref(), Some("lo"));
        assert_eq!(policy.mark, Some(17));
        assert!(policy.transparent);
        assert_eq!(policy.custom_sockopt.len(), 1);
    }

    #[test]
    fn receive_original_destination_rejects_tcp_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10003,
            "protocol": "socks",
            "tag": "socks-origdst-invalid",
            "settings": {},
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"receiveOriginalDestAddress": true}
            }
        }))
        .expect("receiveOriginalDestAddress should deserialize before validation");
        let error = ServerConfig::try_from(inbound)
            .expect_err("receiveOriginalDestAddress must not become a TCP no-op");
        assert!(error.to_string().contains("receiveOriginalDestAddress"));
    }

    #[test]
    fn tcp_brutal_sockopt_rejects_missing_or_mismatched_rate() {
        for sockopt in [
            serde_json::json!({ "tcpCongestion": "brutal" }),
            serde_json::json!({
                "tcpCongestion": "bbr",
                "tcpBrutalRate": "150mbps"
            }),
            serde_json::json!({ "tcpBrutalRate": "150mbps" }),
        ] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 10000,
                "protocol": "socks",
                "tag": "socks-invalid-brutal",
                "settings": {},
                "streamSettings": {
                    "network": "tcp",
                    "sockopt": sockopt
                }
            }))
            .expect("socket policy should deserialize before validation");
            let error = ServerConfig::try_from(inbound)
                .expect_err("invalid TCP Brutal socket policy must be rejected");
            assert!(error.to_string().contains("tcpBrutal"), "{error}");
        }
    }

    #[cfg(feature = "grpc_transport")]
    #[test]
    fn grpc_inbound_preserves_xray_custom_service_name() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "socks",
            "tag": "socks-grpc-custom",
            "settings": {},
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "/my/sample path/tun service|multi service"
                }
            }
        }))
        .expect("valid gRPC custom service inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("custom gRPC service should build");
        match config.protocol {
            ServerProxyConfig::Grpc(config) => {
                assert_eq!(
                    config.service_name,
                    "/my/sample path/tun service|multi service"
                );
            }
            other => panic!("expected gRPC protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "grpc_transport")]
    #[test]
    fn grpc_inbound_accepts_empty_service_name_like_xray_v26_2_6() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "socks",
            "tag": "socks-grpc-empty",
            "settings": {},
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": ""
                }
            }
        }))
        .expect("valid empty gRPC service inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("Xray accepts an explicitly empty gRPC serviceName");
        match config.protocol {
            ServerProxyConfig::Grpc(config) => {
                assert!(config.service_name.is_empty())
            }
            other => panic!("expected gRPC protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "grpc_transport")]
    #[test]
    fn grpc_inbound_preserves_multi_mode() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "socks",
            "tag": "socks-grpc-multi",
            "settings": {},
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "chimera-multi",
                    "multiMode": true,
                    "idleTimeout": 7,
                    "healthCheckTimeout": 3
                },
                "sockopt": {
                    "trustedXForwardedFor": ["X-Trusted-CDN"]
                }
            }
        }))
        .expect("valid gRPC multiMode inbound");
        let config =
            ServerConfig::try_from(inbound).expect("gRPC multiMode should build");
        match config.protocol {
            ServerProxyConfig::Grpc(config) => {
                assert_eq!(config.service_name, "chimera-multi");
                assert!(config.multi_mode);
                assert_eq!(config.idle_timeout, 7);
                assert_eq!(config.health_check_timeout, 3);
                assert_eq!(
                    config.trusted_x_forwarded_for,
                    vec!["X-Trusted-CDN".to_string()]
                );
                assert!(matches!(*config.inner, ServerProxyConfig::Socks { .. }));
            }
            other => panic!("expected gRPC protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "hysteria")]
    fn hysteria2_inbound_with_finalmask_settings(
        final_mask: serde_json::Value,
    ) -> InboudItem {
        serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "hysteria2",
            "tag": "hysteria2-finalmask",
            "settings": {
                "clients": [{ "auth": "secret" }]
            },
            "streamSettings": {
                "network": "hysteria2",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": "cert.pem",
                        "keyFile": "key.pem"
                    }]
                },
                "finalmask": final_mask
            }
        }))
        .expect("valid hysteria2 inbound")
    }

    #[cfg(feature = "hysteria")]
    fn hysteria2_inbound_with_finalmask_quic_params(
        quic_params: serde_json::Value,
    ) -> InboudItem {
        hysteria2_inbound_with_finalmask_settings(serde_json::json!({
            "quicParams": quic_params
        }))
    }

    #[cfg(feature = "hysteria")]
    fn hysteria2_inbound_with_finalmask(
        max_idle_timeout: i64,
        max_incoming_streams: i64,
    ) -> InboudItem {
        hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
            "maxIdleTimeout": max_idle_timeout,
            "maxIncomingStreams": max_incoming_streams
        }))
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_accepts_xray_transport_auth_without_users() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "hysteria2",
            "tag": "hysteria2-transport-auth",
            "settings": {
                "version": 2
            },
            "streamSettings": {
                "network": "hysteria2",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": "cert.pem",
                        "keyFile": "key.pem"
                    }]
                },
                "hysteriaSettings": {
                    "version": 2,
                    "auth": "transport-auth-token"
                }
            }
        }))
        .expect("valid Xray hysteria2 transport auth inbound");

        let config = ServerConfig::try_from(inbound).expect(
            "Xray transport-level auth should satisfy Hysteria2 authentication",
        );
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(config.clients.len(), 1);
                assert_eq!(config.clients[0].password, "transport-auth-token");
                assert_eq!(config.clients[0].email, None);
                assert!(config.xray_compat);
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_rejects_unsupported_active_transport_features() {
        for udp_hop in [
            serde_json::json!({"ports": 443}),
            serde_json::json!({"ports": "443,8443"}),
            serde_json::json!({"interval": 5}),
            serde_json::json!({"interval": "5-10"}),
        ] {
            let err = ServerConfig::try_from(
                hysteria2_inbound_with_finalmask_quic_params(
                    serde_json::json!({"udpHop": udp_hop}),
                ),
            )
            .expect_err("configured Xray UDP hop must fail explicitly");
            assert!(err.to_string().contains("udpHop"), "{err}");
        }

        for inert_udp_hop in [
            serde_json::json!({}),
            serde_json::json!({"ports": 0, "interval": 0}),
            serde_json::json!({"ports": "", "interval": "0-0"}),
        ] {
            ServerConfig::try_from(hysteria2_inbound_with_finalmask_quic_params(
                serde_json::json!({"udpHop": inert_udp_hop}),
            ))
            .expect("empty/inert Xray UDP hop should remain compatible");
        }

        let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask_settings(
            serde_json::json!({"tcp": [{"type": "unsupported-mask"}]}),
        ))
        .expect_err("configured TCP finalmask chain must fail explicitly");
        assert!(err.to_string().contains("finalmask.tcp"), "{err}");

        let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask_settings(
            serde_json::json!({"udp": [{"type": "unsupported-mask"}]}),
        ))
        .expect_err("unknown UDP finalmask type must fail explicitly");
        assert!(err.to_string().contains("not implemented"), "{err}");
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_accepts_salamander_and_gecko_udp_masks() {
        use crate::config::server_config::Hysteria2UdpFinalMask;

        let config = ServerConfig::try_from(
            hysteria2_inbound_with_finalmask_settings(serde_json::json!({
                "udp": [{
                    "type": "salamander",
                    "settings": {"password": "secret"}
                }]
            })),
        )
        .expect("single Xray Salamander UDP mask should build");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => assert!(matches!(
                config.udp_finalmask,
                Some(Hysteria2UdpFinalMask::Salamander { ref password })
                    if password == "secret"
            )),
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }

        let config = ServerConfig::try_from(
            hysteria2_inbound_with_finalmask_settings(serde_json::json!({
                "udp": [{
                    "type": "salamander",
                    "settings": {
                        "password": "secret",
                        "packetSize": "600-1200"
                    }
                }]
            })),
        )
        .expect("Xray packetSize enables Gecko framing over Salamander");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => assert!(matches!(
                config.udp_finalmask,
                Some(Hysteria2UdpFinalMask::Gecko {
                    ref password,
                    min_packet_size: 600,
                    max_packet_size: 1200,
                }) if password == "secret"
            )),
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_max_idle_timeout_matches_xray_default() {
        let config = ServerConfig::try_from(hysteria2_inbound_with_finalmask(0, 0))
            .expect("Xray zero maxIdleTimeout should use its default");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(config.xray_max_idle_timeout_secs, Some(30));
                assert_eq!(config.xray_max_incoming_streams, Some(1024));
                assert_eq!(config.xray_disable_path_mtu_discovery, Some(false));
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_rejects_out_of_range_max_idle_timeout() {
        let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask(3, 0))
            .expect_err("Xray rejects maxIdleTimeout below four seconds");
        assert!(err.to_string().contains("maxIdleTimeout"));
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_keep_alive_period_matches_xray_bounds() {
        for keep_alive_period in [0_u64, 2, 60] {
            let config = ServerConfig::try_from(
                hysteria2_inbound_with_finalmask_quic_params(
                    serde_json::json!({ "keepAlivePeriod": keep_alive_period }),
                ),
            )
            .expect("Xray accepts zero or bounded keepAlivePeriod");
            match config.protocol {
                ServerProxyConfig::Hysteria2 { config } => {
                    assert_eq!(
                        config.xray_keep_alive_period_secs,
                        Some(keep_alive_period)
                    );
                }
                other => panic!("expected hysteria2 protocol, got {other:?}"),
            }
        }

        for keep_alive_period in [1, 61] {
            let err = ServerConfig::try_from(
                hysteria2_inbound_with_finalmask_quic_params(
                    serde_json::json!({ "keepAlivePeriod": keep_alive_period }),
                ),
            )
            .expect_err("Xray rejects out-of-range keepAlivePeriod");
            assert!(err.to_string().contains("keepAlivePeriod"));
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_max_incoming_streams_matches_xray_bounds() {
        let config = ServerConfig::try_from(hysteria2_inbound_with_finalmask(
            30,
            1_i64 << 61,
        ))
        .expect("large Xray maxIncomingStreams should clamp to QUIC stream limit");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(config.xray_max_incoming_streams, Some(1_u64 << 60));
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }

        let err = ServerConfig::try_from(hysteria2_inbound_with_finalmask(30, 7))
            .expect_err("Xray rejects maxIncomingStreams below eight");
        assert!(err.to_string().contains("maxIncomingStreams"));
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_preserves_xray_path_mtu_discovery_flag() {
        let config = ServerConfig::try_from(
            hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
                "disablePathMTUDiscovery": true
            })),
        )
        .expect("valid Xray path MTU discovery setting should build");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(config.xray_disable_path_mtu_discovery, Some(true));
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_receive_windows_match_xray_bounds() {
        let config = ServerConfig::try_from(
            hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
                "initStreamReceiveWindow": 32768,
                "maxStreamReceiveWindow": 65536,
                "initConnectionReceiveWindow": 131072,
                "maxConnectionReceiveWindow": 262144
            })),
        )
        .expect("valid Xray Hysteria2 receive windows should build");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(config.xray_init_stream_receive_window, Some(32_768));
                assert_eq!(config.xray_max_stream_receive_window, Some(65_536));
                assert_eq!(
                    config.xray_init_connection_receive_window,
                    Some(131_072)
                );
                assert_eq!(config.xray_max_connection_receive_window, Some(262_144));
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }

        for field in [
            "initStreamReceiveWindow",
            "maxStreamReceiveWindow",
            "initConnectionReceiveWindow",
            "maxConnectionReceiveWindow",
        ] {
            let mut params = serde_json::Map::new();
            params.insert(field.to_string(), serde_json::json!(16_383));
            let err = ServerConfig::try_from(
                hysteria2_inbound_with_finalmask_quic_params(
                    serde_json::Value::Object(params),
                ),
            )
            .expect_err("Xray rejects receive windows below 16384");
            assert!(err.to_string().contains(field), "{err}");
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_congestion_matches_xray_settings() {
        let config = ServerConfig::try_from(
            hysteria2_inbound_with_finalmask_quic_params(serde_json::json!({
                "congestion": "FORCE-BRUTAL",
                "bbrProfile": "AGGRESSIVE",
                "brutalUp": "8 mbps",
                "brutalDown": "0.5 mbps"
            })),
        )
        .expect("valid Xray Hysteria2 congestion settings should build");
        match config.protocol {
            ServerProxyConfig::Hysteria2 { config } => {
                assert_eq!(config.xray_congestion.as_deref(), Some("force-brutal"));
                assert_eq!(config.xray_bbr_profile.as_deref(), Some("aggressive"));
                assert_eq!(config.xray_brutal_up, Some(1024 * 1024));
                assert_eq!(config.xray_brutal_down, Some(65_536));
            }
            other => panic!("expected hysteria2 protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "hysteria")]
    #[test]
    fn hysteria2_finalmask_congestion_rejects_xray_invalid_values() {
        for (params, expected) in [
            (serde_json::json!({"congestion": "cubic"}), "congestion"),
            (serde_json::json!({"bbrProfile": "turbo"}), "bbrProfile"),
            (
                serde_json::json!({
                    "congestion": "bbr",
                    "bbrProfile": "aggressive"
                }),
                "not supported when Xray may use BBR",
            ),
            (
                serde_json::json!({
                    "congestion": "brutal",
                    "bbrProfile": "conservative"
                }),
                "not supported when Xray may use BBR",
            ),
            (
                serde_json::json!({"congestion": "force-brutal"}),
                "requires brutalUp",
            ),
            (serde_json::json!({"brutalUp": "8 kbps"}), "brutalUp"),
            (serde_json::json!({"brutalDown": "8 kbps"}), "brutalDown"),
        ] {
            let err = ServerConfig::try_from(
                hysteria2_inbound_with_finalmask_quic_params(params),
            )
            .expect_err("invalid Xray congestion settings must be rejected");
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_inbound_builds_without_accounts() {
        let config = ServerConfig::try_from(inbound_for_protocol("http"))
            .expect("HTTP CONNECT inbound should build");
        match config.protocol {
            ServerProxyConfig::Http {
                accounts,
                allow_transparent,
                user_level,
            } => {
                assert!(accounts.is_empty());
                assert!(!allow_transparent);
                assert_eq!(user_level, 0);
            }
            other => panic!("expected http protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_inbound_preserves_xray_user_level() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "http",
            "tag": "http-policy",
            "settings": {
                "userLevel": 7
            }
        }))
        .expect("valid HTTP policy inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("Xray HTTP settings.userLevel should be accepted");
        match config.protocol {
            ServerProxyConfig::Http { user_level, .. } => assert_eq!(user_level, 7),
            other => panic!("expected http protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_inbound_preserves_allow_transparent() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "http",
            "tag": "http-transparent",
            "settings": {
                "allowTransparent": true
            }
        }))
        .expect("valid HTTP transparent inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("transparent HTTP inbound should build");
        match config.protocol {
            ServerProxyConfig::Http {
                allow_transparent, ..
            } => assert!(allow_transparent),
            other => panic!("expected http protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "mixed")]
    #[test]
    fn mixed_inbound_builds_with_noauth_defaults() {
        let config = ServerConfig::try_from(inbound_for_protocol("mixed"))
            .expect("mixed inbound should build");
        match config.protocol {
            ServerProxyConfig::Mixed {
                accounts,
                udp_enabled,
            } => {
                assert!(!accounts.auth_required());
                assert!(accounts.snapshot().is_empty());
                assert!(!udp_enabled);
            }
            other => panic!("expected mixed protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn shadowsocks_inbound_builds_legacy_tcp() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "shadowsocks",
            "tag": "ss-in",
            "settings": {
                "method": "aes-128-gcm",
                "password": "secret",
                "email": "ss@example.test",
                "network": "tcp"
            }
        }))
        .expect("valid shadowsocks inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("legacy Shadowsocks TCP should build");
        match config.protocol {
            ServerProxyConfig::Shadowsocks { users, identity } => {
                assert!(identity.is_none());
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].method, "aes-128-gcm");
                assert_eq!(users[0].password, "secret");
                assert_eq!(users[0].email, "ss@example.test");
            }
            other => panic!("expected shadowsocks protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn shadowsocks_inbound_preserves_multiple_legacy_users() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "shadowsocks",
            "tag": "ss-multi-user",
            "settings": {
                "clients": [{
                    "method": "aes-128-gcm",
                    "password": "secret-a",
                    "email": "a@example.test"
                }, {
                    "method": "chacha20-ietf-poly1305",
                    "password": "secret-b",
                    "email": "b@example.test"
                }],
                "network": "tcp,udp"
            }
        }))
        .expect("valid Shadowsocks multi-user inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("legacy Shadowsocks multi-user should build");
        match config.protocol {
            ServerProxyConfig::Shadowsocks { users, identity } => {
                assert!(identity.is_none());
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].email, "a@example.test");
                assert_eq!(users[1].email, "b@example.test");
            }
            other => panic!("expected shadowsocks protocol, got {other:?}"),
        }
        assert_eq!(config.transport, Transport::TcpAndUdp);
    }

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn shadowsocks_inbound_preserves_2022_multi_user_eih() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "shadowsocks",
            "tag": "ss-2022-multi-user",
            "settings": {
                "method": "2022-blake3-aes-128-gcm",
                "password": "AAECAwQFBgcICQoLDA0ODw==",
                "clients": [{
                    "password": "EBESExQVFhcYGRobHB0eHw==",
                    "email": "user-a@example.test"
                }, {
                    "password": "ICEiIyQlJicoKSorLC0uLw==",
                    "email": "user-b@example.test"
                }],
                "network": "tcp,udp"
            }
        }))
        .expect("valid Shadowsocks 2022 multi-user shape");
        let config = ServerConfig::try_from(inbound)
            .expect("2022 multi-user EIH should build");
        match config.protocol {
            ServerProxyConfig::Shadowsocks { users, identity } => {
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].method, "2022-blake3-aes-128-gcm");
                assert_eq!(users[0].email, "user-a@example.test");
                assert_eq!(users[1].email, "user-b@example.test");
                let identity = identity.expect("server EIH identity");
                assert_eq!(identity.method, "2022-blake3-aes-128-gcm");
                assert_eq!(identity.password, "AAECAwQFBgcICQoLDA0ODw==");
            }
            other => panic!("expected shadowsocks protocol, got {other:?}"),
        }
        assert_eq!(config.transport, Transport::TcpAndUdp);
    }

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn shadowsocks_inbound_builds_tcp_and_udp_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "shadowsocks",
            "tag": "ss-udp",
            "settings": {
                "method": "aes-128-gcm",
                "password": "secret",
                "network": "tcp,udp"
            }
        }))
        .expect("valid shadowsocks inbound shape");
        let config = ServerConfig::try_from(inbound)
            .expect("Shadowsocks TCP+UDP should build");
        assert_eq!(config.transport, Transport::TcpAndUdp);
    }

    #[test]
    fn inbound_builder_compiles_xray_sniffing_and_exclusions() {
        let inbound = serde_json::from_value::<InboudItem>(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-sniff",
            "settings": {"address": "127.0.0.1", "port": 53},
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "https", "ssl"],
                "routeOnly": true,
                "domainsExcluded": ["domain:example.com", "regexp:^private\\."],
                "ipsExcluded": ["192.0.2.0/24"]
            }
        }))
        .expect("literal sniffing inbound should parse");
        let config = ServerConfig::try_from(inbound)
            .expect("Xray sniffing config should compile");
        let sniffing = config.sniffing.expect("compiled sniffing config");
        assert!(sniffing.enabled);
        assert!(sniffing.route_only);
        assert!(sniffing.dest_override_http);
        assert!(sniffing.dest_override_tls);
        assert!(sniffing.excludes_domain("api.example.com"));
        assert!(sniffing.excludes_domain("private.test"));
        assert!(!sniffing.excludes_domain("public.test"));
        assert!(sniffing.excludes_ip("192.0.2.7".parse().unwrap()));
        assert!(!sniffing.excludes_ip("198.51.100.7".parse().unwrap()));

        let quic_only = serde_json::from_value::<InboudItem>(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-sniff-quic",
            "settings": {"address": "127.0.0.1", "port": 53},
            "sniffing": {"enabled": true, "destOverride": ["quic"]}
        }))
        .expect("literal QUIC compatibility sniffing inbound should parse");
        let quic_config = ServerConfig::try_from(quic_only)
            .expect("Xray QUIC destOverride should be accepted as a no-op");
        let quic_sniffing =
            quic_config.sniffing.expect("compiled QUIC sniffing config");
        assert!(quic_sniffing.enabled);
        assert!(!quic_sniffing.dest_override_http);
        assert!(!quic_sniffing.dest_override_tls);

        for sniffing in [
            serde_json::json!({"enabled": true, "metadataOnly": true}),
            serde_json::json!({"enabled": true, "destOverride": ["fakedns"]}),
            serde_json::json!({"enabled": true, "domainsExcluded": ["regexp:(invalid"]}),
            serde_json::json!({"enabled": true, "ipsExcluded": ["192.0.2.0/99"]}),
        ] {
            let inbound = serde_json::from_value::<InboudItem>(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 10000,
                "protocol": "dokodemo-door",
                "tag": "dokodemo-sniff-invalid",
                "settings": {"address": "127.0.0.1", "port": 53},
                "sniffing": sniffing
            }))
            .expect("literal invalid sniffing inbound should parse");
            let error = ServerConfig::try_from(inbound)
                .expect_err("unsupported or malformed sniffing must fail closed");
            assert!(error.to_string().contains("sniffing"));
        }
    }

    #[test]
    fn dokodemo_door_udp_network_builds_udp_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-udp",
            "settings": {
                "address": "127.0.0.1",
                "port": 5353
            },
            "streamSettings": {
                "network": "udp"
            }
        }))
        .expect("valid dokodemo udp inbound item");

        let config =
            ServerConfig::try_from(inbound).expect("dokodemo udp should build");
        assert_eq!(config.transport, Transport::Udp);
        match config.protocol {
            ServerProxyConfig::DokodemoDoor { config } => {
                assert_eq!(config.target.port(), 5353);
            }
            other => panic!("expected dokodemo-door, got {other:?}"),
        }
    }

    #[test]
    fn dokodemo_udp_preserves_generic_listener_sockopts() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10004,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-udp-sockopt",
            "settings": {"address": "127.0.0.1", "port": 5353},
            "streamSettings": {
                "network": "udp",
                "sockopt": {
                    "interface": "lo",
                    "mark": 17,
                    "tproxy": "redirect",
                    "receiveOriginalDestAddress": true,
                    "customSockopt": [{
                        "system": "linux",
                        "network": "udp4",
                        "level": "1",
                        "opt": "2",
                        "value": "1",
                        "type": "int"
                    }]
                }
            }
        }))
        .expect("UDP listener sockopts should deserialize");
        let config = ServerConfig::try_from(inbound)
            .expect("generic UDP listener sockopts should build");
        let policy = config
            .tcp_socket_policy
            .expect("UDP listener policy should be retained");
        assert_eq!(policy.bind_interface.as_deref(), Some("lo"));
        assert_eq!(policy.mark, Some(17));
        assert!(policy.transparent);
        assert!(policy.receive_original_destination);
        assert_eq!(policy.custom_sockopt.len(), 1);
        assert!(!policy.has_tcp_only_options());

        let invalid: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10005,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-udp-tcp-only-sockopt",
            "settings": {"address": "127.0.0.1", "port": 5353},
            "streamSettings": {
                "network": "udp",
                "sockopt": {"tcpFastOpen": true}
            }
        }))
        .expect("TCP-only UDP sockopt should deserialize before validation");
        let error = ServerConfig::try_from(invalid)
            .expect_err("TCP-only UDP listener option must fail closed");
        assert!(error.to_string().contains("TCP socket options"));
    }

    #[test]
    fn dokodemo_door_rejects_udp_security_layers() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-udp-tls",
            "settings": {
                "address": "127.0.0.1",
                "port": 5353
            },
            "streamSettings": {
                "network": "udp",
                "security": "tls"
            }
        }))
        .expect("valid dokodemo udp inbound item");

        let err = ServerConfig::try_from(inbound)
            .expect_err("udp security layers should be rejected");
        assert!(err.to_string().contains(
            "dokodemo-door udp transport does not support streamSettings.security"
        ));
    }

    #[test]
    fn xray_internal_tunnel_uses_rewrite_address_and_dokodemo_semantics() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 62789,
            "protocol": "tunnel",
            "settings": {"rewriteAddress": "127.0.0.1"},
            "tag": "api"
        }))
        .expect("valid Xray internal tunnel inbound");

        let config = ServerConfig::try_from(inbound)
            .expect("Xray internal tunnel should build");
        match config.protocol {
            ServerProxyConfig::DokodemoDoor { config } => {
                assert_eq!(config.target.port(), 62789);
                assert_eq!(config.target.address().to_string(), "127.0.0.1");
            }
            other => panic!("expected dokodemo-door semantics, got {other:?}"),
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    fn vless_reality_inbound(reality_settings: serde_json::Value) -> InboudItem {
        serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-reality-test",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "user@example.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": reality_settings
            }
        }))
        .expect("valid vless reality inbound item")
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    fn base_reality_settings() -> serde_json::Value {
        serde_json::json!({
            "show": false,
            "dest": "www.apple.com:443",
            "xver": 0,
            "serverNames": ["www.apple.com"],
            "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
            "shortIds": ["4ac97aaf8b9b0356"],
            "maxTimeDiff": 0,
            "minClient": "",
            "maxClient": ""
        })
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_preserves_multiple_clients() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-multi-user",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "user-a@example.com"
                    },
                    {
                        "id": "e041e73e-a0a0-49f5-9754-6401aa621fb7",
                        "email": "user-b@example.com"
                    }
                ],
                "decryption": "none"
            }
        }))
        .expect("valid vless inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vless inbound config should build");

        match config.protocol {
            ServerProxyConfig::Vless { users, .. } => {
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].user_id, "3ac9b383-75a1-431c-8184-106c80eb2273");
                assert_eq!(users[0].user_label, "user-a@example.com");
                assert_eq!(users[0].flow, "");
                assert_eq!(users[1].user_id, "e041e73e-a0a0-49f5-9754-6401aa621fb7");
                assert_eq!(users[1].user_label, "user-b@example.com");
                assert_eq!(users[1].flow, "");
            }
            other => panic!("expected vless protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_preserves_client_flow() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-vision-flow",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "vision-user@example.com",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.apple.com:443",
                    "xver": 0,
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "maxTimeDiff": 0,
                    "minClient": "",
                    "maxClient": ""
                }
            }
        }))
        .expect("valid vless inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vless inbound config should build");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
                ServerProxyConfig::Vless { users, .. } => {
                    assert_eq!(users.len(), 1);
                    assert_eq!(users[0].flow, "xtls-rprx-vision");
                }
                other => {
                    panic!("expected vless protocol inside reality, got {other:?}")
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => match tls.inner.as_ref() {
                ServerProxyConfig::Vless { users, .. } => {
                    assert_eq!(users.len(), 1);
                    assert_eq!(users[0].flow, "xtls-rprx-vision");
                }
                other => panic!("expected vless protocol inside tls, got {other:?}"),
            },
            ServerProxyConfig::Vless { users, .. } => {
                assert_eq!(users.len(), 1);
                assert_eq!(users[0].flow, "xtls-rprx-vision");
            }
            other => panic!("expected vless protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn vless_reality_builder_preserves_cipher_suites() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-reality-cipher-suites",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "user@example.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.apple.com:443",
                    "xver": 0,
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "cipherSuites": [
                        "TLS_CHACHA20_POLY1305_SHA256",
                        "TLS_AES_128_GCM_SHA256"
                    ],
                    "maxTimeDiff": 0,
                    "minClient": "",
                    "maxClient": ""
                }
            }
        }))
        .expect("valid vless inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vless reality inbound config should build");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => {
                assert_eq!(reality.min_client_version, None);
                assert_eq!(
                    reality.cipher_suites,
                    vec![
                        crate::reality::CipherSuite::CHACHA20_POLY1305_SHA256,
                        crate::reality::CipherSuite::AES_128_GCM_SHA256,
                    ]
                );
                assert_eq!(
                    reality.to_reality_server_config().cipher_suites,
                    reality.cipher_suites
                );
            }
            other => panic!("expected reality protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn vless_reality_rejects_missing_short_ids() {
        let mut settings = base_reality_settings();
        settings
            .as_object_mut()
            .expect("reality settings object")
            .remove("shortIds");

        let err = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect_err("xray-compatible REALITY inbound requires shortIds");
        assert!(
            err.to_string()
                .contains("reality inbound requires at least one shortId")
        );
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn vless_reality_preserves_explicit_min_client_version() {
        let mut settings = base_reality_settings();
        settings["minClient"] = serde_json::json!("25.1.2");

        let config = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect("explicit minClient should override the Xray default");
        match config.protocol {
            ServerProxyConfig::Reality(reality) => {
                assert_eq!(reality.min_client_version, Some([25, 1, 2]));
            }
            other => panic!("expected reality protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn vless_reality_rejects_invalid_client_version_shape() {
        let mut settings = base_reality_settings();
        settings["minClient"] = serde_json::json!("1.8");

        let err = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect_err("minClient without patch component should fail");
        assert!(
            err.to_string()
                .contains("minClientVer must use major.minor.patch format")
        );
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn vless_reality_rejects_outbound_only_settings() {
        let mut settings = base_reality_settings();
        settings["publicKey"] = serde_json::json!("client-side-public-key");

        let err = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect_err("publicKey is not an inbound setting");
        assert!(
            err.to_string()
                .contains("reality publicKey is an outbound/client setting")
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_inherits_settings_flow() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-settings-flow",
            "settings": {
                "flow": "xtls-rprx-vision",
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "inherited-flow@example.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.apple.com:443",
                    "xver": 0,
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "maxTimeDiff": 0,
                    "minClient": "",
                    "maxClient": ""
                }
            }
        }))
        .expect("valid vless inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vless inbound config should build");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
                ServerProxyConfig::Vless { users, .. } => {
                    assert_eq!(users.len(), 1);
                    assert_eq!(users[0].flow, "xtls-rprx-vision");
                }
                other => {
                    panic!("expected vless protocol inside reality, got {other:?}")
                }
            },
            other => panic!("expected reality protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_unknown_settings_flow() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-invalid-settings-flow",
            "settings": {
                "flow": "xtls-rprx-vision-udp443",
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "bad-settings-flow@example.com"
                    }
                ],
                "decryption": "none"
            }
        }))
        .expect("valid vless inbound item");

        let err = ServerConfig::try_from(inbound)
            .expect_err("unsupported vless settings flow should fail validation");
        assert!(
            err.to_string().contains(
                "vless clients.flow doesn't support xtls-rprx-vision-udp443"
            )
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_unknown_client_flow() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-invalid-flow",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "bad-flow@example.com",
                        "flow": "xtls-rprx-vision-udp443"
                    }
                ],
                "decryption": "none"
            }
        }))
        .expect("valid vless inbound item");

        let err = ServerConfig::try_from(inbound)
            .expect_err("unsupported vless flow should fail validation");
        assert!(
            err.to_string().contains(
                "vless clients.flow doesn't support xtls-rprx-vision-udp443"
            )
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_vision_without_tls_or_reality() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-vision-no-tls",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "vision-user@example.com",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            }
        }))
        .expect("valid vless inbound item");

        let err = ServerConfig::try_from(inbound)
            .expect_err("vision without tls/reality should fail");
        assert!(err.to_string().contains(
            "xtls-rprx-vision requires streamSettings.security=tls or reality"
        ));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_accepts_mixed_plain_and_vision_users() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-mixed-flow-users",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "plain-user@example.com"
                    },
                    {
                        "id": "e041e73e-a0a0-49f5-9754-6401aa621fb7",
                        "email": "vision-user@example.com",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.apple.com:443",
                    "xver": 0,
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "maxTimeDiff": 0,
                    "minClient": "",
                    "maxClient": ""
                }
            }
        }))
        .expect("valid vless inbound item");

        let server_config = ServerConfig::try_from(inbound)
            .expect("mixed plain and vision users should build");
        assert_eq!(server_config.tag, "vless-mixed-flow-users");
    }

    #[cfg(all(feature = "vless", feature = "ws"))]
    #[test]
    fn vless_builder_rejects_vision_over_websocket() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-vision-ws",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "vision-user@example.com",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "security": "tls",
                "wsSettings": {
                    "host": "example.com",
                    "path": "/ws"
                },
                "tlsSettings": {
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .expect("valid vless inbound item");

        let err = ServerConfig::try_from(inbound)
            .expect_err("vision over websocket should fail");
        assert!(
            err.to_string()
                .contains("xtls-rprx-vision does not support websocket transport")
        );
    }

    #[cfg(all(feature = "tls", feature = "vless"))]
    #[test]
    fn vless_xhttp_accepts_http3_tls_configuration() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-http3",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "user@example.com"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                },
                "xhttpSettings": {
                    "path": "/xhttp"
                },
                "sockopt": {
                    "v6only": true,
                    "interface": "lo",
                    "mark": 17,
                    "tproxy": "redirect",
                    "customSockopt": [{
                        "system": "linux",
                        "network": "udp4",
                        "level": "1",
                        "opt": "2",
                        "value": "1",
                        "type": "int"
                    }]
                },
                "finalmask": {
                    "quicParams": {
                        "congestion": "RENO",
                        "maxIdleTimeout": 45,
                        "maxIncomingStreams": 64,
                        "initStreamReceiveWindow": 32768,
                        "maxStreamReceiveWindow": 65536,
                        "initConnectionReceiveWindow": 131072,
                        "maxConnectionReceiveWindow": 262144,
                        "disablePathMTUDiscovery": true
                    }
                }
            }
        }))
        .expect("valid inbound item");

        let server = ServerConfig::try_from(inbound)
            .expect("XHTTP/3 TLS configuration should build");
        let policy = server
            .tcp_socket_policy
            .as_ref()
            .expect("XHTTP/3 generic listener sockopts should be retained");
        assert!(policy.ipv6_only);
        assert_eq!(policy.bind_interface.as_deref(), Some("lo"));
        assert_eq!(policy.mark, Some(17));
        assert!(policy.transparent);
        assert_eq!(policy.custom_sockopt.len(), 1);
        assert!(!policy.has_tcp_only_options());
        let ServerProxyConfig::Tls(tls) = server.protocol else {
            panic!("expected TLS-wrapped XHTTP protocol");
        };
        assert_eq!(tls.alpn_protocols, vec!["h3"]);
        let ServerProxyConfig::Xhttp { config, .. } = *tls.inner else {
            panic!("expected XHTTP inside TLS");
        };
        assert_eq!(config.xray_congestion.as_deref(), Some("reno"));
        assert_eq!(config.xray_max_idle_timeout_secs, Some(45));
        assert_eq!(config.xray_max_incoming_streams, Some(64));
        assert_eq!(config.xray_init_stream_receive_window, Some(32_768));
        assert_eq!(config.xray_max_stream_receive_window, Some(65_536));
        assert_eq!(config.xray_init_connection_receive_window, Some(131_072));
        assert_eq!(config.xray_max_connection_receive_window, Some(262_144));
        assert_eq!(config.xray_disable_path_mtu_discovery, Some(true));
    }

    #[cfg(feature = "vless")]
    fn xhttp_inbound_with_quic_params(quic_params: serde_json::Value) -> InboudItem {
        serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-quic-params",
            "settings": {
                "clients": [{ "id": "3ac9b383-75a1-431c-8184-106c80eb2273" }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": { "path": "/xhttp" },
                "finalmask": { "quicParams": quic_params }
            }
        }))
        .expect("valid XHTTP inbound")
    }

    #[cfg(all(feature = "tls", feature = "vless"))]
    #[test]
    fn vless_xhttp_accepts_xray_force_brutal_configuration() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-force-brutal",
            "settings": {
                "clients": [{ "id": "3ac9b383-75a1-431c-8184-106c80eb2273" }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                },
                "xhttpSettings": { "path": "/xhttp" },
                "finalmask": {
                    "quicParams": {
                        "congestion": "force-brutal",
                        "brutalUp": "8 mbps"
                    }
                }
            }
        }))
        .expect("valid inbound item");

        let server = ServerConfig::try_from(inbound)
            .expect("Xray force-brutal XHTTP/3 configuration should build");
        let ServerProxyConfig::Tls(tls) = server.protocol else {
            panic!("expected TLS-wrapped XHTTP protocol");
        };
        let ServerProxyConfig::Xhttp { config, .. } = *tls.inner else {
            panic!("expected XHTTP inside TLS");
        };
        assert_eq!(config.xray_congestion.as_deref(), Some("force-brutal"));
        assert_eq!(config.xray_brutal_up, Some(1024 * 1024));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_xhttp_validates_xray_bbr_profile_without_fake_parity() {
        for (congestion, profile) in
            [("reno", "aggressive"), ("force-brutal", "conservative")]
        {
            let mut quic_params = serde_json::json!({
                "congestion": congestion,
                "bbrProfile": profile,
            });
            if congestion == "force-brutal" {
                quic_params["brutalUp"] = serde_json::json!("8 mbps");
            }
            let inbound = xhttp_inbound_with_quic_params(quic_params);
            ServerConfig::try_from(inbound)
                .expect("BBR profile is inert when Xray does not use BBR");
        }

        for profile in ["conservative", "aggressive"] {
            let inbound = xhttp_inbound_with_quic_params(serde_json::json!({
                "congestion": "bbr",
                "bbrProfile": profile,
            }));
            let err = ServerConfig::try_from(inbound).expect_err(
                "unsupported active Xray BBR profile must not be silently ignored",
            );
            assert!(
                err.to_string().contains(
                    "finalmask.quicParams.bbrProfile conservative/aggressive is not supported when Xray may use BBR"
                ),
                "unexpected error: {err}"
            );
        }

        let inbound = xhttp_inbound_with_quic_params(serde_json::json!({
            "bbrProfile": "turbo",
        }));
        let err = ServerConfig::try_from(inbound)
            .expect_err("Xray-invalid BBR profile must fail");
        assert!(
            err.to_string().contains(
                "finalmask.quicParams.bbrProfile must be one of conservative, standard, aggressive"
            ),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_xhttp_finalmask_keep_alive_period_matches_xray_bounds() {
        for keep_alive_period in [0_i64, 2, 60] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "tag": "xhttp-keepalive",
                "settings": {
                    "clients": [{
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "user@example.com"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "path": "/xhttp"
                    },
                    "finalmask": {
                        "quicParams": {
                            "keepAlivePeriod": keep_alive_period
                        }
                    }
                }
            }))
            .expect("valid inbound item");

            ServerConfig::try_from(inbound)
                .expect("Xray-valid XHTTP keepAlivePeriod should build");
        }

        for keep_alive_period in [1_i64, 61] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "tag": "xhttp-keepalive",
                "settings": {
                    "clients": [{
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "user@example.com"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "path": "/xhttp"
                    },
                    "finalmask": {
                        "quicParams": {
                            "keepAlivePeriod": keep_alive_period
                        }
                    }
                }
            }))
            .expect("valid inbound item");

            let err = ServerConfig::try_from(inbound)
                .expect_err("Xray-invalid XHTTP keepAlivePeriod should fail");
            assert!(
                err.to_string().contains(
                    "finalmask.quicParams.keepAlivePeriod must be 0 or between 2 and 60 seconds"
                ),
                "unexpected error: {err}"
            );
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn vless_xhttp_reality_builds_nested_protocol_chain() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "xhttp-reality",
            "settings": {
                "clients": [
                    {
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                        "email": "user@example.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "sockopt": {
                    "trustedXForwardedFor": ["X-Trusted-CDN"]
                },
                "realitySettings": {
                    "show": false,
                    "dest": "www.apple.com:443",
                    "xver": 0,
                    "serverNames": ["www.apple.com"],
                    "privateKey": "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI",
                    "shortIds": ["4ac97aaf8b9b0356"],
                    "maxTimeDiff": 0,
                    "minClient": "",
                    "maxClient": ""
                },
                "xhttpSettings": {
                    "host": "www.apple.com",
                    "path": "/xhttp"
                }
            }
        }))
        .expect("valid inbound item");

        let config = ServerConfig::try_from(inbound).expect("xhttp reality config");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => match reality.inner.as_ref() {
                ServerProxyConfig::Xhttp { config, inner } => {
                    assert_eq!(
                        config.trusted_x_forwarded_for,
                        vec!["X-Trusted-CDN".to_string()]
                    );
                    assert!(matches!(
                        inner.as_ref(),
                        ServerProxyConfig::Vless { .. }
                    ));
                }
                other => panic!("expected xhttp inside reality, got {other:?}"),
            },
            other => panic!("expected reality protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn reality_settings_accepts_ip_dest_with_explicit_server_names() {
        let mut settings = base_reality_settings();
        let settings_object =
            settings.as_object_mut().expect("reality settings object");
        settings_object
            .insert("dest".to_string(), serde_json::json!("127.0.0.1:9443"));
        settings_object.insert(
            "serverNames".to_string(),
            serde_json::json!(["www.apple.com"]),
        );

        let config = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect("ip dest with explicit serverNames should build reality config");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => {
                assert_eq!(reality.dest.to_string(), "127.0.0.1:9443");
                assert_eq!(reality.server_names, vec!["www.apple.com".to_string()]);
            }
            other => panic!("expected reality protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn reality_settings_rejects_ip_dest_without_explicit_server_names() {
        let mut settings = base_reality_settings();
        let settings_object =
            settings.as_object_mut().expect("reality settings object");
        settings_object
            .insert("dest".to_string(), serde_json::json!("127.0.0.1:9443"));
        settings_object.remove("serverNames");

        let err = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect_err("ip dest without serverNames should fail");
        assert!(err.to_string().contains(
            "reality.dest may be an ip address only when realitySettings.serverNames is explicitly configured"
        ));
    }

    #[cfg(all(feature = "reality", feature = "vless"))]
    #[test]
    fn reality_settings_accepts_xray_target_alias() {
        let mut settings = base_reality_settings();
        let settings_object =
            settings.as_object_mut().expect("reality settings object");
        settings_object.remove("dest");
        settings_object.insert(
            "target".to_string(),
            serde_json::json!("www.example.com:8443"),
        );

        let config = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect("target alias should build reality config");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => {
                assert_eq!(reality.dest.to_string(), "www.example.com:8443");
            }
            other => panic!("expected reality protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_requires_explicit_none_decryption() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "vless",
            "tag": "vless-missing-decryption",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }]
            }
        }))
        .expect("valid inbound json shape");

        let err = ServerConfig::try_from(inbound)
            .expect_err("missing vless decryption should fail");
        assert!(
            err.to_string().contains(
                "vless settings.decryption must be explicitly set to none"
            )
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_non_none_decryption() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10001,
            "protocol": "vless",
            "tag": "vless-invalid-decryption",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "aes-128-gcm"
            }
        }))
        .expect("valid inbound json shape");

        let err = ServerConfig::try_from(inbound)
            .expect_err("non-none vless decryption should fail");
        assert!(
            err.to_string()
                .contains("vless settings.decryption must be none")
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_unknown_stream_security() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10002,
            "protocol": "vless",
            "tag": "vless-unknown-security",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "definitely-not-a-security-layer"
            }
        }))
        .expect("valid inbound json shape");

        let err = ServerConfig::try_from(inbound)
            .expect_err("unknown stream security must not downgrade to plaintext");
        assert!(err.to_string().contains(
            "unsupported streamSettings.security=definitely-not-a-security-layer"
        ));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_accepts_dest_only_fallback() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10002,
            "protocol": "vless",
            "tag": "vless-fallbacks",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none",
                "fallbacks": [{ "dest": "127.0.0.1:8080", "xver": 0 }]
            }
        }))
        .expect("valid inbound json shape");

        let config = ServerConfig::try_from(inbound)
            .expect("dest-only VLESS fallback should build");
        match config.protocol {
            ServerProxyConfig::Vless { fallbacks, .. } => {
                assert_eq!(fallbacks.len(), 1);
                assert_eq!(fallbacks[0].dest.to_string(), "127.0.0.1:8080");
            }
            other => panic!("expected vless protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_accepts_numeric_fallback_port() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10002,
            "protocol": "vless",
            "tag": "vless-numeric-fallback",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none",
                "fallbacks": [{ "dest": 8081 }]
            }
        }))
        .expect("valid inbound json shape");

        let config = ServerConfig::try_from(inbound)
            .expect("numeric VLESS fallback port should build");
        match config.protocol {
            ServerProxyConfig::Vless { fallbacks, .. } => {
                assert_eq!(fallbacks[0].dest.to_string(), "127.0.0.1:8081");
            }
            other => panic!("expected vless protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_preserves_fallback_xver() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10002,
            "protocol": "vless",
            "tag": "vless-fallback-xver",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none",
                "fallbacks": [
                    { "dest": 8081, "xver": 1 },
                    { "dest": 8082, "xver": 2 }
                ]
            }
        }))
        .expect("valid inbound json shape");

        let config = ServerConfig::try_from(inbound)
            .expect("PROXY protocol fallback versions should build");
        match config.protocol {
            ServerProxyConfig::Vless { fallbacks, .. } => {
                assert_eq!(fallbacks[0].xver, 1);
                assert_eq!(fallbacks[1].xver, 2);
            }
            other => panic!("expected vless protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_unknown_fallback_xver() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10002,
            "protocol": "vless",
            "tag": "vless-fallback-xver-invalid",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none",
                "fallbacks": [{ "dest": 8081, "xver": 3 }]
            }
        }))
        .expect("valid inbound json shape");

        let error =
            ServerConfig::try_from(inbound).expect_err("xver=3 must be rejected");
        assert!(
            error
                .to_string()
                .contains("vless fallback xver must be 0, 1, or 2; got 3")
        );
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_preserves_fallback_match_fields() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10002,
            "protocol": "vless",
            "tag": "vless-fallback-path",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none",
                "fallbacks": [{
                    "name": "EXAMPLE.COM",
                    "alpn": "H2",
                    "dest": "127.0.0.1:8080",
                    "path": "/fallback",
                    "type": "tcp",
                    "xver": 0
                }]
            }
        }))
        .expect("valid inbound json shape");

        let config = ServerConfig::try_from(inbound)
            .expect("VLESS fallback match fields should build");
        match config.protocol {
            ServerProxyConfig::Vless { fallbacks, .. } => {
                assert_eq!(fallbacks.len(), 1);
                assert_eq!(fallbacks[0].name, "example.com");
                assert_eq!(fallbacks[0].alpn, "h2");
                assert_eq!(fallbacks[0].path, "/fallback");
                assert_eq!(fallbacks[0].xver, 0);
            }
            other => panic!("expected vless protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn vmess_builder_defaults_security_to_auto() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10003,
            "protocol": "vmess",
            "tag": "vmess-auto-security",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "email": "vmess@example.com"
                }]
            }
        }))
        .expect("valid vmess inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vmess inbound config should build");

        match config.protocol {
            ServerProxyConfig::Vmess { users } => {
                assert_eq!(users[0].cipher, "auto");
            }
            other => panic!("expected vmess protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn vmess_builder_preserves_client_security() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10004,
            "protocol": "vmess",
            "tag": "vmess-security",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273",
                    "security": "aes-128-gcm"
                }]
            }
        }))
        .expect("valid vmess inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vmess inbound config should build");

        match config.protocol {
            ServerProxyConfig::Vmess { users } => {
                assert_eq!(users[0].cipher, "aes-128-gcm");
            }
            other => panic!("expected vmess protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn vmess_builder_normalizes_xray_short_id() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10005,
            "protocol": "vmess",
            "tag": "vmess-short-id",
            "settings": {
                "clients": [{
                    "id": "test-vmess-user"
                }]
            }
        }))
        .expect("valid vmess short-id inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("Xray-compatible VMess short ID should build");

        match config.protocol {
            ServerProxyConfig::Vmess { users } => {
                assert_eq!(users[0].user_id, "321d83eb-74db-554a-a630-0ad214dc332b");
                assert_eq!(users[0].user_label, users[0].user_id);
            }
            other => panic!("expected vmess protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "vmess")]
    #[test]
    fn vmess_builder_rejects_invalid_uuid_shape() {
        for invalid_id in [
            "",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 10006,
                "protocol": "vmess",
                "tag": "vmess-invalid-id",
                "settings": {
                    "clients": [{"id": invalid_id}]
                }
            }))
            .expect("vmess inbound JSON shape should deserialize");

            let error = ServerConfig::try_from(inbound)
                .expect_err("invalid VMess ID should be rejected");
            assert!(
                error.to_string().contains("invalid VMess UUID"),
                "unexpected error for {invalid_id:?}: {error}"
            );
        }
    }

    #[cfg(all(feature = "vless", feature = "httpupgrade"))]
    #[test]
    fn httpupgrade_accepts_xray_early_data_setting() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10007,
            "protocol": "vless",
            "tag": "vless-httpupgrade-ed",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "httpupgradeSettings": {
                    "host": "example.com",
                    "path": "/upgrade",
                    "acceptProxyProtocol": true,
                    "ed": 2048
                }
            }
        }))
        .expect("valid VLESS HTTPUpgrade inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("Xray HTTPUpgrade ed should be accepted on inbound");

        match config.protocol {
            ServerProxyConfig::HttpUpgrade(httpupgrade) => {
                assert_eq!(httpupgrade.host.as_deref(), Some("example.com"));
                assert_eq!(httpupgrade.path, "/upgrade");
                assert!(httpupgrade.accept_proxy_protocol);
                assert!(matches!(
                    httpupgrade.inner.as_ref(),
                    ServerProxyConfig::Vless { .. }
                ));
            }
            other => panic!("expected HTTPUpgrade protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "vless", feature = "httpupgrade"))]
    #[test]
    fn httpupgrade_path_preserves_xray_whitespace() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10007,
            "protocol": "vless",
            "tag": "vless-httpupgrade-whitespace",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "httpupgradeSettings": {
                    "host": " Example.COM ",
                    "path": "ws "
                }
            }
        }))
        .expect("valid VLESS HTTPUpgrade inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("Xray HTTPUpgrade path whitespace should be preserved");

        match config.protocol {
            ServerProxyConfig::HttpUpgrade(httpupgrade) => {
                assert_eq!(httpupgrade.host.as_deref(), Some(" example.com "));
                assert_eq!(httpupgrade.path, "/ws ");
            }
            other => panic!("expected HTTPUpgrade protocol, got {other:?}"),
        }
    }

    #[cfg(feature = "ws")]
    #[test]
    fn websocket_path_matches_xray_normalization() {
        assert_eq!(normalize_xray_websocket_path(None), "/");
        assert_eq!(normalize_xray_websocket_path(Some(String::new())), "/");
        assert_eq!(
            normalize_xray_websocket_path(Some("chat".to_string())),
            "/chat"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat".to_string())),
            "/chat"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat?ed=2048".to_string())),
            "/chat"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat?%65d=2048".to_string())),
            "/chat"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("chat?ed=2048".to_string())),
            "/chat"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat?foo=bar&ed=2048".to_string())),
            "/chat?foo=bar"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat?ed=".to_string())),
            "/chat?ed="
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat?ed=%".to_string())),
            "/chat?ed=%"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some(
                "/chat?ed=2048&bad%ZZ=x".to_string()
            )),
            "/chat"
        );
        assert_eq!(
            normalize_xray_websocket_path(Some("/chat?ed=2048;bad".to_string())),
            "/chat?ed=2048;bad"
        );
    }

    #[cfg(all(feature = "vless", feature = "ws"))]
    #[test]
    fn websocket_settings_only_host_enters_matching_config() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10005,
            "protocol": "vless",
            "tag": "vless-ws-headers",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "host": " Example.COM ",
                    "path": "/ws",
                    "acceptProxyProtocol": false,
                    "heartbeatPeriod": 7,
                    "headers": {
                        "Host": "edge.example.com",
                        "X-Test": "ok"
                    }
                },
                "sockopt": {
                    "acceptProxyProtocol": true,
                    "trustedXForwardedFor": ["X-Trusted-CDN"]
                }
            }
        }))
        .expect("valid vless websocket inbound item");

        let config = ServerConfig::try_from(inbound)
            .expect("vless websocket inbound config should build");

        match config.protocol {
            ServerProxyConfig::Websocket { targets } => match *targets {
                OneOrSome::One(target) => {
                    assert_eq!(target.matching_path.as_deref(), Some("/ws"));
                    let headers = target
                        .matching_headers
                        .expect("websocket host should be preserved");
                    assert_eq!(
                        headers.get("host"),
                        Some(&" Example.COM ".to_string())
                    );
                    assert!(!headers.contains_key("x-test"));
                    assert!(!headers.contains_key("Host"));
                    assert_eq!(
                        target.trusted_x_forwarded_for,
                        vec!["X-Trusted-CDN".to_string()]
                    );
                    assert!(target.accept_proxy_protocol);
                    assert_eq!(target.heartbeat_period, 7);
                }
                OneOrSome::Some(_) => panic!("expected one websocket target"),
            },
            other => panic!("expected websocket protocol, got {other:?}"),
        }
    }

    #[cfg(all(feature = "vless", feature = "ws"))]
    #[test]
    fn websocket_deprecated_header_host_preserves_xray_text_semantics() {
        fn matching_host(headers: serde_json::Value) -> Option<String> {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 10005,
                "protocol": "vless",
                "tag": "vless-ws-header-fallback",
                "settings": {
                    "clients": [{
                        "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": "/ws",
                        "headers": headers
                    }
                }
            }))
            .expect("valid vless websocket inbound item");

            let config = ServerConfig::try_from(inbound)
                .expect("vless websocket inbound config should build");
            let ServerProxyConfig::Websocket { targets } = config.protocol else {
                panic!("expected websocket protocol");
            };
            let OneOrSome::One(target) = *targets else {
                panic!("expected one websocket target");
            };
            target
                .matching_headers
                .and_then(|headers| headers.get("host").cloned())
        }

        assert_eq!(
            matching_host(serde_json::json!({"Host": " Example.COM "})),
            Some(" Example.COM ".to_string())
        );
        assert_eq!(
            matching_host(serde_json::json!({"hOsT": "example.com"})),
            Some("example.com".to_string())
        );
        assert_eq!(
            matching_host(serde_json::json!({" Host ": "example.com"})),
            None
        );
        assert_eq!(matching_host(serde_json::json!({"Host": ""})), None);
    }
}
