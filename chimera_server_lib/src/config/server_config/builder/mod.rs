mod collectors;
mod stream;
mod tls;

use serde::Deserialize;

use crate::{
    Error,
    address::{Address, BindLocation, NetLocation},
    config::{Protocol, Transport, def::InboudItem},
};

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use crate::util::option::NoneOrSome;

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

use stream::*;
use tls::apply_security_layers;

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
use super::types::{
    InboundSniffingConfig, ServerConfig, ServerProxyConfig, TcpSocketPolicy,
    XhttpServerConfig,
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
        .map(|settings| {
            let network = settings.network.trim();
            network.eq_ignore_ascii_case("xhttp")
                || network.eq_ignore_ascii_case("splithttp")
        })
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
        if stream_settings.is_some_and(|settings| {
            let network = settings.network.trim();
            network.eq_ignore_ascii_case("ws")
                || network.eq_ignore_ascii_case("websocket")
        }) {
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
    let xhttp_settings = stream_settings.xhttp_settings.clone().unwrap_or_default();
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
    protocol: ServerProxyConfig,
    stream_settings: Option<&crate::config::StreamSettings>,
    plan: &VlessTransportPlan,
) -> Result<ServerProxyConfig, Error> {
    let Some(stream_settings) = stream_settings else {
        return Ok(protocol);
    };
    match plan.kind {
        VlessTransportKind::Xhttp => {
            apply_vless_xhttp_transport(protocol, stream_settings, &plan.security)
        }
        VlessTransportKind::Standard => {
            let protocol = apply_websocket_layer(protocol, stream_settings);
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
mod tests;
