mod collectors;
mod tls;

use serde::Deserialize;

use crate::{
    Error,
    address::{Address, BindLocation, NetLocation},
    config::{Protocol, Transport, def::InboudItem},
};

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use crate::util::option::NoneOrSome;

#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;

#[cfg(feature = "ws")]
use super::ws::WebsocketServerConfig;
#[cfg(feature = "ws")]
fn websocket_server_config(
    ws_setting: crate::config::WsSettings,
    protocol: ServerProxyConfig,
) -> WebsocketServerConfig {
    let mut matching_headers = std::collections::HashMap::new();
    let mut host = ws_setting
        .host
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    for (key, value) in ws_setting.headers {
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        if key == "host" {
            if host.is_none() {
                let value = value.trim().to_string();
                if !value.is_empty() {
                    host = Some(value);
                }
            }
        } else {
            matching_headers.insert(key, value);
        }
    }

    if let Some(host) = host {
        matching_headers.insert("host".to_string(), host);
    }

    WebsocketServerConfig {
        matching_path: ws_setting.path,
        matching_headers: if matching_headers.is_empty() {
            None
        } else {
            Some(matching_headers)
        },
        protocol,
    }
}

fn validate_tcp_inbound_network(
    protocol_name: &str,
    stream_settings: &crate::config::StreamSettings,
    allow_xhttp: bool,
) -> Result<String, Error> {
    let configured = stream_settings.network.trim().to_ascii_lowercase();
    let network = match configured.as_str() {
        "" | "raw" | "tcp" => "tcp",
        "ws" | "websocket" => "ws",
        "httpupgrade" => "httpupgrade",
        "grpc" => "grpc",
        "xhttp" | "splithttp" if allow_xhttp => "xhttp",
        unsupported => {
            return Err(Error::InvalidConfig(format!(
                "{protocol_name} inbound streamSettings.network={unsupported} is not supported"
            )));
        }
    };

    #[cfg(feature = "ws")]
    {
        if network == "ws" && stream_settings.ws_settings.is_none() {
            return Err(Error::InvalidConfig(format!(
                "{protocol_name} websocket inbound requires wsSettings"
            )));
        }
        if network != "ws" && stream_settings.ws_settings.is_some() {
            return Err(Error::InvalidConfig(format!(
                "{protocol_name} inbound wsSettings requires streamSettings.network=ws"
            )));
        }
    }
    #[cfg(not(feature = "ws"))]
    if network == "ws" {
        return Err(Error::InvalidConfig(
            "websocket transport requires the ws feature".into(),
        ));
    }

    #[cfg(feature = "httpupgrade")]
    if network != "httpupgrade" && stream_settings.httpupgrade_settings.is_some() {
        return Err(Error::InvalidConfig(format!(
            "{protocol_name} inbound httpupgradeSettings requires streamSettings.network=httpupgrade"
        )));
    }
    #[cfg(feature = "grpc_transport")]
    if network != "grpc" && stream_settings.grpc_settings.is_some() {
        return Err(Error::InvalidConfig(format!(
            "{protocol_name} inbound grpcSettings requires streamSettings.network=grpc"
        )));
    }
    if network != "xhttp" && stream_settings.xhttp_settings.is_some() {
        return Err(Error::InvalidConfig(format!(
            "{protocol_name} inbound xhttpSettings requires streamSettings.network=xhttp"
        )));
    }

    Ok(network.to_string())
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
    if settings.multi_mode {
        return Err(Error::InvalidConfig(
            "grpcSettings.multiMode is not supported yet".into(),
        ));
    }
    let service_name = settings
        .service_name
        .unwrap_or_else(|| "GunService".to_string())
        .trim_matches('/')
        .trim()
        .to_string();
    if service_name.is_empty() {
        return Err(Error::InvalidConfig(
            "grpcSettings.serviceName cannot be empty".into(),
        ));
    }
    let _ = (
        settings.authority,
        settings.idle_timeout,
        settings.health_check_timeout,
        settings.permit_without_stream,
        settings.initial_windows_size,
    );
    Ok(ServerProxyConfig::Grpc(super::types::GrpcServerConfig {
        service_name,
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
    if settings.ed != 0 {
        return Err(Error::InvalidConfig(
            "httpupgradeSettings.ed is not supported yet".into(),
        ));
    }
    let path = settings.path.unwrap_or_default().trim().to_string();
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };
    let host = settings
        .host
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    // Xray's server uses host/path for validation. Custom headers are a
    // client-side request construction option and do not alter inbound matching.
    let _ = settings.header;
    Ok(ServerProxyConfig::HttpUpgrade(HttpUpgradeServerConfig {
        host,
        path,
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

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use super::quic::ServerQuicConfig;
#[cfg(feature = "httpupgrade")]
use super::types::HttpUpgradeServerConfig;
use super::types::{ServerConfig, ServerProxyConfig, XhttpServerConfig};

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
    #[serde(default)]
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
                    user_level: 0,
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

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SniffingEnableGate {
    #[serde(default)]
    enabled: bool,
}

impl TryFrom<InboudItem> for ServerConfig {
    type Error = Error;

    fn try_from(value: InboudItem) -> Result<Self, Self::Error> {
        tracing::info!(
            tag = %value.tag,
            protocol = ?value.protocol,
            listen = ?value.listen,
            port = value.port,
            "building inbound configuration"
        );

        let InboudItem {
            allocate,
            listen,
            port,
            protocol,
            settings,
            sniffing,
            stream_settings,
            tag,
        } = value;

        if allocate.is_some() {
            return Err(Error::InvalidConfig(format!(
                "inbound {tag} uses unsupported Xray allocate settings"
            )));
        }
        if let Some(sniffing) = sniffing {
            let sniffing = serde_json::from_value::<SniffingEnableGate>(sniffing)
                .map_err(|error| {
                    Error::InvalidConfig(format!(
                        "invalid inbound {tag} sniffing settings: {error}"
                    ))
                })?;
            if sniffing.enabled {
                return Err(Error::InvalidConfig(format!(
                    "inbound {tag} enables Xray sniffing, which is not implemented yet"
                )));
            }
        }

        let listen = listen.unwrap_or_else(|| "0.0.0.0".to_string());
        let address = Address::from(&listen).map_err(|err| {
            Error::InvalidConfig(format!(
                "invalid inbound listen for tag {}: {} ({})",
                tag, listen, err
            ))
        })?;
        let bind_location = BindLocation::Address(NetLocation::new(address, port));

        match protocol {
            Protocol::DokodemoDoor => {
                let settings = settings
                    .map(|value| value.deserialize::<DokodemoDoorSettings>())
                    .transpose()
                    .map_err(|err| {
                        Error::InvalidConfig(format!(
                            "invalid dokodemo-door settings: {err}"
                        ))
                    })?
                    .unwrap_or_default();

                let address = match settings.address.as_deref() {
                    Some(value) => Address::from(value)?,
                    None => match &bind_location {
                        BindLocation::Address(addr) => addr.address().clone(),
                    },
                };
                let remote_location =
                    NetLocation::new(address, settings.port.unwrap_or(port));

                let mut protocol = ServerProxyConfig::DokodemoDoor {
                    config: super::types::DokodemoDoorConfig {
                        target: remote_location,
                        follow_redirect: settings.follow_redirect,
                        user_level: settings.user_level,
                    },
                };

                let transport = match stream_settings.as_ref().map(|settings| {
                    settings.network.trim().to_ascii_lowercase()
                }) {
                    Some(network) if network == "udp" => {
                        if let Some(stream_setting) = stream_settings.as_ref()
                            && stream_setting.security.as_deref().unwrap_or("none") != "none"
                        {
                            return Err(Error::InvalidConfig(
                                "dokodemo-door udp transport does not support streamSettings.security"
                                    .into(),
                            ));
                        }
                        Transport::Udp
                    }
                    Some(network)
                        if network.is_empty()
                            || network == "tcp"
                            || network == "httpupgrade"
                            || network == "grpc" =>
                    {
                        if let Some(stream_setting) = stream_settings.as_ref() {
                            protocol =
                                apply_httpupgrade_layer(protocol, stream_setting)?;
                            protocol = apply_grpc_layer(protocol, stream_setting)?;
                            protocol = apply_security_layers(protocol, stream_setting)?;
                        }
                        Transport::Tcp
                    }
                    Some(network) => {
                        return Err(Error::InvalidConfig(format!(
                            "dokodemo-door streamSettings.network={network} is not supported"
                        )));
                    }
                    None => Transport::Tcp,
                };

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport,
                    quic_settings: None,
                })
            }
            #[cfg(feature = "hysteria")]
            Protocol::Hysteria2 => {
                let stream_settings = stream_settings.ok_or_else(|| {
                    Error::InvalidConfig(
                        "hysteria2 inbound missing streamSettings".into(),
                    )
                })?;
                let hysteria_settings = stream_settings.hysteria_settings.as_ref();
                let tls_settings =
                    stream_settings.tls_settings.ok_or_else(|| {
                        Error::InvalidConfig(
                            "hysteria2 inbound requires tlsSettings".into(),
                        )
                    })?;
                let item = tls_settings.certificates[0].clone();
                let cert = item.certificate_file.ok_or_else(|| {
                    Error::InvalidConfig(
                        "hysteria2 inbound currently requires certificateFile"
                            .into(),
                    )
                })?;
                let key = item.key_file.ok_or_else(|| {
                    Error::InvalidConfig(
                        "hysteria2 inbound currently requires keyFile".into(),
                    )
                })?;

                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("hysteria2 inbound requires clients".into())
                })?;
                let config =
                    collect_hysteria2_settings(settings, hysteria_settings)?;
                if config.clients.is_empty() {
                    return Err(Error::InvalidConfig(
                        "hysteria2 inbound requires at least one client".into(),
                    ));
                }

                let quic_settings = Some(ServerQuicConfig {
                    cert,
                    key,
                    alpn_protocols: NoneOrSome::Some(tls_settings.alpn),
                    client_fingerprints: NoneOrSome::None,
                });
                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol: ServerProxyConfig::Hysteria2 { config },
                    transport: Transport::Quic,
                    quic_settings,
                })
            }
            #[cfg(feature = "vless")]
            Protocol::Vless => {
                let vless_settings = settings
                    .as_ref()
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
                let fallbacks =
                    collect_vless_fallbacks(vless_settings.fallbacks)?;
                let settings_flow = vless_settings
                    .flow
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("");
                validate_vless_flow(settings_flow)?;

                let users = settings
                    .as_ref()
                    .and_then(|setting| setting.clients())
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
                        Error::InvalidConfig(
                            "vless inbound requires at least one client".into(),
                        )
                    })?;
                let uses_vision = has_vless_vision_flow(&users);

                let mut protocol = ServerProxyConfig::Vless {
                    users,
                    fallbacks,
                };
                let stream_network = stream_settings
                    .as_ref()
                    .map(|settings| {
                        validate_tcp_inbound_network("vless", settings, true)
                    })
                    .transpose()?
                    .unwrap_or_else(|| "tcp".to_string());
                let uses_xhttp = stream_network == "xhttp";
                let security = stream_settings
                    .as_ref()
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
                }

                #[cfg(feature = "ws")]
                if stream_network == "ws"
                    && let Some(stream_setting) = stream_settings.as_ref()
                        && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                            if uses_vision {
                                return Err(Error::InvalidConfig(
                                    "xtls-rprx-vision does not support websocket transport"
                                        .into(),
                                ));
                            }
                            tracing::info!("use websocket");
                            protocol = ServerProxyConfig::Websocket {
                                targets: Box::new(OneOrSome::One(
                                    websocket_server_config(ws_setting, protocol),
                                )),
                            };
                        }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    if uses_xhttp {
                        let xhttp_settings =
                            stream_setting.xhttp_settings.clone().ok_or_else(|| {
                                Error::InvalidConfig(
                                    "xhttp inbound requires xhttpSettings".into(),
                                )
                            })?;

                        protocol = ServerProxyConfig::Xhttp {
                            config: collect_xhttp_settings(xhttp_settings)?,
                            inner: Box::new(protocol),
                        };

                        match security.as_str() {
                            "none" | "tls" | "reality" => {
                                protocol =
                                    apply_security_layers(protocol, stream_setting)?;
                            }
                            unsupported => {
                                return Err(Error::InvalidConfig(format!(
                                    "xhttp inbound currently supports only security=none, tls, or reality, got {unsupported}"
                                )));
                            }
                        }
                    } else {
                        if uses_vision
                            && matches!(stream_network.as_str(), "httpupgrade" | "grpc")
                        {
                            return Err(Error::InvalidConfig(
                                "xtls-rprx-vision does not support httpupgrade or grpc transport"
                                    .into(),
                            ));
                        }
                        protocol =
                            apply_httpupgrade_layer(protocol, stream_setting)?;
                        protocol = apply_grpc_layer(protocol, stream_setting)?;
                        protocol = apply_security_layers(protocol, stream_setting)?;
                    }
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }
            #[cfg(feature = "vmess")]
            Protocol::Vmess => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("vmess inbound requires clients".into())
                })?;
                let clients = settings.clients().ok_or_else(|| {
                    Error::InvalidConfig("vmess inbound settings.clients is required".into())
                })?;
                let users: Vec<crate::config::server_config::VmessUser> = clients
                    .into_iter()
                    .map(|client| {
                        let user_label = if client.email.is_empty() {
                            client.id.clone()
                        } else {
                            client.email
                        };
                        Ok(crate::config::server_config::VmessUser {
                            user_id: client.id,
                            user_label,
                            user_level: client.level,
                            cipher: client
                                .security
                                .filter(|value| !value.trim().is_empty())
                                .unwrap_or_else(|| "auto".to_string()),
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let mut protocol = ServerProxyConfig::Vmess { users };
                let _stream_network = stream_settings
                    .as_ref()
                    .map(|settings| {
                        validate_tcp_inbound_network("vmess", settings, false)
                    })
                    .transpose()?
                    .unwrap_or_else(|| "tcp".to_string());

                #[cfg(feature = "ws")]
                if _stream_network == "ws"
                    && let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                websocket_server_config(ws_setting, protocol),
                            )),
                        };
                    }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    protocol = apply_httpupgrade_layer(protocol, stream_setting)?;
                    protocol = apply_grpc_layer(protocol, stream_setting)?;
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }

            #[cfg(feature = "trojan")]
            Protocol::Trojan => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("trojan inbound requires clients".into())
                })?;
                let trojan_fallbacks = collect_trojan_fallbacks(&settings)?;
                let trojan_users = collect_trojan_clients(settings)?;
                let mut protocol = ServerProxyConfig::Trojan {
                    users: trojan_users,
                    fallbacks: trojan_fallbacks,
                };
                let _stream_network = stream_settings
                    .as_ref()
                    .map(|settings| {
                        validate_tcp_inbound_network("trojan", settings, false)
                    })
                    .transpose()?
                    .unwrap_or_else(|| "tcp".to_string());

                #[cfg(feature = "ws")]
                if _stream_network == "ws"
                    && let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                websocket_server_config(ws_setting, protocol),
                            )),
                        };
                    }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    protocol = apply_httpupgrade_layer(protocol, stream_setting)?;
                    protocol = apply_grpc_layer(protocol, stream_setting)?;
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }

            #[cfg(feature = "tuic")]
            Protocol::TuicV5 => {
                let stream_settings = stream_settings.ok_or_else(|| {
                    Error::InvalidConfig(
                        "tuic inbound missing streamSettings".into(),
                    )
                })?;
                let tls_settings = stream_settings.tls_settings.ok_or_else(|| {
                    Error::InvalidConfig("tuic inbound requires tlsSettings".into())
                })?;
                let certificate = tls_settings
                    .certificates.first()
                    .ok_or_else(|| {
                        Error::InvalidConfig(
                            "tuic inbound requires at least one certificate".into(),
                        )
                    })?
                    .clone();

                let settings = settings
                    .ok_or_else(|| Error::InvalidConfig("tuic inbound requires settings".into()))?;
                let config = collect_tuic_settings(settings)?;

                let quic_settings = Some(ServerQuicConfig {
                    cert: certificate.certificate_file.ok_or_else(|| {
                        Error::InvalidConfig(
                            "tuic inbound requires certificateFile".into(),
                        )
                    })?,
                    key: certificate.key_file.ok_or_else(|| {
                        Error::InvalidConfig(
                            "tuic inbound requires keyFile".into(),
                        )
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
                })
            }

            Protocol::Xhttp => {
                Err(Error::InvalidConfig(
                    "protocol=xhttp is no longer supported; use protocol=vless with streamSettings.network=xhttp"
                        .into(),
                ))
            }

            #[cfg(feature = "http")]
            Protocol::Http => {
                let (accounts, allow_transparent, user_level) =
                    collect_http_settings(settings)?;
                let mut protocol = ServerProxyConfig::Http {
                    accounts,
                    allow_transparent,
                    user_level,
                };

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone()
                {
                    protocol = ServerProxyConfig::Websocket {
                        targets: Box::new(OneOrSome::One(
                            websocket_server_config(ws_setting, protocol),
                        )),
                    };
                }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    let network = stream_setting.network.trim().to_ascii_lowercase();
                    if !matches!(
                        network.as_str(),
                        "" | "tcp" | "ws" | "websocket" | "httpupgrade" | "grpc"
                    ) {
                        return Err(Error::InvalidConfig(format!(
                            "http inbound streamSettings.network={network} is not supported"
                        )));
                    }
                    protocol = apply_httpupgrade_layer(protocol, stream_setting)?;
                    protocol = apply_grpc_layer(protocol, stream_setting)?;
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }
            #[cfg(not(feature = "http"))]
            Protocol::Http => Err(Error::InvalidConfig(
                "http inbound requires the http feature".into(),
            )),
            #[cfg(feature = "mixed")]
            Protocol::Mixed => {
                let settings = settings.unwrap_or_else(|| {
                    crate::config::SettingObject(serde_json::json!({}))
                });
                let collected = collect_socks_settings(settings, false)?;
                let mut protocol = ServerProxyConfig::Mixed {
                    accounts: collected.accounts,
                    udp_enabled: collected.udp_enabled,
                };

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone()
                {
                    protocol = ServerProxyConfig::Websocket {
                        targets: Box::new(OneOrSome::One(
                            websocket_server_config(ws_setting, protocol),
                        )),
                    };
                }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    let network = stream_setting.network.trim().to_ascii_lowercase();
                    if !matches!(
                        network.as_str(),
                        "" | "tcp" | "ws" | "websocket" | "httpupgrade" | "grpc"
                    ) {
                        return Err(Error::InvalidConfig(format!(
                            "mixed inbound streamSettings.network={network} is not supported"
                        )));
                    }
                    protocol = apply_httpupgrade_layer(protocol, stream_setting)?;
                    protocol = apply_grpc_layer(protocol, stream_setting)?;
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }
            #[cfg(not(feature = "mixed"))]
            Protocol::Mixed => Err(Error::InvalidConfig(
                "mixed inbound requires the mixed feature".into(),
            )),
            #[cfg(feature = "shadowsocks")]
            Protocol::Shadowsocks => {
                let (users, identity, transport) =
                    collect_shadowsocks_users(settings)?;
                let mut protocol =
                    ServerProxyConfig::Shadowsocks { users, identity };

                if !matches!(transport, Transport::Tcp)
                    && stream_settings.is_some()
                {
                    return Err(Error::InvalidConfig(
                        "shadowsocks UDP listeners do not support streamSettings"
                            .into(),
                    ));
                }

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone()
                {
                    protocol = ServerProxyConfig::Websocket {
                        targets: Box::new(OneOrSome::One(
                            websocket_server_config(ws_setting, protocol),
                        )),
                    };
                }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    let network = stream_setting.network.trim().to_ascii_lowercase();
                    if !matches!(
                        network.as_str(),
                        "" | "tcp" | "ws" | "websocket" | "httpupgrade" | "grpc"
                    ) {
                        return Err(Error::InvalidConfig(format!(
                            "shadowsocks inbound streamSettings.network={network} is not supported"
                        )));
                    }
                    protocol = apply_httpupgrade_layer(protocol, stream_setting)?;
                    protocol = apply_grpc_layer(protocol, stream_setting)?;
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport,
                    quic_settings: None,
                })
            }
            #[cfg(not(feature = "shadowsocks"))]
            Protocol::Shadowsocks => Err(Error::InvalidConfig(
                "shadowsocks inbound requires the shadowsocks feature".into(),
            )),

            Protocol::Socks => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("socks inbound requires settings".into())
                })?;
                let collected = collect_socks_settings(settings, true)?;
                let mut protocol = ServerProxyConfig::Socks {
                    accounts: collected.accounts,
                    udp_enabled: collected.udp_enabled,
                    user_level: collected.user_level,
                };
                let _stream_network = stream_settings
                    .as_ref()
                    .map(|settings| {
                        validate_tcp_inbound_network("socks", settings, false)
                    })
                    .transpose()?
                    .unwrap_or_else(|| "tcp".to_string());

                #[cfg(feature = "ws")]
                if _stream_network == "ws"
                    && let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                websocket_server_config(ws_setting, protocol),
                            )),
                        };
                    }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    protocol = apply_httpupgrade_layer(protocol, stream_setting)?;
                    protocol = apply_grpc_layer(protocol, stream_setting)?;
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }
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
    fn inbound_builder_rejects_unimplemented_sniffing_and_allocate() {
        for (field, value) in [
            ("sniffing", serde_json::json!({"enabled": true})),
            ("allocate", serde_json::json!({"strategy": "random"})),
        ] {
            let mut inbound = serde_json::json!({
                "listen": "127.0.0.1",
                "port": 10000,
                "protocol": "dokodemo-door",
                "tag": format!("dokodemo-{field}"),
                "settings": {"address": "127.0.0.1", "port": 53}
            });
            inbound[field] = value;
            let inbound = serde_json::from_value::<InboudItem>(inbound)
                .expect("literal inbound should parse");
            let error = ServerConfig::try_from(inbound)
                .expect_err("unimplemented inbound option must fail closed");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn tcp_inbound_network_validation_matches_xray_aliases_and_rejects_kcp() {
        let raw = serde_json::from_value::<crate::config::StreamSettings>(
            serde_json::json!({"network": "raw"}),
        )
        .expect("raw stream settings");
        assert_eq!(
            validate_tcp_inbound_network("vless", &raw, true).unwrap(),
            "tcp"
        );

        let split_http = serde_json::from_value::<crate::config::StreamSettings>(
            serde_json::json!({"network": "splithttp"}),
        )
        .expect("splithttp stream settings");
        assert_eq!(
            validate_tcp_inbound_network("vless", &split_http, true).unwrap(),
            "xhttp"
        );
        assert!(
            validate_tcp_inbound_network("vmess", &split_http, false)
                .unwrap_err()
                .to_string()
                .contains("not supported")
        );

        for network in ["kcp", "mkcp", "websokcet"] {
            let settings = serde_json::from_value::<crate::config::StreamSettings>(
                serde_json::json!({"network": network}),
            )
            .expect("stream settings");
            let error = validate_tcp_inbound_network("vless", &settings, true)
                .expect_err("unsupported transport must fail closed");
            assert!(error.to_string().contains(network));
        }
    }

    #[cfg(feature = "ws")]
    #[test]
    fn websocket_settings_require_websocket_network() {
        let settings = serde_json::from_value::<crate::config::StreamSettings>(
            serde_json::json!({
                "network": "tcp",
                "wsSettings": {"path": "/ws"}
            }),
        )
        .expect("stream settings");
        let error = validate_tcp_inbound_network("vless", &settings, true)
            .expect_err("mismatched wsSettings must fail closed");
        assert!(error.to_string().contains("wsSettings requires"));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_accept_proxy_protocol_wraps_raw_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-raw-proxy",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"acceptProxyProtocol": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::ProxyProtocol { inner } = config.protocol else {
            panic!("sockopt PROXY protocol must wrap raw transport");
        };
        assert!(matches!(*inner, ServerProxyConfig::Vless { .. }));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_keepalive_wraps_proxy_protocol_outermost() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-keepalive",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "acceptProxyProtocol": true,
                    "tcpKeepAliveIdle": 30,
                    "tcpKeepAliveInterval": 10
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpKeepAlive {
            idle_secs,
            interval_secs,
            inner,
        } = config.protocol
        else {
            panic!("TCP keepalive must be the outer socket wrapper");
        };
        assert_eq!((idle_secs, interval_secs), (30, 10));
        assert!(matches!(*inner, ServerProxyConfig::ProxyProtocol { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_tcp_keepalive_rejects_mixed_signs() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-invalid-keepalive",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpKeepAliveIdle": -1,
                    "tcpKeepAliveInterval": 10
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("tcpKeepAliveIdle"));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_congestion_wraps_other_socket_options_outermost() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-congestion",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpCongestion": "cubic",
                    "tcpWindowClamp": 65535,
                    "tcpUserTimeout": 12345
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpCongestion { algorithm, inner } = config.protocol
        else {
            panic!("TCP_CONGESTION must be the outer socket wrapper");
        };
        assert_eq!(algorithm, "cubic");
        let ServerProxyConfig::TcpWindowClamp { value, inner } = *inner else {
            panic!("TCP_WINDOW_CLAMP must wrap TCP_USER_TIMEOUT");
        };
        assert_eq!(value, 65_535);
        assert!(matches!(*inner, ServerProxyConfig::TcpUserTimeout { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_empty_tcp_congestion_is_ignored() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-congestion-default",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"tcpCongestion": ""}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_non_positive_tcp_window_clamp_is_ignored() {
        for value in [0, -1] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "tag": "vless-window-clamp-disabled",
                "settings": {
                    "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "sockopt": {"tcpWindowClamp": value}
                }
            }))
            .unwrap();
            let config = ServerConfig::try_from(inbound).unwrap();
            assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
        }
    }

    #[cfg(all(feature = "vless", target_os = "linux"))]
    #[test]
    fn socket_mark_wraps_tcp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-mark",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"mark": 255}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindMark { value, inner } = config.protocol else {
            panic!("mark must wrap the TCP listener");
        };
        assert_eq!(value, 255);
        assert!(matches!(*inner, ServerProxyConfig::Vless { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_zero_mark_is_ignored() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-mark-default",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"mark": 0}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport", target_os = "linux"))]
    #[test]
    fn socket_mark_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-mark",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"mark": 255}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindMark { value, inner } = config.protocol else {
            panic!("SO_MARK must wrap the gRPC listener");
        };
        assert_eq!(value, 255);
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", target_os = "linux"))]
    #[test]
    fn socket_mark_wraps_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-mark",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"mark": 255}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindMark { value, inner } = config.protocol else {
            panic!("SO_MARK must wrap the XHTTP listener");
        };
        assert_eq!(value, 255);
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(feature = "vless", feature = "tls", target_os = "linux"))]
    #[test]
    fn socket_mark_wraps_xhttp_http3_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-mark",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"mark": 255},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindMark { value, inner } = config.protocol else {
            panic!("SO_MARK must wrap the XHTTP HTTP/3 listener");
        };
        assert_eq!(value, 255);
        assert!(matches!(*inner, ServerProxyConfig::Tls(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_interface_wraps_listener_options_outermost() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-interface",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"interface": "lo", "tcpFastOpen": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindInterface { name, inner } = config.protocol
        else {
            panic!("interface must be the outer listener option");
        };
        assert_eq!(name, "lo");
        assert!(matches!(*inner, ServerProxyConfig::TcpFastOpen { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_empty_interface_is_ignored() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-interface-default",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"interface": ""}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_interface_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-interface",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"interface": "lo"}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindInterface { name, inner } = config.protocol
        else {
            panic!("interface must wrap the gRPC listener");
        };
        assert_eq!(name, "lo");
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_interface_wraps_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-interface",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"interface": "lo"}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindInterface { name, inner } = config.protocol
        else {
            panic!("interface must wrap the XHTTP listener");
        };
        assert_eq!(name, "lo");
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(
        feature = "vless",
        feature = "tls",
        any(target_os = "android", target_os = "linux")
    ))]
    #[test]
    fn socket_interface_wraps_xhttp_http3_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-interface",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"interface": "lo"},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::BindInterface { name, inner } = config.protocol
        else {
            panic!("interface must wrap the XHTTP HTTP/3 listener");
        };
        assert_eq!(name, "lo");
        assert!(matches!(*inner, ServerProxyConfig::Tls(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_fast_open_wraps_listener_options_outermost() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-fast-open",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpFastOpen": true,
                    "tcpMaxSeg": 1200,
                    "v6only": true
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpFastOpen { value, inner } = config.protocol else {
            panic!("TCP_FASTOPEN must be the outer listener option");
        };
        assert_eq!(value, 256);
        assert!(matches!(*inner, ServerProxyConfig::Ipv6Only { .. }));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_fast_open_preserves_xray_value_semantics() {
        for (input, expected) in [
            (serde_json::json!(false), Some(0)),
            (serde_json::json!(128), Some(128)),
            (serde_json::json!(0), None),
            (serde_json::json!(-1), Some(0)),
        ] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "tag": "vless-fast-open-values",
                "settings": {
                    "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "sockopt": {"tcpFastOpen": input}
                }
            }))
            .unwrap();
            let config = ServerConfig::try_from(inbound).unwrap();
            match expected {
                Some(expected) => {
                    let ServerProxyConfig::TcpFastOpen { value, .. } =
                        config.protocol
                    else {
                        panic!("tcpFastOpen value must build a listener option");
                    };
                    assert_eq!(value, expected);
                }
                None => assert!(matches!(
                    config.protocol,
                    ServerProxyConfig::Vless { .. }
                )),
            }
        }
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_tcp_fast_open_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-fast-open",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"tcpFastOpen": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpFastOpen { value, inner } = config.protocol else {
            panic!("TCP_FASTOPEN must wrap the gRPC listener");
        };
        assert_eq!(value, 256);
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_fast_open_wraps_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-fast-open",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpFastOpen": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpFastOpen { value, inner } = config.protocol else {
            panic!("TCP_FASTOPEN must wrap the XHTTP listener");
        };
        assert_eq!(value, 256);
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(
        feature = "vless",
        feature = "tls",
        any(target_os = "android", target_os = "linux")
    ))]
    #[test]
    fn socket_tcp_fast_open_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-fast-open",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpFastOpen": true},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
        assert!(error.to_string().contains("tcpFastOpen"));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_max_seg_is_outermost_listener_option() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-max-seg",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpKeepAliveIdle": 30,
                    "tcpMaxSeg": 1200,
                    "tcpUserTimeout": 12345
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpMaxSeg { value, inner } = config.protocol else {
            panic!("TCP_MAXSEG must be the outer listener option");
        };
        assert_eq!(value, 1200);
        assert!(matches!(*inner, ServerProxyConfig::TcpUserTimeout { .. }));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_v6only_is_outermost_listener_option() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-v6only",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"tcpMaxSeg": 1200, "v6only": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::Ipv6Only { inner } = config.protocol else {
            panic!("v6only must be the outer listener option");
        };
        assert!(matches!(*inner, ServerProxyConfig::TcpMaxSeg { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_v6only_false_is_ignored() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-v6only-default",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"v6only": false}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_v6only_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-v6only",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"v6only": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::Ipv6Only { inner } = config.protocol else {
            panic!("v6only must wrap the gRPC listener");
        };
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_v6only_wraps_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-v6only",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"v6only": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::Ipv6Only { inner } = config.protocol else {
            panic!("v6only must wrap the XHTTP listener");
        };
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(
        feature = "vless",
        feature = "tls",
        any(target_os = "android", target_os = "linux")
    ))]
    #[test]
    fn socket_v6only_wraps_xhttp_http3_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "::",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-v6only",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"v6only": true},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::Ipv6Only { inner } = config.protocol else {
            panic!("v6only must wrap the XHTTP HTTP/3 listener");
        };
        assert!(matches!(*inner, ServerProxyConfig::Tls(_)));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_non_positive_tcp_max_seg_is_ignored() {
        for value in [0, -1] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "tag": "vless-max-seg-disabled",
                "settings": {
                    "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "sockopt": {"tcpMaxSeg": value}
                }
            }))
            .unwrap();
            let config = ServerConfig::try_from(inbound).unwrap();
            assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
        }
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_tcp_max_seg_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-max-seg",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"tcpMaxSeg": 1200}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpMaxSeg { value, inner } = config.protocol else {
            panic!("TCP_MAXSEG must wrap the gRPC listener");
        };
        assert_eq!(value, 1200);
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_max_seg_wraps_dedicated_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-max-seg",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpMaxSeg": 1200}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpMaxSeg { value, inner } = config.protocol else {
            panic!("TCP_MAXSEG must wrap the XHTTP listener");
        };
        assert_eq!(value, 1200);
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(
        feature = "vless",
        feature = "tls",
        any(target_os = "android", target_os = "linux")
    ))]
    #[test]
    fn socket_tcp_max_seg_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-max-seg",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpMaxSeg": 1200},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
        assert!(error.to_string().contains("tcpMaxSeg"));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_tcp_window_clamp_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-window-clamp",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"tcpWindowClamp": 65535}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpWindowClamp { value, inner } = config.protocol
        else {
            panic!("TCP_WINDOW_CLAMP must wrap the gRPC listener");
        };
        assert_eq!(value, 65_535);
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_tcp_congestion_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-congestion",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"tcpCongestion": "cubic"}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpCongestion { algorithm, inner } = config.protocol
        else {
            panic!("TCP_CONGESTION must wrap the gRPC listener");
        };
        assert_eq!(algorithm, "cubic");
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_congestion_wraps_dedicated_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-congestion",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpCongestion": "cubic"}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpCongestion { algorithm, inner } = config.protocol
        else {
            panic!("TCP_CONGESTION must wrap the XHTTP listener");
        };
        assert_eq!(algorithm, "cubic");
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(
        feature = "vless",
        feature = "tls",
        any(target_os = "android", target_os = "linux")
    ))]
    #[test]
    fn socket_tcp_congestion_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-congestion",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpCongestion": "cubic"},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
        assert!(error.to_string().contains("tcpCongestion"));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_window_clamp_wraps_dedicated_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-window-clamp",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpWindowClamp": 65535}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpWindowClamp { value, inner } = config.protocol
        else {
            panic!("TCP_WINDOW_CLAMP must wrap the XHTTP listener");
        };
        assert_eq!(value, 65_535);
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(
        feature = "vless",
        feature = "tls",
        any(target_os = "android", target_os = "linux")
    ))]
    #[test]
    fn socket_tcp_window_clamp_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-window-clamp",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpWindowClamp": 65535},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
        assert!(error.to_string().contains("tcpWindowClamp"));
    }

    #[cfg(all(feature = "vless", target_os = "linux"))]
    #[test]
    fn socket_tcp_user_timeout_wraps_keepalive_outermost() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-user-timeout",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "sockopt": {
                    "tcpKeepAliveIdle": 30,
                    "tcpUserTimeout": 12345
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpUserTimeout { timeout_ms, inner } =
            config.protocol
        else {
            panic!("TCP_USER_TIMEOUT must be the outer socket wrapper");
        };
        assert_eq!(timeout_ms, 12_345);
        assert!(matches!(*inner, ServerProxyConfig::TcpKeepAlive { .. }));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_non_positive_tcp_user_timeout_is_ignored() {
        for timeout in [0, -1] {
            let inbound: InboudItem = serde_json::from_value(serde_json::json!({
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "tag": "vless-user-timeout-disabled",
                "settings": {
                    "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "sockopt": {"tcpUserTimeout": timeout}
                }
            }))
            .unwrap();
            let config = ServerConfig::try_from(inbound).unwrap();
            assert!(matches!(config.protocol, ServerProxyConfig::Vless { .. }));
        }
    }

    #[cfg(all(feature = "vless", target_os = "linux"))]
    #[test]
    fn socket_tcp_user_timeout_wraps_dedicated_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-user-timeout",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpUserTimeout": 12345}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpUserTimeout { timeout_ms, inner } =
            config.protocol
        else {
            panic!("TCP_USER_TIMEOUT must wrap the XHTTP listener");
        };
        assert_eq!(timeout_ms, 12_345);
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(feature = "vless", feature = "tls", target_os = "linux"))]
    #[test]
    fn socket_tcp_user_timeout_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-user-timeout",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpUserTimeout": 12345},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
        assert!(error.to_string().contains("tcpUserTimeout"));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_tcp_user_timeout_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-user-timeout",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"tcpUserTimeout": 12345}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpUserTimeout { timeout_ms, inner } =
            config.protocol
        else {
            panic!("TCP_USER_TIMEOUT must wrap the gRPC listener");
        };
        assert_eq!(timeout_ms, 12_345);
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_tcp_keepalive_wraps_dedicated_grpc_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-keepalive",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"tcpKeepAliveIdle": 30}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpKeepAlive {
            idle_secs,
            interval_secs,
            inner,
        } = config.protocol
        else {
            panic!("TCP keepalive must wrap the gRPC listener");
        };
        assert_eq!((idle_secs, interval_secs), (30, 0));
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(all(feature = "vless", feature = "grpc_transport"))]
    #[test]
    fn socket_accept_proxy_protocol_wraps_grpc_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-grpc-proxy",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {"serviceName": "proxy"},
                "sockopt": {"acceptProxyProtocol": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::ProxyProtocol { inner } = config.protocol else {
            panic!("sockopt PROXY protocol must wrap gRPC transport");
        };
        assert!(matches!(*inner, ServerProxyConfig::Grpc(_)));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn socket_accept_proxy_protocol_wraps_xhttp_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-proxy",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"acceptProxyProtocol": true}
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::ProxyProtocol { inner } = config.protocol else {
            panic!("sockopt PROXY protocol must wrap XHTTP transport");
        };
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(feature = "vless", any(target_os = "android", target_os = "linux")))]
    #[test]
    fn socket_tcp_keepalive_wraps_dedicated_xhttp_listener() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-keepalive",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {
                    "tcpKeepAliveIdle": 30,
                    "tcpKeepAliveInterval": 10
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::TcpKeepAlive {
            idle_secs,
            interval_secs,
            inner,
        } = config.protocol
        else {
            panic!("TCP keepalive must wrap the XHTTP listener");
        };
        assert_eq!((idle_secs, interval_secs), (30, 10));
        assert!(matches!(*inner, ServerProxyConfig::Xhttp { .. }));
    }

    #[cfg(all(feature = "vless", feature = "tls"))]
    #[test]
    fn socket_tcp_keepalive_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-keepalive",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"tcpKeepAliveIdle": 30},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
        assert!(error.to_string().contains("keepalive"));
    }

    #[cfg(all(feature = "vless", feature = "tls"))]
    #[test]
    fn socket_accept_proxy_protocol_rejects_xhttp_http3() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-xhttp-h3-proxy",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {"path": "/proxy"},
                "sockopt": {"acceptProxyProtocol": true},
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificate": ["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],
                        "key": ["-----BEGIN PRIVATE KEY-----","MIIB","-----END PRIVATE KEY-----"]
                    }]
                }
            }
        }))
        .unwrap();
        let error = ServerConfig::try_from(inbound).unwrap_err();
        assert!(error.to_string().contains("HTTP/3"));
    }

    #[cfg(all(feature = "vless", feature = "ws"))]
    #[test]
    fn websocket_accept_proxy_protocol_wraps_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-ws-proxy",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/ws",
                    "acceptProxyProtocol": true
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::ProxyProtocol { inner } = config.protocol else {
            panic!("PROXY protocol must be outside WebSocket");
        };
        assert!(matches!(*inner, ServerProxyConfig::Websocket { .. }));
    }

    #[cfg(all(feature = "vless", feature = "httpupgrade"))]
    #[test]
    fn httpupgrade_accept_proxy_protocol_wraps_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-httpupgrade-proxy",
            "settings": {
                "clients": [{"id": "3ac9b383-75a1-431c-8184-106c80eb2273"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "httpupgrade",
                "httpupgradeSettings": {
                    "path": "/upgrade",
                    "acceptProxyProtocol": true
                }
            }
        }))
        .unwrap();
        let config = ServerConfig::try_from(inbound).unwrap();
        let ServerProxyConfig::ProxyProtocol { inner } = config.protocol else {
            panic!("PROXY protocol must be outside HTTPUpgrade");
        };
        assert!(matches!(*inner, ServerProxyConfig::HttpUpgrade(_)));
    }

    #[cfg(feature = "vless")]
    #[test]
    fn vless_builder_rejects_mkcp_instead_of_treating_it_as_quic() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "tag": "vless-mkcp",
            "settings": {
                "clients": [{
                    "id": "3ac9b383-75a1-431c-8184-106c80eb2273"
                }],
                "decryption": "none"
            },
            "streamSettings": {"network": "mkcp"}
        }))
        .expect("valid literal inbound");

        let error = ServerConfig::try_from(inbound)
            .expect_err("mKCP must not be treated as QUIC");
        assert!(error.to_string().contains("network=mkcp"));
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
    fn http_inbound_preserves_allow_transparent() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "http",
            "tag": "http-transparent",
            "settings": {
                "allowTransparent": true,
                "userLevel": 7
            }
        }))
        .expect("valid HTTP transparent inbound");
        let config = ServerConfig::try_from(inbound)
            .expect("transparent HTTP inbound should build");
        match config.protocol {
            ServerProxyConfig::Http {
                allow_transparent,
                user_level,
                ..
            } => {
                assert!(allow_transparent);
                assert_eq!(user_level, 7);
            }
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
                "level": 3,
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
                assert_eq!(users[0].user_level, 3);
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
                    "email": "a@example.test",
                    "level": 3
                }, {
                    "method": "chacha20-ietf-poly1305",
                    "password": "secret-b",
                    "email": "b@example.test",
                    "level": 7
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
                assert_eq!(users[0].user_level, 3);
                assert_eq!(users[1].email, "b@example.test");
                assert_eq!(users[1].user_level, 7);
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
                    "email": "user-a@example.test",
                    "level": 5
                }, {
                    "password": "ICEiIyQlJicoKSorLC0uLw==",
                    "email": "user-b@example.test",
                    "level": 9
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
                assert_eq!(users[0].user_level, 5);
                assert_eq!(users[1].email, "user-b@example.test");
                assert_eq!(users[1].user_level, 9);
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
    fn dokodemo_door_udp_network_builds_udp_transport() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 10000,
            "protocol": "dokodemo-door",
            "tag": "dokodemo-udp",
            "settings": {
                "address": "127.0.0.1",
                "port": 5353,
                "userLevel": 7
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
                assert_eq!(config.user_level, 7);
            }
            other => panic!("expected dokodemo-door, got {other:?}"),
        }
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
                "network": "ws",
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
                ServerProxyConfig::Xhttp { inner, .. } => {
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

    #[cfg(all(feature = "vless", feature = "ws"))]
    #[test]
    fn websocket_settings_headers_enter_matching_config() {
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
                    "host": "example.com",
                    "path": "/ws",
                    "headers": {
                        "Host": "edge.example.com",
                        "X-Test": "ok"
                    }
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
                        .expect("websocket headers should be preserved");
                    assert_eq!(
                        headers.get("host"),
                        Some(&"example.com".to_string())
                    );
                    assert_eq!(headers.get("x-test"), Some(&"ok".to_string()));
                    assert!(!headers.contains_key("Host"));
                }
                OneOrSome::Some(_) => panic!("expected one websocket target"),
            },
            other => panic!("expected websocket protocol, got {other:?}"),
        }
    }
}
