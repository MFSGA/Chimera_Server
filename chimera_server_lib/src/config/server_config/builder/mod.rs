mod collectors;
mod finalmask;
#[cfg(feature = "hysteria")]
mod hysteria2;
mod stream;
mod tls;
#[cfg(feature = "vless")]
mod vless;

use serde::Deserialize;

use crate::{
    Error,
    address::{Address, BindLocation, NetLocation},
    config::{Protocol, Transport, def::InboudItem},
};

#[cfg(any(feature = "hysteria", feature = "tuic"))]
use crate::util::option::NoneOrSome;

use finalmask::validate_xray_finalmask_quic_params;
#[cfg(feature = "hysteria")]
use hysteria2::build_hysteria2_server;
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
#[cfg(feature = "vless")]
use vless::build_vless_server;

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
