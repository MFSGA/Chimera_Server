mod collectors;
mod tls;

use serde::Deserialize;

use crate::{
    Error,
    address::{Address, BindLocation, NetLocation},
    config::{Protocol, Transport, def::InboudItem},
    util::option::NoneOrSome,
};

#[cfg(feature = "ws")]
use crate::util::option::OneOrSome;

#[cfg(feature = "ws")]
use super::ws::WebsocketServerConfig;
use super::{
    quic::ServerQuicConfig,
    types::{ServerConfig, ServerProxyConfig},
};

#[cfg(feature = "hysteria")]
use collectors::collect_hysteria2_settings;
use collectors::{collect_socks_accounts, collect_xhttp_settings};

#[cfg(feature = "tuic")]
use collectors::collect_tuic_settings;
#[cfg(feature = "trojan")]
use collectors::{collect_trojan_clients, collect_trojan_fallbacks};
use tls::apply_security_layers;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DokodemoDoorSettings {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    follow_redirect: bool,
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
            ..
        } = value;

        let bind_location = BindLocation::Address(NetLocation::new(
            Address::from(&listen.clone().unwrap_or_else(|| "0.0.0.0".to_string()))
                .unwrap(),
            port,
        ));

        #[cfg(feature = "vless")]
        let vless_users = settings
            .as_ref()
            .and_then(|setting| setting.clients())
            .map(|clients| {
                clients
                    .into_iter()
                    .map(|client| crate::config::server_config::VlessUser {
                        user_id: client.id.clone(),
                        user_label: if client.email.is_empty() {
                            client.id
                        } else {
                            client.email
                        },
                    })
                    .collect::<Vec<_>>()
            });

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
                    },
                };

                if let Some(stream_setting) = stream_settings.as_ref() {
                    protocol = apply_security_layers(protocol, stream_setting)?;
                }

                return Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                });
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
                let users = vless_users.clone().ok_or_else(|| {
                    Error::InvalidConfig(
                        "vless inbound requires at least one client".into(),
                    )
                })?;

                let mut protocol = ServerProxyConfig::Vless { users };
                let uses_xhttp = stream_settings
                    .as_ref()
                    .map(|settings| settings.network.eq_ignore_ascii_case("xhttp"))
                    .unwrap_or(false);

                #[cfg(feature = "ws")]
                if !uses_xhttp {
                    if let Some(stream_setting) = stream_settings.as_ref() {
                        if let Some(ws_setting) = stream_setting.ws_settings.clone() {
                            tracing::info!("use websocket");
                            protocol = ServerProxyConfig::Websocket {
                                targets: Box::new(OneOrSome::One(
                                    WebsocketServerConfig {
                                        matching_path: ws_setting.path,
                                        matching_headers: None,
                                        protocol,
                                    },
                                )),
                            };
                        }
                    }
                }

                if let Some(stream_setting) = stream_settings.as_ref() {
                    if uses_xhttp {
                        let security = stream_setting
                            .security
                            .as_deref()
                            .unwrap_or("none")
                            .to_ascii_lowercase();

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
                            "none" => {}
                            "tls" | "reality" => {
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
                        protocol = apply_security_layers(protocol, stream_setting)?;
                    }
                }

                return Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol,
                    transport: Transport::Tcp,
                    quic_settings: None,
                });
            }
            Protocol::Vmess => todo!(),

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

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref() {
                    if let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                WebsocketServerConfig {
                                    matching_path: ws_setting.path,
                                    matching_headers: None,
                                    protocol,
                                },
                            )),
                        };
                    }
                }

                if let Some(stream_setting) = stream_settings.as_ref() {
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
                let tls_settings =
                    stream_settings.tls_settings.ok_or_else(|| {
                        Error::InvalidConfig(
                            "tuic inbound requires tlsSettings".into(),
                        )
                    })?;
                let certificate = tls_settings
                    .certificates
                    .get(0)
                    .ok_or_else(|| {
                        Error::InvalidConfig(
                            "tuic inbound requires at least one certificate".into(),
                        )
                    })?
                    .clone();
                let cert = certificate.certificate_file.ok_or_else(|| {
                    Error::InvalidConfig(
                        "tuic inbound currently requires certificateFile".into(),
                    )
                })?;
                let key = certificate.key_file.ok_or_else(|| {
                    Error::InvalidConfig(
                        "tuic inbound currently requires keyFile".into(),
                    )
                })?;

                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("tuic inbound requires settings".into())
                })?;
                let config = collect_tuic_settings(settings)?;

                let quic_settings = Some(ServerQuicConfig {
                    cert,
                    key,
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

            Protocol::Socks => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("socks inbound requires settings".into())
                })?;
                let accounts = collect_socks_accounts(settings)?;
                let mut protocol = ServerProxyConfig::Socks { accounts };

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref() {
                    if let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                WebsocketServerConfig {
                                    matching_path: ws_setting.path,
                                    matching_headers: None,
                                    protocol,
                                },
                            )),
                        };
                    }
                }

                if let Some(stream_setting) = stream_settings.as_ref() {
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
                        "id": "114cb5a6-3787-4357-a5da-69b5782cb74f",
                        "email": "user-a@example.com"
                    },
                    {
                        "id": "9d2d3c52-a386-4f2f-a507-0ca29f8d13f0",
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
            ServerProxyConfig::Vless { users } => {
                assert_eq!(users.len(), 2);
                assert_eq!(users[0].user_id, "114cb5a6-3787-4357-a5da-69b5782cb74f");
                assert_eq!(users[0].user_label, "user-a@example.com");
                assert_eq!(users[1].user_id, "9d2d3c52-a386-4f2f-a507-0ca29f8d13f0");
                assert_eq!(users[1].user_label, "user-b@example.com");
            }
            other => panic!("expected vless protocol, got {other:?}"),
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
                        "id": "114cb5a6-3787-4357-a5da-69b5782cb74f",
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
                    "privateKey": "CAe1AlfoOhzR5zwWRYxUSUm2qdzWXM0qDJzbOWUvTno",
                    "shortIds": ["6ba85179e30d4fc2"],
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
}
