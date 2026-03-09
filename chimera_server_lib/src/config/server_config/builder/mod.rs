mod collectors;
mod tls;

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

        let first_client = settings
            .as_ref()
            .and_then(|setting| setting.clients())
            .and_then(|clients| clients.into_iter().next())
            .map(|client| {
                tracing::info!("just use the first user_id");
                let label = if client.email.is_empty() {
                    client.id.clone()
                } else {
                    client.email
                };
                (client.id, label)
            });

        match protocol {
            Protocol::DokodemoDoor => {
                tracing::warn!("DokodemoDoor is not supported yet");
                #[cfg(feature = "vless")]
                {
                    let (user_id, user_label) =
                        first_client.clone().ok_or_else(|| {
                            Error::InvalidConfig(
                                "dokodemodoor fallback requires at least one client"
                                    .into(),
                            )
                        })?;

                    return Ok(ServerConfig {
                        tag,
                        bind_location,
                        protocol: ServerProxyConfig::Vless {
                            user_id,
                            user_label,
                        },
                        transport: Transport::Tcp,
                        quic_settings: None,
                    });
                }

                #[cfg(not(feature = "vless"))]
                {
                    return Err(Error::InvalidConfig(
                        "DokodemoDoor requires the vless feature".into(),
                    ));
                }
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
                    cert: item.certificate_file,
                    key: item.key_file,
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
                let (user_id, user_label) = first_client.clone().ok_or_else(|| {
                    Error::InvalidConfig(
                        "vless inbound requires at least one client".into(),
                    )
                })?;

                let mut protocol = ServerProxyConfig::Vless {
                    user_id,
                    user_label,
                };
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

                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("tuic inbound requires settings".into())
                })?;
                let config = collect_tuic_settings(settings)?;

                let quic_settings = Some(ServerQuicConfig {
                    cert: certificate.certificate_file,
                    key: certificate.key_file,
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
