mod collectors;
mod tls;

use crate::{
    address::{Address, BindLocation, NetLocation},
    config::{def::InboudItem, Protocol, StreamSettings, Transport},
    util::option::NoneOrSome,
    Error,
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
use collectors::collect_socks_accounts;
#[cfg(feature = "xhttp")]
use collectors::{collect_xhttp_settings, collect_xhttp_transport_settings};

#[cfg(feature = "tuic")]
use collectors::collect_tuic_settings;
#[cfg(feature = "trojan")]
use collectors::{collect_trojan_clients, collect_trojan_fallbacks};
use tls::apply_security_layers;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StreamNetwork {
    Tcp,
    Ws,
    Xhttp,
}

fn parse_stream_network(stream_settings: Option<&StreamSettings>) -> Result<StreamNetwork, Error> {
    let Some(stream_settings) = stream_settings else {
        return Ok(StreamNetwork::Tcp);
    };

    let normalized = stream_settings
        .network
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "tcp".to_string());

    match normalized.as_str() {
        "tcp" | "raw" => Ok(StreamNetwork::Tcp),
        "ws" | "websocket" => Ok(StreamNetwork::Ws),
        "xhttp" | "splithttp" => Ok(StreamNetwork::Xhttp),
        other => Err(Error::InvalidConfig(format!(
            "unsupported streamSettings.network: {}",
            other
        ))),
    }
}

fn apply_stream_transport_layer(
    mut protocol: ServerProxyConfig,
    stream_settings: Option<&StreamSettings>,
    network: StreamNetwork,
) -> Result<ServerProxyConfig, Error> {
    match network {
        StreamNetwork::Tcp => Ok(protocol),
        StreamNetwork::Ws => {
            #[cfg(feature = "ws")]
            {
                let stream_settings = stream_settings.ok_or_else(|| {
                    Error::InvalidConfig("streamSettings.network=ws requires streamSettings".into())
                })?;
                let ws_setting = stream_settings.ws_settings.clone().ok_or_else(|| {
                    Error::InvalidConfig("streamSettings.network=ws requires wsSettings".into())
                })?;
                tracing::info!("use websocket transport");
                protocol = ServerProxyConfig::Websocket {
                    targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                        matching_path: ws_setting.path,
                        matching_headers: None,
                        protocol,
                    })),
                };
                Ok(protocol)
            }

            #[cfg(not(feature = "ws"))]
            {
                let _ = stream_settings;
                Err(Error::InvalidConfig(
                    "streamSettings.network=ws requires the ws feature".into(),
                ))
            }
        }
        StreamNetwork::Xhttp => {
            #[cfg(feature = "xhttp")]
            {
                let stream_settings = stream_settings.ok_or_else(|| {
                    Error::InvalidConfig(
                        "streamSettings.network=xhttp requires streamSettings".into(),
                    )
                })?;
                if stream_settings
                    .security
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some_and(|value| !value.eq_ignore_ascii_case("none"))
                {
                    return Err(Error::InvalidConfig(
                        "xhttp transport currently does not support streamSettings.security".into(),
                    ));
                }
                let config = collect_xhttp_transport_settings(stream_settings)?;
                Ok(ServerProxyConfig::Xhttp {
                    config,
                    inner: Some(Box::new(protocol)),
                })
            }

            #[cfg(not(feature = "xhttp"))]
            {
                let _ = stream_settings;
                Err(Error::InvalidConfig(
                    "streamSettings.network=xhttp requires the xhttp feature".into(),
                ))
            }
        }
    }
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
            Address::from(&listen.clone().unwrap_or_else(|| "0.0.0.0".to_string())).unwrap(),
            port,
        ));

        let (user_id, user_label) = settings
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
            })
            .unwrap_or_else(|| {
                let fallback = "ddb573cb-55f8-4d8d-a609-bd444b14b19b".to_string();
                (fallback.clone(), fallback)
            });

        match protocol {
            Protocol::DokodemoDoor => {
                tracing::warn!("DokodemoDoor is not supported yet");
                #[cfg(feature = "vless")]
                {
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
                    Error::InvalidConfig("hysteria2 inbound missing streamSettings".into())
                })?;
                let hysteria_settings = stream_settings.hysteria_settings.as_ref();
                let tls_settings = stream_settings.tls_settings.ok_or_else(|| {
                    Error::InvalidConfig("hysteria2 inbound requires tlsSettings".into())
                })?;
                let item = tls_settings.certificates[0].clone();

                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("hysteria2 inbound requires clients".into())
                })?;
                let config = collect_hysteria2_settings(settings, hysteria_settings)?;
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
                let mut protocol = ServerProxyConfig::Vless {
                    user_id: user_id.clone(),
                    user_label: user_label.clone(),
                };

                let stream_network = parse_stream_network(stream_settings.as_ref())?;
                protocol = apply_stream_transport_layer(
                    protocol,
                    stream_settings.as_ref(),
                    stream_network,
                )?;

                if stream_network != StreamNetwork::Xhttp {
                    if let Some(stream_setting) = stream_settings.as_ref() {
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

                let stream_network = parse_stream_network(stream_settings.as_ref())?;
                protocol = apply_stream_transport_layer(
                    protocol,
                    stream_settings.as_ref(),
                    stream_network,
                )?;

                if stream_network != StreamNetwork::Xhttp {
                    if let Some(stream_setting) = stream_settings.as_ref() {
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

            #[cfg(feature = "tuic")]
            Protocol::TuicV5 => {
                let stream_settings = stream_settings.ok_or_else(|| {
                    Error::InvalidConfig("tuic inbound missing streamSettings".into())
                })?;
                let tls_settings = stream_settings.tls_settings.ok_or_else(|| {
                    Error::InvalidConfig("tuic inbound requires tlsSettings".into())
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

                let settings = settings
                    .ok_or_else(|| Error::InvalidConfig("tuic inbound requires settings".into()))?;
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

            #[cfg(feature = "xhttp")]
            Protocol::Xhttp => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("xhttp inbound requires settings".into())
                })?;
                let xhttp_config = collect_xhttp_settings(settings)?;

                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol: ServerProxyConfig::Xhttp {
                        config: xhttp_config,
                        inner: None,
                    },
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
            }

            Protocol::Socks => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("socks inbound requires settings".into())
                })?;
                let accounts = collect_socks_accounts(settings)?;
                let mut protocol = ServerProxyConfig::Socks { accounts };

                let stream_network = parse_stream_network(stream_settings.as_ref())?;
                protocol = apply_stream_transport_layer(
                    protocol,
                    stream_settings.as_ref(),
                    stream_network,
                )?;

                if stream_network != StreamNetwork::Xhttp {
                    if let Some(stream_setting) = stream_settings.as_ref() {
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
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::def::InboudItem;

    use super::*;

    #[cfg(all(feature = "vless", feature = "xhttp"))]
    #[test]
    fn vless_xhttp_network_wraps_inner_protocol() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "email": "u@example.com",
                        "flow": "",
                        "id": "550e8400-e29b-41d4-a716-446655440000"
                    }
                ]
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": {
                    "path": "/edge"
                }
            },
            "tag": "inbound-xhttp"
        }))
        .expect("inbound item");

        let server_config = ServerConfig::try_from(inbound).expect("server config");
        assert_eq!(server_config.transport, Transport::Tcp);

        match server_config.protocol {
            ServerProxyConfig::Xhttp { config, inner } => {
                assert_eq!(config.path, "/edge/");
                let inner = inner.expect("xhttp transport should wrap an inner protocol");
                assert!(matches!(*inner, ServerProxyConfig::Vless { .. }));
            }
            other => panic!("unexpected protocol: {:?}", other),
        }
    }

    #[cfg(all(feature = "vless", feature = "xhttp"))]
    #[test]
    fn xhttp_network_rejects_security_layer_for_now() {
        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "listen": "127.0.0.1",
            "port": 8443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "email": "u@example.com",
                        "flow": "",
                        "id": "550e8400-e29b-41d4-a716-446655440000"
                    }
                ]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "xhttpSettings": {
                    "path": "/edge"
                }
            },
            "tag": "inbound-xhttp"
        }))
        .expect("inbound item");

        let err = ServerConfig::try_from(inbound).expect_err("xhttp with tls should fail for now");
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
