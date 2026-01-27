mod collectors;
mod tls;

use crate::{
    address::{Address, BindLocation, NetLocation},
    config::{def::InboudItem, Protocol, Transport},
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
use collectors::{collect_socks_accounts, collect_xhttp_settings};

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
                Ok(ServerConfig {
                    tag,
                    bind_location,
                    protocol: ServerProxyConfig::Vless {
                        user_id,
                        user_label,
                    },
                    transport: Transport::Tcp,
                    quic_settings: None,
                })
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
            Protocol::Vless => {
                let mut protocol = ServerProxyConfig::Vless {
                    user_id: user_id.clone(),
                    user_label: user_label.clone(),
                };

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref() {
                    if let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                                matching_path: ws_setting.path,
                                matching_headers: None,
                                protocol,
                            })),
                        };
                    }
                }

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
                            targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                                matching_path: ws_setting.path,
                                matching_headers: None,
                                protocol,
                            })),
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

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref() {
                    if let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(WebsocketServerConfig {
                                matching_path: ws_setting.path,
                                matching_headers: None,
                                protocol,
                            })),
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
