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
fn has_non_vision_vless_flow(
    users: &[crate::config::server_config::VlessUser],
) -> bool {
    users.iter().any(|user| user.flow != "xtls-rprx-vision")
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
                    },
                };

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
                if !vless_settings.fallbacks.is_empty() {
                    return Err(Error::InvalidConfig(
                        "vless settings.fallbacks is not supported yet".into(),
                    ));
                }
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
                let mixes_plain_and_vision =
                    uses_vision && has_non_vision_vless_flow(&users);

                let mut protocol = ServerProxyConfig::Vless { users };
                let uses_xhttp = stream_settings
                    .as_ref()
                    .map(|settings| settings.network.eq_ignore_ascii_case("xhttp"))
                    .unwrap_or(false);
                let security = stream_settings
                    .as_ref()
                    .and_then(|settings| settings.security.as_deref())
                    .unwrap_or("none")
                    .to_ascii_lowercase();

                if uses_vision {
                    if mixes_plain_and_vision {
                        return Err(Error::InvalidConfig(
                            "xtls-rprx-vision users cannot share one inbound with plain vless users"
                                .into(),
                        ));
                    }
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
                if !uses_xhttp
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
                            cipher: client
                                .security
                                .filter(|value| !value.trim().is_empty())
                                .unwrap_or_else(|| "auto".to_string()),
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let mut protocol = ServerProxyConfig::Vmess { users };

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                websocket_server_config(ws_setting, protocol),
                            )),
                        };
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
                if let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                websocket_server_config(ws_setting, protocol),
                            )),
                        };
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

            Protocol::Socks => {
                let settings = settings.ok_or_else(|| {
                    Error::InvalidConfig("socks inbound requires settings".into())
                })?;
                let accounts = collect_socks_accounts(settings)?;
                let mut protocol = ServerProxyConfig::Socks { accounts };

                #[cfg(feature = "ws")]
                if let Some(stream_setting) = stream_settings.as_ref()
                    && let Some(ws_setting) = stream_setting.ws_settings.clone() {
                        tracing::info!("use websocket");
                        protocol = ServerProxyConfig::Websocket {
                            targets: Box::new(OneOrSome::One(
                                websocket_server_config(ws_setting, protocol),
                            )),
                        };
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
            ServerProxyConfig::Vless { users } => {
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
                ServerProxyConfig::Vless { users } => {
                    assert_eq!(users.len(), 1);
                    assert_eq!(users[0].flow, "xtls-rprx-vision");
                }
                other => {
                    panic!("expected vless protocol inside reality, got {other:?}")
                }
            },
            #[cfg(feature = "tls")]
            ServerProxyConfig::Tls(tls) => match tls.inner.as_ref() {
                ServerProxyConfig::Vless { users } => {
                    assert_eq!(users.len(), 1);
                    assert_eq!(users[0].flow, "xtls-rprx-vision");
                }
                other => panic!("expected vless protocol inside tls, got {other:?}"),
            },
            ServerProxyConfig::Vless { users } => {
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
    fn vless_reality_defaults_missing_short_ids_to_zero() {
        let mut settings = base_reality_settings();
        settings
            .as_object_mut()
            .expect("reality settings object")
            .remove("shortIds");

        let config = ServerConfig::try_from(vless_reality_inbound(settings))
            .expect("missing shortIds should use shoes-compatible default");

        match config.protocol {
            ServerProxyConfig::Reality(reality) => {
                assert_eq!(reality.short_ids, vec![[0u8; 8]]);
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
                ServerProxyConfig::Vless { users } => {
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
    fn vless_builder_rejects_mixed_plain_and_vision_users() {
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

        let err = ServerConfig::try_from(inbound)
            .expect_err("mixed plain and vision users should fail");
        assert!(err.to_string().contains(
            "xtls-rprx-vision users cannot share one inbound with plain vless users"
        ));
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
    fn vless_builder_rejects_fallbacks_until_implemented() {
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
                "fallbacks": [{ "dest": "127.0.0.1:8080" }]
            }
        }))
        .expect("valid inbound json shape");

        let err = ServerConfig::try_from(inbound)
            .expect_err("vless fallbacks should fail explicitly");
        assert!(
            err.to_string()
                .contains("vless settings.fallbacks is not supported yet")
        );
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
