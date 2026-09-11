use prost::Message;

use super::*;

pub(super) fn decode_socks_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<SocksOutboundEndpoint> {
    let message_type = outbound
        .proxy_settings_type
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.');
    if message_type != TYPE_PROXY_SOCKS_CLIENT_CONFIG
        && message_type != TYPE_PROXY_SOCKS_CLIENT_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "SOCKS outbound {} is missing Xray client settings",
                outbound.tag
            ),
        ));
    }
    let value = outbound.proxy_settings_value.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS outbound {} settings are empty", outbound.tag),
        )
    })?;
    let config = SocksClientConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid SOCKS outbound {} settings: {error}", outbound.tag),
        )
    })?;
    let server = config.server.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS outbound {} requires a server endpoint", outbound.tag),
        )
    })?;
    let port = u16::try_from(server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("SOCKS outbound {} has invalid server port", outbound.tag),
            )
        })?;
    let address = decode_ip_or_domain(server.address.as_ref()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SOCKS outbound {} has invalid server address", outbound.tag),
        )
    })?;
    let (username, password) = match server.user.and_then(|user| user.account) {
        Some(account) => {
            let account_type = account.r#type.trim_start_matches('.');
            if account_type != TYPE_PROXY_SOCKS_ACCOUNT
                && account_type != "v2ray.core.proxy.socks.Account"
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "SOCKS outbound {} has unsupported account type {}",
                        outbound.tag, account.r#type
                    ),
                ));
            }
            let account = SocksAccountPayload::decode(account.value.as_slice())
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "invalid SOCKS outbound {} account: {error}",
                            outbound.tag
                        ),
                    )
                })?;
            (Some(account.username), Some(account.password))
        }
        None => (None, None),
    };
    Ok(SocksOutboundEndpoint {
        server: NetLocation::new(address, port),
        username,
        password,
    })
}

pub(super) fn decode_vless_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<VlessOutboundEndpoint> {
    let message_type = outbound
        .proxy_settings_type
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.');
    if message_type != TYPE_PROXY_VLESS_CLIENT_CONFIG
        && message_type != TYPE_PROXY_VLESS_CLIENT_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "VLESS outbound {} is missing Xray client settings",
                outbound.tag
            ),
        ));
    }
    let value = outbound.proxy_settings_value.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} settings are empty", outbound.tag),
        )
    })?;
    let config = VlessClientConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid VLESS outbound {} settings: {error}", outbound.tag),
        )
    })?;
    let server = config.vnext.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} requires a vnext endpoint", outbound.tag),
        )
    })?;
    let port = u16::try_from(server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("VLESS outbound {} has invalid server port", outbound.tag),
            )
        })?;
    let address = decode_ip_or_domain(server.address.as_ref()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} has invalid server address", outbound.tag),
        )
    })?;
    let account = server.user.and_then(|user| user.account).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("VLESS outbound {} requires exactly one user", outbound.tag),
        )
    })?;
    let account_type = account.r#type.trim_start_matches('.');
    if account_type != TYPE_PROXY_VLESS_ACCOUNT
        && account_type != TYPE_PROXY_VLESS_ACCOUNT_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "VLESS outbound {} has unsupported account type {}",
                outbound.tag, account.r#type
            ),
        ));
    }
    let account =
        VlessAccountPayload::decode(account.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid VLESS outbound {} account: {error}", outbound.tag),
            )
        })?;
    if !account.flow.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "VLESS outbound {} flow {} is not implemented yet",
                outbound.tag, account.flow
            ),
        ));
    }
    if !account.encryption.trim().eq_ignore_ascii_case("none") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "VLESS outbound {} encryption {} is not implemented",
                outbound.tag, account.encryption
            ),
        ));
    }
    let user_id = parse_xray_uuid(&account.id).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
    })?;
    Ok(VlessOutboundEndpoint {
        server: NetLocation::new(address, port),
        user_id,
        flow: account.flow,
    })
}

pub(super) fn decode_trojan_outbound(
    outbound: &OutboundSummary,
) -> std::io::Result<TrojanOutboundEndpoint> {
    let message_type = outbound
        .proxy_settings_type
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('.');
    if message_type != TYPE_PROXY_TROJAN_CLIENT_CONFIG
        && message_type != TYPE_PROXY_TROJAN_CLIENT_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} is missing Xray client settings",
                outbound.tag
            ),
        ));
    }
    let value = outbound.proxy_settings_value.as_deref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan outbound {} settings are empty", outbound.tag),
        )
    })?;
    let config = TrojanClientConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid Trojan outbound {} settings: {error}", outbound.tag),
        )
    })?;
    let server = config.server.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} requires a server endpoint",
                outbound.tag
            ),
        )
    })?;
    let port = u16::try_from(server.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Trojan outbound {} has invalid server port", outbound.tag),
            )
        })?;
    let address = decode_ip_or_domain(server.address.as_ref()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} has invalid server address",
                outbound.tag
            ),
        )
    })?;
    let account = server.user.and_then(|user| user.account).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan outbound {} requires exactly one user", outbound.tag),
        )
    })?;
    let account_type = account.r#type.trim_start_matches('.');
    if account_type != TYPE_PROXY_TROJAN_ACCOUNT
        && account_type != TYPE_PROXY_TROJAN_ACCOUNT_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Trojan outbound {} has unsupported account type {}",
                outbound.tag, account.r#type
            ),
        ));
    }
    let account =
        TrojanAccountPayload::decode(account.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid Trojan outbound {} account: {error}", outbound.tag),
            )
        })?;
    if account.password.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Trojan outbound {} password is empty", outbound.tag),
        ));
    }
    Ok(TrojanOutboundEndpoint {
        server: NetLocation::new(address, port),
        password: account.password,
    })
}

pub(super) fn decode_outbound_transport(
    outbound: &OutboundSummary,
) -> std::io::Result<OutboundTransport> {
    decode_sender_transport(
        outbound.sender_settings_type.as_deref(),
        outbound.sender_settings_value.as_deref(),
    )
}

pub(crate) fn validate_outbound_sender_settings(
    message_type: Option<&str>,
    value: Option<&[u8]>,
) -> std::io::Result<()> {
    decode_sender_transport(message_type, value).map(|_| ())
}

pub(super) fn decode_sender_transport(
    message_type: Option<&str>,
    value: Option<&[u8]>,
) -> std::io::Result<OutboundTransport> {
    let Some(message_type) = message_type else {
        return Ok(OutboundTransport::Raw);
    };
    let message_type = message_type.trim_start_matches('.');
    if message_type != TYPE_APP_SENDER_CONFIG
        && message_type != TYPE_APP_SENDER_CONFIG_V2RAY
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported outbound sender settings type {message_type}"),
        ));
    }
    let value = value.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "outbound sender settings payload is empty",
        )
    })?;
    let sender = SenderConfigPayload::decode(value).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid outbound sender settings: {error}"),
        )
    })?;
    let Some(stream) = sender.stream_settings else {
        return Ok(OutboundTransport::Raw);
    };
    let reality = decode_reality_security(&stream)?;
    let tls = if reality.is_none() {
        decode_tls_security(&stream)?
    } else {
        None
    };
    match stream.protocol_name.trim().to_ascii_lowercase().as_str() {
        "" | "raw" | "tcp" => Ok(match (tls, reality) {
            (Some(settings), None) => OutboundTransport::Tls(settings),
            (None, Some(settings)) => OutboundTransport::Reality(settings),
            (None, None) => OutboundTransport::Raw,
            (Some(_), Some(_)) => {
                unreachable!("one Xray stream has one security type")
            }
        }),
        "ws" | "websocket" => {
            if reality.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "REALITY outbound with WebSocket transport is not implemented yet",
                ));
            }
            let tls = tls.map(|mut settings| {
                if settings.alpn.is_empty() {
                    settings.alpn.push("http/1.1".to_string());
                }
                settings
            });
            let transport = stream
                .transport_settings
                .iter()
                .find(|transport| {
                    matches!(
                        transport.protocol_name.trim().to_ascii_lowercase().as_str(),
                        "ws" | "websocket"
                    )
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "WebSocket outbound is missing transport settings",
                    )
                })?;
            let settings = transport.settings.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "WebSocket outbound transport settings are empty",
                )
            })?;
            let settings_type = settings.r#type.trim_start_matches('.');
            if settings_type != TYPE_TRANSPORT_WEBSOCKET_CONFIG
                && settings_type != TYPE_TRANSPORT_WEBSOCKET_CONFIG_V2RAY
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported WebSocket outbound settings type {}",
                        settings.r#type
                    ),
                ));
            }
            let settings = WebsocketConfigPayload::decode(settings.value.as_slice())
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid outbound WebSocket settings: {error}"),
                    )
                })?;
            Ok(OutboundTransport::Websocket {
                tls,
                settings: OutboundWebsocketClientSettings {
                    host: settings.host,
                    path: if settings.path.is_empty() {
                        "/".to_string()
                    } else {
                        settings.path
                    },
                    headers: settings.header,
                    ed: settings.ed,
                    heartbeat_period: settings.heartbeat_period,
                },
            })
        }
        "httpupgrade" | "http-upgrade" => {
            if reality.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "REALITY outbound with HTTPUpgrade transport is not implemented yet",
                ));
            }
            let tls = tls.map(|mut settings| {
                if settings.alpn.is_empty() {
                    settings.alpn.push("http/1.1".to_string());
                }
                settings
            });
            let transport = stream
                .transport_settings
                .iter()
                .find(|transport| {
                    matches!(
                        transport.protocol_name.trim().to_ascii_lowercase().as_str(),
                        "httpupgrade" | "http-upgrade"
                    )
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "HTTPUpgrade outbound is missing transport settings",
                    )
                })?;
            let settings = transport.settings.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTPUpgrade outbound transport settings are empty",
                )
            })?;
            let settings_type = settings.r#type.trim_start_matches('.');
            if settings_type != TYPE_TRANSPORT_HTTPUPGRADE_CONFIG
                && settings_type != TYPE_TRANSPORT_HTTPUPGRADE_CONFIG_V2RAY
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported HTTPUpgrade outbound settings type {}",
                        settings.r#type
                    ),
                ));
            }
            let settings =
                HttpUpgradeConfigPayload::decode(settings.value.as_slice())
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "invalid outbound HTTPUpgrade settings: {error}"
                            ),
                        )
                    })?;
            if settings
                .header
                .keys()
                .any(|name| name.eq_ignore_ascii_case("host"))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTPUpgrade outbound headers can't contain Host; use host instead",
                ));
            }
            Ok(OutboundTransport::HttpUpgrade {
                tls,
                settings: OutboundHttpUpgradeClientSettings {
                    host: settings.host,
                    path: if settings.path.is_empty() {
                        "/".to_string()
                    } else {
                        settings.path
                    },
                    headers: settings.header,
                    ed: settings.ed,
                },
            })
        }
        #[cfg(feature = "grpc_transport")]
        "grpc" => {
            let tls = tls.map(|mut settings| {
                if settings.alpn.is_empty() {
                    settings.alpn.push("h2".to_string());
                }
                settings
            });
            let transport = stream
                .transport_settings
                .iter()
                .find(|transport| {
                    transport.protocol_name.trim().eq_ignore_ascii_case("grpc")
                })
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "gRPC outbound is missing transport settings",
                    )
                })?;
            let settings = transport.settings.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "gRPC outbound transport settings are empty",
                )
            })?;
            let settings_type = settings.r#type.trim_start_matches('.');
            if settings_type != TYPE_TRANSPORT_GRPC_CONFIG
                && settings_type != TYPE_TRANSPORT_GRPC_CONFIG_V2RAY
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported gRPC outbound settings type {}",
                        settings.r#type
                    ),
                ));
            }
            let settings = GrpcConfigPayload::decode(settings.value.as_slice())
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid outbound gRPC settings: {error}"),
                    )
                })?;
            Ok(OutboundTransport::Grpc {
                tls,
                reality,
                settings: OutboundGrpcClientSettings {
                    authority: settings.authority,
                    service_name: settings.service_name,
                    multi_mode: settings.multi_mode,
                    idle_timeout: settings.idle_timeout.max(0),
                    health_check_timeout: settings.health_check_timeout.max(0),
                    permit_without_stream: settings.permit_without_stream,
                    initial_windows_size: settings.initial_windows_size.max(0),
                    user_agent: settings.user_agent,
                },
            })
        }
        network => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("outbound transport {network} is not implemented yet"),
        )),
    }
}

pub(super) fn decode_reality_security(
    stream: &OutboundStreamConfigPayload,
) -> std::io::Result<Option<OutboundRealityClientSettings>> {
    let security = stream.security_type.trim_start_matches('.');
    if security != TYPE_TRANSPORT_REALITY_CONFIG
        && !security.eq_ignore_ascii_case("reality")
    {
        return Ok(None);
    }
    let message = stream
        .security_settings
        .iter()
        .find(|message| {
            message.r#type.trim_start_matches('.') == TYPE_TRANSPORT_REALITY_CONFIG
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY outbound is missing REALITY security settings",
            )
        })?;
    let reality =
        RealityConfigPayload::decode(message.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid outbound REALITY settings: {error}"),
            )
        })?;
    if !reality.dest.is_empty()
        || !reality.r#type.is_empty()
        || reality.xver != 0
        || !reality.server_names.is_empty()
        || !reality.private_key.is_empty()
        || !reality.min_client_ver.is_empty()
        || !reality.max_client_ver.is_empty()
        || reality.max_time_diff != 0
        || !reality.short_ids.is_empty()
        || !reality.mldsa65_seed.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY outbound contains server-side settings",
        ));
    }
    if !matches!(
        reality.fingerprint.trim().to_ascii_lowercase().as_str(),
        "" | "chrome"
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "REALITY outbound fingerprint {} is not implemented; only chrome is supported",
                reality.fingerprint
            ),
        ));
    }
    if reality.public_key.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY outbound publicKey must contain exactly 32 bytes",
        ));
    }
    if reality.short_id.len() != 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "REALITY outbound shortId must contain exactly 8 bytes",
        ));
    }
    if !reality.mldsa65_verify.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY outbound ML-DSA verification is not implemented yet",
        ));
    }
    if !reality.master_key_log.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY outbound masterKeyLog is not implemented yet",
        ));
    }
    if !reality.spider_x.is_empty() && reality.spider_x != "/" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "REALITY outbound spiderX fallback crawling is not implemented yet",
        ));
    }
    let public_key: [u8; 32] =
        reality.public_key.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY outbound publicKey has invalid length",
            )
        })?;
    let short_id: [u8; 8] =
        reality.short_id.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY outbound shortId has invalid length",
            )
        })?;
    Ok(Some(OutboundRealityClientSettings {
        public_key,
        short_id,
        server_name: reality.server_name,
    }))
}

pub(super) fn decode_tls_security(
    stream: &OutboundStreamConfigPayload,
) -> std::io::Result<Option<OutboundTlsClientSettings>> {
    let security = stream.security_type.trim_start_matches('.');
    if security.is_empty() || security.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if security != TYPE_TRANSPORT_TLS_CONFIG
        && security != TYPE_TRANSPORT_TLS_CONFIG_V2RAY
        && !security.eq_ignore_ascii_case("tls")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("outbound security {security} is not implemented yet"),
        ));
    }
    let tls_message = stream
        .security_settings
        .iter()
        .find(|message| {
            let message_type = message.r#type.trim_start_matches('.');
            message_type == TYPE_TRANSPORT_TLS_CONFIG
                || message_type == TYPE_TRANSPORT_TLS_CONFIG_V2RAY
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS outbound is missing TLS security settings",
            )
        })?;
    let tls =
        TlsConfigPayload::decode(tls_message.value.as_slice()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid outbound TLS settings: {error}"),
            )
        })?;
    let custom_root_certificates = validate_tls_payload(&tls)?;
    Ok(Some(OutboundTlsClientSettings {
        server_name: tls.server_name,
        alpn: tls.next_protocol,
        disable_system_root: tls.disable_system_root,
        custom_root_certificates,
    }))
}

pub(super) fn validate_tls_payload(
    tls: &TlsConfigPayload,
) -> std::io::Result<Vec<Vec<u8>>> {
    let mut custom_root_certificates = Vec::new();
    for certificate in &tls.certificate {
        if certificate.usage != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TLS outbound certificates only support AUTHORITY_VERIFY usage",
            ));
        }
        if !certificate.key.is_empty() || !certificate.key_path.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "TLS outbound client certificates are not implemented",
            ));
        }
        let bytes = if !certificate.certificate_path.trim().is_empty() {
            std::fs::read(certificate.certificate_path.trim()).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to read outbound TLS certificate {}: {error}",
                        certificate.certificate_path
                    ),
                )
            })?
        } else if !certificate.certificate.is_empty() {
            certificate.certificate.clone()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TLS outbound verify certificate is empty",
            ));
        };
        custom_root_certificates.push(bytes);
    }
    if tls.enable_session_resumption {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TLS enableSessionResumption is not implemented for outbound yet",
        ));
    }
    if !tls.min_version.is_empty() || !tls.max_version.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TLS minVersion/maxVersion are not implemented for outbound yet",
        ));
    }
    if !tls.cipher_suites.is_empty()
        || !tls.fingerprint.is_empty()
        || tls.reject_unknown_sni
        || !tls.master_key_log.is_empty()
        || !tls.curve_preferences.is_empty()
        || !tls.verify_peer_cert_by_name.is_empty()
        || !tls.ech_server_keys.is_empty()
        || !tls.ech_config_list.is_empty()
        || !tls.pinned_peer_cert_sha256.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "advanced TLS verification/fingerprint/ECH settings are not implemented for outbound yet",
        ));
    }
    Ok(custom_root_certificates)
}

pub(super) fn decode_ip_or_domain(
    value: Option<&IpOrDomainPayload>,
) -> Option<Address> {
    match value?.address.as_ref()? {
        ip_or_domain_payload::Address::Ip(bytes) => match bytes.as_slice() {
            [a, b, c, d] => {
                Some(Address::Ipv4(std::net::Ipv4Addr::new(*a, *b, *c, *d)))
            }
            bytes if bytes.len() == 16 => {
                let bytes: [u8; 16] = bytes.try_into().ok()?;
                Some(Address::Ipv6(std::net::Ipv6Addr::from(bytes)))
            }
            _ => None,
        },
        ip_or_domain_payload::Address::Domain(domain) if !domain.is_empty() => {
            Some(Address::Hostname(domain.clone()))
        }
        ip_or_domain_payload::Address::Domain(_) => None,
    }
}
