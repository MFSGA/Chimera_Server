use super::super::*;
use super::*;
use crate::{address::Address, config::def::OutboundItem, runtime::OutboundSummary};
use base64::Engine as _;
use prost::Message;

pub(crate) fn compile_static_outbound(
    item: &OutboundItem,
) -> Result<OutboundSummary, String> {
    let protocol = item.protocol.trim().to_ascii_lowercase();
    let sender_settings = match item
        .stream_settings
        .as_ref()
        .filter(|settings| !settings.is_null())
    {
        None => None,
        Some(settings) if protocol == "trojan" => {
            Some(encode_static_sender_settings(settings, &item.tag)?)
        }
        Some(_) if matches!(protocol.as_str(), "socks" | "vless") => {
            return Err(format!(
                "{} outbound {} streamSettings are not implemented yet; refusing to downgrade transport security",
                protocol, item.tag
            ));
        }
        Some(_) => None,
    };
    let (proxy_settings_type, proxy_settings_value) = match protocol.as_str() {
        "socks" => {
            let settings = item.settings.as_ref().ok_or_else(|| {
                format!("socks outbound {} requires settings", item.tag)
            })?;
            let config: StaticSocksClientConfig =
                settings.deserialize().map_err(|error| {
                    format!("invalid socks outbound {} settings: {error}", item.tag)
                })?;
            let payload = encode_static_socks_config(config)?;
            (
                Some(TYPE_PROXY_SOCKS_CLIENT_CONFIG.to_string()),
                Some(payload.encode_to_vec()),
            )
        }
        "vless" => {
            let settings = item.settings.as_ref().ok_or_else(|| {
                format!("vless outbound {} requires settings", item.tag)
            })?;
            let config: StaticVlessClientConfig =
                settings.deserialize().map_err(|error| {
                    format!("invalid vless outbound {} settings: {error}", item.tag)
                })?;
            let payload = encode_static_vless_config(config)?;
            (
                Some(TYPE_PROXY_VLESS_CLIENT_CONFIG.to_string()),
                Some(payload.encode_to_vec()),
            )
        }
        "trojan" => {
            let settings = item.settings.as_ref().ok_or_else(|| {
                format!("trojan outbound {} requires settings", item.tag)
            })?;
            let config: StaticTrojanClientConfig =
                settings.deserialize().map_err(|error| {
                    format!("invalid trojan outbound {} settings: {error}", item.tag)
                })?;
            let payload = encode_static_trojan_config(config)?;
            (
                Some(TYPE_PROXY_TROJAN_CLIENT_CONFIG.to_string()),
                Some(payload.encode_to_vec()),
            )
        }
        _ => (None, None),
    };
    Ok(OutboundSummary {
        tag: item.tag.clone(),
        protocol: item.protocol.clone(),
        proxy_settings_type,
        proxy_settings_value,
        sender_settings_type: sender_settings
            .as_ref()
            .map(|_| TYPE_APP_SENDER_CONFIG.to_string()),
        sender_settings_value: sender_settings
            .map(|settings| settings.encode_to_vec()),
    })
}

fn encode_static_sender_settings(
    value: &serde_json::Value,
    outbound_tag: &str,
) -> Result<SenderConfigPayload, String> {
    let settings: StaticOutboundStreamSettings =
        serde_json::from_value(value.clone()).map_err(|error| {
            format!("invalid outbound {outbound_tag} streamSettings: {error}")
        })?;
    let (protocol_name, transport_settings) = match settings
        .network
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "raw" | "tcp" => ("tcp".to_string(), Vec::new()),
        "ws" | "websocket" => {
            let websocket = encode_static_websocket_config(
                settings.ws_settings.unwrap_or_default(),
            )?;
            (
                "websocket".to_string(),
                vec![OutboundTransportConfigPayload {
                    protocol_name: "websocket".to_string(),
                    settings: Some(TypedMessagePayload {
                        r#type: TYPE_TRANSPORT_WEBSOCKET_CONFIG.to_string(),
                        value: websocket.encode_to_vec(),
                    }),
                }],
            )
        }
        "httpupgrade" | "http-upgrade" => {
            let http_upgrade = encode_static_httpupgrade_config(
                settings.http_upgrade_settings.unwrap_or_default(),
            )?;
            (
                "httpupgrade".to_string(),
                vec![OutboundTransportConfigPayload {
                    protocol_name: "httpupgrade".to_string(),
                    settings: Some(TypedMessagePayload {
                        r#type: TYPE_TRANSPORT_HTTPUPGRADE_CONFIG.to_string(),
                        value: http_upgrade.encode_to_vec(),
                    }),
                }],
            )
        }
        #[cfg(feature = "grpc_transport")]
        "grpc" => {
            let grpc = encode_static_grpc_config(
                settings.grpc_settings.unwrap_or_default(),
            )?;
            (
                "grpc".to_string(),
                vec![OutboundTransportConfigPayload {
                    protocol_name: "grpc".to_string(),
                    settings: Some(TypedMessagePayload {
                        r#type: TYPE_TRANSPORT_GRPC_CONFIG.to_string(),
                        value: grpc.encode_to_vec(),
                    }),
                }],
            )
        }
        network => {
            return Err(format!(
                "outbound {outbound_tag} transport {network} is not implemented yet"
            ));
        }
    };
    let security = settings.security.trim().to_ascii_lowercase();
    let (security_type, security_settings) = match security.as_str() {
        "" | "none" => (String::new(), Vec::new()),
        "tls" => {
            let tls =
                encode_static_tls_config(settings.tls_settings.unwrap_or_default())?;
            (
                TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                vec![TypedMessagePayload {
                    r#type: TYPE_TRANSPORT_TLS_CONFIG.to_string(),
                    value: tls.encode_to_vec(),
                }],
            )
        }
        "reality" => {
            let reality = encode_static_reality_config(
                settings.reality_settings.unwrap_or_default(),
            )?;
            (
                TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                vec![TypedMessagePayload {
                    r#type: TYPE_TRANSPORT_REALITY_CONFIG.to_string(),
                    value: reality.encode_to_vec(),
                }],
            )
        }
        security => {
            return Err(format!(
                "outbound {outbound_tag} security {security} is not implemented yet"
            ));
        }
    };
    Ok(SenderConfigPayload {
        stream_settings: Some(OutboundStreamConfigPayload {
            transport_settings,
            protocol_name,
            security_type,
            security_settings,
        }),
    })
}

fn encode_static_websocket_config(
    mut config: StaticOutboundWebsocketSettings,
) -> Result<WebsocketConfigPayload, String> {
    let mut host_header_key = None;
    for key in config.headers.keys() {
        if key.eq_ignore_ascii_case("host") {
            host_header_key = Some(key.clone());
            break;
        }
    }
    if let Some(key) = host_header_key {
        if config.host.is_empty()
            && let Some(host) = config.headers.get(&key)
        {
            config.host = host.clone();
        }
        config.headers.remove(&key);
    }

    let (path, ed) = normalize_websocket_path(&config.path)?;
    Ok(WebsocketConfigPayload {
        host: config.host,
        path,
        header: config.headers,
        accept_proxy_protocol: config.accept_proxy_protocol,
        ed,
        heartbeat_period: config.heartbeat_period,
    })
}

#[cfg(feature = "grpc_transport")]
pub(crate) fn encode_static_grpc_config(
    mut config: StaticOutboundGrpcSettings,
) -> Result<GrpcConfigPayload, String> {
    if config.idle_timeout <= 0 {
        config.idle_timeout = 0;
    }
    if config.health_check_timeout <= 0 {
        config.health_check_timeout = 0;
    }
    if config.initial_windows_size < 0 {
        config.initial_windows_size = 0;
    }
    Ok(GrpcConfigPayload {
        authority: config.authority,
        service_name: config.service_name,
        multi_mode: config.multi_mode,
        idle_timeout: config.idle_timeout,
        health_check_timeout: config.health_check_timeout,
        permit_without_stream: config.permit_without_stream,
        initial_windows_size: config.initial_windows_size,
        user_agent: config.user_agent,
    })
}

fn encode_static_httpupgrade_config(
    mut config: StaticOutboundHttpUpgradeSettings,
) -> Result<HttpUpgradeConfigPayload, String> {
    for key in config.headers.keys() {
        if key.eq_ignore_ascii_case("host") {
            return Err(
                "HTTPUpgrade outbound headers can't contain Host; use host instead"
                    .into(),
            );
        }
    }
    let (path, ed) = normalize_websocket_path(&config.path)?;
    Ok(HttpUpgradeConfigPayload {
        host: config.host,
        path,
        header: std::mem::take(&mut config.headers),
        accept_proxy_protocol: config.accept_proxy_protocol,
        ed,
    })
}

fn normalize_websocket_path(path: &str) -> Result<(String, u32), String> {
    let path = if path.is_empty() { "/" } else { path };
    let Some((base, query)) = path.split_once('?') else {
        return Ok((path.to_string(), 0));
    };
    let mut ed = 0u32;
    let mut kept = Vec::new();
    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=')
            && key == "ed"
        {
            ed = value.parse::<u32>().unwrap_or_default();
            continue;
        }
        if !part.is_empty() {
            kept.push(part);
        }
    }
    let normalized = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    Ok((
        if normalized.is_empty() {
            "/".to_string()
        } else {
            normalized
        },
        ed,
    ))
}

fn encode_static_reality_config(
    config: StaticOutboundRealitySettings,
) -> Result<RealityConfigPayload, String> {
    let fingerprint = config.fingerprint.trim().to_ascii_lowercase();
    if !matches!(fingerprint.as_str(), "" | "chrome") {
        return Err(format!(
            "REALITY outbound fingerprint {} is not implemented; only chrome is supported",
            config.fingerprint
        ));
    }
    if !config.mldsa65_verify.trim().is_empty() {
        return Err(
            "REALITY outbound ML-DSA verification is not implemented yet".into(),
        );
    }
    if !config.master_key_log.trim().is_empty() {
        return Err("REALITY outbound masterKeyLog is not implemented yet".into());
    }
    if !config.spider_x.trim().is_empty() && config.spider_x.trim() != "/" {
        return Err(
            "REALITY outbound spiderX fallback crawling is not implemented; only '/' is accepted"
                .into(),
        );
    }
    let public_key_text = if config.public_key.trim().is_empty() {
        config.password.trim()
    } else {
        config.public_key.trim()
    };
    if public_key_text.is_empty() {
        return Err(
            "REALITY outbound requires publicKey (or legacy password)".into()
        );
    }
    let public_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(public_key_text)
        .map_err(|error| format!("invalid REALITY outbound publicKey: {error}"))?;
    let public_key: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        "invalid REALITY outbound publicKey: decoded key must contain exactly 32 bytes"
            .to_string()
    })?;
    let short_id_text = config.short_id.trim();
    if short_id_text.len() > 16 || !short_id_text.len().is_multiple_of(2) {
        return Err("invalid REALITY outbound shortId length".into());
    }
    let mut short_id = [0u8; 8];
    for (index, chunk) in short_id_text.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| "invalid REALITY outbound shortId".to_string())?;
        short_id[index] = u8::from_str_radix(text, 16)
            .map_err(|_| "invalid REALITY outbound shortId".to_string())?;
    }
    Ok(RealityConfigPayload {
        show: config.show,
        dest: String::new(),
        r#type: String::new(),
        xver: 0,
        server_names: Vec::new(),
        private_key: Vec::new(),
        min_client_ver: Vec::new(),
        max_client_ver: Vec::new(),
        max_time_diff: 0,
        short_ids: Vec::new(),
        mldsa65_seed: Vec::new(),
        fingerprint: if fingerprint.is_empty() {
            "chrome".to_string()
        } else {
            fingerprint
        },
        server_name: config.server_name,
        public_key: public_key.to_vec(),
        short_id: short_id.to_vec(),
        mldsa65_verify: Vec::new(),
        spider_x: if config.spider_x.trim().is_empty() {
            "/".to_string()
        } else {
            config.spider_x
        },
        spider_y: Vec::new(),
        master_key_log: String::new(),
    })
}

fn encode_static_tls_config(
    config: StaticOutboundTlsSettings,
) -> Result<TlsConfigPayload, String> {
    if config.allow_insecure {
        return Err(
            "TLS allowInsecure is removed by current Xray and is not accepted"
                .into(),
        );
    }
    let certificates = config
        .certificates
        .into_iter()
        .map(encode_static_tls_certificate)
        .collect::<Result<Vec<_>, _>>()?;
    if config.enable_session_resumption {
        return Err(
            "TLS enableSessionResumption is not implemented for outbound yet".into(),
        );
    }
    if !config.min_version.is_empty() || !config.max_version.is_empty() {
        return Err(
            "TLS minVersion/maxVersion are not implemented for outbound yet".into(),
        );
    }
    if !config.cipher_suites.is_empty() {
        return Err("TLS cipherSuites are not implemented for outbound yet".into());
    }
    if !config.fingerprint.is_empty() {
        return Err(
            "TLS fingerprint/uTLS is not implemented for outbound yet".into()
        );
    }
    if config.reject_unknown_sni {
        return Err(
            "TLS rejectUnknownSni is a server-side option and is not accepted here"
                .into(),
        );
    }
    if !config.master_key_log.is_empty()
        || !config.curve_preferences.is_empty()
        || !config.verify_peer_cert_by_name.is_empty()
        || !config.pinned_peer_cert_sha256.is_empty()
        || !config.ech_server_keys.is_empty()
        || !config.ech_config_list.is_empty()
    {
        return Err(
            "advanced TLS verification/fingerprint/ECH settings are not implemented for outbound yet"
                .into(),
        );
    }
    Ok(TlsConfigPayload {
        certificate: certificates,
        server_name: config.server_name,
        next_protocol: config.alpn,
        enable_session_resumption: false,
        disable_system_root: config.disable_system_root,
        min_version: String::new(),
        max_version: String::new(),
        cipher_suites: String::new(),
        fingerprint: String::new(),
        reject_unknown_sni: false,
        master_key_log: String::new(),
        curve_preferences: Vec::new(),
        verify_peer_cert_by_name: Vec::new(),
        ech_server_keys: Vec::new(),
        ech_config_list: String::new(),
        pinned_peer_cert_sha256: Vec::new(),
    })
}

fn encode_static_tls_certificate(
    certificate: StaticOutboundTlsCertificate,
) -> Result<TlsCertificatePayload, String> {
    if !certificate.key_file.trim().is_empty() || !certificate.key.is_empty() {
        return Err(
            "TLS outbound client certificates are not implemented; only usage=verify trust roots are supported"
                .into(),
        );
    }
    let usage = certificate.usage.trim().to_ascii_lowercase();
    if usage != "verify" {
        return Err(format!(
            "TLS outbound certificate usage {} is not implemented; only verify is supported",
            if usage.is_empty() {
                "encipherment"
            } else {
                usage.as_str()
            }
        ));
    }
    let certificate_bytes = if !certificate.certificate_file.trim().is_empty() {
        std::fs::read(certificate.certificate_file.trim()).map_err(|error| {
            format!(
                "failed to read outbound TLS certificate {}: {error}",
                certificate.certificate_file
            )
        })?
    } else if !certificate.certificate.is_empty() {
        certificate.certificate.join("\n").into_bytes()
    } else {
        return Err("TLS outbound verify certificate requires certificate or certificateFile".into());
    };
    Ok(TlsCertificatePayload {
        certificate: certificate_bytes,
        key: Vec::new(),
        usage: 1,
        certificate_path: String::new(),
        key_path: String::new(),
    })
}

fn encode_static_socks_config(
    mut config: StaticSocksClientConfig,
) -> Result<SocksClientConfigPayload, String> {
    let (server, user) = if let Some(address) = config.address.take() {
        if config.port == 0 {
            return Err("SOCKS outbound port must be between 1 and 65535".into());
        }
        let user = (!config.user.is_empty()).then_some(StaticSocksUserConfig {
            level: config.level,
            email: config.email,
            user: config.user,
            pass: config.pass,
        });
        (
            StaticSocksServerConfig {
                address,
                port: config.port,
                users: Vec::new(),
            },
            user,
        )
    } else {
        if config.servers.len() != 1 {
            return Err(
                "SOCKS settings servers must contain exactly one endpoint".into()
            );
        }
        let mut server = config.servers.remove(0);
        if server.port == 0 {
            return Err("SOCKS outbound port must be between 1 and 65535".into());
        }
        if server.users.len() > 1 {
            return Err(
                "SOCKS outbound server users must contain at most one member".into(),
            );
        }
        let user = server.users.pop();
        (server, user)
    };

    let address = encode_ip_or_domain(&server.address)?;
    let user = user.map(encode_static_socks_user);
    Ok(SocksClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(address),
            port: u32::from(server.port),
            user,
        }),
    })
}

fn encode_static_vless_config(
    mut config: StaticVlessClientConfig,
) -> Result<VlessClientConfigPayload, String> {
    let (server, user) = if let Some(address) = config.address.take() {
        if config.port == 0 {
            return Err("VLESS outbound port must be between 1 and 65535".into());
        }
        (
            StaticVlessServerConfig {
                address,
                port: config.port,
                users: Vec::new(),
            },
            StaticVlessUserConfig {
                level: config.level,
                email: config.email,
                id: config.id,
                flow: config.flow,
                encryption: config.encryption,
            },
        )
    } else {
        if config.vnext.len() != 1 {
            return Err(
                "VLESS settings vnext must contain exactly one endpoint".into()
            );
        }
        let mut server = config.vnext.remove(0);
        if server.port == 0 {
            return Err("VLESS outbound port must be between 1 and 65535".into());
        }
        if server.users.len() != 1 {
            return Err(
                "VLESS outbound vnext users must contain exactly one member".into(),
            );
        }
        let user = server.users.remove(0);
        (server, user)
    };

    if !user.flow.trim().is_empty() {
        return Err(format!(
            "VLESS outbound flow {} is not implemented yet; only empty flow is supported",
            user.flow
        ));
    }
    if !user.encryption.trim().eq_ignore_ascii_case("none") {
        return Err(format!(
            "VLESS outbound encryption must be none, got {}",
            user.encryption
        ));
    }
    parse_xray_uuid(&user.id)?;

    let account = VlessAccountPayload {
        id: user.id,
        flow: user.flow,
        encryption: user.encryption,
    };
    Ok(VlessClientConfigPayload {
        vnext: Some(SocksServerEndpointPayload {
            address: Some(encode_ip_or_domain(&server.address)?),
            port: u32::from(server.port),
            user: Some(OutboundUserPayload {
                level: user.level,
                email: user.email,
                account: Some(TypedMessagePayload {
                    r#type: TYPE_PROXY_VLESS_ACCOUNT.to_string(),
                    value: account.encode_to_vec(),
                }),
            }),
        }),
    })
}

fn encode_static_trojan_config(
    mut config: StaticTrojanClientConfig,
) -> Result<TrojanClientConfigPayload, String> {
    let server = if let Some(address) = config.address.take() {
        StaticTrojanServerConfig {
            address,
            port: config.port,
            level: config.level,
            email: config.email,
            password: config.password,
            flow: config.flow,
        }
    } else {
        if config.servers.len() != 1 {
            return Err(
                "Trojan settings servers must contain exactly one endpoint".into()
            );
        }
        config.servers.remove(0)
    };
    if server.port == 0 {
        return Err("Trojan outbound port must be between 1 and 65535".into());
    }
    if server.password.is_empty() {
        return Err("Trojan outbound password is required".into());
    }
    if !server.flow.is_empty() {
        return Err(
            "Trojan outbound flow is removed by current Xray and must be empty"
                .into(),
        );
    }
    Ok(TrojanClientConfigPayload {
        server: Some(SocksServerEndpointPayload {
            address: Some(encode_ip_or_domain(&server.address)?),
            port: u32::from(server.port),
            user: Some(OutboundUserPayload {
                level: server.level,
                email: server.email,
                account: Some(TypedMessagePayload {
                    r#type: TYPE_PROXY_TROJAN_ACCOUNT.to_string(),
                    value: TrojanAccountPayload {
                        password: server.password,
                    }
                    .encode_to_vec(),
                }),
            }),
        }),
    })
}

fn encode_ip_or_domain(value: &str) -> Result<IpOrDomainPayload, String> {
    let address = Address::from(value)
        .map_err(|error| format!("invalid outbound address {value}: {error}"))?;
    let address = match address {
        Address::Ipv4(ip) => ip_or_domain_payload::Address::Ip(ip.octets().to_vec()),
        Address::Ipv6(ip) => ip_or_domain_payload::Address::Ip(ip.octets().to_vec()),
        Address::Hostname(domain) => ip_or_domain_payload::Address::Domain(domain),
    };
    Ok(IpOrDomainPayload {
        address: Some(address),
    })
}

pub(crate) fn parse_xray_uuid(value: &str) -> Result<[u8; 16], String> {
    let text = value.as_bytes();
    if text.len() < 32 || text.len() > 36 {
        if text.is_empty() || text.len() > 30 {
            return Err(format!("invalid VLESS UUID: {value}"));
        }
        let mut input = [0u8; 16].to_vec();
        input.extend_from_slice(text);
        let digest = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            &input,
        );
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&digest.as_ref()[..16]);
        uuid[6] = (uuid[6] & 0x0f) | (5 << 4);
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        return Ok(uuid);
    }

    let mut uuid = [0u8; 16];
    let mut source = text;
    let mut offset = 0usize;
    for group_len in [8usize, 4, 4, 4, 12] {
        if source.first() == Some(&b'-') {
            source = &source[1..];
        }
        if source.len() < group_len {
            return Err(format!("invalid VLESS UUID: {value}"));
        }
        for pair in source[..group_len].as_chunks::<2>().0 {
            let encoded = std::str::from_utf8(pair)
                .map_err(|_| format!("invalid VLESS UUID: {value}"))?;
            uuid[offset] = u8::from_str_radix(encoded, 16)
                .map_err(|_| format!("invalid VLESS UUID: {value}"))?;
            offset += 1;
        }
        source = &source[group_len..];
    }
    Ok(uuid)
}

fn encode_static_socks_user(user: StaticSocksUserConfig) -> OutboundUserPayload {
    let account = SocksAccountPayload {
        username: user.user,
        password: user.pass,
    };
    OutboundUserPayload {
        level: user.level,
        email: user.email,
        account: Some(TypedMessagePayload {
            r#type: TYPE_PROXY_SOCKS_ACCOUNT.to_string(),
            value: account.encode_to_vec(),
        }),
    }
}
