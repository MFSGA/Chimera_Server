use super::*;

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

fn validate_vless_flow(flow: &str) -> Result<(), Error> {
    match flow {
        "" | "xtls-rprx-vision" => Ok(()),
        unsupported => Err(Error::InvalidConfig(format!(
            "vless clients.flow doesn't support {unsupported}"
        ))),
    }
}

fn has_vless_vision_flow(users: &[crate::config::server_config::VlessUser]) -> bool {
    users.iter().any(|user| user.flow == "xtls-rprx-vision")
}

struct VlessCorePlan {
    protocol: ServerProxyConfig,
    uses_vision: bool,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VlessTransportKind {
    Xhttp,
    Standard,
}

struct VlessTransportPlan {
    kind: VlessTransportKind,
    security: String,
}

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

pub(super) fn build_vless_server(
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
