use super::*;

fn finalmask_udp_hop_is_inert(udp_hop: &crate::config::FinalMaskUdpHop) -> bool {
    fn value_is_zero(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => true,
            serde_json::Value::Number(number) => {
                number.as_i64() == Some(0) || number.as_u64() == Some(0)
            }
            serde_json::Value::String(value) => {
                matches!(value.as_str(), "" | "0" | "0-0")
            }
            _ => false,
        }
    }

    value_is_zero(&udp_hop.ports) && value_is_zero(&udp_hop.interval)
}

fn parse_hysteria2_finalmask_packet_size(
    value: &serde_json::Value,
) -> Result<(i32, i32), Error> {
    let (left, right) = if let Some(value) = value.as_i64() {
        let value = i32::try_from(value).map_err(|_| {
            Error::InvalidConfig(
                "hysteria2 finalmask packetSize is out of int32 range".into(),
            )
        })?;
        (value, value)
    } else if let Some(value) = value.as_str() {
        if value.is_empty() {
            (0, 0)
        } else if let Ok(value) = value.parse::<i32>() {
            (value, value)
        } else {
            let split_index = if let Some(value) = value.strip_prefix('-') {
                value.find('-').map(|index| index + 1)
            } else {
                value.find('-')
            }
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "invalid hysteria2 finalmask packetSize range {value:?}"
                ))
            })?;
            let (left, right) = value.split_at(split_index);
            let right = &right[1..];
            (
                left.parse::<i32>().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid hysteria2 finalmask packetSize range {value:?}"
                    ))
                })?,
                right.parse::<i32>().map_err(|_| {
                    Error::InvalidConfig(format!(
                        "invalid hysteria2 finalmask packetSize range {value:?}"
                    ))
                })?,
            )
        }
    } else {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask packetSize must be an integer or range string"
                .into(),
        ));
    };
    Ok(if left <= right {
        (left, right)
    } else {
        (right, left)
    })
}

fn collect_hysteria2_udp_finalmask(
    masks: &[serde_json::Value],
) -> Result<Option<crate::config::server_config::Hysteria2UdpFinalMask>, Error> {
    use crate::config::server_config::Hysteria2UdpFinalMask;

    if masks.is_empty() {
        return Ok(None);
    }
    if masks.len() != 1 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.udp currently supports exactly one salamander mask"
                .into(),
        ));
    }

    let mask = masks[0].as_object().ok_or_else(|| {
        Error::InvalidConfig("hysteria2 finalmask.udp mask must be an object".into())
    })?;
    let mask_type = mask
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::InvalidConfig(
                "hysteria2 finalmask.udp mask requires a string type".into(),
            )
        })?;
    if !mask_type.eq_ignore_ascii_case("salamander") {
        return Err(Error::InvalidConfig(format!(
            "hysteria2 finalmask.udp mask type {mask_type:?} is not implemented yet"
        )));
    }

    let settings = mask.get("settings").and_then(serde_json::Value::as_object);
    let packet_size = settings
        .and_then(|settings| settings.get("packetSize"))
        .map(parse_hysteria2_finalmask_packet_size)
        .transpose()?;
    let password = settings
        .and_then(|settings| settings.get("password"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    if password.len() < 4 {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.udp salamander password must be at least 4 bytes"
                .into(),
        ));
    }

    if let Some((min_packet_size, max_packet_size)) = packet_size
        && max_packet_size > 0
    {
        if min_packet_size <= 0 || max_packet_size > 2048 {
            return Err(Error::InvalidConfig(
                "gecko: invalid min/max packet size".into(),
            ));
        }
        return Ok(Some(Hysteria2UdpFinalMask::Gecko {
            password,
            min_packet_size: min_packet_size as usize,
            max_packet_size: max_packet_size as usize,
        }));
    }

    Ok(Some(Hysteria2UdpFinalMask::Salamander { password }))
}

#[derive(Default)]
struct Hysteria2XrayQuicPlan {
    enabled: bool,
    congestion: Option<String>,
    bbr_profile: Option<String>,
    brutal_up: Option<u64>,
    brutal_down: Option<u64>,
    max_idle_timeout_secs: Option<u64>,
    keep_alive_period_secs: Option<u64>,
    max_incoming_streams: Option<u64>,
    receive_windows: Option<(u64, u64, u64, u64)>,
    disable_path_mtu_discovery: Option<bool>,
    udp_finalmask: Option<crate::config::server_config::Hysteria2UdpFinalMask>,
}

fn plan_hysteria2_xray_quic(
    final_mask: Option<&crate::config::FinalMaskSettings>,
) -> Result<Hysteria2XrayQuicPlan, Error> {
    let Some(final_mask) = final_mask else {
        return Ok(Hysteria2XrayQuicPlan::default());
    };
    if !final_mask.tcp.is_empty() {
        return Err(Error::InvalidConfig(
            "hysteria2 finalmask.tcp mask chains are not supported".into(),
        ));
    }
    let udp_finalmask = collect_hysteria2_udp_finalmask(&final_mask.udp)?;

    let Some(quic_params) = final_mask.quic_params.as_ref() else {
        return Ok(Hysteria2XrayQuicPlan {
            enabled: udp_finalmask.is_some(),
            udp_finalmask,
            ..Hysteria2XrayQuicPlan::default()
        });
    };
    if quic_params
        .udp_hop
        .as_ref()
        .is_some_and(|udp_hop| !finalmask_udp_hop_is_inert(udp_hop))
    {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.udpHop is not supported unless it is empty/inert"
                .into(),
        ));
    }

    let validated = validate_xray_finalmask_quic_params(quic_params, true)?;
    Ok(Hysteria2XrayQuicPlan {
        enabled: true,
        congestion: Some(validated.congestion),
        bbr_profile: Some(validated.bbr_profile),
        brutal_up: Some(validated.brutal_up),
        brutal_down: validated.brutal_down,
        max_idle_timeout_secs: Some(if validated.max_idle_timeout == 0 {
            30
        } else {
            validated.max_idle_timeout
        }),
        keep_alive_period_secs: Some(validated.keep_alive_period),
        max_incoming_streams: Some(if validated.max_incoming_streams == 0 {
            1024
        } else {
            validated.max_incoming_streams
        }),
        receive_windows: Some(validated.receive_windows),
        disable_path_mtu_discovery: Some(quic_params.disable_path_mtu_discovery),
        udp_finalmask,
    })
}

fn apply_hysteria2_xray_quic_plan(
    mut config: crate::config::server_config::Hysteria2ServerConfig,
    plan: Hysteria2XrayQuicPlan,
) -> crate::config::server_config::Hysteria2ServerConfig {
    config.xray_compat |= plan.enabled;
    config.xray_congestion = plan.congestion;
    config.xray_bbr_profile = plan.bbr_profile;
    config.xray_brutal_up = plan.brutal_up;
    config.xray_brutal_down = plan.brutal_down;
    config.xray_max_idle_timeout_secs = plan.max_idle_timeout_secs;
    config.xray_keep_alive_period_secs = plan.keep_alive_period_secs;
    config.xray_max_incoming_streams = plan.max_incoming_streams;
    config.xray_disable_path_mtu_discovery = plan.disable_path_mtu_discovery;
    config.udp_finalmask = plan.udp_finalmask;
    if let Some((init_stream, max_stream, init_connection, max_connection)) =
        plan.receive_windows
    {
        config.xray_init_stream_receive_window = Some(init_stream);
        config.xray_max_stream_receive_window = Some(max_stream);
        config.xray_init_connection_receive_window = Some(init_connection);
        config.xray_max_connection_receive_window = Some(max_connection);
    }
    config
}

fn plan_hysteria2_quic_settings(
    stream_settings: &crate::config::StreamSettings,
) -> Result<ServerQuicConfig, Error> {
    let tls_settings = stream_settings.tls_settings.as_ref().ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound requires tlsSettings".into())
    })?;
    let item = tls_settings.certificates[0].clone();
    let cert = item.certificate_file.ok_or_else(|| {
        Error::InvalidConfig(
            "hysteria2 inbound currently requires certificateFile".into(),
        )
    })?;
    let key = item.key_file.ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound currently requires keyFile".into())
    })?;
    Ok(ServerQuicConfig {
        cert,
        key,
        alpn_protocols: NoneOrSome::Some(tls_settings.alpn.clone()),
        client_fingerprints: NoneOrSome::None,
    })
}

pub(super) fn build_hysteria2_server(
    context: InboundBuildContext,
    settings: Option<crate::config::SettingObject>,
) -> Result<ServerConfig, Error> {
    let stream_settings = context.stream_settings().ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound missing streamSettings".into())
    })?;
    let xray_quic_plan =
        plan_hysteria2_xray_quic(stream_settings.final_mask.as_ref())?;
    let quic_settings = plan_hysteria2_quic_settings(stream_settings)?;
    let settings = settings.ok_or_else(|| {
        Error::InvalidConfig("hysteria2 inbound requires clients".into())
    })?;
    let config = collect_hysteria2_settings(
        settings,
        stream_settings.hysteria_settings.as_ref(),
    )?;
    let config = apply_hysteria2_xray_quic_plan(config, xray_quic_plan);
    if config.clients.is_empty() {
        return Err(Error::InvalidConfig(
            "hysteria2 inbound requires at least one client".into(),
        ));
    }
    Ok(context.finish(
        ServerProxyConfig::Hysteria2 { config },
        Transport::Quic,
        Some(quic_settings),
    ))
}
