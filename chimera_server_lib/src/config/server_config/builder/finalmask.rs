use super::*;

pub(super) fn parse_xray_finalmask_bandwidth(input: &str) -> Result<u64, Error> {
    let value = input.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Ok(0);
    }
    let split = value
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit() && *c != '.')
        .map(|(idx, _)| idx)
        .unwrap_or(value.len());
    let number = value[..split].parse::<f64>().map_err(|_| {
        Error::InvalidConfig(format!(
            "invalid finalmask.quicParams bandwidth value: {input}"
        ))
    })?;
    let multiplier = match value[split..].trim() {
        "" | "b" | "bps" => 1_u64,
        "k" | "kb" | "kbps" => 1024,
        "m" | "mb" | "mbps" => 1024 * 1024,
        "g" | "gb" | "gbps" => 1024 * 1024 * 1024,
        "t" | "tb" | "tbps" => 1024_u64.pow(4),
        unit => {
            return Err(Error::InvalidConfig(format!(
                "unsupported finalmask.quicParams bandwidth unit: {unit}"
            )));
        }
    };
    let bits_per_second = number * multiplier as f64;
    if !bits_per_second.is_finite()
        || bits_per_second < 0.0
        || bits_per_second > u64::MAX as f64
    {
        return Err(Error::InvalidConfig(format!(
            "invalid finalmask.quicParams bandwidth value: {input}"
        )));
    }
    Ok(bits_per_second as u64 / 8)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidatedFinalMaskQuicParams {
    pub(super) congestion: String,
    pub(super) bbr_profile: String,
    pub(super) brutal_up: u64,
    pub(super) brutal_down: Option<u64>,
    pub(super) max_idle_timeout: u64,
    pub(super) keep_alive_period: u64,
    pub(super) max_incoming_streams: u64,
    pub(super) receive_windows: (u64, u64, u64, u64),
}

pub(super) fn validate_xray_finalmask_quic_params(
    params: &crate::config::FinalMaskQuicParams,
    validate_brutal_down: bool,
) -> Result<ValidatedFinalMaskQuicParams, Error> {
    let congestion = params.congestion.to_ascii_lowercase();
    if !matches!(
        congestion.as_str(),
        "" | "brutal" | "reno" | "bbr" | "force-brutal"
    ) {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.congestion must be one of reno, bbr, brutal, force-brutal (got {})",
            params.congestion
        )));
    }

    let bbr_profile = match params.bbr_profile.to_ascii_lowercase() {
        profile if profile.is_empty() => "standard".to_string(),
        profile
            if matches!(
                profile.as_str(),
                "conservative" | "standard" | "aggressive"
            ) =>
        {
            profile
        }
        _ => {
            return Err(Error::InvalidConfig(format!(
                "finalmask.quicParams.bbrProfile must be one of conservative, standard, aggressive (got {})",
                params.bbr_profile
            )));
        }
    };
    if matches!(bbr_profile.as_str(), "conservative" | "aggressive")
        && !matches!(congestion.as_str(), "reno" | "force-brutal")
    {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.bbrProfile conservative/aggressive is not supported when Xray may use BBR"
                .into(),
        ));
    }

    let brutal_up = parse_xray_finalmask_bandwidth(&params.brutal_up)?;
    if brutal_up != 0 && brutal_up < 65_536 {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.brutalUp must be at least 65536 bytes per second"
                .into(),
        ));
    }
    let brutal_down = validate_brutal_down
        .then(|| {
            let value = parse_xray_finalmask_bandwidth(&params.brutal_down)?;
            if value != 0 && value < 65_536 {
                return Err(Error::InvalidConfig(
                    "finalmask.quicParams.brutalDown must be at least 65536 bytes per second"
                        .into(),
                ));
            }
            Ok(value)
        })
        .transpose()?;
    if congestion == "force-brutal" && brutal_up == 0 {
        return Err(Error::InvalidConfig(
            "finalmask.quicParams.force-brutal requires brutalUp".into(),
        ));
    }

    let max_idle_timeout = params.max_idle_timeout;
    if max_idle_timeout != 0 && !(4..=120).contains(&max_idle_timeout) {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.maxIdleTimeout must be 0 or between 4 and 120 seconds (got {max_idle_timeout})"
        )));
    }
    let keep_alive_period = params.keep_alive_period;
    if keep_alive_period != 0 && !(2..=60).contains(&keep_alive_period) {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.keepAlivePeriod must be 0 or between 2 and 60 seconds (got {keep_alive_period})"
        )));
    }
    let max_incoming_streams = params.max_incoming_streams;
    if max_incoming_streams != 0 && max_incoming_streams < 8 {
        return Err(Error::InvalidConfig(format!(
            "finalmask.quicParams.maxIncomingStreams must be 0 or at least 8 (got {max_incoming_streams})"
        )));
    }

    for (field, value) in [
        ("initStreamReceiveWindow", params.init_stream_receive_window),
        ("maxStreamReceiveWindow", params.max_stream_receive_window),
        (
            "initConnectionReceiveWindow",
            params.init_connection_receive_window,
        ),
        (
            "maxConnectionReceiveWindow",
            params.max_connection_receive_window,
        ),
    ] {
        if value != 0 && value < 16_384 {
            return Err(Error::InvalidConfig(format!(
                "finalmask.quicParams.{field} must be 0 or at least 16384 (got {value})"
            )));
        }
    }

    Ok(ValidatedFinalMaskQuicParams {
        congestion,
        bbr_profile,
        brutal_up,
        brutal_down,
        max_idle_timeout: max_idle_timeout as u64,
        keep_alive_period: keep_alive_period as u64,
        max_incoming_streams: if max_incoming_streams == 0 {
            0
        } else {
            (max_incoming_streams as u64).min(1_u64 << 60)
        },
        receive_windows: (
            params.init_stream_receive_window,
            params.max_stream_receive_window,
            params.init_connection_receive_window,
            params.max_connection_receive_window,
        ),
    })
}
