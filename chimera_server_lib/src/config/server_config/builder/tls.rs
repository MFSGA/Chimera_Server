use crate::{Error, config::StreamSettings};

#[cfg(feature = "reality")]
use crate::reality::{decode_private_key, decode_short_id};

#[cfg(feature = "reality")]
use super::super::types::RealityTransportConfig;
use super::super::types::ServerProxyConfig;
#[cfg(feature = "tls")]
use super::super::types::{
    TlsCertificateConfig, TlsCertificateUsage, TlsServerConfig,
};
#[cfg(feature = "reality")]
use crate::address::{Address, NetLocation};

#[cfg(feature = "reality")]
fn parse_version_triplet(
    value: &Option<String>,
    field: &str,
) -> Result<Option<[u8; 3]>, Error> {
    match value {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => Ok(None),
        Some(text) => {
            let components = text.split('.').collect::<Vec<_>>();
            if components.len() != 3
                || components.iter().any(|component| component.is_empty())
            {
                return Err(Error::InvalidConfig(format!(
                    "{field} must use major.minor.patch format"
                )));
            }

            let mut parts = [0u8; 3];
            for (idx, part) in components.iter().enumerate() {
                parts[idx] = part.parse::<u8>().map_err(|_| {
                    Error::InvalidConfig(format!("invalid {field} value: {text}"))
                })?;
            }
            Ok(Some(parts))
        }
    }
}

#[cfg(feature = "reality")]
fn ensure_reality_inbound_supported_fields(
    settings: &crate::config::RealitySettings,
) -> Result<(), Error> {
    if settings.public_key.is_some() {
        return Err(Error::InvalidConfig(
            "reality publicKey is an outbound/client setting and is not valid for inbound realitySettings"
                .into(),
        ));
    }
    if settings.fingerprint.is_some() {
        return Err(Error::InvalidConfig(
            "reality fingerprint is an outbound/client setting and is not valid for inbound realitySettings"
                .into(),
        ));
    }
    if settings.spider_x.is_some() {
        return Err(Error::InvalidConfig(
            "reality spiderX is an outbound/client setting and is not valid for inbound realitySettings"
                .into(),
        ));
    }
    if settings.xver.unwrap_or_default() != 0 {
        return Err(Error::InvalidConfig(
            "reality xver values other than 0 are not supported yet".into(),
        ));
    }

    Ok(())
}

#[cfg(feature = "reality")]
fn build_reality_layer(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let settings = stream_settings.reality_settings.as_ref().ok_or_else(|| {
        Error::InvalidConfig("reality inbound requires realitySettings".into())
    })?;
    ensure_reality_inbound_supported_fields(settings)?;

    let dest = NetLocation::from_str(&settings.dest, Some(443)).map_err(|_| {
        Error::InvalidConfig(format!(
            "invalid reality.dest value: {}",
            settings.dest
        ))
    })?;

    if !matches!(dest.address(), Address::Hostname(_))
        && settings.server_names.is_empty()
    {
        return Err(Error::InvalidConfig(
            "reality.dest may be an ip address only when realitySettings.serverNames is explicitly configured"
                .into(),
        ));
    }

    let private_key = decode_private_key(&settings.private_key).map_err(|err| {
        Error::InvalidConfig(format!("invalid reality privateKey: {err}"))
    })?;

    if settings.short_ids.is_empty() {
        return Err(Error::InvalidConfig(
            "reality inbound requires at least one shortId".into(),
        ));
    }
    let configured_short_ids = settings
        .short_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let short_ids = configured_short_ids
        .iter()
        .map(|short_id| {
            decode_short_id(short_id).map_err(|err| {
                Error::InvalidConfig(format!(
                    "invalid reality shortId {short_id}: {err}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Keep xray-core style behavior: maxTimeDiff = 0 means disabled.
    let max_time_diff = settings.max_time_diff.filter(|diff| *diff > 0);
    let min_client_version =
        parse_version_triplet(&settings.min_client_ver, "minClientVer")?;
    let max_client_version =
        parse_version_triplet(&settings.max_client_ver, "maxClientVer")?;

    let mut server_names = settings.server_names.clone();
    if server_names.is_empty()
        && let Address::Hostname(hostname) = dest.address()
    {
        server_names.push(hostname.clone());
    }

    Ok(ServerProxyConfig::Reality(RealityTransportConfig {
        dest,
        private_key,
        short_ids,
        cipher_suites: settings.cipher_suites.clone(),
        max_time_diff,
        min_client_version,
        max_client_version,
        server_names,
        inner: Box::new(protocol),
    }))
}

#[cfg(feature = "tls")]
fn pem_lines_to_bytes(lines: &[String]) -> Vec<u8> {
    lines.join("\n").into_bytes()
}

#[cfg(feature = "tls")]
fn parse_certificate_usage(value: Option<&str>) -> TlsCertificateUsage {
    match value
        .unwrap_or("encipherment")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "verify" => TlsCertificateUsage::Verify,
        "issue" => TlsCertificateUsage::Issue,
        _ => TlsCertificateUsage::Encipherment,
    }
}

#[cfg(feature = "tls")]
fn build_tls_certificate(
    certificate: &crate::config::Certificate,
) -> Result<TlsCertificateConfig, Error> {
    let certificate_path = certificate
        .certificate_file
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let key_path = certificate
        .key_file
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let certificate_pem = pem_lines_to_bytes(&certificate.certificate);
    let key_pem =
        (!certificate.key.is_empty()).then(|| pem_lines_to_bytes(&certificate.key));
    let usage = parse_certificate_usage(certificate.usage.as_deref());

    if certificate_path.is_none() && certificate_pem.is_empty() {
        return Err(Error::InvalidConfig(
            "tls certificate requires certificateFile or certificate".into(),
        ));
    }

    if matches!(usage, TlsCertificateUsage::Encipherment)
        && key_path.is_none()
        && key_pem.is_none()
    {
        return Err(Error::InvalidConfig(
            "tls encipherment certificate requires keyFile or key".into(),
        ));
    }

    Ok(TlsCertificateConfig {
        certificate_path,
        certificate_pem,
        key_path,
        key_pem,
        usage,
    })
}

#[cfg(feature = "tls")]
fn build_tls_layer(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let tls_settings = stream_settings.tls_settings.as_ref().ok_or_else(|| {
        Error::InvalidConfig("tls inbound requires tlsSettings configuration".into())
    })?;

    let certificates = tls_settings
        .certificates
        .iter()
        .map(build_tls_certificate)
        .collect::<Result<Vec<_>, _>>()?;

    if certificates.is_empty() {
        return Err(Error::InvalidConfig(
            "tls inbound requires at least one certificate".into(),
        ));
    }

    Ok(ServerProxyConfig::Tls(TlsServerConfig {
        certificates,
        alpn_protocols: tls_settings.alpn.clone(),
        enable_session_resumption: tls_settings
            .enable_session_resumption
            .unwrap_or(false),
        reject_unknown_sni: tls_settings.reject_unknown_sni.unwrap_or(false),
        min_version: tls_settings.min_version.clone(),
        max_version: tls_settings.max_version.clone(),
        server_name: tls_settings.server_name.clone(),
        inner: Box::new(protocol),
    }))
}

pub(super) fn apply_security_layers(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let security = stream_settings
        .security
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase());

    let protocol = match security.as_deref() {
        None | Some("") | Some("none") => Ok(protocol),
        #[cfg(feature = "tls")]
        Some("tls") => build_tls_layer(protocol, stream_settings),
        #[cfg(not(feature = "tls"))]
        Some("tls") => Err(Error::InvalidConfig(
            "tls security layer requires the tls feature".into(),
        )),
        #[cfg(feature = "reality")]
        Some("reality") => build_reality_layer(protocol, stream_settings),
        #[cfg(not(feature = "reality"))]
        Some("reality") => Err(Error::InvalidConfig(
            "reality security layer requires the reality feature".into(),
        )),
        Some(unsupported) => Err(Error::InvalidConfig(format!(
            "unsupported streamSettings.security={unsupported}"
        ))),
    }?;

    let network = stream_settings.network.trim().to_ascii_lowercase();
    let (keepalive_idle, keepalive_interval) =
        stream_settings.sockopt.as_ref().map_or((0, 0), |settings| {
            (
                settings.tcp_keep_alive_idle,
                settings.tcp_keep_alive_interval,
            )
        });
    if i64::from(keepalive_idle) * i64::from(keepalive_interval) < 0 {
        return Err(Error::InvalidConfig(format!(
            "invalid tcpKeepAliveIdle/tcpKeepAliveInterval values: {keepalive_idle} {keepalive_interval}"
        )));
    }
    let configure_keepalive = keepalive_idle != 0 || keepalive_interval != 0;
    if configure_keepalive
        && !matches!(
            network.as_str(),
            "" | "raw"
                | "tcp"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
        )
    {
        return Err(Error::InvalidConfig(format!(
            "TCP keepalive sockopt is not supported for {network} transport yet"
        )));
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    if configure_keepalive {
        return Err(Error::InvalidConfig(
            "TCP keepalive sockopt is currently supported only on Linux and Android"
                .into(),
        ));
    }

    let congestion_algorithm = stream_settings
        .sockopt
        .as_ref()
        .map_or("", |settings| settings.tcp_congestion.as_str())
        .to_string();
    let configure_congestion = !congestion_algorithm.is_empty();
    if congestion_algorithm.contains('\0') {
        return Err(Error::InvalidConfig(
            "tcpCongestion must not contain NUL bytes".into(),
        ));
    }
    if configure_congestion
        && !matches!(
            network.as_str(),
            "" | "raw"
                | "tcp"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
        )
    {
        return Err(Error::InvalidConfig(format!(
            "tcpCongestion is not supported for {network} transport yet"
        )));
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    if configure_congestion {
        return Err(Error::InvalidConfig(
            "tcpCongestion is currently supported only on Linux and Android".into(),
        ));
    }

    let window_clamp = stream_settings
        .sockopt
        .as_ref()
        .map_or(0, |settings| settings.tcp_window_clamp);
    let configure_window_clamp = window_clamp > 0;
    if configure_window_clamp
        && !matches!(
            network.as_str(),
            "" | "raw"
                | "tcp"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
        )
    {
        return Err(Error::InvalidConfig(format!(
            "tcpWindowClamp is not supported for {network} transport yet"
        )));
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    if configure_window_clamp {
        return Err(Error::InvalidConfig(
            "tcpWindowClamp is currently supported only on Linux and Android".into(),
        ));
    }

    let max_seg = stream_settings
        .sockopt
        .as_ref()
        .map_or(0, |settings| settings.tcp_max_seg);
    let configure_max_seg = max_seg > 0;
    if configure_max_seg
        && !matches!(
            network.as_str(),
            "" | "raw"
                | "tcp"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
        )
    {
        return Err(Error::InvalidConfig(format!(
            "tcpMaxSeg is not supported for {network} transport yet"
        )));
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    if configure_max_seg {
        return Err(Error::InvalidConfig(
            "tcpMaxSeg is currently supported only on Linux and Android".into(),
        ));
    }

    let configure_ipv6_only = stream_settings
        .sockopt
        .as_ref()
        .is_some_and(|settings| settings.v6only);
    if configure_ipv6_only
        && !matches!(
            network.as_str(),
            "" | "raw" | "tcp" | "ws" | "websocket" | "httpupgrade" | "grpc"
        )
    {
        return Err(Error::InvalidConfig(format!(
            "v6only is not supported for {network} transport yet"
        )));
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    if configure_ipv6_only {
        return Err(Error::InvalidConfig(
            "v6only is currently supported only on Linux and Android".into(),
        ));
    }

    let user_timeout_ms = stream_settings
        .sockopt
        .as_ref()
        .map_or(0, |settings| settings.tcp_user_timeout);
    let configure_user_timeout = user_timeout_ms > 0;
    if configure_user_timeout
        && !matches!(
            network.as_str(),
            "" | "raw"
                | "tcp"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
        )
    {
        return Err(Error::InvalidConfig(format!(
            "tcpUserTimeout is not supported for {network} transport yet"
        )));
    }
    #[cfg(not(target_os = "linux"))]
    if configure_user_timeout {
        return Err(Error::InvalidConfig(
            "tcpUserTimeout is currently supported only on Linux".into(),
        ));
    }

    let mut accept_proxy_protocol = false;
    if stream_settings
        .sockopt
        .as_ref()
        .is_some_and(|settings| settings.accept_proxy_protocol)
    {
        if !matches!(
            network.as_str(),
            "" | "raw"
                | "tcp"
                | "ws"
                | "websocket"
                | "httpupgrade"
                | "grpc"
                | "xhttp"
                | "splithttp"
        ) {
            return Err(Error::InvalidConfig(format!(
                "sockopt.acceptProxyProtocol is not supported for {network} transport yet"
            )));
        }
        accept_proxy_protocol = true;
    }
    if stream_settings
        .tcp_settings
        .as_ref()
        .is_some_and(|settings| settings.accept_proxy_protocol)
    {
        if !matches!(network.as_str(), "" | "raw" | "tcp") {
            return Err(Error::InvalidConfig(
                "tcpSettings.acceptProxyProtocol requires raw/tcp transport".into(),
            ));
        }
        accept_proxy_protocol = true;
    }
    #[cfg(feature = "ws")]
    if matches!(network.as_str(), "ws" | "websocket")
        && stream_settings
            .ws_settings
            .as_ref()
            .is_some_and(|settings| settings.accept_proxy_protocol)
    {
        accept_proxy_protocol = true;
    }
    #[cfg(feature = "httpupgrade")]
    if network == "httpupgrade"
        && stream_settings
            .httpupgrade_settings
            .as_ref()
            .is_some_and(|settings| settings.accept_proxy_protocol)
    {
        accept_proxy_protocol = true;
    }

    if configure_max_seg
        && matches!(network.as_str(), "xhttp" | "splithttp")
        && stream_settings
            .tls_settings
            .as_ref()
            .is_some_and(|settings| {
                settings.alpn.len() == 1
                    && settings.alpn[0].eq_ignore_ascii_case("h3")
            })
    {
        return Err(Error::InvalidConfig(
            "XHTTP HTTP/3 does not support tcpMaxSeg".into(),
        ));
    }

    if configure_window_clamp
        && matches!(network.as_str(), "xhttp" | "splithttp")
        && stream_settings
            .tls_settings
            .as_ref()
            .is_some_and(|settings| {
                settings.alpn.len() == 1
                    && settings.alpn[0].eq_ignore_ascii_case("h3")
            })
    {
        return Err(Error::InvalidConfig(
            "XHTTP HTTP/3 does not support tcpWindowClamp".into(),
        ));
    }

    if configure_congestion
        && matches!(network.as_str(), "xhttp" | "splithttp")
        && stream_settings
            .tls_settings
            .as_ref()
            .is_some_and(|settings| {
                settings.alpn.len() == 1
                    && settings.alpn[0].eq_ignore_ascii_case("h3")
            })
    {
        return Err(Error::InvalidConfig(
            "XHTTP HTTP/3 does not support tcpCongestion".into(),
        ));
    }

    if configure_user_timeout
        && matches!(network.as_str(), "xhttp" | "splithttp")
        && stream_settings
            .tls_settings
            .as_ref()
            .is_some_and(|settings| {
                settings.alpn.len() == 1
                    && settings.alpn[0].eq_ignore_ascii_case("h3")
            })
    {
        return Err(Error::InvalidConfig(
            "XHTTP HTTP/3 does not support tcpUserTimeout".into(),
        ));
    }

    if configure_keepalive
        && matches!(network.as_str(), "xhttp" | "splithttp")
        && stream_settings
            .tls_settings
            .as_ref()
            .is_some_and(|settings| {
                settings.alpn.len() == 1
                    && settings.alpn[0].eq_ignore_ascii_case("h3")
            })
    {
        return Err(Error::InvalidConfig(
            "XHTTP HTTP/3 does not support TCP keepalive sockopt".into(),
        ));
    }

    if accept_proxy_protocol
        && matches!(network.as_str(), "xhttp" | "splithttp")
        && stream_settings
            .tls_settings
            .as_ref()
            .is_some_and(|settings| {
                settings.alpn.len() == 1
                    && settings.alpn[0].eq_ignore_ascii_case("h3")
            })
    {
        return Err(Error::InvalidConfig(
            "XHTTP HTTP/3 does not support TCP PROXY protocol".into(),
        ));
    }

    let protocol = if accept_proxy_protocol {
        ServerProxyConfig::ProxyProtocol {
            inner: Box::new(protocol),
        }
    } else {
        protocol
    };
    let protocol = if configure_keepalive {
        ServerProxyConfig::TcpKeepAlive {
            idle_secs: keepalive_idle,
            interval_secs: keepalive_interval,
            inner: Box::new(protocol),
        }
    } else {
        protocol
    };
    let protocol = if configure_user_timeout {
        ServerProxyConfig::TcpUserTimeout {
            timeout_ms: user_timeout_ms,
            inner: Box::new(protocol),
        }
    } else {
        protocol
    };
    let protocol = if configure_window_clamp {
        ServerProxyConfig::TcpWindowClamp {
            value: window_clamp,
            inner: Box::new(protocol),
        }
    } else {
        protocol
    };
    let protocol = if configure_congestion {
        ServerProxyConfig::TcpCongestion {
            algorithm: congestion_algorithm,
            inner: Box::new(protocol),
        }
    } else {
        protocol
    };
    let protocol = if configure_max_seg {
        ServerProxyConfig::TcpMaxSeg {
            value: max_seg,
            inner: Box::new(protocol),
        }
    } else {
        protocol
    };
    if configure_ipv6_only {
        Ok(ServerProxyConfig::Ipv6Only {
            inner: Box::new(protocol),
        })
    } else {
        Ok(protocol)
    }
}
