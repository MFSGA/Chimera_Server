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
            let mut parts = [0u8; 3];
            for (idx, part) in text
                .split('.')
                .filter(|s| !s.is_empty())
                .take(3)
                .enumerate()
            {
                parts[idx] = part.parse::<u8>().map_err(|_| {
                    Error::InvalidConfig(format!("invalid {field} value: {text}"))
                })?;
            }
            Ok(Some(parts))
        }
    }
}

#[cfg(feature = "reality")]
fn build_reality_layer(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let settings = stream_settings.reality_settings.as_ref().ok_or_else(|| {
        Error::InvalidConfig("reality inbound requires realitySettings".into())
    })?;

    let dest = NetLocation::from_str(&settings.dest, Some(443)).map_err(|_| {
        Error::InvalidConfig(format!(
            "invalid reality.dest value: {}",
            settings.dest
        ))
    })?;

    if !matches!(dest.address(), Address::Hostname(_)) {
        return Err(Error::InvalidConfig(
            "reality.dest must be a hostname (ip addresses are not supported)"
                .into(),
        ));
    }

    let private_key = decode_private_key(&settings.private_key).map_err(|err| {
        Error::InvalidConfig(format!("invalid reality privateKey: {err}"))
    })?;

    let short_ids = settings
        .short_ids
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
    if server_names.is_empty() {
        if let Address::Hostname(hostname) = dest.address() {
            server_names.push(hostname.clone());
        }
    }

    Ok(ServerProxyConfig::Reality(RealityTransportConfig {
        dest,
        private_key,
        short_ids,
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
        .map(|value| value.to_ascii_lowercase());

    match security.as_deref() {
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
        _ => Ok(protocol),
    }
}
