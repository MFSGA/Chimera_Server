use crate::{
    config::StreamSettings,
    reality::{decode_private_key, decode_short_id},
    Error,
};

use super::super::types::{RealityTransportConfig, ServerProxyConfig, TlsServerConfig};
use crate::address::{Address, NetLocation};

fn parse_version_triplet(value: &Option<String>, field: &str) -> Result<Option<[u8; 3]>, Error> {
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
                parts[idx] = part
                    .parse::<u8>()
                    .map_err(|_| Error::InvalidConfig(format!("invalid {field} value: {text}")))?;
            }
            Ok(Some(parts))
        }
    }
}

fn build_reality_layer(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let settings = stream_settings
        .reality_settings
        .as_ref()
        .ok_or_else(|| Error::InvalidConfig("reality inbound requires realitySettings".into()))?;

    let dest = NetLocation::from_str(&settings.dest, Some(443)).map_err(|_| {
        Error::InvalidConfig(format!("invalid reality.dest value: {}", settings.dest))
    })?;

    if !matches!(dest.address(), Address::Hostname(_)) {
        return Err(Error::InvalidConfig(
            "reality.dest must be a hostname (ip addresses are not supported)".into(),
        ));
    }

    let private_key = decode_private_key(&settings.private_key)
        .map_err(|err| Error::InvalidConfig(format!("invalid reality privateKey: {err}")))?;

    let short_ids = settings
        .short_ids
        .iter()
        .map(|short_id| {
            decode_short_id(short_id).map_err(|err| {
                Error::InvalidConfig(format!("invalid reality shortId {short_id}: {err}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let max_time_diff = settings.max_time_diff;
    let min_client_version = parse_version_triplet(&settings.min_client_ver, "minClientVer")?;
    let max_client_version = parse_version_triplet(&settings.max_client_ver, "maxClientVer")?;

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

fn build_tls_layer(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let tls_settings = stream_settings.tls_settings.as_ref().ok_or_else(|| {
        Error::InvalidConfig("tls inbound requires tlsSettings configuration".into())
    })?;

    let certificate = tls_settings
        .certificates
        .get(0)
        .ok_or_else(|| {
            Error::InvalidConfig("tls inbound requires at least one certificate".into())
        })?
        .clone();

    Ok(ServerProxyConfig::Tls(TlsServerConfig {
        certificate_path: certificate.certificate_file,
        private_key_path: certificate.key_file,
        alpn_protocols: tls_settings.alpn.clone(),
        inner: Box::new(protocol),
    }))
}

pub(super) fn apply_security_layers(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    match stream_settings
        .security
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("tls") => build_tls_layer(protocol, stream_settings),
        Some("reality") => build_reality_layer(protocol, stream_settings),
        _ => Ok(protocol),
    }
}
