use crate::{config::StreamSettings, Error};

use super::super::types::{ServerProxyConfig, TlsServerConfig};

pub(super) fn apply_tls_if_needed(
    protocol: ServerProxyConfig,
    stream_settings: &StreamSettings,
) -> Result<ServerProxyConfig, Error> {
    let needs_tls = stream_settings
        .security
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case("tls"))
        .unwrap_or(false);

    if !needs_tls {
        return Ok(protocol);
    }

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
