use std::sync::Arc;

#[cfg(feature = "tls")]
use std::io::Cursor;

#[cfg(feature = "tls")]
use rustls::{
    ClientConfig, RootCertStore,
    client::Resumption,
    pki_types::ServerName,
    version::{TLS12, TLS13},
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsConnector;

#[cfg(any(feature = "tls", test))]
use crate::address::Address;
use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::def::OutboundStreamSettings,
    resolver::{Resolver, resolve_single_address},
    util::socket::new_tcp_socket,
};

#[derive(Debug, Clone)]
pub(crate) enum OutboundTransportConfig {
    Tcp,
    #[cfg(feature = "tls")]
    Tls(TlsOutboundTransportConfig),
}

#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub(crate) struct TlsOutboundTransportConfig {
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl OutboundTransportConfig {
    pub(crate) fn compile(
        server: &NetLocation,
        stream: Option<&OutboundStreamSettings>,
        outbound_tag: &str,
    ) -> Result<Self, String> {
        let network = stream
            .map(|stream| stream.network.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if !network.is_empty() && network != "tcp" {
            return Err(format!(
                "outbound {outbound_tag} requires TCP network, got {network}"
            ));
        }

        let security = stream
            .and_then(|stream| stream.security.as_deref())
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        match security.as_str() {
            "" | "none" => {
                if stream.is_some_and(|stream| stream.tls_settings.is_some()) {
                    return Err(format!(
                        "outbound {outbound_tag} provides tlsSettings without security=tls"
                    ));
                }
                Ok(Self::Tcp)
            }
            "tls" => {
                #[cfg(feature = "tls")]
                {
                    compile_tls_transport(server, stream, outbound_tag)
                        .map(Self::Tls)
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = server;
                    Err(format!("outbound {outbound_tag} requires the tls feature"))
                }
            }
            other => Err(format!(
                "outbound {outbound_tag} uses unsupported security {other}"
            )),
        }
    }

    pub(crate) async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        server: &NetLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let address = resolve_single_address(resolver, server).await?;
        let socket = new_tcp_socket(None, address.is_ipv6())?;
        let stream = socket.connect(address).await?;
        stream.set_nodelay(true)?;
        let stream: Box<dyn AsyncStream> = Box::new(stream);

        match self {
            Self::Tcp => Ok(stream),
            #[cfg(feature = "tls")]
            Self::Tls(config) => {
                let connector =
                    TlsConnector::from(Arc::clone(&config.client_config));
                let stream = connector
                    .connect(config.server_name.clone(), stream)
                    .await
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            format!("outbound TLS handshake failed: {error}"),
                        )
                    })?;
                Ok(Box::new(stream))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp)
    }

    #[cfg(all(test, feature = "tls"))]
    pub(crate) fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }
}

#[cfg(feature = "tls")]
fn compile_tls_transport(
    server: &NetLocation,
    stream: Option<&OutboundStreamSettings>,
    outbound_tag: &str,
) -> Result<TlsOutboundTransportConfig, String> {
    let settings = stream
        .and_then(|stream| stream.tls_settings.as_ref())
        .cloned()
        .unwrap_or_default();

    if settings.allow_insecure {
        return Err(format!(
            "outbound {outbound_tag} does not support removed allowInsecure semantics"
        ));
    }
    for (field, value) in [
        ("fingerprint", settings.fingerprint.as_deref()),
        (
            "pinnedPeerCertSha256",
            settings.pinned_peer_cert_sha256.as_deref(),
        ),
        (
            "verifyPeerCertByName",
            settings.verify_peer_cert_by_name.as_deref(),
        ),
        ("echConfigList", settings.ech_config_list.as_deref()),
    ] {
        if value.is_some_and(|value| !value.trim().is_empty()) {
            return Err(format!(
                "outbound {outbound_tag} TLS field {field} is not supported yet"
            ));
        }
    }

    let mut roots = RootCertStore::empty();
    if !settings.disable_system_root {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots.add(certificate).map_err(|error| {
                format!(
                    "outbound {outbound_tag} failed to load a system root: {error}"
                )
            })?;
        }
        if roots.is_empty() && !native.errors.is_empty() {
            return Err(format!(
                "outbound {outbound_tag} could not load system roots: {:?}",
                native.errors
            ));
        }
    }

    for certificate in settings.certificates {
        if certificate
            .certificate_file
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(format!(
                "outbound {outbound_tag} certificateFile is not supported yet; use inline certificate"
            ));
        }
        if certificate
            .key_file
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || !certificate.key.is_empty()
        {
            return Err(format!(
                "outbound {outbound_tag} client certificates are not supported yet"
            ));
        }
        let usage = certificate
            .usage
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if usage != "verify" {
            return Err(format!(
                "outbound {outbound_tag} inline TLS certificate must use usage=verify"
            ));
        }
        if certificate.certificate.is_empty() {
            return Err(format!(
                "outbound {outbound_tag} inline verify certificate must not be empty"
            ));
        }
        let pem = certificate.certificate.join("\n");
        let mut reader = Cursor::new(pem.as_bytes());
        let mut count = 0usize;
        for certificate in rustls_pemfile::certs(&mut reader) {
            let certificate = certificate.map_err(|error| {
                format!(
                    "outbound {outbound_tag} has invalid inline TLS certificate: {error}"
                )
            })?;
            roots.add(certificate).map_err(|error| {
                format!(
                    "outbound {outbound_tag} rejected inline TLS certificate: {error}"
                )
            })?;
            count += 1;
        }
        if count == 0 {
            return Err(format!(
                "outbound {outbound_tag} inline TLS certificate contains no PEM certificates"
            ));
        }
    }

    if roots.is_empty() {
        return Err(format!(
            "outbound {outbound_tag} TLS has no trusted root certificates"
        ));
    }

    let versions = tls_versions(
        settings.min_version.as_deref(),
        settings.max_version.as_deref(),
        outbound_tag,
    )?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|error| {
            format!("outbound {outbound_tag} has invalid TLS version range: {error}")
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = settings
        .alpn
        .into_iter()
        .map(|protocol| {
            let protocol = protocol.trim().as_bytes().to_vec();
            if protocol.is_empty() || protocol.len() > u8::MAX as usize {
                return Err(format!(
                    "outbound {outbound_tag} has invalid ALPN protocol length"
                ));
            }
            Ok(protocol)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if !settings.enable_session_resumption {
        client_config.resumption = Resumption::disabled();
    }

    let server_name = settings
        .server_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match server.address() {
            Address::Hostname(hostname) => hostname.clone(),
            Address::Ipv4(address) => address.to_string(),
            Address::Ipv6(address) => address.to_string(),
        });
    let server_name = ServerName::try_from(server_name.trim().to_string()).map_err(
        |error| {
            format!(
                "outbound {outbound_tag} has invalid TLS serverName {server_name}: {error}"
            )
        },
    )?;

    Ok(TlsOutboundTransportConfig {
        client_config: Arc::new(client_config),
        server_name,
    })
}

#[cfg(feature = "tls")]
fn tls_versions(
    minimum: Option<&str>,
    maximum: Option<&str>,
    outbound_tag: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, String> {
    let parse = |value: Option<&str>, default: u8| -> Result<u8, String> {
        let value = value.unwrap_or_default().trim().to_ascii_lowercase();
        match value.as_str() {
            "" => Ok(default),
            "1.2" | "tls1.2" | "tls12" => Ok(12),
            "1.3" | "tls1.3" | "tls13" => Ok(13),
            other => Err(format!(
                "outbound {outbound_tag} uses unsupported TLS version {other}"
            )),
        }
    };
    let minimum = parse(minimum, 12)?;
    let maximum = parse(maximum, 13)?;
    if minimum > maximum {
        return Err(format!(
            "outbound {outbound_tag} TLS minVersion exceeds maxVersion"
        ));
    }
    Ok(match (minimum, maximum) {
        (12, 12) => vec![&TLS12],
        (12, 13) => vec![&TLS13, &TLS12],
        (13, 13) => vec![&TLS13],
        _ => {
            return Err(format!(
                "outbound {outbound_tag} has an invalid TLS version range"
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::def::OutboundTlsSettings;

    #[test]
    fn plain_tcp_is_the_default_transport() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        assert!(
            OutboundTransportConfig::compile(&server, None, "proxy")
                .unwrap()
                .is_tcp()
        );
    }

    #[test]
    fn rejects_non_tcp_networks_before_connecting() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "websocket".into(),
            security: None,
            tls_settings: None,
        };
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("requires TCP network")
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_compiles_with_an_inline_verify_root() {
        let generated =
            rcgen::generate_simple_self_signed(["proxy.example".to_string()])
                .unwrap();
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let stream = OutboundStreamSettings {
            network: "tcp".into(),
            security: Some("tls".into()),
            tls_settings: Some(OutboundTlsSettings {
                server_name: Some("proxy.example".into()),
                disable_system_root: true,
                min_version: Some("1.2".into()),
                max_version: Some("1.3".into()),
                alpn: vec!["http/1.1".into()],
                certificates: vec![crate::config::def::OutboundTlsCertificate {
                    certificate: vec![generated.cert.pem()],
                    usage: Some("verify".into()),
                    ..crate::config::def::OutboundTlsCertificate::default()
                }],
                ..OutboundTlsSettings::default()
            }),
        };
        let transport =
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .expect("inline verify root should compile");
        assert!(transport.is_tls());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_requires_trust_and_rejects_unsafe_or_unimplemented_fields() {
        let server =
            NetLocation::new(Address::Hostname("proxy.example".into()), 443);
        let mut stream = OutboundStreamSettings {
            network: "tcp".into(),
            security: Some("tls".into()),
            tls_settings: Some(OutboundTlsSettings {
                disable_system_root: true,
                ..OutboundTlsSettings::default()
            }),
        };
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("no trusted root")
        );

        stream.tls_settings.as_mut().unwrap().allow_insecure = true;
        assert!(
            OutboundTransportConfig::compile(&server, Some(&stream), "proxy")
                .unwrap_err()
                .contains("allowInsecure")
        );
    }
}
