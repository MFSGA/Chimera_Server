use std::{
    fs::File,
    io::{self, BufReader, Cursor},
    sync::Arc,
};

use async_trait::async_trait;
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
            PrivateSec1KeyDer,
        },
        version::{TLS12, TLS13},
    },
};

use crate::{
    async_stream::AsyncStream,
    config::server_config::{TlsCertificateConfig, TlsCertificateUsage},
    handler::tcp::tcp_handler::{
        TcpServerConnectionContext, TcpServerHandler, TcpServerSetupResult,
    },
};
#[cfg(feature = "vless")]
use crate::{
    config::server_config::{VlessFallback, VlessUser},
    handler::vless_handler::{
        ParsedVisionUser, VisionRecordIo, parse_vision_users,
        setup_tls_vision_server_stream,
    },
};

enum TlsInner {
    Handler(Box<dyn TcpServerHandler>),
    #[cfg(feature = "vless")]
    VisionVless {
        users: Vec<ParsedVisionUser>,
        fallbacks: Vec<VlessFallback>,
        inbound_tag: String,
    },
}

pub struct TlsServerHandler {
    acceptor: TlsAcceptor,
    inner: TlsInner,
}

impl TlsServerHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificates: Vec<TlsCertificateConfig>,
        alpn_protocols: Vec<String>,
        enable_session_resumption: bool,
        _reject_unknown_sni: bool,
        min_version: Option<String>,
        max_version: Option<String>,
        _server_name: Option<String>,
        inner: Box<dyn TcpServerHandler>,
    ) -> io::Result<Self> {
        let config = build_server_config(
            &certificates,
            &alpn_protocols,
            enable_session_resumption,
            min_version.as_deref(),
            max_version.as_deref(),
        )?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            inner: TlsInner::Handler(inner),
        })
    }

    #[cfg(feature = "vless")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_vision_vless(
        certificates: Vec<TlsCertificateConfig>,
        alpn_protocols: Vec<String>,
        enable_session_resumption: bool,
        _reject_unknown_sni: bool,
        min_version: Option<String>,
        max_version: Option<String>,
        _server_name: Option<String>,
        users: &[VlessUser],
        fallbacks: &[VlessFallback],
        inbound_tag: &str,
    ) -> io::Result<Self> {
        let config = build_server_config(
            &certificates,
            &alpn_protocols,
            enable_session_resumption,
            min_version.as_deref(),
            max_version.as_deref(),
        )?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            inner: TlsInner::VisionVless {
                users: parse_vision_users(users),
                fallbacks: fallbacks.to_vec(),
                inbound_tag: inbound_tag.to_string(),
            },
        })
    }
}

impl std::fmt::Debug for TlsServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServerHandler").finish()
    }
}

#[async_trait]
impl TcpServerHandler for TlsServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_context(
            server_stream,
            TcpServerConnectionContext::default(),
        )
        .await
    }

    async fn setup_server_stream_with_context(
        &self,
        server_stream: Box<dyn AsyncStream>,
        mut context: TcpServerConnectionContext,
    ) -> io::Result<TcpServerSetupResult> {
        match &self.inner {
            TlsInner::Handler(inner) => {
                let tls_stream = self.acceptor.accept(server_stream).await?;
                let connection = tls_stream.get_ref().1;
                context.server_name =
                    connection.server_name().map(ToOwned::to_owned);
                context.alpn_protocol = connection
                    .alpn_protocol()
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .map(ToOwned::to_owned);
                inner
                    .setup_server_stream_with_context(Box::new(tls_stream), context)
                    .await
            }
            #[cfg(feature = "vless")]
            TlsInner::VisionVless {
                users,
                fallbacks,
                inbound_tag,
            } => {
                let tls_stream = self
                    .acceptor
                    .accept(VisionRecordIo::new(server_stream))
                    .await?;
                setup_tls_vision_server_stream(
                    tls_stream,
                    users,
                    fallbacks,
                    inbound_tag,
                )
                .await
            }
        }
    }
}

fn build_server_config(
    certificates: &[TlsCertificateConfig],
    alpn_protocols: &[String],
    enable_session_resumption: bool,
    min_version: Option<&str>,
    max_version: Option<&str>,
) -> io::Result<rustls::ServerConfig> {
    let certificate = certificates
        .iter()
        .find(|certificate| {
            matches!(certificate.usage, TlsCertificateUsage::Encipherment)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no encipherment certificate found for TLS server",
            )
        })?;
    let cert_chain = load_certs(certificate)?;
    let private_key = load_private_key(certificate)?;

    let versions = tls_versions(min_version, max_version)?;
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    config.alpn_protocols = tls_alpn_protocols(alpn_protocols);
    config.send_tls13_tickets = if enable_session_resumption { 2 } else { 0 };

    Ok(config)
}

fn load_certs(
    certificate: &TlsCertificateConfig,
) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = open_pem_reader(
        certificate.certificate_path.as_deref(),
        &certificate.certificate_pem,
        "certificate",
    )?;
    let certs: Vec<CertificateDer<'static>> =
        certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificates found in certificate file",
        ));
    }

    Ok(certs)
}

fn load_private_key(
    certificate: &TlsCertificateConfig,
) -> io::Result<PrivateKeyDer<'static>> {
    let key_bytes = certificate
        .key_pem
        .as_deref()
        .filter(|bytes| !bytes.is_empty());

    let mut reader = open_pem_reader(
        certificate.key_path.as_deref(),
        key_bytes.unwrap_or(&[]),
        "private key",
    )?;
    if let Some(key) = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<PrivatePkcs8KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    let mut reader = open_pem_reader(
        certificate.key_path.as_deref(),
        key_bytes.unwrap_or(&[]),
        "private key",
    )?;
    if let Some(key) = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<PrivatePkcs1KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    let mut reader = open_pem_reader(
        certificate.key_path.as_deref(),
        key_bytes.unwrap_or(&[]),
        "private key",
    )?;
    if let Some(key) = ec_private_keys(&mut reader)
        .collect::<Result<Vec<PrivateSec1KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "no valid private keys found",
    ))
}

fn open_pem_reader(
    path: Option<&str>,
    inline_pem: &[u8],
    label: &str,
) -> io::Result<BufReader<Box<dyn io::Read>>> {
    if let Some(path) = path {
        let file = File::open(path)?;
        return Ok(BufReader::new(Box::new(file)));
    }

    if inline_pem.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no {label} provided"),
        ));
    }

    Ok(BufReader::new(Box::new(Cursor::new(inline_pem.to_vec()))))
}

fn tls_alpn_protocols(alpn_protocols: &[String]) -> Vec<Vec<u8>> {
    if alpn_protocols.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        alpn_protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect()
    }
}

fn tls_versions(
    min_version: Option<&str>,
    max_version: Option<&str>,
) -> io::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let parse = |value: Option<&str>, default: u8, field: &str| -> io::Result<u8> {
        match value.unwrap_or_default().trim() {
            "" => Ok(default),
            "1.2" => Ok(12),
            "1.3" => Ok(13),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported tls {field}: {other}"),
            )),
        }
    };
    let minimum = parse(min_version, 12, "minVersion")?;
    let maximum = parse(max_version, 13, "maxVersion")?;
    if minimum > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tls minVersion exceeds maxVersion",
        ));
    }

    Ok(match (minimum, maximum) {
        (12, 12) => vec![&TLS12],
        (12, 13) => vec![&TLS13, &TLS12],
        (13, 13) => vec![&TLS13],
        _ => unreachable!("validated TLS version bounds"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_alpn_uses_xray_server_defaults() {
        assert_eq!(
            tls_alpn_protocols(&[]),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(
            tls_alpn_protocols(&["custom".into()]),
            vec![b"custom".to_vec()]
        );
    }

    #[test]
    fn tls_versions_apply_xray_server_bounds() {
        assert_eq!(tls_versions(None, None).unwrap(), vec![&TLS13, &TLS12]);
        assert_eq!(
            tls_versions(Some("1.2"), Some("1.2")).unwrap(),
            vec![&TLS12]
        );
        assert_eq!(tls_versions(Some("1.3"), None).unwrap(), vec![&TLS13]);
        assert!(tls_versions(Some("1.3"), Some("1.2")).is_err());
        assert!(tls_versions(Some("1.1"), None).is_err());
    }
}
