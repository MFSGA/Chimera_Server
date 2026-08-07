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
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
    },
};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

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

#[derive(Debug)]
struct XraySniResolver {
    certified_key: Arc<CertifiedKey>,
    names: Vec<String>,
}

impl ResolvesServerCert for XraySniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        sni_matches_names(sni, &self.names).then(|| self.certified_key.clone())
    }
}

fn sni_matches_names(sni: &str, names: &[String]) -> bool {
    let sni = sni.to_ascii_lowercase();
    let wildcard = sni.find('.').map(|index| format!("*{}", &sni[index..]));
    names
        .iter()
        .any(|name| name == &sni || wildcard.as_deref() == Some(name.as_str()))
}

impl TlsServerHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificates: Vec<TlsCertificateConfig>,
        alpn_protocols: Vec<String>,
        enable_session_resumption: bool,
        reject_unknown_sni: bool,
        min_version: Option<String>,
        max_version: Option<String>,
        _server_name: Option<String>,
        inner: Box<dyn TcpServerHandler>,
    ) -> io::Result<Self> {
        let config = build_server_config(
            &certificates,
            &alpn_protocols,
            enable_session_resumption,
            reject_unknown_sni,
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
        reject_unknown_sni: bool,
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
            reject_unknown_sni,
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

pub(crate) fn build_server_config(
    certificates: &[TlsCertificateConfig],
    alpn_protocols: &[String],
    enable_session_resumption: bool,
    reject_unknown_sni: bool,
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

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain.clone(), private_key.clone_key())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if reject_unknown_sni {
        let certified_key = CertifiedKey::from_der(
            cert_chain.clone(),
            private_key,
            config.crypto_provider(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        config.cert_resolver = Arc::new(XraySniResolver {
            certified_key: Arc::new(certified_key),
            names: certificate_dns_names(&cert_chain[0])?,
        });
    }

    if !alpn_protocols.is_empty() {
        config.alpn_protocols = alpn_protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();
    }
    config.send_tls13_tickets = if enable_session_resumption { 2 } else { 0 };
    apply_tls_version_overrides(&mut config, min_version, max_version)?;

    Ok(config)
}

fn certificate_dns_names(
    certificate: &CertificateDer<'_>,
) -> io::Result<Vec<String>> {
    let (_, parsed) =
        x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
            .map_err(|err| {
                io::Error::new(io::ErrorKind::InvalidData, err.to_string())
            })?;
    let mut names = Vec::new();
    if let Some(common_name) = parsed.subject().iter_common_name().next()
        && let Ok(common_name) = common_name.as_str()
    {
        names.push(common_name.to_ascii_lowercase());
    }
    if let Ok(Some(subject_alt_name)) = parsed.subject_alternative_name() {
        for name in &subject_alt_name.value.general_names {
            if let GeneralName::DNSName(name) = name {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    Ok(names)
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

fn apply_tls_version_overrides(
    _config: &mut rustls::ServerConfig,
    min_version: Option<&str>,
    max_version: Option<&str>,
) -> io::Result<()> {
    if let Some(value) = min_version {
        match value {
            "1.2" | "1.3" | "" => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported tls minVersion: {other}"),
                ));
            }
        }
    }

    if let Some(value) = max_version {
        match value {
            "1.2" | "1.3" | "" => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported tls maxVersion: {other}"),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_matching_follows_xray_exact_and_wildcard_rules() {
        let names = vec!["proxy.example".into(), "*.example.com".into()];
        assert!(sni_matches_names("PROXY.EXAMPLE", &names));
        assert!(sni_matches_names("api.example.com", &names));
        assert!(!sni_matches_names("deep.api.example.com", &names));
        assert!(!sni_matches_names("unknown.example", &names));
    }

    #[test]
    fn certificate_dns_names_reads_subject_alt_names() {
        let generated = rcgen::generate_simple_self_signed([
            "proxy.example".to_string(),
            "api.example.com".to_string(),
        ])
        .unwrap();
        let certificate = CertificateDer::from(generated.cert.der().to_vec());
        let names = certificate_dns_names(&certificate).unwrap();
        assert!(names.iter().any(|name| name == "proxy.example"));
        assert!(names.iter().any(|name| name == "api.example.com"));
    }
}
