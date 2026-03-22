#![cfg(feature = "tls")]

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
    },
};

use crate::{
    async_stream::AsyncStream,
    config::server_config::{TlsCertificateConfig, TlsCertificateUsage},
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
};

pub struct TlsServerHandler {
    acceptor: TlsAcceptor,
    inner: Box<dyn TcpServerHandler>,
}

impl TlsServerHandler {
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
            inner,
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
        let tls_stream = self.acceptor.accept(server_stream).await?;
        self.inner.setup_server_stream(Box::new(tls_stream)).await
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

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    let mut config = config;
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
