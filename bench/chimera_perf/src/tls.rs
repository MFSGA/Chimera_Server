use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::{Arc, Once},
};

use anyhow::{Context, Result};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig,
    SignatureScheme,
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rustls_pemfile::{certs, private_key};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static PROVIDER: Once = Once::new();

pub trait BenchIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> BenchIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedBenchIo = Box<dyn BenchIo>;

pub fn install_provider() {
    PROVIDER.call_once(|| {
        let _ = CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
}

pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    install_provider();
    let cert_file = File::open(cert_path)
        .with_context(|| format!("open TLS certificate {}", cert_path.display()))?;
    let key_file = File::open(key_path)
        .with_context(|| format!("open TLS private key {}", key_path.display()))?;
    let certificates = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS certificate chain")?;
    let key = private_key(&mut BufReader::new(key_file))
        .context("parse TLS private key")?
        .context("TLS private key is missing")?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("build TLS server config")
}

pub async fn accept(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<BoxedBenchIo> {
    let stream = TlsAcceptor::from(config)
        .accept(stream)
        .await
        .context("accept inner TLS 1.3 connection")?;
    Ok(Box::new(stream))
}

pub async fn connect(stream: TcpStream, server_name: &str) -> Result<BoxedBenchIo> {
    install_provider();
    let config =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
    let server_name = ServerName::try_from(server_name.to_owned())
        .context("invalid TLS server name")?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .context("connect inner TLS 1.3 session")?;
    Ok(Box::new(stream))
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

pub fn plain(stream: TcpStream) -> BoxedBenchIo {
    Box::new(stream)
}

pub fn invalid_tls_mode(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
