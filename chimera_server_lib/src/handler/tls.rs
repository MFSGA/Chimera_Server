#![cfg(feature = "tls")]

use std::{
    fs::File,
    io::{self, BufReader},
    sync::Arc,
};

use async_trait::async_trait;
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
            PrivateSec1KeyDer,
        },
    },
    TlsAcceptor,
};

use crate::{
    async_stream::AsyncStream,
    handler::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult},
};

pub struct TlsServerHandler {
    acceptor: TlsAcceptor,
    inner: Box<dyn TcpServerHandler>,
}

impl TlsServerHandler {
    pub fn new(
        certificate_path: String,
        private_key_path: String,
        alpn_protocols: Vec<String>,
        inner: Box<dyn TcpServerHandler>,
    ) -> io::Result<Self> {
        let config = build_server_config(&certificate_path, &private_key_path, &alpn_protocols)?;
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
    certificate_path: &str,
    private_key_path: &str,
    alpn_protocols: &[String],
) -> io::Result<rustls::ServerConfig> {
    let cert_chain = load_certs(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;

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

    Ok(config)
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificates found in certificate file",
        ));
    }

    Ok(certs)
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    if let Some(key) = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<PrivatePkcs8KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    if let Some(key) = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<PrivatePkcs1KeyDer<'static>>, _>>()?
        .into_iter()
        .next()
    {
        return Ok(PrivateKeyDer::from(key));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
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
