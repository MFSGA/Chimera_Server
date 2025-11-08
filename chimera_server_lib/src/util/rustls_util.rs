use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::pki_types::pem::PemObject;

fn get_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTANCE: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

pub fn create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> rustls::ServerConfig {
    let certs = vec![
        rustls::pki_types::CertificateDer::from_pem_slice(cert_bytes)
            .unwrap()
            .into_owned(),
    ];

    let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes).unwrap();

    let builder = rustls::ServerConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = if client_fingerprints.is_empty() {
        builder.with_no_client_auth()
    } else {
        todo!()
    };
    let mut config = builder
        .with_single_cert(certs, privkey)
        .expect("bad certificate/key");

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.max_fragment_size = None;
    config.max_early_data_size = u32::MAX;
    config.ignore_client_order = true;

    config
}
