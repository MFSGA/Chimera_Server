#![allow(dead_code)] // TLS config helpers are consumed by optional QUIC/REALITY paths.

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

fn get_hysteria2_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTANCE: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

#[derive(Debug)]
struct ClientFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    webpki_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    client_fingerprints: BTreeSet<Vec<u8>>,
}

impl rustls::server::danger::ClientCertVerifier for ClientFingerprintVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        !self.client_fingerprints.is_empty()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            let _ = webpki_verifier.verify_client_cert(
                end_entity,
                _intermediates,
                _now,
            )?;
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        }

        let fingerprint = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            end_entity.as_ref(),
        );
        let fingerprint_bytes = fingerprint.as_ref();

        if self.client_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown client fingerprint: {hex_fingerprint}"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.supported_algs,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.supported_algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn process_fingerprints(
    client_fingerprints: &[String],
) -> Option<BTreeSet<Vec<u8>>> {
    let mut result = BTreeSet::new();

    for fingerprint in client_fingerprints {
        let clean_fp = fingerprint.replace([':', ' '], "");

        if clean_fp.len() % 2 != 0 {
            tracing::warn!(
                "Invalid client fingerprint, odd number of hex chars: {fingerprint}"
            );
            return None;
        }

        let bytes = (0..clean_fp.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_fp[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>();

        match bytes {
            Ok(b) => {
                result.insert(b);
            }
            Err(_) => {
                tracing::warn!(
                    "Invalid client fingerprint, could not convert to hex: {fingerprint}"
                );
                return None;
            }
        }
    }

    Some(result)
}

pub fn create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> std::io::Result<rustls::ServerConfig> {
    let privkey = parse_private_key(key_bytes)?;
    create_server_config_with_provider(
        cert_bytes,
        privkey,
        alpn_protocols,
        client_fingerprints,
        get_crypto_provider(),
    )
}

pub(crate) fn create_hysteria2_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> std::io::Result<rustls::ServerConfig> {
    let privkey = parse_private_key(key_bytes)?;
    let crypto_provider = hysteria2_crypto_provider(&privkey, client_fingerprints);
    create_server_config_with_provider(
        cert_bytes,
        privkey,
        alpn_protocols,
        client_fingerprints,
        crypto_provider,
    )
}

fn parse_private_key(
    key_bytes: &[u8],
) -> std::io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse private key: {e}"),
        )
    })
}

fn hysteria2_crypto_provider(
    privkey: &rustls::pki_types::PrivateKeyDer<'static>,
    client_fingerprints: &[String],
) -> Arc<rustls::crypto::CryptoProvider> {
    // Client certificates can use signature algorithms that Ring does not
    // verify, so retain AWS-LC whenever fingerprint authentication is enabled.
    if !client_fingerprints.is_empty() {
        return get_crypto_provider();
    }

    let ring_provider = get_hysteria2_crypto_provider();
    if ring_provider
        .key_provider
        .load_private_key(privkey.clone_key())
        .is_ok()
    {
        ring_provider
    } else {
        // AWS-LC supports additional server key types, including ECDSA P-521.
        get_crypto_provider()
    }
}

fn create_server_config_with_provider(
    cert_bytes: &[u8],
    privkey: rustls::pki_types::PrivateKeyDer<'static>,
    alpn_protocols: &[String],
    client_fingerprints: &[String],
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
) -> std::io::Result<rustls::ServerConfig> {
    let certs: Vec<_> =
        rustls::pki_types::CertificateDer::pem_slice_iter(cert_bytes)
            .filter_map(|cert| cert.ok())
            .map(|cert| cert.into_owned())
            .collect();

    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no valid certificates found in PEM data",
        ));
    }

    let supported_algs = crypto_provider.signature_verification_algorithms;
    let builder = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            std::io::Error::other(format!(
                "failed to set TLS protocol versions: {e}"
            ))
        })?;

    let builder = if client_fingerprints.is_empty() {
        builder.with_no_client_auth()
    } else {
        let fingerprints = process_fingerprints(client_fingerprints);
        let fingerprints = fingerprints.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "failed to process client fingerprints",
            )
        })?;
        builder.with_client_cert_verifier(Arc::new(ClientFingerprintVerifier {
            supported_algs,
            webpki_verifier: None,
            client_fingerprints: fingerprints,
        }))
    };

    let mut config = builder.with_single_cert(certs, privkey).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad certificate/key: {e}"),
        )
    })?;

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.max_fragment_size = None;
    config.max_early_data_size = u32::MAX;
    config.ignore_client_order = true;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{
        create_hysteria2_server_config, create_server_config, get_crypto_provider,
        get_hysteria2_crypto_provider,
    };
    use std::sync::Arc;

    fn test_certificate() -> (Vec<u8>, Vec<u8>) {
        let generated =
            rcgen::generate_simple_self_signed(["localhost".to_string()])
                .expect("generate test certificate");
        (
            generated.cert.pem().into_bytes(),
            generated.signing_key.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn generic_server_config_keeps_aws_lc_provider() {
        let (cert, key) = test_certificate();
        let config = create_server_config(
            &cert,
            &key,
            &["h3".into()],
            &[
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                    .into(),
            ],
        )
        .expect("create generic server config with client fingerprint");

        assert!(Arc::ptr_eq(
            config.crypto_provider(),
            &get_crypto_provider()
        ));
    }

    #[test]
    fn hysteria2_server_config_uses_ring_provider() {
        let (cert, key) = test_certificate();
        let config =
            create_hysteria2_server_config(&cert, &key, &["h3".into()], &[])
                .expect("create Hysteria2 server config");

        assert!(Arc::ptr_eq(
            config.crypto_provider(),
            &get_hysteria2_crypto_provider()
        ));
    }

    #[test]
    fn hysteria2_server_config_keeps_aws_lc_for_client_fingerprints() {
        let (cert, key) = test_certificate();
        let config = create_hysteria2_server_config(
            &cert,
            &key,
            &["h3".into()],
            &[
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                    .into(),
            ],
        )
        .expect("create Hysteria2 server config with client fingerprint");

        assert!(Arc::ptr_eq(
            config.crypto_provider(),
            &get_crypto_provider()
        ));
    }

    #[test]
    fn hysteria2_server_config_falls_back_to_aws_lc_for_p521_key() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512)
            .expect("generate P-521 key");
        let params = rcgen::CertificateParams::new(["localhost".to_string()])
            .expect("create certificate parameters");
        let cert = params.self_signed(&key).expect("create P-521 certificate");
        let config = create_hysteria2_server_config(
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            &["h3".into()],
            &[],
        )
        .expect("create Hysteria2 server config for P-521 key");

        assert!(Arc::ptr_eq(
            config.crypto_provider(),
            &get_crypto_provider()
        ));
    }
}
