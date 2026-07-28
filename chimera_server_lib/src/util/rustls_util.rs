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

fn get_supported_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    get_crypto_provider().signature_verification_algorithms
}

fn get_disabled_verifier() -> Arc<ClientFingerprintVerifier> {
    static INSTANCE: OnceLock<Arc<ClientFingerprintVerifier>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            Arc::new(ClientFingerprintVerifier {
                supported_algs: get_supported_algorithms(),
                webpki_verifier: None,
                client_fingerprints: BTreeSet::new(),
            })
        })
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

    let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse private key: {e}"),
            )
        })?;

    let builder = rustls::ServerConfig::builder_with_provider(get_crypto_provider())
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
            supported_algs: get_supported_algorithms(),
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
