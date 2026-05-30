use std::io::{Error, ErrorKind, Result};

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use rcgen::SignatureAlgorithm;

/// A signing key that places the REALITY HMAC into the certificate signature.
///
/// The certificate public key is a real Ed25519 public key, but the X.509
/// signature bytes are HMAC-SHA512(auth_key, ed25519_public_key).
struct HmacSigningKey {
    hmac_key: hmac::Key,
    public_key: [u8; 32],
}

impl rcgen::SigningKey for HmacSigningKey {
    fn sign(&self, _msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let tag = hmac::sign(&self.hmac_key, &self.public_key);
        Ok(tag.as_ref().to_vec())
    }
}

impl rcgen::PublicKeyData for HmacSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// Generate a HMAC-signed Ed25519 certificate for REALITY.
///
/// Returns DER bytes for the certificate and the Ed25519 keypair used later to
/// sign the TLS CertificateVerify message.
pub fn generate_hmac_certificate(
    auth_key: &[u8; 32],
    hostname: &str,
) -> Result<(Vec<u8>, Ed25519KeyPair)> {
    let signing_key = Ed25519KeyPair::generate()
        .map_err(|_| Error::other("Failed to generate Ed25519 keypair"))?;

    let public_key: [u8; 32] =
        signing_key.public_key().as_ref().try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "Ed25519 public key is not 32 bytes")
        })?;

    let hmac_key = HmacSigningKey {
        hmac_key: hmac::Key::new(hmac::HMAC_SHA512, auth_key),
        public_key,
    };

    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names =
        vec![rcgen::SanType::DnsName(hostname.try_into().map_err(
            |_| Error::new(ErrorKind::InvalidInput, "Invalid hostname"),
        )?)];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0u8]));

    let cert = params
        .self_signed(&hmac_key)
        .map_err(|e| Error::other(format!("Failed to create certificate: {e}")))?;
    let cert_der = cert.der().to_vec();

    tracing::debug!(
        "REALITY: Generated HMAC certificate ({} bytes)",
        cert_der.len()
    );

    Ok((cert_der, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_signature_offset(cert_der: &[u8]) -> Option<usize> {
        for i in (0..cert_der.len().saturating_sub(66)).rev() {
            if cert_der[i] == 0x03
                && cert_der[i + 1] == 0x41
                && cert_der[i + 2] == 0x00
            {
                return Some(i + 3);
            }
        }
        None
    }

    #[test]
    fn test_generate_hmac_certificate() {
        let auth_key = [42u8; 32];
        let result = generate_hmac_certificate(&auth_key, "test.example.com");

        assert!(result.is_ok());

        let (cert_der, _signing_key) = result.unwrap();
        assert!(cert_der.len() > 100);
        assert!(cert_der.len() < 1000);
        assert_eq!(cert_der[0], 0x30);
    }

    #[test]
    fn test_hmac_placed_at_certificate_signature() {
        let auth_key = [0x42u8; 32];

        let (cert_der, signing_key) =
            generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let sig_offset = find_signature_offset(&cert_der)
            .expect("should find signature offset in certificate");

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let expected_hmac = hmac::sign(&hmac_key, signing_key.public_key().as_ref());

        assert_eq!(
            &cert_der[sig_offset..sig_offset + 64],
            expected_hmac.as_ref()
        );
    }

    #[test]
    fn test_different_keys_produce_different_certificates() {
        let auth_key = [99u8; 32];

        let (cert1, key1) =
            generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let (cert2, key2) =
            generate_hmac_certificate(&auth_key, "test.example.com").unwrap();

        assert_ne!(key1.public_key().as_ref(), key2.public_key().as_ref());
        assert_ne!(cert1, cert2);
    }
}
