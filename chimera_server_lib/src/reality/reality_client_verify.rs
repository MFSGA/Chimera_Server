// REALITY client certificate verification
//
// This module handles HMAC verification of REALITY server certificates.
// In REALITY protocol, the server embeds HMAC-SHA512(auth_key, ed25519_public_key)
// in the signature field of the certificate.

use std::io;

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use subtle::ConstantTimeEq;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// Extract the DER-encoded certificate from a TLS 1.3 Certificate message
///
/// Certificate message structure:
/// - certificate_request_context (1 byte length + data)
/// - certificate_list length (3 bytes)
/// - For each certificate entry:
///   - cert_data length (3 bytes)
///   - cert_data (DER-encoded X.509 certificate)
///   - extensions length (2 bytes)
///   - extensions data
#[inline]
pub fn extract_certificate_der(certificate_message: &[u8]) -> io::Result<&[u8]> {
    // Skip handshake header (type + 3-byte length)
    if certificate_message.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message too short",
        ));
    }

    let mut pos = 4; // Skip handshake header

    // certificate_request_context length (1 byte)
    if pos >= certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at context length",
        ));
    }
    let context_len = certificate_message[pos] as usize;
    pos += 1 + context_len;

    // certificate_list length (3 bytes)
    if pos + 3 > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at list length",
        ));
    }
    let _list_len = u32::from_be_bytes([
        0,
        certificate_message[pos],
        certificate_message[pos + 1],
        certificate_message[pos + 2],
    ]) as usize;
    pos += 3;

    // First certificate entry: cert_data length (3 bytes)
    if pos + 3 > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at cert length",
        ));
    }
    let cert_len = u32::from_be_bytes([
        0,
        certificate_message[pos],
        certificate_message[pos + 1],
        certificate_message[pos + 2],
    ]) as usize;
    pos += 3;

    // Extract the DER-encoded certificate
    if pos + cert_len > certificate_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Certificate message truncated at cert data",
        ));
    }

    Ok(&certificate_message[pos..pos + cert_len])
}

/// Verify the HMAC signature embedded in the REALITY certificate
///
/// In REALITY protocol, the server embeds HMAC-SHA512(auth_key, ed25519_public_key)
/// in the signature field of the certificate.
///
/// Uses proper X.509 parsing via x509-parser crate for robust extraction.
#[inline]
pub fn verify_certificate_hmac(
    cert_der: &[u8],
    auth_key: &[u8; 32],
) -> io::Result<()> {
    // Parse the X.509 certificate properly
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse X.509 certificate: {}", e),
        )
    })?;

    // Extract the public key from SubjectPublicKeyInfo
    let spki = cert.public_key();
    let pubkey_data: &[u8] = &spki.subject_public_key.data;
    let signature: &[u8] = &cert.signature_value.data;

    tracing::debug!(
        "REALITY CLIENT: Parsed certificate - pubkey len={}, sig len={}",
        pubkey_data.len(),
        signature.len()
    );

    // Verify this is an Ed25519 public key (32 bytes)
    if pubkey_data.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Ed25519 public key (32 bytes), got {} bytes",
                pubkey_data.len()
            ),
        ));
    }

    // Verify signature is exactly 64 bytes (HMAC-SHA512 output).
    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected 64-byte signature for HMAC-SHA512 verification, got {} bytes",
                signature.len()
            ),
        ));
    }

    // Compute expected HMAC: HMAC-SHA512(auth_key, ed25519_public_key)
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_tag = hmac::sign(&hmac_key, pubkey_data);
    let expected_signature = hmac_tag.as_ref();

    tracing::debug!(
        "REALITY CLIENT: HMAC verification - ed25519_pubkey={:02x?}",
        pubkey_data
    );
    tracing::debug!(
        "REALITY CLIENT: HMAC verification - expected_sig={:02x?}",
        expected_signature
    );
    tracing::debug!(
        "REALITY CLIENT: HMAC verification - actual_sig={:02x?}",
        signature
    );

    // Compare full 64-byte signature with expected HMAC using constant-time comparison.
    if expected_signature.ct_eq(signature).unwrap_u8() == 0 {
        tracing::warn!(
            "REALITY CLIENT: Certificate HMAC mismatch - not a REALITY server"
        );
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Certificate HMAC verification failed - not a REALITY-signed certificate",
        ));
    }

    tracing::info!("REALITY CLIENT: Certificate HMAC verified successfully");
    Ok(())
}

/// Extract the Ed25519 public key from a DER-encoded certificate.
#[inline]
pub fn extract_ed25519_public_key(cert_der: &[u8]) -> io::Result<[u8; 32]> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse X.509 certificate: {}", e),
        )
    })?;

    let spki = cert.public_key();
    let pubkey_data: &[u8] = &spki.subject_public_key.data;

    if pubkey_data.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Ed25519 public key (32 bytes), got {} bytes",
                pubkey_data.len()
            ),
        ));
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(pubkey_data);
    Ok(public_key)
}

/// Parse a CertificateVerify message and extract its Ed25519 signature.
#[inline]
pub fn extract_certificate_verify_signature(
    cert_verify_message: &[u8],
) -> io::Result<Vec<u8>> {
    if cert_verify_message.len() < 72 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CertificateVerify message too short: {} bytes",
                cert_verify_message.len()
            ),
        ));
    }

    if cert_verify_message[0] != 0x0f {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected CertificateVerify type (0x0f), got 0x{:02x}",
                cert_verify_message[0]
            ),
        ));
    }

    let pos = 4;
    let sig_alg =
        u16::from_be_bytes([cert_verify_message[pos], cert_verify_message[pos + 1]]);
    if sig_alg != 0x0807 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unsupported signature algorithm: 0x{:04x}, expected Ed25519 (0x0807)",
                sig_alg
            ),
        ));
    }

    let sig_len = u16::from_be_bytes([
        cert_verify_message[pos + 2],
        cert_verify_message[pos + 3],
    ]) as usize;
    if sig_len != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid Ed25519 signature length: {}, expected 64", sig_len),
        ));
    }

    let sig_start = pos + 4;
    if sig_start + sig_len > cert_verify_message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CertificateVerify message truncated",
        ));
    }

    Ok(cert_verify_message[sig_start..sig_start + sig_len].to_vec())
}

/// Verify the TLS 1.3 CertificateVerify Ed25519 signature.
///
/// The signature covers 64 spaces, the server CertificateVerify context string,
/// a separator byte, and the transcript hash up to but not including CertificateVerify.
#[inline]
pub fn verify_certificate_verify_signature(
    public_key: &[u8; 32],
    signature: &[u8],
    transcript_hash: &[u8],
) -> io::Result<()> {
    if signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid signature length: {}, expected 64", signature.len()),
        ));
    }

    let mut signed_content = Vec::with_capacity(64 + 34 + transcript_hash.len());
    signed_content.extend_from_slice(&[0x20u8; 64]);
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(transcript_hash);

    let public_key = UnparsedPublicKey::new(&ED25519, public_key);
    public_key.verify(&signed_content, signature).map_err(|_| {
        tracing::warn!(
            "REALITY CLIENT: CertificateVerify signature verification failed"
        );
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "CertificateVerify signature verification failed",
        )
    })?;

    tracing::debug!(
        "REALITY CLIENT: CertificateVerify signature verified successfully"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair;

    #[test]
    fn test_verify_certificate_hmac_with_real_cert() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Failed to generate Ed25519 key pair");
        let params =
            rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
                .expect("Failed to create certificate params");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed certificate");
        let mut cert_der = cert.der().to_vec();

        let signing_key = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(
            key_pair.serialized_der(),
        )
        .expect("Failed to parse key");
        let public_key_bytes = signing_key.public_key().as_ref();

        let (_, parsed_cert) = X509Certificate::from_der(&cert_der)
            .expect("Failed to parse certificate");
        let sig_offset = parsed_cert.signature_value.data.as_ptr() as usize
            - cert_der.as_ptr() as usize;

        let auth_key = [0x42u8; 32];
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let hmac_tag = hmac::sign(&hmac_key, public_key_bytes);
        cert_der[sig_offset..sig_offset + 64].copy_from_slice(hmac_tag.as_ref());

        verify_certificate_hmac(&cert_der, &auth_key).unwrap();
    }

    #[test]
    fn test_verify_certificate_hmac_rejects_partial_signature_match() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("Failed to generate Ed25519 key pair");
        let params =
            rcgen::CertificateParams::new(vec!["test.example.com".to_string()])
                .expect("Failed to create certificate params");
        let cert = params
            .self_signed(&key_pair)
            .expect("Failed to create self-signed certificate");
        let mut cert_der = cert.der().to_vec();

        let signing_key = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(
            key_pair.serialized_der(),
        )
        .expect("Failed to parse key");
        let public_key_bytes = signing_key.public_key().as_ref();

        let (_, parsed_cert) = X509Certificate::from_der(&cert_der)
            .expect("Failed to parse certificate");
        let sig_offset = parsed_cert.signature_value.data.as_ptr() as usize
            - cert_der.as_ptr() as usize;

        let auth_key = [0x42u8; 32];
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let hmac_tag = hmac::sign(&hmac_key, public_key_bytes);
        cert_der[sig_offset..sig_offset + 32]
            .copy_from_slice(&hmac_tag.as_ref()[..32]);
        cert_der[sig_offset + 32..sig_offset + 64].fill(0);

        let result = verify_certificate_hmac(&cert_der, &auth_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_extract_certificate_verify_signature() {
        let signature = [0xABu8; 64];
        let payload_len = 2 + 2 + 64;

        let mut message = Vec::new();
        message.push(0x0f);
        message.push(0x00);
        message.push(0x00);
        message.push(payload_len as u8);
        message.push(0x08);
        message.push(0x07);
        message.push(0x00);
        message.push(0x40);
        message.extend_from_slice(&signature);

        let result = extract_certificate_verify_signature(&message).unwrap();
        assert_eq!(result, signature.to_vec());
    }

    #[test]
    fn test_verify_certificate_verify_signature_valid() {
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");
        let public_key: [u8; 32] =
            key_pair.public_key().as_ref().try_into().unwrap();
        let transcript_hash = [0x42u8; 32];

        let mut signed_content = Vec::new();
        signed_content.extend_from_slice(&[0x20u8; 64]);
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_content.push(0x00);
        signed_content.extend_from_slice(&transcript_hash);

        let signature = key_pair.sign(&signed_content);
        verify_certificate_verify_signature(
            &public_key,
            signature.as_ref(),
            &transcript_hash,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_certificate_verify_signature_wrong_transcript() {
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate()
            .expect("Failed to generate Ed25519 key pair");
        let public_key: [u8; 32] =
            key_pair.public_key().as_ref().try_into().unwrap();
        let transcript_hash = [0x42u8; 32];
        let wrong_transcript_hash = [0x43u8; 32];

        let mut signed_content = Vec::new();
        signed_content.extend_from_slice(&[0x20u8; 64]);
        signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed_content.push(0x00);
        signed_content.extend_from_slice(&transcript_hash);

        let signature = key_pair.sign(&signed_content);
        let result = verify_certificate_verify_signature(
            &public_key,
            signature.as_ref(),
            &wrong_transcript_hash,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
