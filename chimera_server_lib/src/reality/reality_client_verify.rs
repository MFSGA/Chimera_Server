// REALITY client certificate verification
//
// This module handles HMAC verification of REALITY server certificates.
// In REALITY protocol, the server embeds HMAC-SHA512(auth_key, ed25519_public_key)
// in the signature field of the certificate.

use std::io;

use aws_lc_rs::hmac;
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
/// in the signature field of the certificate. We compare the first 32 bytes.
///
/// Uses proper X.509 parsing via x509-parser crate for robust extraction.
#[inline]
pub fn verify_certificate_hmac(cert_der: &[u8], auth_key: &[u8; 32]) -> io::Result<()> {
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

    // Verify signature is long enough (should be 64 bytes for Ed25519, containing HMAC-SHA512)
    if signature.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Signature too short for HMAC verification: {} bytes",
                signature.len()
            ),
        ));
    }

    // Compute expected HMAC: HMAC-SHA512(auth_key, ed25519_public_key)
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    let hmac_tag = hmac::sign(&hmac_key, pubkey_data);
    let expected_signature = &hmac_tag.as_ref()[..32]; // First 32 bytes

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
        &signature[..32]
    );

    // Compare first 32 bytes of signature with expected HMAC using constant-time comparison
    if expected_signature.ct_eq(&signature[..32]).unwrap_u8() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Certificate HMAC verification failed - signature mismatch",
        ));
    }

    tracing::info!("REALITY CLIENT: Certificate HMAC verified successfully");
    Ok(())
}
