// Common constants and helpers shared between REALITY client and server implementations
//
// This module provides:
// - TLS constants (content types, alert codes, version bytes, handshake types)
// - Close notify alert construction

use std::io::{self, Error, ErrorKind};

use super::reality_aead::encrypt_tls13_record_for_suite;
use super::reality_cipher_suite::CipherSuite;

// TLS ContentType values
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const CONTENT_TYPE_ALERT: u8 = 0x15;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// TLS alert levels and descriptions
pub const ALERT_LEVEL_WARNING: u8 = 0x01;
pub const ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

// TLS version bytes (used on wire for compatibility)
// TLS 1.2 version bytes: 0x03, 0x03
// Used in TLS 1.3 for compatibility (appears in record layer)
pub const VERSION_TLS_1_2_MAJOR: u8 = 0x03;
pub const VERSION_TLS_1_2_MINOR: u8 = 0x03;

// TLS 1.3 handshake message types
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;

// TLS 1.3 record size limits per RFC 8446
//
// The TLS record header's `length` field specifies the size of the ENCRYPTED payload.
// Per RFC 8446, the TLS 1.3 limit is stricter than TLS 1.2:
//
// - TLS 1.3: Plaintext limit = 16,384 bytes (2^14)
//   Encryption overhead allowance = 256 bytes
//   Ciphertext limit = 16,384 + 256 = 16,640 bytes
//
// - TLS 1.2: Plaintext limit = 16,384 bytes (2^14)
//   Encryption overhead allowance = 2,048 bytes
//   Ciphertext limit = 16,384 + 2,048 = 18,432 bytes
//
// REALITY uses TLS 1.3, so we MUST use the TLS 1.3 limit. Using the larger
// TLS 1.2 limit causes "record overflow" errors in libraries like utls.

/// Maximum TLS 1.3 ciphertext payload size (16,640 bytes)
pub const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 256;

/// Maximum plaintext payload size for a single TLS 1.3 record
///
/// RFC 8446 Section 5.1: "The record layer fragments information blocks into
/// TLSPlaintext records carrying data in chunks of 2^14 bytes or less."
///
/// This is the hard limit enforced by TLS implementations.
/// The 256-byte allowance in MAX_TLS_CIPHERTEXT_LEN is for:
/// - AEAD tag (16 bytes for AES-GCM)
/// - Content type byte (1 byte)
/// - Optional padding (up to 239 bytes)
///
/// We MUST NOT exceed 16384 bytes of actual plaintext per record, or clients
/// will reject with "record overflow" error.
pub const MAX_TLS_PLAINTEXT_LEN: usize = 16384;

/// TLS record header size (ContentType + ProtocolVersion + Length)
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum TLS record size (ciphertext + header)
pub const TLS_MAX_RECORD_SIZE: usize =
    MAX_TLS_CIPHERTEXT_LEN + TLS_RECORD_HEADER_SIZE;

/// Buffer capacity for ciphertext read (2x TLS max record for safety)
pub const CIPHERTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Buffer capacity for plaintext read
pub const PLAINTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Strip TLS 1.3 content type trailer from decrypted plaintext.
///
/// TLS 1.3 format: content || type_byte. This zero-allocation helper returns
/// the content type and valid content length without mutating the input.
#[inline]
#[cfg(test)]
pub fn strip_content_type_slice(plaintext: &[u8]) -> io::Result<(u8, usize)> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    let content_type = plaintext[plaintext.len() - 1];

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok((content_type, plaintext.len() - 1))
}

/// Strip TLS 1.3 content type trailer from decrypted plaintext.
#[cfg(test)]
pub fn strip_content_type(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    let (content_type, valid_len) = strip_content_type_slice(plaintext)?;
    plaintext.truncate(valid_len);
    Ok(content_type)
}

/// Strip TLS 1.3 content type trailer and optional zero padding.
///
/// TLS 1.3 format: content || type_byte || padding_zeros. Use this for
/// records from external implementations that may add padding.
pub fn strip_content_type_with_padding(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    while !plaintext.is_empty() && *plaintext.last().unwrap() == 0 {
        plaintext.pop();
    }

    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"));
    }

    let content_type = plaintext.pop().unwrap();

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok(content_type)
}

/// Build an encrypted close_notify alert for TLS 1.3
///
/// In TLS 1.3, alerts must be encrypted like application data.
pub fn build_close_notify_alert(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    seq_num: u64,
) -> io::Result<Vec<u8>> {
    // Build alert message: level(1) + description(0) + ContentType
    let alert_with_type = vec![
        ALERT_LEVEL_WARNING,
        ALERT_DESC_CLOSE_NOTIFY,
        CONTENT_TYPE_ALERT, // ContentType byte for TLS 1.3
    ];

    // Build TLS header with correct ciphertext length
    let ciphertext_len = (alert_with_type.len() + 16) as u16; // plaintext + tag
    let mut tls_header = [
        CONTENT_TYPE_APPLICATION_DATA,
        VERSION_TLS_1_2_MAJOR,
        VERSION_TLS_1_2_MINOR,
        0x00,
        0x00, // Length will be set
    ];
    tls_header[3..5].copy_from_slice(&ciphertext_len.to_be_bytes());

    // Encrypt the alert
    let ciphertext = encrypt_tls13_record_for_suite(
        cipher_suite,
        key,
        iv,
        seq_num,
        &alert_with_type,
        &tls_header,
    )?;

    // Build complete TLS record
    let mut record = Vec::with_capacity(5 + ciphertext.len());
    record.push(CONTENT_TYPE_APPLICATION_DATA);
    record.push(VERSION_TLS_1_2_MAJOR);
    record.push(VERSION_TLS_1_2_MINOR);
    record.push(((ciphertext.len() >> 8) & 0xff) as u8);
    record.push((ciphertext.len() & 0xff) as u8);
    record.extend_from_slice(&ciphertext);

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_content_type_app_data() {
        let mut plaintext = vec![0x01, 0x02, 0x03, CONTENT_TYPE_APPLICATION_DATA];
        let content_type = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_strip_content_type_preserves_data_zeros() {
        let mut plaintext = vec![0x01, 0x00, 0x00, CONTENT_TYPE_APPLICATION_DATA];
        let content_type = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_strip_with_padding_strips_only_padding_zeros() {
        let mut plaintext =
            vec![0x01, 0x00, CONTENT_TYPE_APPLICATION_DATA, 0x00, 0x00];
        let content_type = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x00]);
    }

    #[test]
    fn test_strip_with_padding_all_zeros_fails() {
        let mut plaintext = vec![0x00, 0x00, 0x00];
        let result = strip_content_type_with_padding(&mut plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn test_strip_with_padding_rejects_invalid_type() {
        let mut plaintext = vec![0x01, 0xff, 0x00];
        let result = strip_content_type_with_padding(&mut plaintext);
        assert!(result.is_err());
    }
}
