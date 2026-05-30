// TLS 1.3 Encryption/Decryption Helpers
//
// AES-GCM encryption for TLS 1.3 records using aws-lc-rs

use std::io::{Error, ErrorKind, Result};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use super::common::{
    VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR, strip_content_type_with_padding,
};
use super::reality_cipher_suite::CipherSuite;

/// AEAD key for TLS 1.3 record encryption and decryption.
///
/// Mirrors shoes' reusable key wrapper so the record layer can move away from
/// rebuilding AEAD keys for every record without changing today's AES-128 path.
pub(crate) struct AeadKey(LessSafeKey);

impl AeadKey {
    /// Create an AEAD key for a selected TLS 1.3 cipher suite.
    pub(crate) fn new(cipher_suite: CipherSuite, key: &[u8]) -> Result<Self> {
        let expected_len = cipher_suite.key_len();
        if key.len() != expected_len {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Invalid key length for {}: {} (expected {})",
                    cipher_suite,
                    key.len(),
                    expected_len
                ),
            ));
        }

        let unbound_key =
            UnboundKey::new(cipher_suite.algorithm(), key).map_err(|e| {
                Error::new(ErrorKind::InvalidInput, format!("Invalid key: {e:?}"))
            })?;

        Ok(Self(LessSafeKey::new(unbound_key)))
    }

    /// Encrypt in-place, appending the AEAD authentication tag.
    pub(crate) fn seal_in_place(
        &self,
        buf: &mut Vec<u8>,
        iv: &[u8],
        sequence_number: u64,
        additional_data: &[u8],
    ) -> Result<()> {
        let nonce = Self::make_nonce(iv, sequence_number)?;
        self.0
            .seal_in_place_append_tag(nonce, Aad::from(additional_data), buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Encryption failed: {e:?}"),
                )
            })
    }

    /// Encrypt by copying plaintext into an owned buffer.
    pub(crate) fn seal(
        &self,
        plaintext: &[u8],
        iv: &[u8],
        sequence_number: u64,
        additional_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut in_out = plaintext.to_vec();
        self.seal_in_place(&mut in_out, iv, sequence_number, additional_data)?;
        Ok(in_out)
    }

    /// Decrypt in-place and return the plaintext portion of the provided buffer.
    pub(crate) fn open_in_place_slice<'a>(
        &self,
        buf: &'a mut [u8],
        iv: &[u8],
        sequence_number: u64,
        additional_data: &[u8],
    ) -> Result<&'a mut [u8]> {
        let nonce = Self::make_nonce(iv, sequence_number)?;
        self.0
            .open_in_place(nonce, Aad::from(additional_data), buf)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Decryption failed: {e:?}"),
                )
            })
    }

    /// Decrypt by copying ciphertext into an owned buffer.
    pub(crate) fn open(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        sequence_number: u64,
        additional_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut in_out = ciphertext.to_vec();
        let plaintext = self.open_in_place_slice(
            &mut in_out,
            iv,
            sequence_number,
            additional_data,
        )?;
        let plaintext_len = plaintext.len();
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }

    /// Construct TLS 1.3 nonce: base IV XOR sequence number.
    fn make_nonce(iv: &[u8], sequence_number: u64) -> Result<Nonce> {
        if iv.len() != 12 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid IV length: {} (expected 12)", iv.len()),
            ));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(iv);

        let seq_bytes = sequence_number.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }

        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|e| {
            Error::new(ErrorKind::InvalidInput, format!("Invalid nonce: {e:?}"))
        })
    }
}

pub(crate) fn encrypt_tls13_record_for_suite(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    AeadKey::new(cipher_suite, key)?.seal(
        plaintext,
        iv,
        sequence_number,
        additional_data,
    )
}

pub(crate) fn decrypt_tls13_record_for_suite(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    ciphertext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    AeadKey::new(cipher_suite, key)?.open(
        ciphertext,
        iv,
        sequence_number,
        additional_data,
    )
}

/// Encrypt TLS 1.3 record using AES-128-GCM.
///
/// # Arguments
/// * `key` - AES key (16 bytes for AES-128)
/// * `iv` - Base IV (12 bytes)
/// * `sequence_number` - TLS record sequence number
/// * `plaintext` - Plaintext data (including ContentType trailer)
/// * `additional_data` - TLS record header for AEAD
///
/// # Returns
/// Ciphertext with authentication tag appended
#[cfg(test)]
pub fn encrypt_tls13_record(
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    encrypt_tls13_record_for_suite(
        CipherSuite::AES_128_GCM_SHA256,
        key,
        iv,
        sequence_number,
        plaintext,
        additional_data,
    )
}

/// Decrypt TLS 1.3 record using AES-128-GCM
///
/// # Arguments
/// * `key` - AES key (16 bytes for AES-128)
/// * `iv` - Base IV (12 bytes)
/// * `sequence_number` - TLS record sequence number
/// * `ciphertext` - Ciphertext with authentication tag
/// * `additional_data` - TLS record header for AEAD
///
/// # Returns
/// Plaintext data (including ContentType trailer)
#[cfg(test)]
pub fn decrypt_tls13_record(
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    ciphertext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    decrypt_tls13_record_for_suite(
        CipherSuite::AES_128_GCM_SHA256,
        key,
        iv,
        sequence_number,
        ciphertext,
        additional_data,
    )
}

/// Decrypt TLS 1.3 handshake message
///
/// Decrypts and extracts handshake message, removing ContentType trailer
pub(crate) fn decrypt_handshake_message_for_suite(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    ciphertext: &[u8],
    record_length: u16,
) -> Result<Vec<u8>> {
    // Additional data for decryption
    let mut additional_data = Vec::new();
    additional_data.push(0x17); // ApplicationData
    additional_data
        .extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]); // TLS 1.2
    additional_data.extend_from_slice(&record_length.to_be_bytes());

    let mut plaintext = decrypt_tls13_record_for_suite(
        cipher_suite,
        key,
        iv,
        sequence_number,
        ciphertext,
        &additional_data,
    )?;

    let _ = strip_content_type_with_padding(&mut plaintext)?;

    Ok(plaintext)
}

/// Decrypt TLS 1.3 handshake message using AES-128-GCM.
///
/// Decrypts and extracts handshake message, removing ContentType trailer.
#[cfg(test)]
pub fn decrypt_handshake_message(
    key: &[u8],
    iv: &[u8],
    sequence_number: u64,
    ciphertext: &[u8],
    record_length: u16,
) -> Result<Vec<u8>> {
    decrypt_handshake_message_for_suite(
        CipherSuite::AES_128_GCM_SHA256,
        key,
        iv,
        sequence_number,
        ciphertext,
        record_length,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_record() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Hello, TLS 1.3!";
        let aad = b"additional data";

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        let decrypted =
            decrypt_tls13_record(&key, &iv, 0, &ciphertext, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aead_key_uses_cipher_suite_metadata() {
        for cipher_suite in [
            CipherSuite::AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384,
            CipherSuite::CHACHA20_POLY1305_SHA256,
        ] {
            let key = vec![0x42u8; cipher_suite.key_len()];
            let iv = vec![0x99u8; cipher_suite.nonce_len()];
            let plaintext = b"cipher suite aware record";
            let aad = b"additional data";

            let aead_key = AeadKey::new(cipher_suite, &key).unwrap();
            let ciphertext = aead_key.seal(plaintext, &iv, 7, aad).unwrap();
            let decrypted = aead_key.open(&ciphertext, &iv, 7, aad).unwrap();

            assert_eq!(&decrypted[..], plaintext);
        }
    }

    #[test]
    fn test_aead_key_rejects_wrong_cipher_suite_key_length() {
        let result = AeadKey::new(CipherSuite::AES_256_GCM_SHA384, &[0u8; 16]);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_roundtrip_handshake() {
        let key = vec![0x11u8; 16];
        let iv = vec![0x22u8; 12];
        let handshake_msg = vec![0x33u8; 50];

        // Manually encrypt like encrypt_handshake_to_records does
        let mut plaintext = handshake_msg.clone();
        plaintext.push(0x16); // ContentType: Handshake

        let ciphertext_length = (plaintext.len() + 16) as u16;
        let aad: [u8; 5] = [
            0x17, // ApplicationData
            0x03,
            0x03, // TLS 1.2
            (ciphertext_length >> 8) as u8,
            (ciphertext_length & 0xff) as u8,
        ];

        let ciphertext =
            encrypt_tls13_record(&key, &iv, 0, &plaintext, &aad).unwrap();

        let decrypted =
            decrypt_handshake_message(&key, &iv, 0, &ciphertext, ciphertext_length)
                .unwrap();

        assert_eq!(decrypted, handshake_msg);
    }

    #[test]
    fn test_encrypt_with_sequence_number() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test with sequence";
        let aad = b"aad";

        // Test that different sequence numbers produce different ciphertexts
        let cipher1 = encrypt_tls13_record(&key, &iv, 1, plaintext, aad).unwrap();
        let cipher2 = encrypt_tls13_record(&key, &iv, 2, plaintext, aad).unwrap();
        let cipher3 = encrypt_tls13_record(&key, &iv, 100, plaintext, aad).unwrap();

        // Ciphertexts should all be different
        assert_ne!(cipher1, cipher2);
        assert_ne!(cipher2, cipher3);
        assert_ne!(cipher1, cipher3);

        // But they should all decrypt correctly
        let decrypt1 = decrypt_tls13_record(&key, &iv, 1, &cipher1, aad).unwrap();
        let decrypt2 = decrypt_tls13_record(&key, &iv, 2, &cipher2, aad).unwrap();
        let decrypt3 = decrypt_tls13_record(&key, &iv, 100, &cipher3, aad).unwrap();

        assert_eq!(decrypt1, plaintext);
        assert_eq!(decrypt2, plaintext);
        assert_eq!(decrypt3, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_sequence_number() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test sequence";
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 5, plaintext, aad).unwrap();

        // Decrypting with wrong sequence number should fail
        let result = decrypt_tls13_record(&key, &iv, 6, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test AAD";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        // Decrypting with wrong AAD should fail
        let result = decrypt_tls13_record(&key, &iv, 0, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let invalid_key = vec![0x42u8; 15]; // Wrong length (not 16)
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test";
        let aad = b"aad";

        let result = encrypt_tls13_record(&invalid_key, &iv, 0, plaintext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_encrypt_invalid_iv_length() {
        let key = vec![0x42u8; 16];
        let invalid_iv = vec![0x99u8; 11]; // Wrong length (not 12)
        let plaintext = b"Test";
        let aad = b"aad";

        let result = encrypt_tls13_record(&key, &invalid_iv, 0, plaintext, aad);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test corruption";
        let aad = b"aad";

        let mut ciphertext =
            encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        // Corrupt the ciphertext
        ciphertext[5] ^= 0xFF;

        let result = decrypt_tls13_record(&key, &iv, 0, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let ciphertext = encrypt_tls13_record(&key, &iv, 0, plaintext, aad).unwrap();

        // Should still produce a ciphertext with auth tag
        assert!(ciphertext.len() >= 16); // At least the auth tag

        let decrypted =
            decrypt_tls13_record(&key, &iv, 0, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = vec![0xAB; 16384]; // 16KB
        let aad = b"aad";

        let ciphertext =
            encrypt_tls13_record(&key, &iv, 42, &plaintext, aad).unwrap();
        let decrypted =
            decrypt_tls13_record(&key, &iv, 42, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
