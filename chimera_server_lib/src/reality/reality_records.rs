// TLS 1.3 record encryption with automatic fragmentation
//
// Handles encrypting plaintext into TLS records, automatically splitting
// large data into multiple records to stay within TLS 1.3 size limits.

use std::io::{self, Error, ErrorKind};

use super::common::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE,
    MAX_TLS_CIPHERTEXT_LEN, MAX_TLS_PLAINTEXT_LEN, TLS_RECORD_HEADER_SIZE,
};
use super::reality_aead::AeadKey;
#[cfg(test)]
use super::reality_cipher_suite::CipherSuite;

/// Encrypts plaintext into TLS 1.3 records.
///
/// Manages the write-side sequence number and handles record framing while
/// reusing the per-direction AEAD key across all fragmented records.
pub(crate) struct RecordEncryptor<'a> {
    key: &'a AeadKey,
    iv: &'a [u8],
    seq: &'a mut u64,
}

impl<'a> RecordEncryptor<'a> {
    #[inline]
    pub(crate) fn new(key: &'a AeadKey, iv: &'a [u8], seq: &'a mut u64) -> Self {
        Self { key, iv, seq }
    }

    /// Encrypt application data into TLS 1.3 records.
    #[inline]
    pub(crate) fn encrypt_app_data(
        &mut self,
        plaintext: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        if plaintext.is_empty() {
            return Ok(());
        }

        if plaintext.len() <= MAX_TLS_PLAINTEXT_LEN {
            let original_len = plaintext.len();
            if let Err(err) = self.encrypt_record_in_place(
                plaintext,
                out,
                CONTENT_TYPE_APPLICATION_DATA,
            ) {
                plaintext.truncate(original_len);
                return Err(err);
            }
        } else {
            let total_len = plaintext.len();
            let num_records = total_len.div_ceil(MAX_TLS_PLAINTEXT_LEN);
            tracing::debug!(
                "REALITY: Fragmenting {} bytes into {} TLS records (max {} bytes/record)",
                total_len,
                num_records,
                MAX_TLS_PLAINTEXT_LEN
            );
            self.encrypt_fragmented(plaintext, out, CONTENT_TYPE_APPLICATION_DATA)?;
        }

        plaintext.clear();
        Ok(())
    }

    /// Encrypt handshake data into TLS 1.3 records.
    #[inline]
    pub(crate) fn encrypt_handshake(
        &mut self,
        handshake_data: &[u8],
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        if handshake_data.is_empty() {
            return Ok(());
        }

        if handshake_data.len() <= MAX_TLS_PLAINTEXT_LEN {
            let mut buf = handshake_data.to_vec();
            self.encrypt_record_in_place(&mut buf, out, CONTENT_TYPE_HANDSHAKE)?;
        } else {
            let total_len = handshake_data.len();
            let num_records = total_len.div_ceil(MAX_TLS_PLAINTEXT_LEN);
            tracing::debug!(
                "REALITY: Fragmenting {} bytes of handshake data into {} TLS records (max {} bytes/record)",
                total_len,
                num_records,
                MAX_TLS_PLAINTEXT_LEN
            );
            self.encrypt_fragmented(handshake_data, out, CONTENT_TYPE_HANDSHAKE)?;
        }

        Ok(())
    }

    /// Encrypt handshake data with TLS 1.3 inner padding to match a target record size.
    ///
    /// `target_record_size` includes the 5-byte TLS record header. If it is zero,
    /// smaller than the minimum ciphertext, or too large for one TLS record, no
    /// padding is added.
    #[inline]
    pub(crate) fn encrypt_handshake_with_padding(
        &mut self,
        handshake_data: &[u8],
        out: &mut Vec<u8>,
        target_record_size: usize,
    ) -> io::Result<()> {
        if handshake_data.is_empty() {
            return Ok(());
        }

        if handshake_data.len() > MAX_TLS_PLAINTEXT_LEN {
            let chunks: Vec<_> =
                handshake_data.chunks(MAX_TLS_PLAINTEXT_LEN).collect();
            for (idx, chunk) in chunks.iter().enumerate() {
                let mut buf = chunk.to_vec();
                if idx == chunks.len() - 1 && target_record_size > 0 {
                    self.encrypt_record_with_padding(
                        &mut buf,
                        out,
                        CONTENT_TYPE_HANDSHAKE,
                        target_record_size,
                    )?;
                } else {
                    self.encrypt_record_in_place(
                        &mut buf,
                        out,
                        CONTENT_TYPE_HANDSHAKE,
                    )?;
                }
            }
            return Ok(());
        }

        let mut buf = handshake_data.to_vec();
        if target_record_size > 0 {
            self.encrypt_record_with_padding(
                &mut buf,
                out,
                CONTENT_TYPE_HANDSHAKE,
                target_record_size,
            )?;
        } else {
            self.encrypt_record_in_place(&mut buf, out, CONTENT_TYPE_HANDSHAKE)?;
        }

        Ok(())
    }

    /// Encrypt a close_notify alert into a TLS 1.3 record.
    #[inline]
    pub(crate) fn encrypt_close_notify(
        &mut self,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        let mut alert = vec![0x01, 0x00];
        self.encrypt_record_in_place(&mut alert, out, CONTENT_TYPE_ALERT)
    }

    /// Encrypt a single TLS 1.3 record in-place and append it to `out`.
    #[inline]
    fn encrypt_record_in_place(
        &mut self,
        buf: &mut Vec<u8>,
        out: &mut Vec<u8>,
        content_type: u8,
    ) -> io::Result<()> {
        let next_seq = checked_next_sequence(*self.seq)?;

        // Match shoes: reserve only the TLS inner content-type byte and AEAD tag
        // so a full plaintext record does not double its retained Vec capacity.
        buf.reserve_exact(1 + 16);
        buf.push(content_type);
        let ciphertext_len = buf.len() + 16;
        debug_assert!(
            ciphertext_len <= MAX_TLS_CIPHERTEXT_LEN,
            "BUG: ciphertext_len {} exceeds MAX_TLS_CIPHERTEXT_LEN {}",
            ciphertext_len,
            MAX_TLS_CIPHERTEXT_LEN
        );

        let header = make_record_header(ciphertext_len);
        self.key.seal_in_place(buf, self.iv, *self.seq, &header)?;
        *self.seq = next_seq;

        out.reserve(TLS_RECORD_HEADER_SIZE + buf.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(buf);

        Ok(())
    }

    /// Encrypt a single TLS 1.3 record and add zero padding after the inner content type.
    #[inline]
    fn encrypt_record_with_padding(
        &mut self,
        buf: &mut Vec<u8>,
        out: &mut Vec<u8>,
        content_type: u8,
        target_record_size: usize,
    ) -> io::Result<()> {
        let next_seq = checked_next_sequence(*self.seq)?;

        buf.push(content_type);

        let current_inner_len = buf.len();
        let target_inner_len =
            target_record_size.saturating_sub(TLS_RECORD_HEADER_SIZE + 16);
        if target_inner_len > current_inner_len
            && target_inner_len <= MAX_TLS_PLAINTEXT_LEN + 1
        {
            let padding = target_inner_len - current_inner_len;
            buf.resize(buf.len() + padding, 0);
            tracing::trace!(
                "REALITY: Added {} bytes of TLS 1.3 inner padding (target={}, current={})",
                padding,
                target_record_size,
                TLS_RECORD_HEADER_SIZE + current_inner_len + 16
            );
        }

        let ciphertext_len = buf.len() + 16;
        debug_assert!(
            ciphertext_len <= MAX_TLS_CIPHERTEXT_LEN,
            "BUG: ciphertext_len {} exceeds MAX_TLS_CIPHERTEXT_LEN {}",
            ciphertext_len,
            MAX_TLS_CIPHERTEXT_LEN
        );

        let header = make_record_header(ciphertext_len);
        self.key.seal_in_place(buf, self.iv, *self.seq, &header)?;
        *self.seq = next_seq;

        out.reserve(TLS_RECORD_HEADER_SIZE + buf.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(buf);

        Ok(())
    }

    /// Encrypt data larger than 16KB by fragmenting into multiple records.
    #[inline]
    fn encrypt_fragmented(
        &mut self,
        data: &[u8],
        out: &mut Vec<u8>,
        content_type: u8,
    ) -> io::Result<()> {
        for chunk in data.chunks(MAX_TLS_PLAINTEXT_LEN) {
            let mut buf = chunk.to_vec();
            self.encrypt_record_in_place(&mut buf, out, content_type)?;
        }
        Ok(())
    }
}

/// Decrypts TLS 1.3 records into plaintext.
///
/// Manages the read-side sequence number and strips the TLS 1.3 inner content
/// type plus optional zero padding from decrypted records.
pub(crate) struct RecordDecryptor<'a> {
    key: &'a AeadKey,
    iv: &'a [u8],
    seq: &'a mut u64,
}

impl<'a> RecordDecryptor<'a> {
    #[inline]
    pub(crate) fn new(key: &'a AeadKey, iv: &'a [u8], seq: &'a mut u64) -> Self {
        Self { key, iv, seq }
    }

    /// Decrypt a TLS 1.3 record in-place, returning content type and plaintext.
    #[inline]
    pub(crate) fn decrypt_record_in_place<'b>(
        &mut self,
        ciphertext: &'b mut [u8],
        record_len: u16,
    ) -> io::Result<(u8, &'b [u8])> {
        let next_seq = checked_next_sequence(*self.seq)?;
        let aad = make_record_header(record_len as usize);

        let plaintext = self
            .key
            .open_in_place_slice(ciphertext, self.iv, *self.seq, &aad)?;
        *self.seq = next_seq;

        let mut valid_end = plaintext.len();
        while valid_end > 0 && plaintext[valid_end - 1] == 0 {
            valid_end -= 1;
        }
        if valid_end == 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Plaintext is all zeros",
            ));
        }

        let content_type = plaintext[valid_end - 1];
        valid_end -= 1;

        if !matches!(
            content_type,
            CONTENT_TYPE_HANDSHAKE
                | CONTENT_TYPE_APPLICATION_DATA
                | CONTENT_TYPE_ALERT
        ) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid content type: 0x{content_type:02x}"),
            ));
        }

        Ok((content_type, &plaintext[..valid_end]))
    }
}

#[inline]
fn make_record_header(ciphertext_len: usize) -> [u8; TLS_RECORD_HEADER_SIZE] {
    [
        CONTENT_TYPE_APPLICATION_DATA,
        0x03,
        0x03, // TLS 1.2 version for compatibility
        (ciphertext_len >> 8) as u8,
        (ciphertext_len & 0xff) as u8,
    ]
}

/// Encrypt plaintext into TLS 1.3 application data records, fragmenting if necessary.
///
/// This function handles the TLS 1.3 record size limit by splitting large plaintext
/// into multiple records of at most `MAX_TLS_PLAINTEXT_LEN` bytes each.
///
/// # Arguments
/// * `plaintext` - The plaintext data to encrypt (will be cleared after encryption)
/// * `app_write_key` - The application traffic key (16 bytes for AES-128-GCM)
/// * `app_write_iv` - The application traffic IV (12 bytes)
/// * `write_seq` - Mutable reference to the write sequence number (incremented per record)
/// * `ciphertext_buf` - Buffer to append encrypted TLS records to
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if encryption fails
#[inline]
#[cfg(test)]
pub fn encrypt_plaintext_to_records(
    plaintext: &mut Vec<u8>,
    app_write_key: &[u8],
    app_write_iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    encrypt_plaintext_to_records_for_suite(
        CipherSuite::AES_128_GCM_SHA256,
        plaintext,
        app_write_key,
        app_write_iv,
        write_seq,
        ciphertext_buf,
    )
}

/// Encrypt plaintext into TLS 1.3 application data records for a selected cipher suite.
#[inline]
#[cfg(test)]
pub(crate) fn encrypt_plaintext_to_records_for_suite(
    cipher_suite: CipherSuite,
    plaintext: &mut Vec<u8>,
    app_write_key: &[u8],
    app_write_iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    if plaintext.is_empty() {
        return Ok(());
    }

    let aead_key = AeadKey::new(cipher_suite, app_write_key)?;
    let mut encryptor = RecordEncryptor::new(&aead_key, app_write_iv, write_seq);
    encryptor.encrypt_app_data(plaintext, ciphertext_buf)
}

#[inline]
fn checked_next_sequence(seq: u64) -> io::Result<u64> {
    seq.checked_add(1)
        .ok_or_else(|| Error::other("TLS sequence number exhausted"))
}

/// Encrypt handshake data into TLS 1.3 records, fragmenting if necessary.
///
/// This function handles the TLS 1.3 record size limit by splitting large handshake
/// data into multiple records of at most `MAX_TLS_PLAINTEXT_LEN` bytes each.
///
/// Unlike application data encryption, handshake records use content type 0x16 (handshake)
/// inside the encrypted payload, though the outer record type is still 0x17 (application_data)
/// as per TLS 1.3 encrypted record format.
///
/// # Arguments
/// * `handshake_data` - The combined handshake messages to encrypt
/// * `key` - The handshake traffic key (16 bytes for AES-128-GCM)
/// * `iv` - The handshake traffic IV (12 bytes)
/// * `write_seq` - Mutable reference to the write sequence number (incremented per record)
/// * `ciphertext_buf` - Buffer to append encrypted TLS records to
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if encryption fails
#[inline]
#[cfg(test)]
pub fn encrypt_handshake_to_records(
    handshake_data: &[u8],
    key: &[u8],
    iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    encrypt_handshake_to_records_for_suite(
        CipherSuite::AES_128_GCM_SHA256,
        handshake_data,
        key,
        iv,
        write_seq,
        ciphertext_buf,
    )
}

/// Encrypt handshake data into TLS 1.3 records for a selected cipher suite.
#[inline]
#[cfg(test)]
pub(crate) fn encrypt_handshake_to_records_for_suite(
    cipher_suite: CipherSuite,
    handshake_data: &[u8],
    key: &[u8],
    iv: &[u8],
    write_seq: &mut u64,
    ciphertext_buf: &mut Vec<u8>,
) -> io::Result<()> {
    if handshake_data.is_empty() {
        return Ok(());
    }

    let aead_key = AeadKey::new(cipher_suite, key)?;
    let mut encryptor = RecordEncryptor::new(&aead_key, iv, write_seq);
    encryptor.encrypt_handshake(handshake_data, ciphertext_buf)
}

#[cfg(test)]
mod tests;
