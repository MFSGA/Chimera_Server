use std::io::{self, Write};

use super::{HandshakeState, RealityServerConnection};
use crate::reality::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA, TLS_RECORD_HEADER_SIZE,
};
use crate::reality::reality_reader_writer::{RealityReader, RealityWriter};
use crate::reality::reality_records::{RecordDecryptor, RecordEncryptor};

impl RealityServerConnection {
    /// Decrypt application data using TLS 1.3 keys.
    pub(super) fn process_application_data(&mut self) -> io::Result<()> {
        let (app_read_key, app_read_iv) =
            match (&self.app_read_key, &self.app_read_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => return Ok(()),
            };

        while self.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
            let record_len =
                self.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
                })? as usize;
            let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
            if self.ciphertext_read_buf.len() < total_record_len {
                break;
            }

            let mut received_close_notify = false;
            let mut pending_error = None;
            {
                let ciphertext = self
                    .ciphertext_read_buf
                    .slice_mut(TLS_RECORD_HEADER_SIZE..total_record_len);
                let mut decryptor = RecordDecryptor::new(
                    app_read_key,
                    app_read_iv,
                    &mut self.read_seq,
                );
                let (content_type, plaintext) = decryptor
                    .decrypt_record_in_place(ciphertext, record_len as u16)?;

                match content_type {
                    CONTENT_TYPE_APPLICATION_DATA => {
                        self.plaintext_read_buf.maybe_compact(4096);
                        self.plaintext_read_buf.extend_from_slice(plaintext);
                    }
                    CONTENT_TYPE_ALERT => {
                        if plaintext.len() >= 2 {
                            let alert_level = plaintext[0];
                            let alert_desc = plaintext[1];

                            if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                                tracing::debug!(
                                    "REALITY: Received close_notify alert"
                                );
                                self.received_close_notify = true;
                                received_close_notify = true;
                            } else if alert_level != ALERT_LEVEL_WARNING {
                                tracing::warn!(
                                    "REALITY: Received fatal alert: level={}, desc={}",
                                    alert_level,
                                    alert_desc
                                );
                                pending_error = Some(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    format!("received fatal alert: {}", alert_desc),
                                ));
                            } else {
                                tracing::debug!(
                                    "REALITY: Received warning alert: desc={}",
                                    alert_desc
                                );
                            }
                        }
                    }
                    _ => {
                        pending_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "unexpected post-handshake content type: 0x{:02x}",
                                content_type
                            ),
                        ));
                    }
                }
            }
            self.ciphertext_read_buf.consume(total_record_len);

            if let Some(err) = pending_error {
                return Err(err);
            }
            if received_close_notify {
                return Ok(());
            }
            // Xray may append raw inner-TLS bytes immediately after the outer
            // record carrying Vision Direct. Return after one outer record so
            // VisionReader can inspect the command before we touch rawInput.
            if self.vision_direct_transition {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Get a reader for accessing decrypted plaintext.
    pub fn reader(&mut self) -> RealityReader<'_> {
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf, self.received_close_notify)
    }

    /// Get a writer for buffering plaintext to be encrypted.
    pub fn writer(&mut self) -> RealityWriter<'_> {
        RealityWriter::new(
            &mut self.plaintext_write_buf,
            self.ciphertext_write_buf.len(),
        )
    }

    /// Write buffered TLS messages to the provided writer.
    ///
    /// This encrypts any pending plaintext and writes ciphertext. Large
    /// plaintext is automatically fragmented into TLS-sized records.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            let n = wr.write(&self.ciphertext_write_buf)?;
            self.ciphertext_write_buf.drain(..n);
            return Ok(n);
        }

        if !self.plaintext_write_buf.is_empty() {
            let (app_write_key, app_write_iv) =
                match (&self.app_write_key, &self.app_write_iv) {
                    (Some(key), Some(iv)) => (key, iv),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Application keys not available",
                        ));
                    }
                };

            let mut encryptor = RecordEncryptor::new(
                app_write_key,
                app_write_iv,
                &mut self.write_seq,
            );
            encryptor.encrypt_app_data(
                &mut self.plaintext_write_buf,
                &mut self.ciphertext_write_buf,
            )?;
        }

        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    pub fn wants_write(&self) -> bool {
        !self.ciphertext_write_buf.is_empty() || !self.plaintext_write_buf.is_empty()
    }

    pub fn wants_read(&self) -> bool {
        if self.received_close_notify || self.fatal_error.is_some() {
            return false;
        }
        if self.is_handshaking() {
            return true;
        }
        self.plaintext_read_buf.is_empty()
    }

    pub fn is_handshaking(&self) -> bool {
        !matches!(self.handshake_state, HandshakeState::Complete)
    }

    /// Drain unread bytes still buffered as would-be ciphertext.
    ///
    /// After the VISION direct-mode transition, post-splice raw TCP bytes can
    /// already be buffered here. They are no longer REALITY records and must be
    /// passed back to the raw transport path.
    pub fn take_remaining_ciphertext(&mut self) -> Vec<u8> {
        let pending = self.ciphertext_read_buf.as_slice().to_vec();
        self.ciphertext_read_buf.consume(pending.len());
        pending
    }

    /// Preserve record boundaries while a Vision stream may switch to raw TCP.
    pub fn enable_vision_direct_transition(&mut self) {
        self.vision_direct_transition = true;
    }

    /// Queue a close notification alert.
    pub fn send_close_notify(&mut self) {
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            tracing::debug!(
                "REALITY: Cannot send close_notify - handshake not complete"
            );
            return;
        }

        let (app_write_key, app_write_iv) = match (
            &self.app_write_key,
            &self.app_write_iv,
        ) {
            (Some(key), Some(iv)) => (key, iv),
            _ => {
                tracing::debug!(
                    "REALITY: Cannot send close_notify - application keys not available"
                );
                return;
            }
        };

        let mut encryptor =
            RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
        match encryptor.encrypt_close_notify(&mut self.ciphertext_write_buf) {
            Ok(()) => {
                tracing::debug!("REALITY: Encrypted close_notify alert queued")
            }
            Err(e) => {
                tracing::error!("REALITY: Failed to encrypt close_notify: {}", e)
            }
        }
    }
}
