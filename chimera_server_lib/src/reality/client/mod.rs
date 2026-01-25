mod handshake;
mod process;

use std::io::{self, Read, Write};

use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::encrypt_plaintext_to_records;
use super::slide_buffer::SlideBuffer;
use crate::reality::common::{self, CIPHERTEXT_READ_BUF_CAPACITY, PLAINTEXT_READ_BUF_CAPACITY};
use handshake::generate_client_hello;
use process::{process_application_data, process_encrypted_handshake, process_server_hello};

/// Configuration for REALITY client connections
#[derive(Clone)]
pub struct RealityClientConfig {
    /// Server's X25519 public key (32 bytes)
    pub public_key: [u8; 32],
    /// Short ID for authentication (8 bytes)
    pub short_id: [u8; 8],
    /// Server name for SNI
    pub server_name: String,
}

/// Handshake state machine for REALITY client
enum HandshakeState {
    /// ClientHello sent, waiting for ServerHello
    AwaitingServerHello {
        client_hello_hash: [u8; 32],
        client_hello_bytes: Vec<u8>, // Full ClientHello handshake message
        client_private_key: [u8; 32],
        auth_key: [u8; 32], // REALITY authentication key for HMAC verification
    },
    /// ServerHello received, processing encrypted handshake messages
    ProcessingHandshake {
        client_handshake_traffic_secret: Vec<u8>,
        server_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: u16,
        handshake_transcript_bytes: Vec<u8>, // Accumulated transcript for hash computation
        auth_key: [u8; 32],                  // REALITY authentication key for HMAC verification
    },
    /// Handshake complete, ready for application data
    Complete,
}

/// REALITY client-side connection implementing rustls-compatible API
pub struct RealityClientConnection {
    // Configuration
    pub(super) config: RealityClientConfig,

    // Handshake state
    pub(super) handshake_state: HandshakeState,

    // TLS 1.3 application traffic encryption (post-handshake)
    pub(super) app_read_key: Option<Vec<u8>>,
    pub(super) app_read_iv: Option<Vec<u8>>,
    pub(super) app_write_key: Option<Vec<u8>>,
    pub(super) app_write_iv: Option<Vec<u8>>,
    pub(super) read_seq: u64,
    pub(super) write_seq: u64,
    pub(super) cipher_suite: u16,

    // Pre-allocated buffer for TLS read operations (reused across calls)
    pub(super) tls_read_buffer: Box<[u8; common::TLS_MAX_RECORD_SIZE]>,

    // Buffers for I/O - using SlideBuffer for efficient zero-alloc operations
    pub(super) ciphertext_read_buf: SlideBuffer, // Incoming encrypted TLS records
    pub(super) ciphertext_write_buf: Vec<u8>,    // Outgoing encrypted TLS records
    pub(super) plaintext_read_buf: SlideBuffer,  // Decrypted application data
    pub(super) plaintext_write_buf: Vec<u8>,     // Application data to encrypt
}

impl RealityClientConnection {
    /// Create a new REALITY client connection and generate ClientHello
    pub fn new(config: RealityClientConfig) -> io::Result<Self> {
        let mut conn = RealityClientConnection {
            config,
            handshake_state: HandshakeState::AwaitingServerHello {
                client_hello_hash: [0u8; 32],
                client_hello_bytes: Vec::new(),
                client_private_key: [0u8; 32],
                auth_key: [0u8; 32],
            },
            app_read_key: None,
            app_read_iv: None,
            app_write_key: None,
            app_write_iv: None,
            read_seq: 0,
            write_seq: 0,
            cipher_suite: 0,
            tls_read_buffer: Box::new([0u8; common::TLS_MAX_RECORD_SIZE]),
            ciphertext_read_buf: SlideBuffer::new(CIPHERTEXT_READ_BUF_CAPACITY),
            ciphertext_write_buf: Vec::with_capacity(CIPHERTEXT_READ_BUF_CAPACITY),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::with_capacity(common::TLS_MAX_RECORD_SIZE),
        };

        // Generate ClientHello immediately
        generate_client_hello(&mut conn)?;

        Ok(conn)
    }

    /// Read TLS messages from the provided reader into internal buffer
    ///
    /// Uses pre-allocated buffer to avoid allocation on every call.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        // Compact if remaining capacity is insufficient for a full TLS record
        if self.ciphertext_read_buf.remaining_capacity() < common::TLS_MAX_RECORD_SIZE {
            self.ciphertext_read_buf.compact();
        }

        // Read into pre-allocated buffer
        let n = rd.read(&mut self.tls_read_buffer[..])?;
        if n > 0 {
            self.ciphertext_read_buf
                .extend_from_slice(&self.tls_read_buffer[..n]);
        }
        Ok(n)
    }

    /// Process buffered packets and advance state machine
    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        match &self.handshake_state {
            HandshakeState::AwaitingServerHello { .. } => {
                process_server_hello(self)?;
            }
            HandshakeState::ProcessingHandshake { .. } => {
                process_encrypted_handshake(self)?;
            }
            HandshakeState::Complete => {
                process_application_data(self)?;
            }
        }

        Ok(RealityIoState::new(self.plaintext_read_buf.len()))
    }

    /// Get a reader for accessing decrypted plaintext
    pub fn reader(&mut self) -> RealityReader<'_> {
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf)
    }

    /// Get a writer for buffering plaintext to be encrypted
    pub fn writer(&mut self) -> RealityWriter<'_> {
        RealityWriter::new(&mut self.plaintext_write_buf)
    }

    /// Write buffered TLS messages to the provided writer
    ///
    /// Large plaintext is automatically fragmented into multiple TLS records
    /// to comply with the TLS 1.3 record size limit.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        // If handshake not complete, just write buffered handshake data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            let n = wr.write(&self.ciphertext_write_buf)?;
            self.ciphertext_write_buf.drain(..n);
            return Ok(n);
        }

        // Encrypt any pending plaintext (with automatic fragmentation for large data)
        if !self.plaintext_write_buf.is_empty() {
            let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Application keys not available",
                    ))
                }
            };

            encrypt_plaintext_to_records(
                &mut self.plaintext_write_buf,
                app_write_key,
                app_write_iv,
                &mut self.write_seq,
                &mut self.ciphertext_write_buf,
            )?;
        }

        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    /// Check if the connection wants to write data
    pub fn wants_write(&self) -> bool {
        !self.ciphertext_write_buf.is_empty() || !self.plaintext_write_buf.is_empty()
    }

    /// Check if handshake is still in progress
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.handshake_state, HandshakeState::Complete)
    }

    /// Queue a close notification alert
    pub fn send_close_notify(&mut self) {
        // In TLS 1.3, alerts must be encrypted like application data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            tracing::debug!("REALITY CLIENT: Cannot send close_notify - handshake not complete");
            return;
        }

        // Get application keys
        let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => {
                tracing::debug!(
                    "REALITY CLIENT: Cannot send close_notify - application keys not available"
                );
                return;
            }
        };

        // Use common helper to build encrypted close_notify alert
        match common::build_close_notify_alert(app_write_key, app_write_iv, self.write_seq) {
            Ok(record) => {
                self.write_seq += 1;
                self.ciphertext_write_buf.extend_from_slice(&record);
                tracing::debug!("REALITY CLIENT: Encrypted close_notify alert queued");
            }
            Err(e) => {
                tracing::error!("REALITY CLIENT: Failed to encrypt close_notify: {}", e);
            }
        }
    }
}

#[inline(always)]
pub fn feed_reality_client_connection(
    client_connection: &mut RealityClientConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = client_connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed TLS connection: {e}"),
            )
        })?;
        i += n;
    }
    Ok(())
}
