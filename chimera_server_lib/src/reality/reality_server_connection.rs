// REALITY server-side connection
//
// This implements a rustls-compatible API for REALITY protocol server connections,
// allowing REALITY to be used as a drop-in replacement for rustls.

use std::io::{self, Read};

use super::slide_buffer::SlideBuffer;
use crate::address::{Address, NetLocation};

use super::common::{
    CIPHERTEXT_READ_BUF_CAPACITY, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_FINISHED, PLAINTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE,
    TLS_RECORD_HEADER_SIZE,
};
use super::reality_aead::{AeadKey, decrypt_handshake_message_for_suite};
use super::reality_auth::{decrypt_session_id, derive_auth_key, perform_ecdh};
use super::reality_certificate::generate_hmac_certificate;
use super::reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
use super::reality_io_state::RealityIoState;
use super::reality_records::RecordEncryptor;
use super::reality_tls13_keys::{
    compute_finished_verify_data_for_suite, derive_application_secrets_for_suite,
    derive_handshake_keys_for_suite, derive_traffic_keys_for_suite,
};
use super::reality_tls13_messages::*;
use super::reality_util::{
    extract_client_cipher_suites, extract_client_public_key, extract_client_random,
    extract_session_id_slice, negotiate_cipher_suite,
};
use aws_lc_rs::{
    agreement, digest,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;

#[path = "reality_server_connection/io.rs"]
mod connection_io;
#[cfg(test)]
mod tests;

/// Configuration for REALITY server connections
#[derive(Clone, Debug)]
pub struct RealityServerConfig {
    /// Server's X25519 private key (32 bytes)
    pub private_key: [u8; 32],
    /// List of valid short IDs for authentication (8 bytes each)
    pub short_ids: Vec<[u8; 8]>,
    /// Destination server used for REALITY handshake mirroring.
    pub dest: NetLocation,
    /// Server names accepted by the inbound and used for certificate generation.
    pub server_names: Vec<String>,
    /// Maximum allowed time difference in milliseconds (None = no check)
    pub max_time_diff: Option<u64>,
    /// Minimum accepted client version (3 bytes: major.minor.patch)
    pub min_client_version: Option<[u8; 3]>,
    /// Maximum accepted client version (3 bytes: major.minor.patch)
    pub max_client_version: Option<[u8; 3]>,
    /// Supported TLS 1.3 cipher suites (empty = use defaults)
    pub cipher_suites: Vec<CipherSuite>,
}

/// Handshake state machine for REALITY server
enum HandshakeState {
    /// Initial state, waiting for ClientHello
    Initial,
    /// ClientHello validated, waiting to build response with dest record structure.
    ClientHelloValidated { info: ClientHelloInfo },
    /// ServerHello and encrypted handshake messages sent, waiting for client Finished
    ServerHelloSent {
        handshake_hash_with_server_finished: Vec<u8>, // Hash including server Finished (for verifying client Finished)
        client_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: CipherSuite,
    },
    /// Handshake complete, ready for application data
    Complete,
}

/// Information extracted from ClientHello during validation phase.
#[derive(Clone)]
pub struct ClientHelloInfo {
    /// Session ID from ClientHello, echoed in ServerHello.
    pub session_id: Vec<u8>,
    /// Client's X25519 public key from key_share extension.
    pub client_public_key: [u8; 32],
    /// Derived REALITY auth key for HMAC certificate generation.
    pub auth_key: [u8; 32],
    /// Negotiated TLS 1.3 cipher suite.
    pub cipher_suite: CipherSuite,
    /// Raw ClientHello handshake bytes without the TLS record header.
    pub client_hello_handshake: Vec<u8>,
}

/// REALITY server-side connection implementing rustls-compatible API
pub struct RealityServerConnection {
    // Configuration
    config: RealityServerConfig,

    // Handshake state
    handshake_state: HandshakeState,

    // TLS 1.3 application traffic encryption (post-handshake)
    app_read_key: Option<AeadKey>,
    app_read_iv: Option<Vec<u8>>,
    app_write_key: Option<AeadKey>,
    app_write_iv: Option<Vec<u8>>,
    read_seq: u64,
    write_seq: u64,
    cipher_suite: Option<CipherSuite>,

    // Pre-allocated buffer for TLS read operations (reused across calls)
    tls_read_buffer: Box<[u8; TLS_MAX_RECORD_SIZE]>,

    // Buffers for I/O - using SlideBuffer for efficient zero-alloc operations
    ciphertext_read_buf: SlideBuffer, // Incoming encrypted TLS records
    ciphertext_write_buf: Vec<u8>,    // Outgoing encrypted TLS records
    plaintext_read_buf: SlideBuffer,  // Decrypted application data
    plaintext_write_buf: Vec<u8>,     // Application data to encrypt
    received_close_notify: bool,      // Peer sent close_notify alert
    fatal_error: Option<io::ErrorKind>, // Fatal error occurred, connection unusable
    vision_direct_transition: bool,
}

fn timestamp_diff(
    now: std::time::Duration,
    client_timestamp: u64,
) -> std::time::Duration {
    now.abs_diff(std::time::Duration::from_secs(client_timestamp))
}

impl RealityServerConnection {
    /// Create a new REALITY server connection
    pub fn new(config: RealityServerConfig) -> io::Result<Self> {
        Ok(RealityServerConnection {
            config,
            handshake_state: HandshakeState::Initial,
            app_read_key: None,
            app_read_iv: None,
            app_write_key: None,
            app_write_iv: None,
            read_seq: 0,
            write_seq: 0,
            cipher_suite: None,
            tls_read_buffer: Box::new([0u8; TLS_MAX_RECORD_SIZE]),
            ciphertext_read_buf: SlideBuffer::new(CIPHERTEXT_READ_BUF_CAPACITY),
            ciphertext_write_buf: Vec::new(),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::new(),
            received_close_notify: false,
            fatal_error: None,
            vision_direct_transition: false,
        })
    }

    /// Read TLS messages from the provided reader into internal buffer
    ///
    /// This does NOT decrypt - call process_new_packets() for that.
    /// Uses pre-allocated buffer to avoid allocation on every call.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        // Compact if remaining capacity is insufficient for a full TLS record
        if self.ciphertext_read_buf.remaining_capacity() < TLS_MAX_RECORD_SIZE {
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

    /// Process buffered TLS messages and advance handshake/decrypt data
    ///
    /// Returns I/O state with available plaintext bytes and write status.
    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        if self.received_close_notify {
            return Ok(RealityIoState::new(self.plaintext_read_buf.len()));
        }

        let result = self.process_new_packets_inner();

        if let Err(ref err) = result {
            match err.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(err.kind());
                }
                _ => {}
            }
        }

        result
    }

    fn process_new_packets_inner(&mut self) -> io::Result<RealityIoState> {
        loop {
            let before_state = std::mem::discriminant(&self.handshake_state);
            let before_ciphertext_len = self.ciphertext_read_buf.len();
            let before_plaintext_len = self.plaintext_read_buf.len();

            match &self.handshake_state {
                HandshakeState::Initial => {
                    self.process_client_hello()?;
                }
                HandshakeState::ClientHelloValidated { .. } => {
                    self.build_server_response_internal(&[])?;
                }
                HandshakeState::ServerHelloSent { .. } => {
                    if !self.process_client_finished()? {
                        break;
                    }
                }
                HandshakeState::Complete => {
                    self.process_application_data()?;
                }
            }

            if self.received_close_notify {
                break;
            }

            // Do not let the outer progress loop immediately process another
            // record in Vision mode. The plaintext may contain Direct, making
            // every following buffered byte xray's rawInput rather than TLS.
            if self.vision_direct_transition
                && before_plaintext_len != self.plaintext_read_buf.len()
            {
                break;
            }

            let progressed = before_state
                != std::mem::discriminant(&self.handshake_state)
                || before_ciphertext_len != self.ciphertext_read_buf.len()
                || before_plaintext_len != self.plaintext_read_buf.len();

            if !progressed {
                break;
            }
        }

        Ok(RealityIoState::new(self.plaintext_read_buf.len()))
    }

    /// Public API: validate a complete ClientHello without building the response.
    pub fn validate_client_hello(&mut self, client_hello: &[u8]) -> io::Result<()> {
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        if !matches!(self.handshake_state, HandshakeState::Initial) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "validate_client_hello called in wrong state",
            ));
        }

        let result = self.process_client_hello_validation(client_hello);
        if let Err(ref err) = result {
            match err.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(err.kind());
                }
                _ => {}
            }
        }
        result
    }

    /// Public API: build a server response after `validate_client_hello`.
    ///
    /// `dest_records` follows shoes' template: ServerHello, CCS, then one or
    /// more encrypted handshake records from the camouflage destination.
    pub fn build_server_response(
        &mut self,
        dest_records: Vec<bytes::Bytes>,
    ) -> io::Result<()> {
        if !matches!(
            self.handshake_state,
            HandshakeState::ClientHelloValidated { .. }
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "build_server_response called in wrong state",
            ));
        }

        self.build_server_response_internal(&dest_records)
    }

    /// Process ClientHello message and send ServerHello using the default record shape.
    fn process_client_hello(&mut self) -> io::Result<()> {
        // Need at least TLS record header (5 bytes)
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(()); // Need more data
        }

        // Parse TLS record length
        let record_len = self.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
        })? as usize;

        // Check if we have the complete record
        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(()); // Need more data
        }

        // Copy the ClientHello record to a Vec for processing
        // (We need to keep it around for transcript hashing and AAD modification)
        let client_hello: Vec<u8> =
            self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);

        self.process_client_hello_validation(&client_hello)?;
        self.build_server_response_internal(&[])
    }

    fn process_client_hello_validation(
        &mut self,
        client_hello: &[u8],
    ) -> io::Result<()> {
        if client_hello.len() < TLS_RECORD_HEADER_SIZE + 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too short",
            ));
        }

        let client_random = extract_client_random(client_hello)?;
        let session_id = extract_session_id_slice(client_hello)?;
        let client_public_key = extract_client_public_key(client_hello)?;

        tracing::debug!(
            client_random_len = client_random.len(),
            "REALITY: ClientHello received"
        );

        let shared_secret =
            perform_ecdh(&self.config.private_key, &client_public_key).map_err(
                |e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
            )?;

        let salt = &client_random[0..20];
        let auth_key =
            derive_auth_key(&shared_secret, salt, b"REALITY").map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            })?;

        if session_id.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid session ID length",
            ));
        }

        let nonce = &client_random[20..32];
        let mut encrypted_session_id_arr = [0u8; 32];
        encrypted_session_id_arr.copy_from_slice(session_id);

        let client_hello_handshake = &client_hello[TLS_RECORD_HEADER_SIZE..];
        let mut aad_for_decryption = client_hello_handshake.to_vec();
        if aad_for_decryption.len() >= 39 + 32 {
            aad_for_decryption[39..39 + 32].fill(0);
        }

        let decrypted_session_id = decrypt_session_id(
            &encrypted_session_id_arr,
            &auth_key,
            nonce,
            &aad_for_decryption,
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Session ID decrypt failed: {:?}", e),
            )
        })?;

        let client_version = &decrypted_session_id[0..3];
        let client_timestamp = u32::from_be_bytes([
            decrypted_session_id[4],
            decrypted_session_id[5],
            decrypted_session_id[6],
            decrypted_session_id[7],
        ]) as u64;
        let client_short_id = &decrypted_session_id[8..16];

        tracing::debug!(
            client_version_len = client_version.len(),
            has_client_timestamp = true,
            "REALITY: Client session metadata decrypted"
        );

        let mut client_short_id_arr = [0u8; 8];
        client_short_id_arr.copy_from_slice(client_short_id);
        let short_id_ok =
            self.config.short_ids.iter().fold(false, |acc, valid_id| {
                acc | (client_short_id_arr.ct_eq(valid_id).unwrap_u8() == 1)
            });

        if !short_id_ok {
            tracing::warn!(
                configured_short_ids = self.config.short_ids.len(),
                "REALITY: Client short_id not in configured list"
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid short_id",
            ));
        }

        if let Some(max_diff_ms) = self.config.max_time_diff {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| io::Error::other("System time error"))?;
            let time_diff = timestamp_diff(now, client_timestamp);
            let max_diff = std::time::Duration::from_millis(max_diff_ms);

            if time_diff > max_diff {
                tracing::warn!(
                    time_diff_ms = time_diff.as_millis(),
                    max_diff_ms,
                    "REALITY: Client timestamp outside allowed skew"
                );
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Timestamp difference {} ms exceeds maximum {} ms",
                        time_diff.as_millis(),
                        max_diff_ms
                    ),
                ));
            }
        }

        if let Some(min_ver) = &self.config.min_client_version
            && client_version < &min_ver[..]
        {
            tracing::warn!(
                configured_min_version_len = min_ver.len(),
                "REALITY: Client version is below minimum"
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Client version is below minimum",
            ));
        }

        if let Some(max_ver) = &self.config.max_client_version
            && client_version > &max_ver[..]
        {
            tracing::warn!(
                configured_max_version_len = max_ver.len(),
                "REALITY: Client version is above maximum"
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Client version is above maximum",
            ));
        }

        tracing::info!(
            client_version_len = client_version.len(),
            "REALITY: Client authentication successful"
        );

        let client_cipher_suites = extract_client_cipher_suites(client_hello)?;
        let server_cipher_suites = if self.config.cipher_suites.is_empty() {
            DEFAULT_CIPHER_SUITES
        } else {
            &self.config.cipher_suites
        };
        let cipher_suite =
            negotiate_cipher_suite(server_cipher_suites, &client_cipher_suites)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "No common TLS 1.3 cipher suite found",
                    )
                })?;
        tracing::debug!(
            ?cipher_suite,
            client_cipher_suite_count = client_cipher_suites.len(),
            "REALITY: Negotiated cipher suite"
        );

        self.handshake_state = HandshakeState::ClientHelloValidated {
            info: ClientHelloInfo {
                session_id: session_id.to_vec(),
                client_public_key,
                auth_key,
                cipher_suite,
                client_hello_handshake: client_hello_handshake.to_vec(),
            },
        };

        Ok(())
    }

    fn build_server_response_internal(
        &mut self,
        dest_records: &[bytes::Bytes],
    ) -> io::Result<()> {
        let HandshakeState::ClientHelloValidated { info } =
            std::mem::replace(&mut self.handshake_state, HandshakeState::Initial)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "build_server_response_internal called without ClientHelloValidated state",
            ));
        };

        let cipher_suite = info.cipher_suite;

        // Step 4: Generate our server X25519 keypair
        let rng = SystemRandom::new();
        let mut our_private_bytes = [0u8; 32];
        rng.fill(&mut our_private_bytes)
            .map_err(|_| io::Error::other("RNG failed"))?;

        let our_private_key = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &our_private_bytes,
        )
        .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
        let our_public_key_bytes = our_private_key
            .compute_public_key()
            .map_err(|_| io::Error::other("Failed to compute public key"))?;

        // Step 5: Generate server random
        let mut server_random = [0u8; 32];
        rng.fill(&mut server_random)
            .map_err(|_| io::Error::other("RNG failed"))?;

        // Step 7: Build ServerHello
        let server_hello = construct_server_hello(
            &server_random,
            &info.session_id,
            cipher_suite.id(),
            our_public_key_bytes.as_ref(),
        )?;

        // Step 8: Compute transcript hashes
        let digest_alg = cipher_suite.digest_algorithm();

        let mut ch_transcript = digest::Context::new(digest_alg);
        ch_transcript.update(&info.client_hello_handshake);
        let client_hello_hash = ch_transcript.finish();

        let mut ch_sh_transcript = digest::Context::new(digest_alg);
        ch_sh_transcript.update(&info.client_hello_handshake);
        ch_sh_transcript.update(&server_hello);

        // Clone before finalizing
        let mut handshake_transcript = ch_sh_transcript.clone();
        let server_hello_hash = ch_sh_transcript.finish();

        // Step 9: Perform ECDH for TLS 1.3 key derivation
        let peer_public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            &info.client_public_key,
        );
        let mut tls_shared_secret = [0u8; 32];
        agreement::agree(
            &our_private_key,
            peer_public_key,
            io::Error::other("ECDH failed"),
            |key_material| {
                tls_shared_secret.copy_from_slice(key_material);
                Ok(())
            },
        )?;

        // Step 10: Derive TLS 1.3 keys
        let hs_keys = derive_handshake_keys_for_suite(
            cipher_suite,
            &tls_shared_secret,
            client_hello_hash.as_ref(),
            server_hello_hash.as_ref(),
        )?;

        // Use the first configured server name for the generated certificate.
        // When dest is an IP address, config validation requires an explicit
        // serverNames list so the REALITY certificate still has a hostname.
        let cert_hostname = self
            .config
            .server_names
            .first()
            .map(String::as_str)
            .or_else(|| match self.config.dest.address() {
                Address::Hostname(hostname) => Some(hostname.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY requires a hostname serverName for certificate generation",
                )
            })?;

        // Step 11: Generate HMAC-signed certificate
        let (cert_der, signing_key) =
            generate_hmac_certificate(&info.auth_key, cert_hostname)?;

        // Step 12: Build encrypted handshake messages
        let encrypted_extensions = construct_encrypted_extensions()?;
        handshake_transcript.update(&encrypted_extensions);

        let certificate = construct_certificate(&cert_der)?;
        handshake_transcript.update(&certificate);

        let cert_verify_hash = handshake_transcript.clone().finish();
        let certificate_verify =
            construct_certificate_verify(&signing_key, cert_verify_hash.as_ref())?;
        handshake_transcript.update(&certificate_verify);

        let handshake_hash_before_finished = handshake_transcript.clone().finish();

        // Step 13: Derive server handshake traffic keys for encryption
        let (server_hs_key, server_hs_iv) = derive_traffic_keys_for_suite(
            &hs_keys.server_handshake_traffic_secret,
            cipher_suite,
        )?;

        // Step 14: Build server Finished message first (before encryption)
        let server_verify_data = compute_finished_verify_data_for_suite(
            cipher_suite,
            &hs_keys.server_handshake_traffic_secret,
            handshake_hash_before_finished.as_ref(),
        )?;
        let server_finished = construct_finished(&server_verify_data)?;

        // Step 15: Encrypt the handshake messages. With dest records, mirror
        // shoes' REALITY shape: a large first encrypted record means combined
        // mode, while small records mean one TLS message per record.
        let mut handshake_ciphertext = Vec::new();
        let mut handshake_seq = 0u64;
        let hs_aead_key = AeadKey::new(cipher_suite, &server_hs_key)?;
        let mut encryptor =
            RecordEncryptor::new(&hs_aead_key, &server_hs_iv, &mut handshake_seq);
        let dest_encrypted_records = dest_records.get(2..).unwrap_or(&[]);
        let is_combined_mode = dest_encrypted_records
            .first()
            .map(|record| record.len() > 512)
            .unwrap_or(true);

        let messages: [&[u8]; 4] = [
            &encrypted_extensions,
            &certificate,
            &certificate_verify,
            &server_finished,
        ];

        if is_combined_mode {
            let mut combined_plaintext = Vec::new();
            for message in messages {
                combined_plaintext.extend_from_slice(message);
            }
            let target_size = dest_encrypted_records
                .first()
                .map(|record| record.len())
                .unwrap_or(0);

            tracing::debug!(
                "REALITY SERVER: Combined mode - EE={}, Cert={}, CV={}, Fin={}, Total={}, target={}",
                encrypted_extensions.len(),
                certificate.len(),
                certificate_verify.len(),
                server_finished.len(),
                combined_plaintext.len(),
                target_size
            );

            encryptor.encrypt_handshake_with_padding(
                &combined_plaintext,
                &mut handshake_ciphertext,
                target_size,
            )?;
        } else {
            tracing::debug!(
                "REALITY SERVER: Separate mode - {} dest records, encrypting {} messages separately",
                dest_encrypted_records.len(),
                messages.len()
            );

            for (idx, message) in messages.iter().enumerate() {
                let target_size = dest_encrypted_records
                    .get(idx)
                    .map(|record| record.len())
                    .unwrap_or(0);
                encryptor.encrypt_handshake_with_padding(
                    message,
                    &mut handshake_ciphertext,
                    target_size,
                )?;
            }
        }

        // Update transcript with server Finished (needed for client Finished verification)
        handshake_transcript.update(&server_finished);
        let handshake_hash_with_server_finished = handshake_transcript.finish();

        // Step 16: Buffer all handshake messages to write buffer
        // ServerHello (plaintext)
        self.ciphertext_write_buf
            .extend_from_slice(&write_record_header(
                CONTENT_TYPE_HANDSHAKE,
                server_hello.len() as u16,
            ));
        self.ciphertext_write_buf.extend_from_slice(&server_hello);

        // ChangeCipherSpec (for compatibility)
        self.ciphertext_write_buf
            .extend_from_slice(&write_record_header(
                CONTENT_TYPE_CHANGE_CIPHER_SPEC,
                1,
            ));
        self.ciphertext_write_buf.push(0x01);

        // Encrypted handshake record(s) - may be fragmented into multiple records
        self.ciphertext_write_buf
            .extend_from_slice(&handshake_ciphertext);

        tracing::info!(
            "REALITY: ServerHello and encrypted handshake messages buffered ({} bytes)",
            self.ciphertext_write_buf.len()
        );

        // Step 17: Update handshake state
        self.handshake_state = HandshakeState::ServerHelloSent {
            handshake_hash_with_server_finished: handshake_hash_with_server_finished
                .as_ref()
                .to_vec(),
            client_handshake_traffic_secret: hs_keys
                .client_handshake_traffic_secret
                .clone(),
            master_secret: hs_keys.master_secret,
            cipher_suite,
        };

        Ok(())
    }

    /// Process client's Finished message and complete handshake.
    ///
    /// Returns false when the buffered input does not yet contain a complete record.
    fn process_client_finished(&mut self) -> io::Result<bool> {
        // Check if we have enough data for a TLS record header BEFORE extracting state
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false); // Need more data
        }

        // Check for ChangeCipherSpec (TLS 1.3 compatibility message)
        if self.ciphertext_read_buf[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            // ChangeCipherSpec record
            let ccs_len =
                self.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
                })? as usize;

            // Need complete ChangeCipherSpec record
            if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE + ccs_len {
                return Ok(false); // Need more data
            }

            // Skip ChangeCipherSpec (compatibility message)
            tracing::debug!(
                "REALITY: Skipping ChangeCipherSpec (compatibility message)"
            );
            self.ciphertext_read_buf
                .consume(TLS_RECORD_HEADER_SIZE + ccs_len);

            // Check if we have the next record header
            if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
                return Ok(false); // Need more data
            }
        }

        // Parse TLS record length
        let record_len = self.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
        })? as usize;

        // Check if we have the complete record
        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(false); // Need more data
        }

        // Verify it's ApplicationData (encrypted Finished)
        if self.ciphertext_read_buf[0] != CONTENT_TYPE_APPLICATION_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected ApplicationData (0x17), got 0x{:02x}",
                    self.ciphertext_read_buf[0]
                ),
            ));
        }

        // NOW we're committed to processing - take ownership of handshake state
        // This avoids cloning Vec<u8> fields
        let old_state =
            std::mem::replace(&mut self.handshake_state, HandshakeState::Complete);
        let (
            client_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_hash_with_server_finished,
        ) = match old_state {
            HandshakeState::ServerHelloSent {
                client_handshake_traffic_secret,
                master_secret,
                cipher_suite,
                handshake_hash_with_server_finished,
            } => (
                client_handshake_traffic_secret, // moved, not cloned
                master_secret,                   // moved, not cloned
                cipher_suite,
                handshake_hash_with_server_finished,
            ),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid state for process_client_finished",
                ));
            }
        };

        // Extract the encrypted Finished record (copy to Vec for decryption)
        let record: Vec<u8> = self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);
        let ciphertext = &record[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header

        // Derive client handshake traffic keys for decryption
        let (client_hs_key, client_hs_iv) = derive_traffic_keys_for_suite(
            &client_handshake_traffic_secret,
            cipher_suite,
        )?;

        // Decrypt the Finished message (sequence number = 0 for client's first encrypted record)
        let plaintext = decrypt_handshake_message_for_suite(
            cipher_suite,
            &client_hs_key,
            &client_hs_iv,
            0, // Client's first encrypted record
            ciphertext,
            record_len as u16,
        )?;

        // Verify it's a Finished message (type 0x14)
        if plaintext.is_empty() || plaintext[0] != HANDSHAKE_TYPE_FINISHED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected Finished message",
            ));
        }

        // Extract verify_data (skip type(1) + length(3) = 4 bytes)
        if plaintext.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Finished message too short",
            ));
        }
        let client_verify_data = &plaintext[4..];

        // Compute expected client Finished verify_data
        // IMPORTANT: Use hash that includes server Finished (per TLS 1.3 RFC 8446)
        let expected_verify_data = compute_finished_verify_data_for_suite(
            cipher_suite,
            &client_handshake_traffic_secret,
            &handshake_hash_with_server_finished,
        )?;

        // Verify it matches using constant-time comparison to prevent timing attacks
        if client_verify_data
            .ct_eq(expected_verify_data.as_slice())
            .unwrap_u8()
            == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Client Finished verify_data mismatch",
            ));
        }

        tracing::debug!("REALITY: Client Finished verified successfully");

        // Derive application secrets
        // IMPORTANT: Use hash that includes server Finished (per TLS 1.3 RFC 8446)
        let (client_app_secret, server_app_secret) =
            derive_application_secrets_for_suite(
                cipher_suite,
                &master_secret,
                &handshake_hash_with_server_finished,
            )?;

        // Derive application traffic keys
        let (client_app_key_bytes, client_app_iv) =
            derive_traffic_keys_for_suite(&client_app_secret, cipher_suite)?;
        let (server_app_key_bytes, server_app_iv) =
            derive_traffic_keys_for_suite(&server_app_secret, cipher_suite)?;
        let client_app_key = AeadKey::new(cipher_suite, &client_app_key_bytes)?;
        let server_app_key = AeadKey::new(cipher_suite, &server_app_key_bytes)?;

        // Store application traffic keys
        self.app_read_key = Some(client_app_key);
        self.app_read_iv = Some(client_app_iv);
        self.app_write_key = Some(server_app_key);
        self.app_write_iv = Some(server_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = Some(cipher_suite);

        // Handshake state already set to Complete above

        tracing::debug!("REALITY: Handshake complete, application keys derived");

        Ok(true)
    }
}

#[inline(always)]
pub fn feed_reality_server_connection(
    server_connection: &mut RealityServerConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = server_connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed TLS connection: {e}"),
            )
        })?;
        i += n;
    }
    Ok(())
}
