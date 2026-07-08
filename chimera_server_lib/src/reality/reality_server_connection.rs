// REALITY server-side connection
//
// This implements a rustls-compatible API for REALITY protocol server connections,
// allowing REALITY to be used as a drop-in replacement for rustls.

use std::io::{self, Read, Write};

use super::slide_buffer::SlideBuffer;
use crate::address::{Address, NetLocation};

use super::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CIPHERTEXT_READ_BUF_CAPACITY,
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_FINISHED, OUTGOING_BUFFER_LIMIT, PLAINTEXT_READ_BUF_CAPACITY,
    TLS_MAX_RECORD_SIZE, TLS_RECORD_HEADER_SIZE,
};
use super::reality_aead::{AeadKey, decrypt_handshake_message_for_suite};
use super::reality_auth::{decrypt_session_id, derive_auth_key, perform_ecdh};
use super::reality_certificate::generate_hmac_certificate;
use super::reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::{RecordDecryptor, RecordEncryptor};
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
            ciphertext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            received_close_notify: false,
            fatal_error: None,
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
                .map_err(|_| io::Error::other("System time error"))?
                .as_secs();

            let time_diff_secs = now.abs_diff(client_timestamp);
            let max_diff_secs = max_diff_ms / 1000;

            if time_diff_secs > max_diff_secs {
                tracing::warn!(
                    "REALITY: Client timestamp {} differs from server {} by {} seconds (max: {} seconds)",
                    client_timestamp,
                    now,
                    time_diff_secs,
                    max_diff_secs
                );
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Timestamp difference {} seconds exceeds maximum {} seconds",
                        time_diff_secs, max_diff_secs
                    ),
                ));
            }
        }

        if let Some(min_ver) = &self.config.min_client_version
            && client_version < &min_ver[..]
        {
            tracing::warn!(
                "REALITY: Client version {:?} is below minimum {:?}",
                client_version,
                min_ver
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Client version {:?} is below minimum {:?}",
                    client_version, min_ver
                ),
            ));
        }

        if let Some(max_ver) = &self.config.max_client_version
            && client_version > &max_ver[..]
        {
            tracing::warn!(
                "REALITY: Client version {:?} is above maximum {:?}",
                client_version,
                max_ver
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "Client version {:?} is above maximum {:?}",
                    client_version, max_ver
                ),
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
            unreachable!()
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

    /// Decrypt application data using TLS 1.3 keys
    fn process_application_data(&mut self) -> io::Result<()> {
        // Check if we have application keys
        let (app_read_key, app_read_iv) =
            match (&self.app_read_key, &self.app_read_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => return Ok(()), // Keys not ready yet
            };
        // Process all complete TLS records in the buffer
        while self.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
            // Parse TLS record header
            let record_len =
                self.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
                })? as usize;

            // Check if we have the complete record
            let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
            if self.ciphertext_read_buf.len() < total_record_len {
                break; // Need more data
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
                        // Compact plaintext buffer if needed before extending
                        self.plaintext_read_buf.maybe_compact(4096);

                        // Append to plaintext buffer (without ContentType)
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
        }

        Ok(())
    }

    /// Get a reader for accessing decrypted plaintext
    pub fn reader(&mut self) -> RealityReader<'_> {
        // SlideBuffer handles compaction internally via maybe_compact()
        // Compact before returning reader if we've consumed significant data
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf, self.received_close_notify)
    }

    /// Get a writer for buffering plaintext to be encrypted
    pub fn writer(&mut self) -> RealityWriter<'_> {
        RealityWriter::new(&mut self.plaintext_write_buf)
    }

    /// Write buffered TLS messages to the provided writer
    ///
    /// This encrypts any pending plaintext and writes ciphertext.
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

        // Write buffered ciphertext
        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    /// Check if the connection wants to write data
    pub fn wants_write(&self) -> bool {
        !self.ciphertext_write_buf.is_empty() || !self.plaintext_write_buf.is_empty()
    }

    /// Check if the connection wants to read more TLS data.
    pub fn wants_read(&self) -> bool {
        if self.received_close_notify || self.fatal_error.is_some() {
            return false;
        }

        if self.is_handshaking() {
            return true;
        }

        self.plaintext_read_buf.is_empty()
    }

    /// Check if handshake is still in progress
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

    /// Queue a close notification alert
    pub fn send_close_notify(&mut self) {
        // In TLS 1.3, alerts must be encrypted like application data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            tracing::debug!(
                "REALITY: Cannot send close_notify - handshake not complete"
            );
            return;
        }

        // Get application keys
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
                tracing::debug!("REALITY: Encrypted close_notify alert queued");
            }
            Err(e) => {
                tracing::error!("REALITY: Failed to encrypt close_notify: {}", e);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::{RealityClientConfig, RealityClientConnection};
    use aws_lc_rs::{
        agreement,
        rand::{SecureRandom, SystemRandom},
    };

    fn test_reality_keypair() -> ([u8; 32], [u8; 32]) {
        let rng = SystemRandom::new();
        let mut private_key_bytes = [0u8; 32];
        rng.fill(&mut private_key_bytes).unwrap();
        let private_key = agreement::PrivateKey::from_private_key(
            &agreement::X25519,
            &private_key_bytes,
        )
        .unwrap();
        let public_key_bytes: [u8; 32] = private_key
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        (private_key_bytes, public_key_bytes)
    }

    fn test_client_hello(server_public_key: [u8; 32]) -> Vec<u8> {
        test_client_hello_with(server_public_key, [0u8; 8], Vec::new())
    }

    fn test_client_hello_with(
        server_public_key: [u8; 32],
        short_id: [u8; 8],
        cipher_suites: Vec<CipherSuite>,
    ) -> Vec<u8> {
        let mut client = RealityClientConnection::new(RealityClientConfig {
            public_key: server_public_key,
            short_id,
            server_name: "example.com".to_string(),
            cipher_suites,
        })
        .unwrap();
        let mut client_hello = Vec::new();
        client.write_tls(&mut client_hello).unwrap();
        client_hello
    }

    fn test_server_config(private_key: [u8; 32]) -> RealityServerConfig {
        RealityServerConfig {
            private_key,
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(
                Address::Hostname("example.com".to_string()),
                443,
            ),
            server_names: vec!["example.com".to_string()],
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        }
    }

    fn record_types(data: &[u8]) -> Vec<u8> {
        let mut types = Vec::new();
        let mut offset = 0;
        while offset + TLS_RECORD_HEADER_SIZE <= data.len() {
            types.push(data[offset]);
            let len =
                u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            offset += TLS_RECORD_HEADER_SIZE + len;
        }
        assert_eq!(offset, data.len());
        types
    }

    #[test]
    fn test_reality_server_connection_creation() {
        let config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            server_names: vec!["example.com".to_string()],
            max_time_diff: Some(60000),
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        };

        let conn = RealityServerConnection::new(config).unwrap();
        assert!(conn.is_handshaking());
        assert!(conn.wants_read());
        assert!(!conn.wants_write());
    }

    #[test]
    fn test_io_state() {
        let config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            server_names: vec!["example.com".to_string()],
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        };

        let mut conn = RealityServerConnection::new(config).unwrap();
        let state = conn.process_new_packets().unwrap();

        assert_eq!(state.plaintext_bytes_to_read(), 0);
        assert!(!conn.wants_write());
    }

    #[test]
    fn validate_client_hello_waits_for_response_build() {
        let (private_key, public_key) = test_reality_keypair();
        let mut conn =
            RealityServerConnection::new(test_server_config(private_key)).unwrap();
        let client_hello = test_client_hello(public_key);

        conn.validate_client_hello(&client_hello).unwrap();

        assert!(matches!(
            conn.handshake_state,
            HandshakeState::ClientHelloValidated { .. }
        ));
        assert!(conn.is_handshaking());
        assert!(!conn.wants_write());
    }

    #[test]
    fn invalid_short_id_takes_precedence_over_cipher_mismatch() {
        let (private_key, public_key) = test_reality_keypair();
        let mut config = test_server_config(private_key);
        config.cipher_suites = vec![CipherSuite::AES_256_GCM_SHA384];
        let mut conn = RealityServerConnection::new(config).unwrap();
        let client_hello = test_client_hello_with(
            public_key,
            [1u8; 8],
            vec![CipherSuite::AES_128_GCM_SHA256],
        );

        let err = conn.validate_client_hello(&client_hello).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("Invalid short_id"));
    }

    #[test]
    fn build_server_response_uses_separate_dest_record_shape() {
        let (private_key, public_key) = test_reality_keypair();
        let mut conn =
            RealityServerConnection::new(test_server_config(private_key)).unwrap();
        let client_hello = test_client_hello(public_key);

        conn.validate_client_hello(&client_hello).unwrap();
        conn.build_server_response(vec![
            bytes::Bytes::from_static(&[
                CONTENT_TYPE_HANDSHAKE,
                0x03,
                0x03,
                0x00,
                0x01,
                0x00,
            ]),
            bytes::Bytes::from_static(&[
                CONTENT_TYPE_CHANGE_CIPHER_SPEC,
                0x03,
                0x03,
                0x00,
                0x01,
                0x01,
            ]),
            bytes::Bytes::from(vec![CONTENT_TYPE_APPLICATION_DATA; 128]),
            bytes::Bytes::from(vec![CONTENT_TYPE_APPLICATION_DATA; 128]),
            bytes::Bytes::from(vec![CONTENT_TYPE_APPLICATION_DATA; 128]),
            bytes::Bytes::from(vec![CONTENT_TYPE_APPLICATION_DATA; 128]),
        ])
        .unwrap();

        let mut response = Vec::new();
        conn.write_tls(&mut response).unwrap();

        assert_eq!(
            record_types(&response),
            vec![
                CONTENT_TYPE_HANDSHAKE,
                CONTENT_TYPE_CHANGE_CIPHER_SPEC,
                CONTENT_TYPE_APPLICATION_DATA,
                CONTENT_TYPE_APPLICATION_DATA,
                CONTENT_TYPE_APPLICATION_DATA,
                CONTENT_TYPE_APPLICATION_DATA,
            ]
        );
    }

    #[test]
    fn fatal_packet_error_is_remembered() {
        let config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            server_names: vec!["example.com".to_string()],
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        };
        let mut conn = RealityServerConnection::new(config).unwrap();

        let invalid_empty_handshake =
            [CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x00];
        conn.read_tls(&mut std::io::Cursor::new(invalid_empty_handshake))
            .unwrap();

        let first_err = conn.process_new_packets().unwrap_err();
        assert_eq!(first_err.kind(), io::ErrorKind::InvalidData);

        let second_err = conn.process_new_packets().unwrap_err();
        assert_eq!(second_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(second_err.to_string(), "connection previously failed");
        assert!(!conn.wants_read());
    }

    #[test]
    fn take_remaining_ciphertext_drains_buffered_bytes() {
        let config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            server_names: vec!["example.com".to_string()],
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        };
        let mut conn = RealityServerConnection::new(config).unwrap();

        let buffered = b"post-splice-raw";
        conn.read_tls(&mut std::io::Cursor::new(buffered)).unwrap();

        assert_eq!(conn.take_remaining_ciphertext(), buffered);
        assert!(conn.take_remaining_ciphertext().is_empty());
    }
}
