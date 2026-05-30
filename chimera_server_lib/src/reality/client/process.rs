use std::io;

use aws_lc_rs::{agreement, digest};

use super::{HandshakeState, RealityClientConnection};
use crate::reality::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED,
    TLS_RECORD_HEADER_SIZE,
};
use crate::reality::reality_aead::{AeadKey, decrypt_handshake_message_for_suite};
use crate::reality::reality_cipher_suite::CipherSuite;
use crate::reality::reality_client_verify::{
    extract_certificate_der, extract_certificate_verify_signature,
    extract_ed25519_public_key, verify_certificate_hmac,
    verify_certificate_verify_signature,
};
use crate::reality::reality_records::{
    RecordDecryptor, encrypt_handshake_to_records_for_suite,
};
use crate::reality::reality_tls13_keys::{
    compute_finished_verify_data_for_suite, derive_application_secrets_for_suite,
    derive_handshake_keys_for_suite, derive_traffic_keys_for_suite,
};
use crate::reality::reality_tls13_messages::construct_finished;
use crate::reality::reality_util::{
    extract_server_cipher_suite, extract_server_public_key,
};

pub(super) fn process_server_hello(
    conn: &mut RealityClientConnection,
) -> io::Result<()> {
    // Extract state
    let (client_hello_hash, client_private_key, auth_key) =
        match &conn.handshake_state {
            HandshakeState::AwaitingServerHello {
                client_hello_hash,
                client_hello_bytes: _,
                client_private_key,
                auth_key,
            } => (*client_hello_hash, *client_private_key, *auth_key),
            _ => return Ok(()), // Wrong state
        };

    // Check if we have enough data for a TLS record header
    if conn.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
        return Ok(()); // Need more data
    }

    // Parse TLS record length
    let record_len = conn.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
    })? as usize;

    // Check if we have the complete record
    let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
    if conn.ciphertext_read_buf.len() < total_record_len {
        return Ok(()); // Need more data
    }

    // Copy ServerHello record to Vec for processing
    let record: Vec<u8> = conn.ciphertext_read_buf[..total_record_len].to_vec();
    conn.ciphertext_read_buf.consume(total_record_len);
    let server_hello = &record[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header (includes handshake header)

    tracing::debug!(
        "REALITY CLIENT: ServerHello for transcript: len={}, bytes={:02x?}",
        server_hello.len(),
        server_hello
    );

    // Extract server public key from ServerHello
    let server_public_key = extract_server_public_key(&record)?;
    let cipher_suite_id = extract_server_cipher_suite(&record)?;
    let selected_suite = CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Server selected unsupported cipher suite: 0x{cipher_suite_id:04x}"
            ),
        )
    })?;
    if selected_suite != CipherSuite::AES_128_GCM_SHA256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported REALITY cipher suite: 0x{cipher_suite_id:04x}"),
        ));
    }
    let cipher_suite = selected_suite;
    let cipher_suite_id = cipher_suite.id();

    // Get the actual ClientHello bytes from our saved state
    let client_hello_bytes = match &conn.handshake_state {
        HandshakeState::AwaitingServerHello {
            client_hello_bytes, ..
        } => client_hello_bytes.clone(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid handshake state",
            ));
        }
    };

    let mut full_transcript = digest::Context::new(&digest::SHA256);
    tracing::debug!(
        "REALITY CLIENT: Transcript includes ClientHello ({} bytes), first bytes: {:02x?}",
        client_hello_bytes.len(),
        &client_hello_bytes[..client_hello_bytes.len().min(20)]
    );
    tracing::debug!(
        "REALITY CLIENT: Transcript includes ServerHello ({} bytes), first bytes: {:02x?}",
        server_hello.len(),
        &server_hello[..server_hello.len().min(20)]
    );
    full_transcript.update(&client_hello_bytes); // Use actual ClientHello bytes, not hash!
    full_transcript.update(server_hello); // ServerHello already includes handshake header
    let server_hello_hash = full_transcript.finish();
    let mut server_hello_hash_arr = [0u8; 32];
    server_hello_hash_arr.copy_from_slice(server_hello_hash.as_ref());

    // Perform ECDH for TLS 1.3 key derivation
    let peer_public_key =
        agreement::UnparsedPublicKey::new(&agreement::X25519, &server_public_key);
    let my_private_key = agreement::PrivateKey::from_private_key(
        &agreement::X25519,
        &client_private_key,
    )
    .map_err(|_| io::Error::other("Failed to create private key"))?;

    let mut tls_shared_secret = [0u8; 32];
    agreement::agree(
        &my_private_key,
        peer_public_key,
        io::Error::other("ECDH failed"),
        |key_material| {
            tls_shared_secret.copy_from_slice(key_material);
            Ok(())
        },
    )?;

    // Derive handshake keys
    let hs_keys = derive_handshake_keys_for_suite(
        cipher_suite,
        &tls_shared_secret,
        &client_hello_hash,
        &server_hello_hash_arr,
    )?;

    tracing::debug!("REALITY: ServerHello processed, handshake keys derived");

    // Initialize transcript with actual ClientHello and ServerHello bytes
    let mut transcript_bytes = Vec::new();
    transcript_bytes.extend_from_slice(&client_hello_bytes);
    transcript_bytes.extend_from_slice(server_hello);

    // Update state
    conn.handshake_state = HandshakeState::ProcessingHandshake {
        client_handshake_traffic_secret: hs_keys
            .client_handshake_traffic_secret
            .clone(),
        server_handshake_traffic_secret: hs_keys
            .server_handshake_traffic_secret
            .clone(),
        master_secret: hs_keys.master_secret.clone(),
        cipher_suite: cipher_suite_id,
        handshake_transcript_bytes: transcript_bytes,
        auth_key, // Pass auth_key for certificate HMAC verification
        handshake_seq: 0,
        accumulated_plaintext: Vec::new(),
    };

    Ok(())
}

pub(super) fn process_encrypted_handshake(
    conn: &mut RealityClientConnection,
) -> io::Result<()> {
    let (
        client_hs_secret,
        server_hs_secret,
        master_secret,
        cipher_suite_id,
        transcript_bytes,
        auth_key,
        mut handshake_seq,
        mut accumulated_plaintext,
    ) = match &conn.handshake_state {
        HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_transcript_bytes,
            auth_key,
            handshake_seq,
            accumulated_plaintext,
        } => (
            client_handshake_traffic_secret.clone(),
            server_handshake_traffic_secret.clone(),
            master_secret.clone(),
            *cipher_suite,
            handshake_transcript_bytes.clone(),
            *auth_key,
            *handshake_seq,
            accumulated_plaintext.clone(),
        ),
        _ => return Ok(()),
    };

    let cipher_suite = CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid REALITY cipher suite in state: 0x{cipher_suite_id:04x}"
            ),
        )
    })?;

    let (server_hs_key, server_hs_iv) =
        derive_traffic_keys_for_suite(&server_hs_secret, cipher_suite)?;

    if handshake_seq == 0 {
        tracing::debug!(
            "REALITY CLIENT: Server HS key={:02x?}, iv={:02x?}",
            &server_hs_key[..16],
            &server_hs_iv
        );
    }

    if conn.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
        return Ok(());
    }

    let record_type = conn.ciphertext_read_buf[0];
    let tls_version = conn.ciphertext_read_buf.get_u16_be(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
    })?;
    let record_len = conn.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
    })? as usize;

    tracing::debug!(
        "REALITY CLIENT: TLS record header: type=0x{:02x}, version=0x{:04x}, len={}",
        record_type,
        tls_version,
        record_len
    );

    let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
    if conn.ciphertext_read_buf.len() < total_record_len {
        return Ok(());
    }

    if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
        tracing::debug!(
            "REALITY CLIENT: Skipping ChangeCipherSpec record ({} bytes)",
            record_len
        );
        conn.ciphertext_read_buf.consume(total_record_len);
        return process_encrypted_handshake(conn);
    }

    if record_type != CONTENT_TYPE_APPLICATION_DATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Application Data record, got 0x{:02x}",
                record_type
            ),
        ));
    }

    let ciphertext: Vec<u8> =
        conn.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
    conn.ciphertext_read_buf.consume(total_record_len);

    tracing::debug!(
        "REALITY CLIENT: Decrypting handshake record #{} - record_len={}",
        handshake_seq,
        record_len
    );

    let plaintext = decrypt_handshake_message_for_suite(
        cipher_suite,
        &server_hs_key,
        &server_hs_iv,
        handshake_seq,
        &ciphertext,
        record_len as u16,
    )?;
    handshake_seq = handshake_seq.checked_add(1).ok_or_else(|| {
        io::Error::other("TLS handshake sequence number exhausted")
    })?;
    accumulated_plaintext.extend_from_slice(&plaintext);

    tracing::debug!(
        "REALITY CLIENT: Decrypted handshake record, accumulated {} bytes",
        accumulated_plaintext.len()
    );

    let mut offset = 0;
    let mut messages_found = 0;
    let mut certificate_verified = false;
    let mut ed25519_public_key = None;
    let mut cert_verify_offset = None;

    while offset < accumulated_plaintext.len() && messages_found < 4 {
        // Each handshake message has: type (1 byte) + length (3 bytes) + data
        if offset + 4 > accumulated_plaintext.len() {
            break;
        }

        let msg_type = accumulated_plaintext[offset];
        let msg_len = u32::from_be_bytes([
            0,
            accumulated_plaintext[offset + 1],
            accumulated_plaintext[offset + 2],
            accumulated_plaintext[offset + 3],
        ]) as usize;

        if offset + 4 + msg_len > accumulated_plaintext.len() {
            break;
        }

        let msg_name = match msg_type {
            HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
            HANDSHAKE_TYPE_CERTIFICATE => "Certificate",
            HANDSHAKE_TYPE_CERTIFICATE_VERIFY => "CertificateVerify",
            HANDSHAKE_TYPE_FINISHED => "Finished",
            _ => "Unknown",
        };

        tracing::info!(
            "REALITY CLIENT: Found {} message (type={}, len={})",
            msg_name,
            msg_type,
            msg_len
        );

        // Verify HMAC signature when we encounter the Certificate message
        if msg_type == HANDSHAKE_TYPE_CERTIFICATE {
            let cert_der = extract_certificate_der(
                &accumulated_plaintext[offset..offset + 4 + msg_len],
            )?;
            verify_certificate_hmac(cert_der, &auth_key)?;
            ed25519_public_key = Some(extract_ed25519_public_key(cert_der)?);
            certificate_verified = true;
        }

        if msg_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
            cert_verify_offset = Some(offset);
        }

        messages_found += 1;
        offset += 4 + msg_len;
    }

    if messages_found < 4 {
        tracing::debug!(
            "REALITY CLIENT: Received {} of 4 handshake messages, waiting for more records",
            messages_found
        );
        conn.handshake_state = HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret: client_hs_secret,
            server_handshake_traffic_secret: server_hs_secret,
            master_secret,
            cipher_suite: cipher_suite_id,
            handshake_transcript_bytes: transcript_bytes,
            auth_key,
            handshake_seq,
            accumulated_plaintext,
        };
        return Ok(());
    }

    if !certificate_verified {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY handshake failed: Certificate message not received or not verified",
        ));
    }

    let mut cert_verify_verified = false;
    if let (Some(public_key), Some(cv_offset)) =
        (ed25519_public_key, cert_verify_offset)
    {
        let mut cv_transcript = digest::Context::new(&digest::SHA256);
        cv_transcript.update(&transcript_bytes);
        cv_transcript.update(&accumulated_plaintext[..cv_offset]);
        let cv_transcript_hash = cv_transcript.finish();

        let cv_msg_len = u32::from_be_bytes([
            0,
            accumulated_plaintext[cv_offset + 1],
            accumulated_plaintext[cv_offset + 2],
            accumulated_plaintext[cv_offset + 3],
        ]) as usize;
        let cv_message =
            &accumulated_plaintext[cv_offset..cv_offset + 4 + cv_msg_len];
        let signature = extract_certificate_verify_signature(cv_message)?;
        verify_certificate_verify_signature(
            &public_key,
            &signature,
            cv_transcript_hash.as_ref(),
        )?;
        cert_verify_verified = true;
    }

    if !cert_verify_verified {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY handshake failed: CertificateVerify not verified",
        ));
    }

    // Build handshake transcript
    let mut handshake_transcript = digest::Context::new(&digest::SHA256);
    handshake_transcript.update(&transcript_bytes); // Contains actual ClientHello + ServerHello bytes
    handshake_transcript.update(&accumulated_plaintext[..offset]); // EncryptedExtensions + Certificate + CertificateVerify + Finished

    let handshake_hash = handshake_transcript.finish();
    let mut handshake_hash_arr = [0u8; 32];
    handshake_hash_arr.copy_from_slice(handshake_hash.as_ref());

    tracing::info!(
        "REALITY CLIENT: Handshake hash for client Finished: {:02x?}",
        handshake_hash_arr
    );
    tracing::info!(
        "REALITY CLIENT: Transcript bytes len={}, accumulated_plaintext len={}",
        transcript_bytes.len(),
        offset
    );

    // Generate client Finished message
    let client_verify_data = compute_finished_verify_data_for_suite(
        cipher_suite,
        &client_hs_secret,
        &handshake_hash_arr,
    )?;
    tracing::info!(
        "REALITY CLIENT: Client verify data: {:02x?}",
        client_verify_data
    );
    let client_finished = construct_finished(&client_verify_data)?;

    // Derive client handshake traffic keys for encryption
    let (client_hs_key, client_hs_iv) =
        derive_traffic_keys_for_suite(&client_hs_secret, cipher_suite)?;

    // Encrypt Finished message
    let mut client_hs_seq = 0u64;
    let buf_len_before = conn.ciphertext_write_buf.len();
    encrypt_handshake_to_records_for_suite(
        cipher_suite,
        &client_finished,
        &client_hs_key,
        &client_hs_iv,
        &mut client_hs_seq,
        &mut conn.ciphertext_write_buf,
    )?;

    tracing::info!(
        "REALITY CLIENT: Client Finished message generated and buffered ({} bytes)",
        conn.ciphertext_write_buf.len() - buf_len_before
    );

    // Derive application secrets
    let (client_app_secret, server_app_secret) =
        derive_application_secrets_for_suite(
            cipher_suite,
            &master_secret,
            &handshake_hash_arr,
        )?;

    // Derive application traffic keys
    let (client_app_key, client_app_iv) =
        derive_traffic_keys_for_suite(&client_app_secret, cipher_suite)?;
    let (server_app_key, server_app_iv) =
        derive_traffic_keys_for_suite(&server_app_secret, cipher_suite)?;

    // Store application keys
    conn.app_read_key = Some(server_app_key);
    conn.app_read_iv = Some(server_app_iv);
    conn.app_write_key = Some(client_app_key);
    conn.app_write_iv = Some(client_app_iv);
    conn.read_seq = 0;
    conn.write_seq = 0;
    conn.cipher_suite = cipher_suite_id;

    // Mark handshake complete
    conn.handshake_state = HandshakeState::Complete;
    tracing::info!("REALITY CLIENT: Handshake complete, application keys derived");

    Ok(())
}

pub(super) fn process_application_data(
    conn: &mut RealityClientConnection,
) -> io::Result<()> {
    let (app_read_key, app_read_iv) = match (&conn.app_read_key, &conn.app_read_iv) {
        (Some(key), Some(iv)) => (key, iv),
        _ => return Ok(()),
    };
    let cipher_suite_id = conn.cipher_suite;
    let cipher_suite = CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid REALITY cipher suite in state: 0x{cipher_suite_id:04x}"
            ),
        )
    })?;
    let aead_key = AeadKey::new(cipher_suite, app_read_key)?;

    while conn.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
        let record_len = conn.ciphertext_read_buf.get_u16_be(3).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Buffer too short")
        })? as usize;

        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if conn.ciphertext_read_buf.len() < total_record_len {
            break;
        }

        let mut received_close_notify = false;
        let mut pending_error = None;
        {
            let ciphertext = conn
                .ciphertext_read_buf
                .slice_mut(TLS_RECORD_HEADER_SIZE..total_record_len);
            let mut decryptor =
                RecordDecryptor::new(&aead_key, app_read_iv, &mut conn.read_seq);
            let (content_type, plaintext) =
                decryptor.decrypt_record_in_place(ciphertext, record_len as u16)?;

            match content_type {
                CONTENT_TYPE_APPLICATION_DATA => {
                    conn.plaintext_read_buf.maybe_compact(4096);
                    conn.plaintext_read_buf.extend_from_slice(plaintext);
                }
                CONTENT_TYPE_ALERT => {
                    if plaintext.len() >= 2 {
                        let alert_level = plaintext[0];
                        let alert_desc = plaintext[1];

                        if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                            tracing::debug!(
                                "REALITY CLIENT: Received close_notify alert"
                            );
                            conn.received_close_notify = true;
                            received_close_notify = true;
                        } else if alert_level != ALERT_LEVEL_WARNING {
                            tracing::warn!(
                                "REALITY CLIENT: Received fatal alert: level={}, desc={}",
                                alert_level,
                                alert_desc
                            );
                            pending_error = Some(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                format!("received fatal alert: {}", alert_desc),
                            ));
                        } else {
                            tracing::debug!(
                                "REALITY CLIENT: Received warning alert: desc={}",
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
        conn.ciphertext_read_buf.consume(total_record_len);

        if let Some(err) = pending_error {
            return Err(err);
        }
        if received_close_notify {
            return Ok(());
        }
    }

    Ok(())
}
