use std::io;

use aws_lc_rs::{agreement, digest};

use super::{HandshakeState, RealityClientConnection};
use crate::reality::common::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, TLS_RECORD_HEADER_SIZE,
};
use crate::reality::reality_aead::{decrypt_handshake_message, decrypt_tls13_record};
use crate::reality::reality_client_verify::{extract_certificate_der, verify_certificate_hmac};
use crate::reality::reality_records::encrypt_handshake_to_records;
use crate::reality::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use crate::reality::reality_tls13_messages::construct_finished;
use crate::reality::reality_util::extract_server_public_key;

pub(super) fn process_server_hello(conn: &mut RealityClientConnection) -> io::Result<()> {
    // Extract state
    let (client_hello_hash, client_private_key, auth_key) = match &conn.handshake_state {
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
    let record_len = conn
        .ciphertext_read_buf
        .get_u16_be(3)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
        as usize;

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

    // Get the actual ClientHello bytes from our saved state
    let client_hello_bytes = match &conn.handshake_state {
        HandshakeState::AwaitingServerHello {
            client_hello_bytes, ..
        } => client_hello_bytes.clone(),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid handshake state",
            ))
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
    let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, &server_public_key);
    let my_private_key =
        agreement::PrivateKey::from_private_key(&agreement::X25519, &client_private_key)
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
    let hs_keys = derive_handshake_keys(
        &tls_shared_secret,
        &client_hello_hash,
        &server_hello_hash_arr,
    )?;

    // Use standard cipher suite
    const CIPHER_SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

    tracing::debug!("REALITY: ServerHello processed, handshake keys derived");

    // Initialize transcript with actual ClientHello and ServerHello bytes
    let mut transcript_bytes = Vec::new();
    transcript_bytes.extend_from_slice(&client_hello_bytes);
    transcript_bytes.extend_from_slice(server_hello);

    // Update state
    conn.handshake_state = HandshakeState::ProcessingHandshake {
        client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret.clone(),
        server_handshake_traffic_secret: hs_keys.server_handshake_traffic_secret.clone(),
        master_secret: hs_keys.master_secret.clone(),
        cipher_suite: CIPHER_SUITE,
        handshake_transcript_bytes: transcript_bytes,
        auth_key, // Pass auth_key for certificate HMAC verification
    };

    Ok(())
}

pub(super) fn process_encrypted_handshake(conn: &mut RealityClientConnection) -> io::Result<()> {
    // Extract state - we need to preserve it across multiple calls
    let (
        client_hs_secret,
        server_hs_secret,
        master_secret,
        cipher_suite,
        transcript_bytes,
        auth_key,
    ) = match &conn.handshake_state {
        HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_transcript_bytes,
            auth_key,
        } => (
            client_handshake_traffic_secret.clone(),
            server_handshake_traffic_secret.clone(),
            master_secret.clone(),
            *cipher_suite,
            handshake_transcript_bytes.clone(),
            *auth_key,
        ),
        _ => return Ok(()),
    };

    // Derive server handshake traffic keys for decryption
    let (server_hs_key, server_hs_iv) = derive_traffic_keys(&server_hs_secret, cipher_suite)?;

    tracing::debug!(
        "REALITY CLIENT: Server HS key={:02x?}, iv={:02x?}",
        &server_hs_key[..16],
        &server_hs_iv
    );

    // Check if we have enough data for a TLS record header
    if conn.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
        return Ok(()); // Need more data
    }

    // Check record type
    let record_type = conn.ciphertext_read_buf[0];
    let tls_version = conn
        .ciphertext_read_buf
        .get_u16_be(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?;
    let record_len = conn
        .ciphertext_read_buf
        .get_u16_be(3)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
        as usize;

    tracing::debug!(
        "REALITY CLIENT: TLS record header: type=0x{:02x}, version=0x{:04x}, len={}",
        record_type,
        tls_version,
        record_len
    );

    // Check if we have the complete record
    let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
    if conn.ciphertext_read_buf.len() < total_record_len {
        return Ok(()); // Need more data
    }

    // Skip ChangeCipherSpec records - these are dummy in TLS 1.3
    if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
        tracing::debug!(
            "REALITY CLIENT: Skipping ChangeCipherSpec record ({} bytes)",
            record_len
        );
        conn.ciphertext_read_buf.consume(total_record_len);
        return process_encrypted_handshake(conn);
    }

    // If it's not Application Data, we have a problem
    if record_type != CONTENT_TYPE_APPLICATION_DATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Expected Application Data record, got 0x{:02x}",
                record_type
            ),
        ));
    }

    // Copy and extract the combined handshake record
    let ciphertext: Vec<u8> =
        conn.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
    conn.ciphertext_read_buf.consume(total_record_len);

    tracing::debug!(
        "REALITY CLIENT: Decrypting combined handshake record - record_type=0x{:02x}, record_len={}, seq=0",
        record_type,
        record_len
    );

    // Try different sequence numbers - some servers count differently
    let mut combined_plaintext = None;
    for seq in 0..3 {
        match decrypt_handshake_message(
            &server_hs_key,
            &server_hs_iv,
            seq,
            &ciphertext,
            record_len as u16,
        ) {
            Ok(plaintext) => {
                combined_plaintext = Some(plaintext);
                break;
            }
            Err(_) if seq < 2 => {
                tracing::debug!(
                    "REALITY CLIENT: Decryption failed with seq={}, trying next",
                    seq
                );
                continue;
            }
            Err(e) => {
                tracing::error!(
                    "REALITY CLIENT: Failed to decrypt combined handshake with all sequence numbers: {}",
                    e
                );
                return Err(e);
            }
        }
    }

    let combined_plaintext = combined_plaintext.unwrap();

    tracing::info!(
        "REALITY CLIENT: Successfully decrypted combined handshake record ({} bytes plaintext)",
        combined_plaintext.len()
    );

    // Now parse the individual handshake messages from the combined plaintext
    let mut offset = 0;
    let mut messages_found = 0;
    let mut certificate_verified = false;

    while offset < combined_plaintext.len() && messages_found < 4 {
        // Each handshake message has: type (1 byte) + length (3 bytes) + data
        if offset + 4 > combined_plaintext.len() {
            break;
        }

        let msg_type = combined_plaintext[offset];
        let msg_len = u32::from_be_bytes([
            0,
            combined_plaintext[offset + 1],
            combined_plaintext[offset + 2],
            combined_plaintext[offset + 3],
        ]) as usize;

        if offset + 4 + msg_len > combined_plaintext.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid handshake message length: {} at offset {}",
                    msg_len, offset
                ),
            ));
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
            let cert_der =
                extract_certificate_der(&combined_plaintext[offset..offset + 4 + msg_len])?;
            verify_certificate_hmac(cert_der, &auth_key)?;
            certificate_verified = true;
        }

        messages_found += 1;
        offset += 4 + msg_len;
    }

    // Check if we got all 4 messages AND the certificate was verified
    if messages_found != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected 4 handshake messages, found {}", messages_found),
        ));
    }

    if !certificate_verified {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY handshake failed: Certificate message not received or not verified",
        ));
    }

    // Build handshake transcript
    let mut handshake_transcript = digest::Context::new(&digest::SHA256);
    handshake_transcript.update(&transcript_bytes); // Contains actual ClientHello + ServerHello bytes
    handshake_transcript.update(&combined_plaintext); // EncryptedExtensions + Certificate + CertificateVerify + Finished

    let handshake_hash = handshake_transcript.finish();
    let mut handshake_hash_arr = [0u8; 32];
    handshake_hash_arr.copy_from_slice(handshake_hash.as_ref());

    tracing::info!(
        "REALITY CLIENT: Handshake hash for client Finished: {:02x?}",
        handshake_hash_arr
    );
    tracing::info!(
        "REALITY CLIENT: Transcript bytes len={}, combined_plaintext len={}",
        transcript_bytes.len(),
        combined_plaintext.len()
    );

    // Generate client Finished message
    let client_verify_data = compute_finished_verify_data(&client_hs_secret, &handshake_hash_arr)?;
    tracing::info!(
        "REALITY CLIENT: Client verify data: {:02x?}",
        client_verify_data
    );
    let client_finished = construct_finished(&client_verify_data)?;

    // Derive client handshake traffic keys for encryption
    let (client_hs_key, client_hs_iv) = derive_traffic_keys(&client_hs_secret, cipher_suite)?;

    // Encrypt Finished message
    let mut client_hs_seq = 0u64;
    let buf_len_before = conn.ciphertext_write_buf.len();
    encrypt_handshake_to_records(
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
        derive_application_secrets(&master_secret, &handshake_hash_arr)?;

    // Derive application traffic keys
    let (client_app_key, client_app_iv) = derive_traffic_keys(&client_app_secret, cipher_suite)?;
    let (server_app_key, server_app_iv) = derive_traffic_keys(&server_app_secret, cipher_suite)?;

    // Store application keys
    conn.app_read_key = Some(server_app_key);
    conn.app_read_iv = Some(server_app_iv);
    conn.app_write_key = Some(client_app_key);
    conn.app_write_iv = Some(client_app_iv);
    conn.read_seq = 0;
    conn.write_seq = 0;
    conn.cipher_suite = cipher_suite;

    // Mark handshake complete
    conn.handshake_state = HandshakeState::Complete;
    tracing::info!("REALITY CLIENT: Handshake complete, application keys derived");

    Ok(())
}

pub(super) fn process_application_data(conn: &mut RealityClientConnection) -> io::Result<()> {
    let (app_read_key, app_read_iv) = match (&conn.app_read_key, &conn.app_read_iv) {
        (Some(key), Some(iv)) => (key, iv),
        _ => return Ok(()),
    };

    while conn.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
        let record_len = conn
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;

        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if conn.ciphertext_read_buf.len() < total_record_len {
            break;
        }

        // Copy record header for decryption AAD
        let tls_header: [u8; TLS_RECORD_HEADER_SIZE] = [
            conn.ciphertext_read_buf[0],
            conn.ciphertext_read_buf[1],
            conn.ciphertext_read_buf[2],
            conn.ciphertext_read_buf[3],
            conn.ciphertext_read_buf[4],
        ];
        let ciphertext: Vec<u8> =
            conn.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
        conn.ciphertext_read_buf.consume(total_record_len);

        let mut plaintext = decrypt_tls13_record(
            app_read_key,
            app_read_iv,
            conn.read_seq,
            &ciphertext,
            &tls_header,
        )?;

        conn.read_seq += 1;

        // TLS 1.3: Remove ContentType trailer byte
        if !plaintext.is_empty() {
            let content_type = plaintext.pop().unwrap();

            if content_type != CONTENT_TYPE_APPLICATION_DATA && content_type != CONTENT_TYPE_ALERT {
                tracing::warn!(
                    "REALITY CLIENT: Unexpected ContentType: 0x{:02x}",
                    content_type
                );
            }
        }

        // Compact plaintext buffer if needed before extending
        conn.plaintext_read_buf.maybe_compact(4096);
        conn.plaintext_read_buf.extend_from_slice(&plaintext);
    }

    Ok(())
}
