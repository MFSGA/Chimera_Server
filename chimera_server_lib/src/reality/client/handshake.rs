use std::io;

use aws_lc_rs::{
    agreement,
    rand::{SecureRandom, SystemRandom},
};

use super::{HandshakeState, RealityClientConnection};
use crate::reality::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
use crate::reality::reality_tls13_messages::{construct_client_hello, write_record_header};

pub(super) fn generate_client_hello(conn: &mut RealityClientConnection) -> io::Result<()> {
    let rng = SystemRandom::new();

    // Generate our X25519 keypair
    let mut our_private_bytes = [0u8; 32];
    rng.fill(&mut our_private_bytes)
        .map_err(|_| io::Error::other("RNG failed"))?;

    let our_private_key =
        agreement::PrivateKey::from_private_key(&agreement::X25519, &our_private_bytes)
            .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
    let our_public_key_bytes = our_private_key
        .compute_public_key()
        .map_err(|_| io::Error::other("Failed to compute public key"))?;

    // Generate client random
    let mut client_random = [0u8; 32];
    rng.fill(&mut client_random)
        .map_err(|_| io::Error::other("RNG failed"))?;

    // Perform ECDH with server's public key to derive auth key
    let shared_secret = perform_ecdh(&our_private_bytes, &conn.config.public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Use slice directly from client_random to avoid copying
    let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], b"REALITY")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Create session ID with REALITY metadata
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| io::Error::other("System time error"))?
        .as_secs();

    let mut session_id_plaintext = [0u8; 16];
    session_id_plaintext[0] = 1; // Protocol version major
    session_id_plaintext[1] = 8; // Protocol version minor
    session_id_plaintext[2] = 0; // Protocol version patch
    session_id_plaintext[3] = 0; // Padding byte
    // Timestamp (4 bytes as uint32, in seconds)
    session_id_plaintext[4..8].copy_from_slice(&(timestamp as u32).to_be_bytes());
    // Short ID (8 bytes)
    session_id_plaintext[8..16].copy_from_slice(&conn.config.short_id);

    // Create a 32-byte SessionId (16 bytes plaintext + 16 bytes zeros for padding)
    let mut session_id_for_hello = [0u8; 32];
    session_id_for_hello[0..16].copy_from_slice(&session_id_plaintext);

    // Build ClientHello with plaintext SessionId first
    let mut client_hello = construct_client_hello(
        &client_random,
        &session_id_for_hello,
        our_public_key_bytes.as_ref(),
        &conn.config.server_name,
    )?;

    // Now encrypt the SessionId using the ClientHello with zeroed SessionId as AAD
    // Use slice directly from client_random to avoid copying
    let nonce = &client_random[20..32];

    // Zero out the SessionId in ClientHello to create AAD (matches what server will use)
    // SessionId is at offset 39 in ClientHello handshake
    client_hello[39..71].fill(0);

    tracing::debug!("REALITY CLIENT: Encrypting SessionId");
    tracing::debug!("  auth_key={:02x?}", &auth_key);
    tracing::debug!("  nonce={:02x?}", nonce);
    tracing::debug!("  plaintext={:02x?}", &session_id_plaintext);
    tracing::debug!(
        "  aad_len={} (ClientHello with zero SessionId)",
        client_hello.len()
    );
    tracing::debug!("  aad[0..4]={:02x?}", &client_hello[0..4]);

    let encrypted_session_id = encrypt_session_id(&session_id_plaintext, &auth_key, nonce, &client_hello)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    tracing::debug!(
        "REALITY CLIENT: Encrypted SessionId={:02x?}",
        &encrypted_session_id
    );

    // Replace the zeros with the encrypted SessionId
    client_hello[39..71].copy_from_slice(&encrypted_session_id);

    // Wrap in TLS record
    let mut record =
        write_record_header(super::super::common::CONTENT_TYPE_HANDSHAKE, client_hello.len() as u16);
    record.extend_from_slice(&client_hello);

    // Buffer for sending
    conn.ciphertext_write_buf.extend_from_slice(&record);

    // Update state
    conn.handshake_state = HandshakeState::AwaitingServerHello {
        client_hello_hash: digest_client_hello(&client_hello),
        client_hello_bytes: client_hello.clone(), // Save the actual ClientHello bytes
        client_private_key: our_private_bytes,
        auth_key, // Save auth_key for HMAC certificate verification
    };

    tracing::debug!(
        "REALITY: ClientHello generated and buffered ({} bytes)",
        record.len()
    );

    Ok(())
}

fn digest_client_hello(client_hello: &[u8]) -> [u8; 32] {
    let mut ch_transcript = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ch_transcript.update(client_hello);
    let client_hello_hash = ch_transcript.finish();
    let mut client_hello_hash_arr = [0u8; 32];
    client_hello_hash_arr.copy_from_slice(client_hello_hash.as_ref());
    client_hello_hash_arr
}
