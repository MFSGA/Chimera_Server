use std::io;

use aws_lc_rs::{
    agreement,
    kem::{DecapsulationKey, ML_KEM_768},
    rand::{SecureRandom, SystemRandom},
};

use super::{HandshakeState, RealityClientConnection};
use crate::reality::reality_auth::{
    derive_auth_key, encrypt_session_id, perform_ecdh,
};
use crate::reality::reality_cipher_suite::DEFAULT_CIPHER_SUITES;
use crate::reality::reality_tls13_messages::{
    DEFAULT_ALPN_PROTOCOLS, construct_client_hello_with_key_shares,
    write_record_header,
};

const XRAY_COMPAT_CLIENT_VERSION: [u8; 3] = [26, 7, 28];

pub(super) fn generate_client_hello(
    conn: &mut RealityClientConnection,
) -> io::Result<()> {
    let rng = SystemRandom::new();

    // Generate our X25519 keypair
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

    // Generate client random
    let mut client_random = [0u8; 32];
    rng.fill(&mut client_random)
        .map_err(|_| io::Error::other("RNG failed"))?;

    // Perform ECDH with server's public key to derive auth key
    let shared_secret = perform_ecdh(&our_private_bytes, &conn.config.public_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Use slice directly from client_random to avoid copying
    let auth_key =
        derive_auth_key(&shared_secret, &client_random[0..20], b"REALITY").map_err(
            |e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
        )?;

    // Create session ID with REALITY metadata
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| io::Error::other("System time error"))?
        .as_secs();

    let mut session_id_plaintext = [0u8; 16];
    session_id_plaintext[0..3].copy_from_slice(&XRAY_COMPAT_CLIENT_VERSION);
    session_id_plaintext[3] = 0; // Padding byte
    // Timestamp (4 bytes as uint32, in seconds)
    session_id_plaintext[4..8].copy_from_slice(&(timestamp as u32).to_be_bytes());
    // Short ID (8 bytes)
    session_id_plaintext[8..16].copy_from_slice(&conn.config.short_id);

    // Create a 32-byte SessionId (16 bytes plaintext + 16 bytes zeros for padding)
    let mut session_id_for_hello = [0u8; 32];
    session_id_for_hello[0..16].copy_from_slice(&session_id_plaintext);

    // Build ClientHello with plaintext SessionId first
    // Use configured cipher suites or defaults if none specified
    let cipher_suites = if conn.config.cipher_suites.is_empty() {
        DEFAULT_CIPHER_SUITES.to_vec()
    } else {
        conn.config.cipher_suites.clone()
    };
    let cipher_suite_ids: Vec<u16> =
        cipher_suites.iter().map(|suite| suite.id()).collect();
    let mlkem_decapsulation_key = DecapsulationKey::generate(&ML_KEM_768)
        .map_err(|_| io::Error::other("Failed to generate ML-KEM-768 key"))?;
    let mlkem_encapsulation_key = mlkem_decapsulation_key
        .encapsulation_key()
        .map_err(|_| io::Error::other("Failed to derive ML-KEM-768 public key"))?;
    let mlkem_public_key = mlkem_encapsulation_key
        .key_bytes()
        .map_err(|_| io::Error::other("Failed to encode ML-KEM-768 public key"))?;
    let x25519_public_key: [u8; 32] = our_public_key_bytes
        .as_ref()
        .try_into()
        .map_err(|_| io::Error::other("X25519 public key has an invalid length"))?;
    let mut hybrid_key_share =
        Vec::with_capacity(mlkem_public_key.as_ref().len() + 32);
    hybrid_key_share.extend_from_slice(mlkem_public_key.as_ref());
    hybrid_key_share.extend_from_slice(&x25519_public_key);
    let client_key_shares = [
        (0x11ec, hybrid_key_share.as_slice()), // X25519MLKEM768
        (0x001d, x25519_public_key.as_slice()), // X25519 fallback share
    ];
    let mut client_hello = construct_client_hello_with_key_shares(
        &client_random,
        &session_id_for_hello,
        &client_key_shares,
        &conn.config.server_name,
        &cipher_suite_ids,
        DEFAULT_ALPN_PROTOCOLS,
    )?;

    // Now encrypt the SessionId using the ClientHello with zeroed SessionId as AAD
    // Use slice directly from client_random to avoid copying
    let nonce = &client_random[20..32];

    // Zero out the SessionId in ClientHello to create AAD (matches what server will use)
    // SessionId is at offset 39 in ClientHello handshake
    client_hello[39..71].fill(0);

    tracing::debug!(
        "REALITY CLIENT: Encrypting SessionId (auth_key_len={}, nonce_len={}, plaintext_len={}, aad_len={})",
        auth_key.len(),
        nonce.len(),
        session_id_plaintext.len(),
        client_hello.len()
    );

    let encrypted_session_id =
        encrypt_session_id(&session_id_plaintext, &auth_key, nonce, &client_hello)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    tracing::debug!(
        "REALITY CLIENT: Encrypted SessionId generated (len={})",
        encrypted_session_id.len()
    );

    // Replace the zeros with the encrypted SessionId
    client_hello[39..71].copy_from_slice(&encrypted_session_id);

    // Wrap in TLS record
    let mut record = write_record_header(
        super::super::common::CONTENT_TYPE_HANDSHAKE,
        client_hello.len() as u16,
    );
    record.extend_from_slice(&client_hello);

    // Buffer for sending
    conn.ciphertext_write_buf.extend_from_slice(&record);

    // Update state
    conn.handshake_state = HandshakeState::AwaitingServerHello {
        client_hello_bytes: client_hello.clone(), // Save the actual ClientHello bytes
        client_private_key: our_private_bytes,
        auth_key, // Save auth_key for HMAC certificate verification
        mlkem_decapsulation_key: Some(mlkem_decapsulation_key),
    };

    tracing::debug!(
        "REALITY: ClientHello generated and buffered ({} bytes)",
        record.len()
    );

    Ok(())
}
