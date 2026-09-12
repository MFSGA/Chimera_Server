use std::io::Write;

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
        dest: NetLocation::new(Address::Hostname("example.com".to_string()), 443),
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
        let len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
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
fn writer_counts_pending_tls_output_toward_combined_limit() {
    let (private_key, _) = test_reality_keypair();
    let mut conn =
        RealityServerConnection::new(test_server_config(private_key)).unwrap();
    conn.ciphertext_write_buf =
        vec![0; crate::reality::common::OUTGOING_BUFFER_LIMIT - 3];

    let mut writer = conn.writer();
    assert_eq!(writer.write(b"hello").unwrap(), 3);
    assert_eq!(writer.write(b"world").unwrap(), 0);
    assert_eq!(conn.plaintext_write_buf, b"hel");
}

#[test]
fn timestamp_diff_preserves_xray_millisecond_precision() {
    let now = std::time::Duration::new(1_000, 750_000_000);

    assert_eq!(
        timestamp_diff(now, 1_000),
        std::time::Duration::from_millis(750)
    );
    assert_eq!(
        timestamp_diff(now, 1_001),
        std::time::Duration::from_millis(250)
    );
    assert!(
        timestamp_diff(now, 1_000) > std::time::Duration::from_millis(749),
        "current Xray compares the exact duration rather than rounded seconds"
    );
    assert_eq!(
        timestamp_diff(now, 1_000),
        std::time::Duration::from_millis(750),
        "the exact maxTimeDiff boundary remains accepted"
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

    let invalid_empty_handshake = [CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x00];
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
