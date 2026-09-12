use std::{
    future::poll_fn,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Barrier,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use aws_lc_rs::cipher::{EncryptingKey as CipherEncryptingKey, EncryptionContext};
use bytes::{Buf, BufMut, BytesMut};
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    },
    net::UdpSocket,
    time::timeout,
};

use crate::{
    address::{Address, BindLocation, NetLocation},
    async_stream::AsyncPing,
    beginning::udp::run_session_based_udp,
    config::{
        Transport,
        server_config::{ServerConfig, ServerProxyConfig},
    },
    handler::xudp::frame::{
        FrameMetadata, FrameOption, SessionStatus, TargetNetwork,
    },
    runtime::RuntimeState,
};

use super::super::fnv1a::Fnv1aHasher;
use super::*;

struct TestStream(DuplexStream);

impl AsyncRead for TestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsyncPing for TestStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for TestStream {}

fn vmess_user(user_id: &str, user_label: &str, cipher: &str) -> VmessUser {
    vmess_user_with_level(user_id, user_label, cipher, 0)
}

fn vmess_user_with_level(
    user_id: &str,
    user_label: &str,
    cipher: &str,
    user_level: u32,
) -> VmessUser {
    VmessUser {
        user_id: user_id.into(),
        user_label: user_label.into(),
        user_level,
        cipher: cipher.into(),
    }
}

static NEXT_AUTH_ID_RANDOM: AtomicU32 = AtomicU32::new(0x1234_5678);

fn build_auth_id(user_id: &str, time_secs: u64) -> [u8; 16] {
    build_auth_id_with_random(user_id, time_secs, [0x12, 0x34, 0x56, 0x78])
}

fn build_auth_id_with_random(
    user_id: &str,
    time_secs: u64,
    random: [u8; 4],
) -> [u8; 16] {
    let instruction_key = command_key_for_user_id(user_id);
    let derived_key =
        super::super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
    let unbound_key = UnboundCipherKey::new(&AES_128, &derived_key[0..16]).unwrap();
    let encrypting_key = CipherEncryptingKey::ecb(unbound_key).unwrap();

    let mut auth_id = [0u8; 16];
    auth_id[0..8].copy_from_slice(&time_secs.to_be_bytes());
    auth_id[8..12].copy_from_slice(&random);
    let checksum = super::super::crc32::crc32c(&auth_id[0..12]);
    auth_id[12..16].copy_from_slice(&checksum.to_be_bytes());
    encrypting_key
        .less_safe_encrypt(&mut auth_id, EncryptionContext::None)
        .unwrap();
    auth_id
}

fn build_plain_request_header(command: u8) -> Vec<u8> {
    build_plain_request_header_with_cipher(command, 5)
}

fn build_plain_request_header_with_cipher(command: u8, cipher: u8) -> Vec<u8> {
    let mut header = vec![0u8; 80];
    header[0] = 1;
    for (index, byte) in header[1..34].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(1);
    }
    header[34] = 0x01;
    header[35] = cipher;
    header[37] = command;
    let mut cursor = 38;
    if command != COMMAND_MUX {
        header[cursor..cursor + 2].copy_from_slice(&443u16.to_be_bytes());
        cursor += 2;
        header[cursor] = 1;
        cursor += 1;
        header[cursor..cursor + 4].copy_from_slice(&[127, 0, 0, 1]);
        cursor += 4;
    }

    let mut fnv_hasher = Fnv1aHasher::new();
    fnv_hasher.write(&header[..cursor]);
    header[cursor..cursor + 4].copy_from_slice(&fnv_hasher.finish().to_be_bytes());
    cursor += 4;
    header.truncate(cursor);
    header
}

fn build_plain_tcp_header_with_address(
    address_type: u8,
    address_payload: &[u8],
    margin: &[u8],
) -> Vec<u8> {
    assert!(margin.len() <= 15);
    let mut header = vec![0u8; 38];
    header[0] = 1;
    for (index, byte) in header[1..34].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(1);
    }
    header[34] = 0x01;
    header[35] = ((margin.len() as u8) << 4) | 5;
    header[37] = COMMAND_TCP;
    header.extend_from_slice(&443u16.to_be_bytes());
    header.push(address_type);
    header.extend_from_slice(address_payload);
    header.extend_from_slice(margin);

    let mut fnv_hasher = Fnv1aHasher::new();
    fnv_hasher.write(&header);
    header.extend_from_slice(&fnv_hasher.finish().to_be_bytes());
    header
}

fn encrypt_request_header(user_id: &str, header: &[u8]) -> Vec<u8> {
    assert!(header.len() <= u16::MAX as usize);
    let instruction_key = command_key_for_user_id(user_id);
    let cert_hash = build_auth_id_with_random(
        user_id,
        current_time_secs(),
        NEXT_AUTH_ID_RANDOM
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes(),
    );
    let nonce = [0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f];

    let header_length_aead_key = super::super::sha2::kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
    );
    let header_length_nonce = super::super::sha2::kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
    );
    let mut encrypted_length = [0u8; 18];
    encrypted_length[0..2].copy_from_slice(&(header.len() as u16).to_be_bytes());
    let unbound_key =
        UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();
    let mut sealing_key = SealingKey::new(
        unbound_key,
        SingleUseNonce::new(&header_length_nonce[0..12]),
    );
    let tag = sealing_key
        .seal_in_place_separate_tag(
            Aad::from(&cert_hash),
            &mut encrypted_length[0..2],
        )
        .unwrap();
    encrypted_length[2..].copy_from_slice(tag.as_ref());

    let header_aead_key = super::super::sha2::kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &cert_hash, &nonce],
    );
    let header_nonce = super::super::sha2::kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
    );
    let unbound_key =
        UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
    let mut sealing_key =
        SealingKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));
    let mut encrypted_header = header.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut encrypted_header)
        .unwrap();
    encrypted_header.extend_from_slice(tag.as_ref());

    let mut request = Vec::with_capacity(
        16 + encrypted_length.len() + nonce.len() + encrypted_header.len(),
    );
    request.extend_from_slice(&cert_hash);
    request.extend_from_slice(&encrypted_length);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&encrypted_header);
    request
}

fn build_request(user_id: &str, command: u8) -> Vec<u8> {
    encrypt_request_header(user_id, &build_plain_request_header(command))
}

fn build_tcp_request(user_id: &str) -> Vec<u8> {
    build_request(user_id, COMMAND_TCP)
}

fn build_mux_request(user_id: &str, xudp_frame: &[u8]) -> Vec<u8> {
    let mut request = build_request(user_id, COMMAND_MUX);
    request.extend_from_slice(&(xudp_frame.len() as u16).to_be_bytes());
    request.extend_from_slice(xudp_frame);
    request
}

fn current_time_secs() -> u64 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs()
}

#[tokio::test]
async fn runtime_user_store_updates_existing_handler_without_rebuild() {
    let inbound_tag = "vmess-runtime-users";
    let first_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let second_id = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
    let first = vmess_user(first_id, "first-user", "none");
    let second = vmess_user(second_id, "second-user", "none");
    let runtime = RuntimeState::new(
        vec![ServerConfig {
            tag: inbound_tag.to_string(),
            bind_location: BindLocation::Address(NetLocation::new(
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                10001,
            )),
            protocol: ServerProxyConfig::Vmess {
                users: vec![first.clone()],
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        }],
        Vec::new(),
    );
    let handler = VmessTcpServerHandler::new(vec![first.clone()], true, inbound_tag);
    let context = TcpServerConnectionContext {
        handshake_runtime: Some(runtime.data_plane().inbound_handshake_runtime()),
        ..TcpServerConnectionContext::default()
    };

    let (mut first_client, first_server) = duplex(1024);
    first_client
        .write_all(&build_tcp_request(first_id))
        .await
        .unwrap();
    let first_result = handler
        .setup_server_stream_with_context(
            Box::new(TestStream(first_server)),
            context.clone(),
        )
        .await
        .expect("initial VMess user should authenticate");
    let TcpServerSetupResult::TcpForward {
        traffic_context, ..
    } = first_result
    else {
        panic!("VMess TCP request should produce a TCP forward");
    };
    assert_eq!(
        traffic_context.and_then(|context| context.identity),
        Some("first-user".to_string())
    );

    let store = runtime
        .vmess_user_store(inbound_tag)
        .expect("single VMess inbound should expose runtime users");
    store
        .update::<(), (), _>(|users| {
            users.push(second.clone());
            Ok(())
        })
        .unwrap();

    let (mut second_client, second_server) = duplex(1024);
    second_client
        .write_all(&build_tcp_request(second_id))
        .await
        .unwrap();
    let second_result = handler
        .setup_server_stream_with_context(
            Box::new(TestStream(second_server)),
            context,
        )
        .await
        .expect("new VMess user should authenticate without rebuilding handler");
    let TcpServerSetupResult::TcpForward {
        traffic_context, ..
    } = second_result
    else {
        panic!("VMess TCP request should produce a TCP forward");
    };
    assert_eq!(
        traffic_context.and_then(|context| context.identity),
        Some("second-user".to_string())
    );
}

#[tokio::test]
async fn authenticated_truncated_headers_return_errors_instead_of_panicking() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "truncation-test", "none")],
        true,
        "vmess-truncation",
    );

    for command in [COMMAND_TCP, COMMAND_MUX] {
        let full_header = build_plain_request_header(command);
        for prefix_length in 0..full_header.len() {
            let request =
                encrypt_request_header(user_id, &full_header[..prefix_length]);
            let (mut client, server) = duplex(1024);
            client
                .write_all(&request)
                .await
                .expect("write authenticated truncated VMess header");

            let error = match handler
                .setup_server_stream(Box::new(TestStream(server)))
                .await
            {
                Ok(_) => panic!(
                    "authenticated VMess header prefix {prefix_length} for command {command} must fail"
                ),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::InvalidData
                ),
                "prefix {prefix_length}, command {command}: {error}"
            );
        }
    }
}

#[tokio::test]
async fn supported_cipher_matrix_negotiates() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    for (configured_cipher, requested_cipher) in [
        ("aes-128-gcm", 3),
        ("chacha20-poly1305", 4),
        ("auto", 3),
        ("auto", 4),
        ("auto", 5),
    ] {
        let handler = VmessTcpServerHandler::new(
            vec![vmess_user(user_id, "cipher-user", configured_cipher)],
            false,
            "vmess-cipher-matrix",
        );
        let header =
            build_plain_request_header_with_cipher(COMMAND_TCP, requested_cipher);
        let request = encrypt_request_header(user_id, &header);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write supported VMess cipher request");

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("supported VMess cipher request must succeed");

        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }
}

#[tokio::test]
async fn configured_client_security_does_not_restrict_inbound_cipher() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    for (configured_cipher, requested_cipher) in
        [("none", 3), ("aes-128-gcm", 4), ("chacha20-poly1305", 5)]
    {
        let handler = VmessTcpServerHandler::new(
            vec![vmess_user(user_id, "cipher-parity", configured_cipher)],
            false,
            "vmess-cipher-parity",
        );
        let header =
            build_plain_request_header_with_cipher(COMMAND_TCP, requested_cipher);
        let request = encrypt_request_header(user_id, &header);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write VMess request with independently selected cipher");

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("VMess inbound must not enforce client-side account security");

        assert!(matches!(result, TcpServerSetupResult::TcpForward { .. }));
    }
}

#[tokio::test]
async fn unsupported_cipher_values_are_rejected() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    for requested_cipher in [1, 2, 0x0f] {
        let handler = VmessTcpServerHandler::new(
            vec![vmess_user(user_id, "unsupported-cipher", "auto")],
            false,
            "vmess-unsupported-cipher",
        );
        let header =
            build_plain_request_header_with_cipher(COMMAND_TCP, requested_cipher);
        let request = encrypt_request_header(user_id, &header);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write unsupported VMess cipher request");

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => panic!("unsupported VMess cipher must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn authenticated_empty_domain_and_unknown_address_type_are_rejected() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "invalid-address-test", "none")],
        false,
        "vmess-invalid-address",
    );

    for (description, header) in [
        (
            "empty domain",
            build_plain_tcp_header_with_address(2, &[0], &[]),
        ),
        (
            "unknown address type",
            build_plain_tcp_header_with_address(0xff, &[], &[]),
        ),
    ] {
        let request = encrypt_request_header(user_id, &header);
        let (mut client, server) = duplex(1024);
        client
            .write_all(&request)
            .await
            .expect("write invalid authenticated VMess header");

        let error = match handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
        {
            Ok(_) => {
                panic!("authenticated VMess {description} must be rejected")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn authenticated_ipv6_header_with_max_margin_parses() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "ipv6-margin-test", "none")],
        false,
        "vmess-ipv6-margin",
    );
    let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6);
    let header = build_plain_tcp_header_with_address(3, &ipv6.octets(), &[0xa5; 15]);
    let request = encrypt_request_header(user_id, &header);
    let (mut client, server) = duplex(1024);
    client
        .write_all(&request)
        .await
        .expect("write authenticated IPv6 VMess header");

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("authenticated IPv6 VMess header must parse");

    match result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            traffic_context,
            ..
        } => {
            assert_eq!(remote_location, NetLocation::new(Address::Ipv6(ipv6), 443));
            assert_eq!(
                traffic_context.and_then(|context| context.identity),
                Some("ipv6-margin-test".to_string())
            );
        }
        _ => panic!("IPv6 VMess header returned a non-TCP result"),
    }
}

#[test]
fn command_key_matches_xray_core_vector() {
    assert_eq!(
        command_key_for_user_id("3ac9b383-75a1-431c-8184-106c80eb2273"),
        [
            0xe0, 0x13, 0x98, 0xbf, 0x63, 0xa6, 0x5d, 0x23, 0x30, 0xf7, 0x64, 0xf6,
            0xb8, 0xf1, 0x99, 0x46,
        ]
    );
}

#[test]
fn authenticate_user_rejects_replayed_auth_id() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "replay-user", "none")],
        false,
        "vmess-replay",
    );
    let now = 1_000_000;
    let auth_id = build_auth_id(user_id, now);

    handler
        .authenticate_user_at(&auth_id, now)
        .expect("first VMess AuthID use must succeed");
    let error = match handler.authenticate_user_at(&auth_id, now) {
        Ok(_) => panic!("second VMess AuthID use must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("replayed VMess AuthID"));
}

#[test]
fn concurrent_replay_check_allows_exactly_one_authentication() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = Arc::new(VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "concurrent-user", "none")],
        false,
        "vmess-concurrent-replay",
    ));
    let now = 2_000_000;
    let auth_id = build_auth_id(user_id, now);
    let barrier = Arc::new(Barrier::new(8));

    let results = std::thread::scope(|scope| {
        (0..8)
            .map(|_| {
                let handler = Arc::clone(&handler);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    handler.authenticate_user_at(&auth_id, now).is_ok()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("VMess replay test thread"))
            .collect::<Vec<_>>()
    });

    assert_eq!(results.into_iter().filter(|accepted| *accepted).count(), 1);
}

#[test]
fn same_timestamp_with_different_random_values_is_allowed() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "random-user", "none")],
        false,
        "vmess-random-auth-id",
    );
    let now = 3_000_000;
    let first = build_auth_id_with_random(user_id, now, [1, 2, 3, 4]);
    let second = build_auth_id_with_random(user_id, now, [5, 6, 7, 8]);

    handler
        .authenticate_user_at(&first, now)
        .expect("first unique VMess AuthID must succeed");
    handler
        .authenticate_user_at(&second, now)
        .expect("second unique VMess AuthID in the same second must succeed");
}

#[test]
fn replay_filter_keeps_previous_generation_at_rotation_boundary() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "window-user", "none")],
        false,
        "vmess-replay-window",
    );
    let issued_at = 4_000_000;
    let auth_id = build_auth_id(user_id, issued_at);

    handler
        .authenticate_user_at(&auth_id, issued_at)
        .expect("initial VMess AuthID use must succeed");
    let replay = match handler.authenticate_user_at(&auth_id, issued_at + 119) {
        Ok(_) => panic!("VMess AuthID must remain blocked before TTL expiry"),
        Err(error) => error,
    };
    assert_eq!(replay.kind(), std::io::ErrorKind::PermissionDenied);
    let boundary_replay =
        match handler.authenticate_user_at(&auth_id, issued_at + 120) {
            Ok(_) => panic!(
                "VMess AuthID must remain blocked in the previous replay generation"
            ),
            Err(error) => error,
        };
    assert_eq!(boundary_replay.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn full_handshake_replay_is_rejected_before_header_processing() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "full-replay-user", "none")],
        false,
        "vmess-full-replay",
    );
    let request = build_tcp_request(user_id);

    let (mut first_client, first_server) = duplex(1024);
    first_client
        .write_all(&request)
        .await
        .expect("write first VMess replay fixture");
    handler
        .setup_server_stream(Box::new(TestStream(first_server)))
        .await
        .expect("first VMess request must succeed");

    let (mut replay_client, replay_server) = duplex(1024);
    replay_client
        .write_all(&request)
        .await
        .expect("write replayed VMess request");
    let error = match handler
        .setup_server_stream(Box::new(TestStream(replay_server)))
        .await
    {
        Ok(_) => panic!("replayed full VMess handshake must fail"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("replayed VMess AuthID"));
}

#[test]
fn replay_cache_does_not_rotate_backward_on_clock_rollback() {
    let first = [3u8; 16];
    let second = [4u8; 16];
    let mut cache = VmessReplayCache::default();

    assert!(cache.check_and_insert(first, 10_000));
    assert!(cache.check_and_insert(second, 10_120));
    assert!(!cache.check_and_insert(first, 9_000));
    assert!(!cache.check_and_insert(second, 9_000));
    assert_eq!(cache.last_rotation, 10_120);
}

#[test]
fn replay_cache_rotates_two_generations_like_xray() {
    let first = [1u8; 16];
    let second = [2u8; 16];
    let mut cache = VmessReplayCache::default();

    assert!(cache.check_and_insert(first, 1_000));
    assert!(cache.check_and_insert(second, 1_120));
    assert!(!cache.check_and_insert(first, 1_239));
    assert!(cache.check_and_insert(first, 1_240));
    assert!(cache.current.contains(&first));
    assert!(cache.previous.contains(&second));
}

#[test]
fn poisoned_replay_cache_recovers_without_panicking() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "poison-user", "none")],
        false,
        "vmess-poison-replay",
    );
    let poison_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = handler
                .replay_cache
                .lock()
                .expect("lock replay cache before poisoning");
            panic!("poison VMess replay cache for recovery test");
        }));
    assert!(poison_result.is_err());

    let now = 4_500_000;
    handler
        .authenticate_user_at(&build_auth_id(user_id, now), now)
        .expect("poisoned VMess replay cache must recover");
}

#[test]
fn auth_id_timestamp_window_rejects_past_and_future_values() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let now = 5_000_000;
    for issued_at in [now - 121, now + 121] {
        let handler = VmessTcpServerHandler::new(
            vec![vmess_user(user_id, "time-user", "none")],
            false,
            "vmess-time-window",
        );
        let auth_id = build_auth_id(user_id, issued_at);
        let error = match handler.authenticate_user_at(&auth_id, now) {
            Ok(_) => {
                panic!("VMess AuthID outside the timestamp window must fail")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("timestamp"));
    }
}

#[test]
fn authenticate_user_matches_each_configured_user() {
    let user_a_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let user_b_id = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
    let handler = VmessTcpServerHandler::new(
        vec![
            vmess_user(user_a_id, "user-a", "aes-128-gcm"),
            vmess_user(user_b_id, "user-b", "chacha20-poly1305"),
        ],
        false,
        "vmess-multi",
    );
    let now = current_time_secs();

    let user_a = handler
        .authenticate_user(&build_auth_id(user_a_id, now))
        .expect("first VMess user should authenticate");
    assert_eq!(user_a.user_label, "user-a");

    let user_b = handler
        .authenticate_user(&build_auth_id(user_b_id, now))
        .expect("second VMess user should authenticate");
    assert_eq!(user_b.user_label, "user-b");
}

#[test]
fn runtime_store_same_uuid_authenticates_last_added_user_like_xray() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let store = VmessUserStore::new(vec![
        vmess_user(user_id, "first-user", "none"),
        vmess_user(user_id, "second-user", "none"),
    ]);
    let now = current_time_secs();

    let user = store
        .authenticate_at(&build_auth_id(user_id, now), now)
        .expect("duplicate VMess UUID should still authenticate");
    assert_eq!(user.user_label, "second-user");
}

#[tokio::test]
async fn setup_server_stream_authenticates_each_configured_user() {
    let user_a_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let user_b_id = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
    let handler = VmessTcpServerHandler::new(
        vec![
            vmess_user_with_level(user_a_id, "user-a", "none", 3),
            vmess_user_with_level(user_b_id, "user-b", "none", 7),
        ],
        false,
        "vmess-multi",
    );

    for (user_id, expected_label, expected_level) in
        [(user_a_id, "user-a", 3), (user_b_id, "user-b", 7)]
    {
        let request = build_tcp_request(user_id);
        let (mut client, server) = duplex(1024);
        client.write_all(&request).await.unwrap();

        let result = handler
            .setup_server_stream(Box::new(TestStream(server)))
            .await
            .expect("VMess TCP handshake should succeed");

        match result {
            TcpServerSetupResult::TcpForward {
                remote_location,
                traffic_context,
                ..
            } => {
                assert_eq!(
                    remote_location,
                    NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443)
                );
                let traffic_context =
                    traffic_context.expect("VMess traffic context should exist");
                assert_eq!(
                    traffic_context.identity.as_deref(),
                    Some(expected_label)
                );
                assert_eq!(
                    traffic_context.inbound_tag.as_deref(),
                    Some("vmess-multi")
                );
                assert_eq!(traffic_context.user_level, expected_level);
            }
            _ => panic!("VMess TCP handshake returned a non-TCP result"),
        }
    }
}

#[tokio::test]
async fn setup_server_stream_returns_udp_message_session() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "udp-user", "none")],
        true,
        "vmess-udp",
    );
    let request = build_request(user_id, COMMAND_UDP);
    let (mut client, server) = duplex(1024);
    client.write_all(&request).await.unwrap();

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("VMess UDP handshake should succeed");

    match result {
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            traffic_context,
            ..
        } => {
            assert_eq!(
                remote_location,
                NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443)
            );
            let traffic_context =
                traffic_context.expect("VMess UDP traffic context should exist");
            assert_eq!(traffic_context.identity.as_deref(), Some("udp-user"));
            assert_eq!(traffic_context.inbound_tag.as_deref(), Some("vmess-udp"));
        }
        _ => panic!("VMess UDP handshake returned a non-UDP result"),
    }
}

#[tokio::test]
async fn setup_server_stream_rejects_udp_when_disabled() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "udp-user", "none")],
        false,
        "vmess-udp-disabled",
    );
    let request = build_request(user_id, COMMAND_UDP);
    let (mut client, server) = duplex(1024);
    client.write_all(&request).await.unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("disabled VMess UDP command must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("UDP command is disabled"));
}

#[tokio::test]
async fn fragmented_mux_request_preserves_first_xudp_frame() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "fragmented-vmess-xudp", "none")],
        true,
        "vmess-fragmented-xudp",
    );
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 5353));
    let mut xudp_frame = BytesMut::new();
    FrameMetadata {
        session_id: 43,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(NetLocation::from_ip_addr(target.ip(), target.port())),
        network: Some(TargetNetwork::Udp),
        global_id: None,
    }
    .encode(&mut xudp_frame)
    .expect("encode fragmented VMess XUDP frame");
    xudp_frame.put_u16(4);
    xudp_frame.extend_from_slice(b"ping");
    let request = build_mux_request(user_id, &xudp_frame);

    let (mut client, server) = duplex(1);
    let writer = tokio::spawn(async move {
        for byte in request {
            client
                .write_all(&[byte])
                .await
                .expect("write fragmented VMess MUX byte");
            tokio::task::yield_now().await;
        }
    });
    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("fragmented VMess MUX handshake must succeed");
    let TcpServerSetupResult::SessionBasedUdp {
        mut stream,
        traffic_context,
    } = result
    else {
        panic!("fragmented VMess MUX returned a non-session result");
    };
    let mut payload = [0u8; 16];
    let (message, length) = poll_fn(|cx| {
        let mut read_buffer = ReadBuf::new(&mut payload);
        match Pin::new(&mut *stream).poll_read_session_message(cx, &mut read_buffer)
        {
            Poll::Ready(Ok(message)) => {
                Poll::Ready(Ok((message, read_buffer.filled().len())))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
    .expect("read first fragmented VMess XUDP message");

    let crate::async_stream::SessionMessage::Data {
        session_id,
        target: actual_target,
        global_id,
        is_new,
    } = message
    else {
        panic!("fragmented VMess XUDP first frame decoded as End");
    };
    assert_eq!(session_id, 43);
    assert_eq!(actual_target, target);
    assert_eq!(global_id, None);
    assert!(is_new);
    assert_eq!(&payload[..length], b"ping");
    let context = traffic_context.expect("fragmented VMess XUDP context");
    assert_eq!(context.identity.as_deref(), Some("fragmented-vmess-xudp"));
    writer.await.expect("fragmented VMess MUX writer task");
}

#[tokio::test]
async fn mux_xudp_roundtrips_through_runtime() {
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind VMess XUDP echo socket");
    let echo_address = echo_socket.local_addr().expect("VMess XUDP echo address");
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        let (length, peer) = echo_socket
            .recv_from(&mut buffer)
            .await
            .expect("receive VMess XUDP echo request");
        echo_socket
            .send_to(&buffer[..length], peer)
            .await
            .expect("send VMess XUDP echo response");
    });

    let mut xudp_frame = BytesMut::new();
    FrameMetadata {
        session_id: 52,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(NetLocation::from_ip_addr(
            echo_address.ip(),
            echo_address.port(),
        )),
        network: Some(TargetNetwork::Udp),
        global_id: None,
    }
    .encode(&mut xudp_frame)
    .expect("encode VMess XUDP request metadata");
    xudp_frame.put_u16(4);
    xudp_frame.extend_from_slice(b"ping");

    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "xudp-user", "none")],
        true,
        "vmess-xudp",
    );
    let request = build_mux_request(user_id, &xudp_frame);
    let (mut client, server) = duplex(4096);
    client
        .write_all(&request)
        .await
        .expect("write VMess XUDP request");

    let result = handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
        .expect("VMess MUX/XUDP handshake should succeed");
    let TcpServerSetupResult::SessionBasedUdp {
        stream,
        traffic_context,
    } = result
    else {
        panic!("VMess MUX/XUDP returned a non-session result");
    };
    let context = traffic_context
        .as_ref()
        .expect("VMess XUDP traffic context should exist");
    assert_eq!(context.identity.as_deref(), Some("xudp-user"));
    assert_eq!(context.inbound_tag.as_deref(), Some("vmess-xudp"));

    let relay_task = tokio::spawn(run_session_based_udp(
        stream,
        RuntimeState::new(Vec::new(), Vec::new()).data_plane(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 43152)),
        None,
        traffic_context,
    ));

    let mut encrypted_response_header = [0u8; 38];
    timeout(
        Duration::from_secs(5),
        client.read_exact(&mut encrypted_response_header),
    )
    .await
    .expect("VMess response header timeout")
    .expect("read VMess response header");
    let body_length = client
        .read_u16()
        .await
        .expect("read VMess response body length") as usize;
    let mut body = BytesMut::zeroed(body_length);
    client
        .read_exact(&mut body)
        .await
        .expect("read VMess XUDP response body");
    let metadata = FrameMetadata::decode(&mut body)
        .expect("decode VMess XUDP response")
        .expect("complete VMess XUDP response");
    assert_eq!(metadata.session_id, 52);
    assert_eq!(metadata.status, SessionStatus::Keep);
    assert_eq!(body.get_u16(), 4);
    assert_eq!(&body[..], b"ping");

    echo_task.await.expect("VMess XUDP echo task should finish");
    relay_task.abort();
}

#[tokio::test]
async fn setup_server_stream_rejects_mux_when_udp_disabled() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "xudp-user", "none")],
        false,
        "vmess-xudp-disabled",
    );
    let request = build_request(user_id, COMMAND_MUX);
    let (mut client, server) = duplex(1024);
    client.write_all(&request).await.unwrap();

    let error = match handler
        .setup_server_stream(Box::new(TestStream(server)))
        .await
    {
        Ok(_) => panic!("disabled VMess MUX/XUDP command must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("MUX/XUDP command is disabled"));
}

#[test]
fn authenticate_user_rejects_unknown_uuid() {
    let handler = VmessTcpServerHandler::new(
        vec![
            vmess_user("3ac9b383-75a1-431c-8184-106c80eb2273", "user-a", "auto"),
            vmess_user("e041e73e-a0a0-49f5-9754-6401aa621fb7", "user-b", "auto"),
        ],
        false,
        "vmess-multi",
    );
    let unknown_auth_id =
        build_auth_id("5fdb6b11-c10d-4f81-9985-0f69f92dc82b", current_time_secs());

    let error = match handler.authenticate_user(&unknown_auth_id) {
        Ok(_) => panic!("unknown VMess UUID must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("no matching VMess user"));
}

#[test]
fn authenticate_user_preserves_single_user_behavior() {
    let user_id = "3ac9b383-75a1-431c-8184-106c80eb2273";
    let handler = VmessTcpServerHandler::new(
        vec![vmess_user(user_id, "single-user", "none")],
        false,
        "vmess-single",
    );

    let user = handler
        .authenticate_user(&build_auth_id(user_id, current_time_secs()))
        .expect("single VMess user should authenticate");

    assert_eq!(user.user_label, "single-user");
}
