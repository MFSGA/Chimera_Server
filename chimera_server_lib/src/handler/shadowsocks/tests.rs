use std::{
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
        duplex,
    },
    sync::oneshot,
    time::timeout,
};

use crate::{
    address::{Address, NetLocation},
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::ShadowsocksUser,
};

use super::{
    ShadowsocksCipher, ShadowsocksTcpServerHandler, ShadowsocksUdpCodec,
    ShadowsocksUdpRequest, ShadowsocksUdpUserCodec, ShadowsocksUserStore,
    TaskBackedStream, TimedSaltChecker, decrypt_stream, derive_aead2022_session_key,
    derive_master_key, encrypt_stream, spawn_aead_codec, spawn_aead2022_codec,
};

struct DropNotifyingStream {
    inner: DuplexStream,
    dropped: Option<oneshot::Sender<()>>,
}

impl Drop for DropNotifyingStream {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl AsyncRead for DropNotifyingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DropNotifyingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncPing for DropNotifyingStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for DropNotifyingStream {}

async fn dropping_codec_releases_underlying_stream(
    codec: TaskBackedStream,
    dropped: oneshot::Receiver<()>,
) {
    tokio::task::yield_now().await;
    drop(codec);
    timeout(Duration::from_secs(1), dropped)
        .await
        .expect("dropping codec should cancel both workers")
        .expect("underlying encrypted stream should be released");
}

#[tokio::test]
async fn dropping_legacy_codec_cancels_blocked_workers() {
    let cipher = ShadowsocksCipher::parse("aes-128-gcm").unwrap();
    let master_key: Arc<[u8]> =
        derive_master_key("password", cipher.key_len()).into();
    let (_peer, encrypted) = duplex(256);
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let codec = spawn_aead_codec(
        Box::new(DropNotifyingStream {
            inner: encrypted,
            dropped: Some(dropped_tx),
        }),
        cipher,
        master_key,
        Arc::new(Mutex::new(TimedSaltChecker::default())),
    );

    dropping_codec_releases_underlying_stream(codec, dropped_rx).await;
}

#[tokio::test]
async fn dropping_aead2022_codec_cancels_blocked_workers() {
    let cipher = ShadowsocksCipher::parse("aes-128-gcm").unwrap();
    let psk: Arc<[u8]> = Arc::from(*b"0123456789abcdef");
    let (_peer, encrypted) = duplex(256);
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let codec = spawn_aead2022_codec(
        Box::new(DropNotifyingStream {
            inner: encrypted,
            dropped: Some(dropped_tx),
        }),
        cipher,
        psk,
        Arc::new(Mutex::new(TimedSaltChecker::default())),
    );

    dropping_codec_releases_underlying_stream(codec, dropped_rx).await;
}

#[tokio::test]
async fn codec_shutdown_waits_for_encrypt_worker_and_preserves_read_half() {
    let cipher = ShadowsocksCipher::parse("aes-128-gcm").unwrap();
    let master_key: Arc<[u8]> =
        derive_master_key("password", cipher.key_len()).into();
    let (mut peer, encrypted) = duplex(4096);
    let mut codec = spawn_aead_codec(
        Box::new(DropNotifyingStream {
            inner: encrypted,
            dropped: None,
        }),
        cipher,
        master_key,
        Arc::new(Mutex::new(TimedSaltChecker::default())),
    );

    codec.write_all(b"response").await.unwrap();
    timeout(Duration::from_secs(1), codec.shutdown())
        .await
        .expect("codec write-half shutdown should finish")
        .unwrap();

    assert!(
        codec.encrypt_task.is_none(),
        "shutdown must wait until the encrypt worker closes the encrypted write half"
    );
    assert!(
        !codec.decrypt_task.is_finished(),
        "write-half shutdown must preserve the independent decrypt/read half"
    );

    let mut encrypted_response = Vec::new();
    timeout(
        Duration::from_secs(1),
        peer.read_to_end(&mut encrypted_response),
    )
    .await
    .expect("peer should observe encrypted write-half EOF")
    .unwrap();
    assert!(!encrypted_response.is_empty());
}

#[test]
fn runtime_user_store_preserves_state_and_updates_udp_auth() {
    let initial = ShadowsocksUser {
        method: "aes-128-gcm".to_string(),
        password: "initial-secret".to_string(),
        email: "initial@example.com".to_string(),
        user_level: 1,
    };
    let added = ShadowsocksUser {
        method: "chacha20-ietf-poly1305".to_string(),
        password: "added-secret".to_string(),
        email: "added@example.com".to_string(),
        user_level: 7,
    };
    let store = ShadowsocksUserStore::new(vec![initial.clone()], None)
        .expect("valid runtime user store");
    let tcp_before = store.tcp_users()[0].clone();
    let udp_before = store.udp_users()[0].clone();

    store.add_user(added.clone()).expect("add runtime user");
    assert!(Arc::ptr_eq(&tcp_before, &store.tcp_users()[0]));
    assert!(Arc::ptr_eq(&udp_before, &store.udp_users()[0]));

    let base =
        ShadowsocksUdpCodec::new(vec![initial], None).expect("valid base UDP codec");
    let client = ShadowsocksUdpCodec::new(vec![added], None)
        .expect("valid added-user UDP codec");
    let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 53);
    let packet = client
        .encrypt_test_request(&target, b"runtime-user")
        .expect("encrypt added-user request");
    let request = store
        .udp_codec(&base)
        .decrypt_packet(&packet)
        .expect("runtime codec should accept added user");
    assert_eq!(request.identity, "added@example.com");
    assert_eq!(request.user_level, 7);

    store
        .remove_user_by_email("ADDED@example.com")
        .expect("case-insensitive runtime remove");
    assert!(Arc::ptr_eq(&tcp_before, &store.tcp_users()[0]));
    assert!(Arc::ptr_eq(&udp_before, &store.udp_users()[0]));
}

#[test]
fn tcp_handler_runtime_store_tracks_updates_without_rebuild() {
    let initial = ShadowsocksUser {
        method: "aes-128-gcm".to_string(),
        password: "initial-secret".to_string(),
        email: "initial@example.com".to_string(),
        user_level: 1,
    };
    let added = ShadowsocksUser {
        method: "aes-256-gcm".to_string(),
        password: "added-secret".to_string(),
        email: "added@example.com".to_string(),
        user_level: 9,
    };
    let store = Arc::new(
        ShadowsocksUserStore::new(vec![initial.clone()], None)
            .expect("valid runtime user store"),
    );
    let handler = ShadowsocksTcpServerHandler::new(vec![initial], None, "ss-test")
        .expect("valid TCP handler");
    handler
        .runtime_users
        .set(store.clone())
        .expect("bind runtime store");

    store.add_user(added).expect("add runtime user");
    let users = handler.runtime_users.get().unwrap().tcp_users();
    assert_eq!(users.len(), 2);
    assert_eq!(users[1].identity, "added@example.com");
    assert_eq!(users[1].user_level, 9);
}

#[test]
fn derives_xray_compatible_aes_128_master_key() {
    assert_eq!(
        derive_master_key("password", 16),
        vec![
            0x5f, 0x4d, 0xcc, 0x3b, 0x5a, 0xa7, 0x65, 0xd6, 0x1d, 0x83, 0x27, 0xde,
            0xb8, 0x82, 0xcf, 0x99,
        ]
    );
}

#[test]
fn cipher_aliases_match_xray_names() {
    assert_eq!(
        ShadowsocksCipher::parse("aead_aes_128_gcm").unwrap().name,
        "aes-128-gcm"
    );
    assert_eq!(
        ShadowsocksCipher::parse("chacha20-poly1305").unwrap().name,
        "chacha20-ietf-poly1305"
    );
    assert_eq!(
        ShadowsocksCipher::parse("aead_xchacha20_poly1305")
            .unwrap()
            .name,
        "xchacha20-ietf-poly1305"
    );
}

#[tokio::test]
async fn xchacha_tcp_stream_roundtrips() {
    let cipher = ShadowsocksCipher::parse("xchacha20-poly1305")
        .expect("parse XChaCha cipher");
    let master_key: Arc<[u8]> =
        derive_master_key("password", cipher.key_len()).into();
    let (mut input, input_reader) = duplex(4096);
    let (encrypted_writer, encrypted_reader) = duplex(4096);
    let (output_writer, mut output) = duplex(4096);
    let payload = b"xray-compatible-xchacha-tcp".repeat(64);

    let encrypt_key = master_key.clone();
    let encrypt_task = tokio::spawn(async move {
        encrypt_stream(input_reader, encrypted_writer, cipher, encrypt_key).await
    });
    let decrypt_task = tokio::spawn(async move {
        decrypt_stream(
            encrypted_reader,
            output_writer,
            cipher,
            master_key,
            Arc::new(Mutex::new(TimedSaltChecker::default())),
        )
        .await
    });

    input
        .write_all(&payload)
        .await
        .expect("write XChaCha payload");
    input.shutdown().await.expect("shutdown XChaCha input");
    let mut decoded = Vec::new();
    output
        .read_to_end(&mut decoded)
        .await
        .expect("read XChaCha output");
    encrypt_task
        .await
        .expect("join XChaCha encrypt task")
        .expect("encrypt XChaCha stream");
    decrypt_task
        .await
        .expect("join XChaCha decrypt task")
        .expect("decrypt XChaCha stream");

    assert_eq!(decoded, payload);
}

#[test]
fn xchacha_udp_packet_roundtrips() {
    let codec = ShadowsocksUdpUserCodec::new(ShadowsocksUser {
        method: "xchacha20-poly1305".to_string(),
        password: "password".to_string(),
        email: "xchacha@example.com".to_string(),
        user_level: 0,
    })
    .expect("create XChaCha UDP codec");
    let source = NetLocation::new(Address::from("example.com").unwrap(), 443);
    let payload = b"xray-compatible-xchacha-udp";
    let request = ShadowsocksUdpRequest {
        target_location: source.clone(),
        payload: Vec::new(),
        identity: String::new(),
        user_level: 0,
        user_index: 0,
        client_session_id: None,
    };

    let packet = codec
        .encrypt_packet(&request, &source, payload)
        .expect("encrypt XChaCha UDP packet");
    let decoded = codec
        .decrypt_packet(&packet)
        .expect("decrypt XChaCha UDP packet");

    assert_eq!(decoded.target_location, source);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn aead2022_udp_derives_key_from_eight_byte_session_id() {
    let key = derive_aead2022_session_key(b"0123456789abcdef", b"session!", 16)
        .expect("derive 2022 UDP session key");
    assert_eq!(key.len(), 16);
}

#[test]
fn salt_replay_is_rejected() {
    let mut checker = TimedSaltChecker::default();
    assert!(checker.insert(b"0123456789abcdef"));
    assert!(!checker.insert(b"0123456789abcdef"));
}
