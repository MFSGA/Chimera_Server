use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update},
};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
    duplex,
};

use super::*;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

struct TestStream(DuplexStream);

impl AsyncRead for TestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buffer)
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

fn plain_stream(is_udp: bool) -> (DuplexStream, VmessStream) {
    plain_stream_with_capacity(is_udp, MAX_ENCRYPTED_READ_DATA_SIZE + 64)
}

fn plain_stream_with_capacity(
    is_udp: bool,
    capacity: usize,
) -> (DuplexStream, VmessStream) {
    let (client, server) = duplex(capacity);
    let stream = VmessStream::new(
        Box::new(TestStream(server)),
        is_udp,
        None,
        None,
        None,
        false,
        None,
        None,
    );
    (client, stream)
}

fn shake_reader(seed: &[u8]) -> VmessReader {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.finalize_xof()
}

fn encrypted_stream(
    is_udp: bool,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> (DuplexStream, VmessStream) {
    encrypted_stream_with_algorithm(is_udp, &AES_128_GCM, key, iv)
}

fn encrypted_stream_with_algorithm(
    is_udp: bool,
    algorithm: &'static aws_lc_rs::aead::Algorithm,
    key: &[u8],
    iv: &[u8; 16],
) -> (DuplexStream, VmessStream) {
    let (client, server) = duplex(MAX_ENCRYPTED_READ_DATA_SIZE + 64);
    let opening_key = OpeningKey::new(
        UnboundKey::new(algorithm, key).expect("create VMess opening key"),
        VmessNonceSequence::new(iv),
    );
    let sealing_key = SealingKey::new(
        UnboundKey::new(algorithm, key).expect("create VMess sealing key"),
        VmessNonceSequence::new(iv),
    );
    let stream = VmessStream::new(
        Box::new(TestStream(server)),
        is_udp,
        Some((opening_key, sealing_key)),
        None,
        None,
        false,
        None,
        None,
    );
    (client, stream)
}

fn response_header_info() -> ReadHeaderInfo {
    ReadHeaderInfo {
        response_header_key: [0x71; 16],
        response_header_iv: [0x82; 16],
        response_authentication_v: 0x93,
    }
}

fn response_header_stream(info: ReadHeaderInfo) -> (DuplexStream, VmessStream) {
    let (client, server) = duplex(4096);
    let stream = VmessStream::new(
        Box::new(TestStream(server)),
        true,
        None,
        None,
        None,
        false,
        None,
        Some(info),
    );
    (client, stream)
}

fn encode_response_header(info: &ReadHeaderInfo, content: &[u8]) -> Vec<u8> {
    assert!(content.len() <= u16::MAX as usize);
    let length_key = super::super::sha2::kdf(
        &info.response_header_key,
        &[b"AEAD Resp Header Len Key"],
    );
    let length_nonce = super::super::sha2::kdf(
        &info.response_header_iv,
        &[b"AEAD Resp Header Len IV"],
    );
    let mut encrypted_length = (content.len() as u16).to_be_bytes().to_vec();
    let mut length_sealer = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, &length_key[..16])
            .expect("create VMess response length key"),
        SingleUseNonce::new(&length_nonce[..12]),
    );
    let length_tag = length_sealer
        .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_length)
        .expect("seal VMess response header length");
    encrypted_length.extend_from_slice(length_tag.as_ref());

    let content_key = super::super::sha2::kdf(
        &info.response_header_key,
        &[b"AEAD Resp Header Key"],
    );
    let content_nonce =
        super::super::sha2::kdf(&info.response_header_iv, &[b"AEAD Resp Header IV"]);
    let mut encrypted_content = content.to_vec();
    let mut content_sealer = SealingKey::new(
        UnboundKey::new(&AES_128_GCM, &content_key[..16])
            .expect("create VMess response content key"),
        SingleUseNonce::new(&content_nonce[..12]),
    );
    let content_tag = content_sealer
        .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_content)
        .expect("seal VMess response header content");
    encrypted_content.extend_from_slice(content_tag.as_ref());

    encrypted_length.extend_from_slice(&encrypted_content);
    encrypted_length
}

fn encode_encrypted_frame(key: &[u8; 16], iv: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    encode_encrypted_frame_with_algorithm(&AES_128_GCM, key, iv, payload)
}

fn encode_encrypted_frame_with_algorithm(
    algorithm: &'static aws_lc_rs::aead::Algorithm,
    key: &[u8],
    iv: &[u8; 16],
    payload: &[u8],
) -> Vec<u8> {
    let mut sealing_key = SealingKey::new(
        UnboundKey::new(algorithm, key).expect("create VMess fixture sealing key"),
        VmessNonceSequence::new(iv),
    );
    let mut encrypted = payload.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut encrypted)
        .expect("seal VMess fixture frame");
    let frame_length = encrypted.len() + tag.as_ref().len();
    let mut frame = Vec::with_capacity(frame_length + 2);
    frame.extend_from_slice(&(frame_length as u16).to_be_bytes());
    frame.extend_from_slice(&encrypted);
    frame.extend_from_slice(tag.as_ref());
    frame
}

async fn read_message(
    stream: &mut VmessStream,
    output: &mut [u8],
) -> std::io::Result<usize> {
    poll_fn(|cx| {
        let mut buffer = ReadBuf::new(output);
        match Pin::new(&mut *stream).poll_read_message(cx, &mut buffer) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[test]
fn short_response_headers_are_rejected_without_panicking() {
    for length in 0..4 {
        let header = vec![7u8; length];
        let error = check_header_response(&header, 7)
            .expect_err("short VMess response header must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("too short"));
    }
}

#[test]
fn masked_length_smaller_than_padding_is_rejected() {
    let (seed, padding_len, length_mask) = (0u16..=u16::MAX)
        .find_map(|candidate| {
            let seed = candidate.to_be_bytes();
            let mut preview = LengthMask::new(shake_reader(&seed), true);
            let (padding_len, length_mask) = preview.next_values();
            (padding_len > 0).then_some((seed, padding_len, length_mask))
        })
        .expect("find deterministic VMess padding seed");
    let (_, mut stream) = plain_stream(true);
    stream.read_length_mask = Some(LengthMask::new(shake_reader(&seed), true));
    let decoded_length = padding_len - 1;
    let wire_length = (decoded_length as u16) ^ length_mask;

    let error = stream
        .feed_initial_read_data(&wire_length.to_be_bytes())
        .expect_err("VMess padding larger than frame length must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("padding length"));
}

#[tokio::test]
async fn valid_aead_response_header_can_arrive_one_byte_at_a_time() {
    let info = response_header_info();
    let auth_value = info.response_authentication_v;
    let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 0]);
    wire.extend_from_slice(&[0, 4, b'd', b'a', b't', b'a']);
    let (mut client, mut stream) = response_header_stream(info);
    let writer = tokio::spawn(async move {
        for byte in wire {
            client
                .write_all(&[byte])
                .await
                .expect("write fragmented VMess response byte");
            tokio::task::yield_now().await;
        }
    });
    let mut output = [0u8; 16];

    let length = read_message(&mut stream, &mut output)
        .await
        .expect("read data after fragmented VMess response header");

    assert_eq!(&output[..length], b"data");
    assert_eq!(stream.read_header_state, ReadHeaderState::Done);
    writer.await.expect("fragmented response writer task");
}

#[test]
fn corrupted_aead_response_length_tag_is_rejected() {
    let info = response_header_info();
    let auth_value = info.response_authentication_v;
    let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 0]);
    wire[17] ^= 0x01;
    let (_, mut stream) = response_header_stream(info);

    let error = stream
        .feed_initial_read_data(&wire)
        .expect_err("corrupted VMess response length tag must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("header length"));
}

#[test]
fn corrupted_aead_response_content_tag_is_rejected() {
    let info = response_header_info();
    let auth_value = info.response_authentication_v;
    let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 0]);
    *wire.last_mut().expect("VMess response content tag") ^= 0x01;
    let (_, mut stream) = response_header_stream(info);

    let error = stream
        .feed_initial_read_data(&wire)
        .expect_err("corrupted VMess response content tag must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("response header"));
}

#[test]
fn short_and_command_overflow_response_headers_are_rejected() {
    for content in [
        vec![0x93, 0, 0],
        vec![0x93, 0, 0, 1],
        vec![0x93, 0, 0, 2, 0xaa],
    ] {
        let info = response_header_info();
        let wire = encode_response_header(&info, &content);
        let (_, mut stream) = response_header_stream(info);

        let error = stream
            .feed_initial_read_data(&wire)
            .expect_err("invalid VMess response content shape must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}

#[tokio::test]
async fn response_header_command_bytes_are_consumed_before_data() {
    let info = response_header_info();
    let auth_value = info.response_authentication_v;
    let mut wire = encode_response_header(&info, &[auth_value, 0, 0, 2, 0xaa, 0xbb]);
    wire.extend_from_slice(&[0, 4, b'd', b'a', b't', b'a']);
    let (mut client, mut stream) = response_header_stream(info);
    client
        .write_all(&wire)
        .await
        .expect("write VMess response command and data");
    let mut output = [0u8; 16];

    let length = read_message(&mut stream, &mut output)
        .await
        .expect("read data after VMess response command bytes");

    assert_eq!(&output[..length], b"data");
}

#[tokio::test]
async fn encrypted_udp_frame_roundtrips() {
    let key = [0x11; 16];
    let iv = [0x22; 16];
    let (mut client, mut stream) = encrypted_stream(true, &key, &iv);
    let frame = encode_encrypted_frame(&key, &iv, b"secret");
    client
        .write_all(&frame)
        .await
        .expect("write encrypted VMess UDP frame");
    let mut output = [0u8; 16];

    let length = read_message(&mut stream, &mut output)
        .await
        .expect("read encrypted VMess UDP frame");

    assert_eq!(&output[..length], b"secret");
}

#[tokio::test]
async fn chacha20_poly1305_udp_frame_roundtrips() {
    let key = [0x21; 32];
    let iv = [0x32; 16];
    let algorithm = &aws_lc_rs::aead::CHACHA20_POLY1305;
    let (mut client, mut stream) =
        encrypted_stream_with_algorithm(true, algorithm, &key, &iv);
    let frame =
        encode_encrypted_frame_with_algorithm(algorithm, &key, &iv, b"chacha");
    client
        .write_all(&frame)
        .await
        .expect("write ChaCha20-Poly1305 VMess UDP frame");
    let mut output = [0u8; 16];

    let length = read_message(&mut stream, &mut output)
        .await
        .expect("read ChaCha20-Poly1305 VMess UDP frame");

    assert_eq!(&output[..length], b"chacha");
}

#[tokio::test]
async fn corrupted_chacha20_poly1305_frame_is_rejected() {
    let key = [0x41; 32];
    let iv = [0x52; 16];
    let algorithm = &aws_lc_rs::aead::CHACHA20_POLY1305;
    let (mut client, mut stream) =
        encrypted_stream_with_algorithm(true, algorithm, &key, &iv);
    let mut frame =
        encode_encrypted_frame_with_algorithm(algorithm, &key, &iv, b"chacha");
    *frame.last_mut().expect("ChaCha20-Poly1305 VMess tag") ^= 0x01;
    client
        .write_all(&frame)
        .await
        .expect("write corrupted ChaCha20-Poly1305 VMess frame");
    let mut output = [0u8; 16];

    let error = read_message(&mut stream, &mut output)
        .await
        .expect_err("corrupted ChaCha20-Poly1305 VMess frame must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(output, [0; 16]);
}

#[tokio::test]
async fn corrupted_encrypted_udp_frame_is_rejected() {
    let key = [0x31; 16];
    let iv = [0x42; 16];
    let (mut client, mut stream) = encrypted_stream(true, &key, &iv);
    let mut frame = encode_encrypted_frame(&key, &iv, b"secret");
    *frame.last_mut().expect("encrypted VMess frame tag") ^= 0x01;
    client
        .write_all(&frame)
        .await
        .expect("write corrupted encrypted VMess UDP frame");
    let mut output = [0u8; 16];

    let error = read_message(&mut stream, &mut output)
        .await
        .expect_err("corrupted encrypted VMess UDP frame must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("open failed"));
    assert_eq!(output, [0; 16]);
}

#[tokio::test]
async fn encrypted_eof_requires_a_valid_tag() {
    let key = [0x51; 16];
    let iv = [0x62; 16];

    let (mut valid_client, mut valid_stream) = encrypted_stream(true, &key, &iv);
    valid_client
        .write_all(&encode_encrypted_frame(&key, &iv, b""))
        .await
        .expect("write authenticated VMess EOF frame");
    let mut output = [0u8; 1];
    let length = read_message(&mut valid_stream, &mut output)
        .await
        .expect("read authenticated VMess EOF frame");
    assert_eq!(length, 0);
    assert!(valid_stream.is_eof);

    let (mut invalid_client, mut invalid_stream) = encrypted_stream(true, &key, &iv);
    let mut invalid_frame = encode_encrypted_frame(&key, &iv, b"");
    *invalid_frame
        .last_mut()
        .expect("VMess EOF authentication tag") ^= 0x01;
    invalid_client
        .write_all(&invalid_frame)
        .await
        .expect("write unauthenticated VMess EOF frame");
    let error = read_message(&mut invalid_stream, &mut output)
        .await
        .expect_err("unauthenticated VMess EOF frame must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(!invalid_stream.is_eof);
}

#[test]
fn maximum_plain_frame_fills_processed_buffer() {
    let payload = vec![0x5a; MAX_ENCRYPTED_READ_DATA_SIZE];
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);
    let (_, mut stream) = plain_stream(false);

    stream
        .feed_initial_read_data(&frame)
        .expect("maximum plain VMess frame must decode");

    assert_eq!(stream.processed_end_offset, payload.len());
    assert_eq!(&stream.processed_buf[..payload.len()], payload.as_slice());
}

#[test]
fn oversized_direct_udp_frame_is_rejected() {
    let payload = vec![0x5a; MAX_VMESS_UDP_PAYLOAD_SIZE + 1];
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);
    let (_, mut stream) = plain_stream(true);

    let error = stream
        .feed_initial_read_data(&frame)
        .expect_err("oversized direct VMess UDP frame must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("Xray buffer limit"));
    assert!(stream.processed_message_lengths.is_empty());
}

#[tokio::test]
async fn truncated_plain_frames_return_unexpected_eof() {
    let frame = [0, 3, b'o', b'n', b'e'];

    for prefix_length in 1..frame.len() {
        let (mut client, mut stream) = plain_stream(true);
        client
            .write_all(&frame[..prefix_length])
            .await
            .expect("write truncated VMess data frame");
        client
            .shutdown()
            .await
            .expect("close truncated VMess data writer");
        let mut output = [0u8; 16];

        let error = read_message(&mut stream, &mut output)
            .await
            .expect_err("truncated VMess data frame must fail");

        assert_eq!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof,
            "prefix length {prefix_length}"
        );
    }
}

#[tokio::test]
async fn explicit_empty_frame_marks_protocol_eof() {
    let (mut client, mut stream) = plain_stream(true);
    client
        .write_all(&[0, 0])
        .await
        .expect("write VMess EOF frame");
    let mut output = [0u8; 16];

    let length = read_message(&mut stream, &mut output)
        .await
        .expect("read VMess EOF frame");

    assert_eq!(length, 0);
    assert!(stream.is_eof);
}

#[tokio::test]
async fn small_udp_buffer_preserves_message_for_retry() {
    let (mut client, mut stream) = plain_stream(true);
    client
        .write_all(&[0, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd'])
        .await
        .expect("write VMess UDP caller-buffer fixture");
    let mut small = [0u8; 4];

    let error = read_message(&mut stream, &mut small)
        .await
        .expect_err("small VMess UDP caller buffer must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("exceeds receive buffer"));
    assert_eq!(small, [0; 4]);

    let mut large = [0u8; 16];
    let length = read_message(&mut stream, &mut large)
        .await
        .expect("retry VMess UDP message with a large buffer");
    assert_eq!(&large[..length], b"payload");
}

#[tokio::test]
async fn initial_data_preserves_multiple_udp_message_boundaries() {
    let (_, mut stream) = plain_stream(true);
    stream
        .feed_initial_read_data(&[0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o'])
        .expect("feed multiple initial VMess UDP frames");
    assert_eq!(
        stream
            .processed_message_lengths
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        [3, 3]
    );
    let mut output = [0u8; 16];

    let first = read_message(&mut stream, &mut output)
        .await
        .expect("read first initial VMess UDP frame");
    assert_eq!(&output[..first], b"one");
    let second = read_message(&mut stream, &mut output)
        .await
        .expect("read second initial VMess UDP frame");
    assert_eq!(&output[..second], b"two");
}

#[tokio::test]
async fn plain_udp_writes_length_prefixed_messages() {
    let (mut client, mut stream) = plain_stream(true);

    for payload in [b"one".as_slice(), b"two".as_slice()] {
        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
            .await
            .expect("queue plain VMess UDP message");
        poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .expect("flush plain VMess UDP message");
    }

    let mut encoded = [0u8; 10];
    client
        .read_exact(&mut encoded)
        .await
        .expect("read plain VMess UDP messages");
    assert_eq!(&encoded, &[0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o']);
}

#[tokio::test]
async fn partial_udp_writes_do_not_duplicate_frames_or_eof() {
    let (mut client, mut stream) = plain_stream_with_capacity(true, 1);
    let writer_task = tokio::spawn(async move {
        for payload in [b"one".as_slice(), b"two".as_slice()] {
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                .await
                .expect("queue VMess UDP message through one-byte transport");
            poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                .await
                .expect("flush VMess UDP message through one-byte transport");
        }
        poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
            .await
            .expect("shutdown VMess UDP one-byte transport");
    });

    let mut actual = Vec::new();
    client
        .read_to_end(&mut actual)
        .await
        .expect("read VMess UDP one-byte transport frames");
    writer_task.await.expect("VMess UDP partial writer task");

    assert_eq!(
        actual,
        [0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o', 0, 0,]
    );
}

#[tokio::test]
async fn maximum_plain_udp_write_roundtrips() {
    let (mut client, mut stream) = plain_stream(true);
    let payload = vec![0x5a; MAX_VMESS_UDP_PAYLOAD_SIZE];

    poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload))
        .await
        .expect("queue maximum plain VMess UDP message");
    poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
        .await
        .expect("flush maximum plain VMess UDP message");

    let mut length = [0u8; 2];
    client
        .read_exact(&mut length)
        .await
        .expect("read maximum VMess UDP length");
    assert_eq!(
        u16::from_be_bytes(length) as usize,
        MAX_VMESS_UDP_PAYLOAD_SIZE
    );
    let mut decoded = vec![0u8; payload.len()];
    client
        .read_exact(&mut decoded)
        .await
        .expect("read maximum VMess UDP payload");
    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn oversized_plain_udp_write_is_rejected() {
    let (_, mut stream) = plain_stream(true);
    let payload = vec![0u8; MAX_VMESS_UDP_PAYLOAD_SIZE + 1];

    let error = poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &payload))
        .await
        .expect_err("oversized plain VMess UDP message must fail");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("too large"));
}

#[tokio::test]
async fn small_tcp_write_is_framed_without_explicit_flush() {
    let (mut client, mut stream) = plain_stream(false);
    stream
        .write_all(b"ping")
        .await
        .expect("write small plain VMess TCP payload");

    let frame = tokio::time::timeout(Duration::from_millis(100), async {
        let length = client.read_u16().await.expect("read VMess frame length");
        let mut payload = vec![0u8; length as usize];
        client
            .read_exact(&mut payload)
            .await
            .expect("read VMess frame payload");
        payload
    })
    .await
    .expect("small VMess write must not wait for flush or EOF");
    assert_eq!(frame, b"ping");
}

#[tokio::test]
async fn padded_tcp_write_drains_tail_without_explicit_flush() {
    let seed = [0x12, 0x34];
    let mut preview = LengthMask::new(shake_reader(&seed), true);
    assert!(preview.next_values().0 > 0, "fixture must split the write");

    let (mut client, mut stream) = plain_stream(false);
    stream.write_length_mask = Some(LengthMask::new(shake_reader(&seed), true));
    let payload = (0..MAX_ENCRYPTED_WRITE_DATA_SIZE)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    stream
        .write_all(&payload)
        .await
        .expect("write padded VMess TCP payload");

    let decoded = tokio::time::timeout(Duration::from_millis(100), async {
        let mut mask = LengthMask::new(shake_reader(&seed), true);
        let mut decoded = Vec::with_capacity(payload.len());
        while decoded.len() < payload.len() {
            let (padding_len, length_mask) = mask.next_values();
            let wire_length =
                client.read_u16().await.expect("read masked frame length");
            let frame_length = (wire_length ^ length_mask) as usize;
            let mut frame = vec![0u8; frame_length];
            client
                .read_exact(&mut frame)
                .await
                .expect("read padded VMess frame");
            decoded.extend_from_slice(&frame[..frame_length - padding_len]);
        }
        decoded
    })
    .await
    .expect("padded VMess write tail must not wait for flush or EOF");
    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn large_tcp_write_is_segmented_without_loss() {
    let (mut client, mut stream) = plain_stream(false);
    let payload = (0..20_000)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    stream
        .write_all(&payload)
        .await
        .expect("write large plain VMess TCP payload");
    stream
        .flush()
        .await
        .expect("flush large plain VMess TCP payload");

    let mut decoded = Vec::with_capacity(payload.len());
    while decoded.len() < payload.len() {
        let length = client
            .read_u16()
            .await
            .expect("read plain VMess TCP frame length")
            as usize;
        assert!(length <= MAX_ENCRYPTED_WRITE_DATA_SIZE);
        let start = decoded.len();
        decoded.resize(start + length, 0);
        client
            .read_exact(&mut decoded[start..])
            .await
            .expect("read plain VMess TCP frame payload");
    }
    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn tcp_shutdown_flushes_payload_and_protocol_eof() {
    let (mut client, mut stream) = plain_stream(false);
    stream
        .write_all(b"payload")
        .await
        .expect("write plain VMess TCP payload before shutdown");
    stream
        .shutdown()
        .await
        .expect("shutdown plain VMess TCP stream");

    let mut encoded = Vec::new();
    client
        .read_to_end(&mut encoded)
        .await
        .expect("read VMess TCP shutdown frames");
    assert_eq!(
        encoded,
        [0, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0, 0]
    );
}

#[tokio::test]
async fn consecutive_plain_udp_frames_preserve_message_boundaries() {
    let (mut client, mut stream) = plain_stream(true);
    client
        .write_all(&[0, 3, b'o', b'n', b'e', 0, 3, b't', b'w', b'o'])
        .await
        .expect("write consecutive plain VMess UDP frames");
    let mut output = [0u8; 16];

    let first = read_message(&mut stream, &mut output)
        .await
        .expect("read first plain VMess UDP frame");
    assert_eq!(&output[..first], b"one");
    let second = read_message(&mut stream, &mut output)
        .await
        .expect("read second plain VMess UDP frame");
    assert_eq!(&output[..second], b"two");
}
