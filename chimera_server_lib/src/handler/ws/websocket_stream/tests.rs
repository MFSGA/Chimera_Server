use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct TestStream(tokio::io::DuplexStream);

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

fn websocket_over(transport: tokio::io::DuplexStream) -> WebsocketStream {
    WebsocketStream::new(Box::new(TestStream(transport)), false, &[])
}

fn masked_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [1u8, 2, 3, 4];
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&[first, 0x80 | payload.len() as u8]);
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ mask[i % 4]),
    );
    frame
}

async fn assert_protocol_close(
    peer: &mut tokio::io::DuplexStream,
    websocket: &mut WebsocketStream,
    reason: &str,
) {
    let mut application_data = [0u8; 8];
    let error = websocket.read(&mut application_data).await.unwrap_err();
    assert_eq!(error.to_string(), format!("websocket: {reason}"));

    let mut response = vec![0u8; 4 + reason.len()];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], 0x88);
    assert_eq!(response[1] as usize, reason.len() + 2);
    assert_eq!(&response[2..4], &1002u16.to_be_bytes());
    assert_eq!(&response[4..], reason.as_bytes());
}

#[tokio::test]
async fn server_sends_configured_heartbeat_ping_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(64);
    let mut websocket = WebsocketStream::new_with_heartbeat(
        Box::new(TestStream(transport)),
        false,
        &[],
        1,
    );

    let reader = tokio::spawn(async move {
        let mut application_data = [0u8; 1];
        websocket.read(&mut application_data).await
    });

    let mut ping = [0u8; 2];
    tokio::time::timeout(Duration::from_millis(1500), peer.read_exact(&mut ping))
        .await
        .expect("heartbeat ping should arrive within Xray's one-second period")
        .unwrap();
    assert_eq!(ping, [0x89, 0x00]);

    reader.abort();
}

#[tokio::test]
async fn server_rejects_unmasked_client_frame_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(64);
    let mut websocket = websocket_over(transport);
    peer.write_all(&[0x82, 0x04, b'p', b'i', b'n', b'g'])
        .await
        .unwrap();

    let mut application_data = [0u8; 4];
    let error = websocket.read(&mut application_data).await.unwrap_err();
    assert_eq!(error.to_string(), "websocket: bad MASK");

    let mut response = [0u8; 12];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(
        response,
        [
            0x88, 0x0a, 0x03, 0xea, b'b', b'a', b'd', b' ', b'M', b'A', b'S', b'K'
        ]
    );
}

#[tokio::test]
async fn server_rejects_reserved_bits_like_xray() {
    for (reserved_bits, reason) in [
        (0x40, "RSV1 set"),
        (0x20, "RSV2 set"),
        (0x10, "RSV3 set"),
        (0x60, "RSV1 set, RSV2 set"),
        (0x70, "RSV1 set, RSV2 set, RSV3 set"),
    ] {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        let mask = [1u8, 2, 3, 4];
        let payload = [
            b'p' ^ mask[0],
            b'i' ^ mask[1],
            b'n' ^ mask[2],
            b'g' ^ mask[3],
        ];
        peer.write_all(&[
            0x82 | reserved_bits,
            0x84,
            mask[0],
            mask[1],
            mask[2],
            mask[3],
            payload[0],
            payload[1],
            payload[2],
            payload[3],
        ])
        .await
        .unwrap();

        let mut application_data = [0u8; 4];
        let error = websocket.read(&mut application_data).await.unwrap_err();
        assert_eq!(error.to_string(), format!("websocket: {reason}"));

        let mut response = vec![0u8; 4 + reason.len()];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 0x88);
        assert_eq!(response[1] as usize, reason.len() + 2);
        assert_eq!(&response[2..4], &1002u16.to_be_bytes());
        assert_eq!(&response[4..], reason.as_bytes());
    }
}

#[tokio::test]
async fn server_rejects_reserved_opcodes_like_xray() {
    for opcode in [3u8, 4, 5, 6, 7, 11, 12, 13, 14, 15] {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        peer.write_all(&masked_frame(0x80 | opcode, b"x"))
            .await
            .unwrap();

        let reason = format!("bad opcode {opcode}");
        assert_protocol_close(&mut peer, &mut websocket, &reason).await;
    }
}

#[tokio::test]
async fn server_immediately_pongs_full_control_payload_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(512);
    let mut websocket = websocket_over(transport);
    let payload: Vec<u8> = (0..125).collect();
    peer.write_all(&masked_frame(0x89, &payload)).await.unwrap();

    let mut application_data = [0u8; 1];
    let mut application_read = Box::pin(websocket.read(&mut application_data));
    let mut pong = vec![0u8; 2 + payload.len()];
    tokio::select! {
        result = peer.read_exact(&mut pong) => { result.unwrap(); },
        result = &mut application_read => panic!("ping unexpectedly completed application read: {result:?}"),
    }
    drop(application_read);

    assert_eq!(pong[0], 0x8a);
    assert_eq!(pong[1], 125);
    assert_eq!(&pong[2..], payload.as_slice());
}

#[tokio::test]
async fn server_ignores_pong_payload_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(512);
    let mut websocket = websocket_over(transport);
    let pong_payload: Vec<u8> = (0..125).collect();
    peer.write_all(&masked_frame(0x8a, &pong_payload))
        .await
        .unwrap();
    peer.write_all(&masked_frame(0x82, b"ping")).await.unwrap();

    let mut application_data = [0u8; 4];
    websocket.read_exact(&mut application_data).await.unwrap();
    assert_eq!(&application_data, b"ping");
}

#[tokio::test]
async fn server_normally_closes_on_invalid_63_bit_length_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(64);
    let mut websocket = websocket_over(transport);
    peer.write_all(&[0x82, 0xff]).await.unwrap();
    peer.write_all(&(1u64 << 63).to_be_bytes()).await.unwrap();

    let mut application_data = [0u8; 1];
    assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);

    let mut response = [0u8; 4];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x88, 0x02, 0x03, 0xe8]);
}

#[tokio::test]
async fn server_rejects_invalid_control_frames_like_xray() {
    for opcode in [0x08u8, 0x09, 0x0a] {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        peer.write_all(&masked_frame(opcode, b"x")).await.unwrap();
        assert_protocol_close(&mut peer, &mut websocket, "FIN not set on control")
            .await;

        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        peer.write_all(&[0x80 | opcode, 0xfe]).await.unwrap();
        assert_protocol_close(&mut peer, &mut websocket, "len > 125 for control")
            .await;
    }
}

#[tokio::test]
async fn server_aggregates_frame_header_errors_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    peer.write_all(&[0xc2, 0x00]).await.unwrap();
    assert_protocol_close(&mut peer, &mut websocket, "RSV1 set, bad MASK").await;

    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    peer.write_all(&[0x08, 0x7e]).await.unwrap();
    assert_protocol_close(
        &mut peer,
        &mut websocket,
        "len > 125 for control, FIN not set on control, bad MASK",
    )
    .await;
}

#[tokio::test]
async fn server_rejects_invalid_close_codes_like_xray() {
    for code in [999u16, 1004, 1005, 1006, 1014, 1015, 1016, 2999] {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        peer.write_all(&masked_frame(0x88, &code.to_be_bytes()))
            .await
            .unwrap();

        let reason = format!("bad close code {code}");
        assert_protocol_close(&mut peer, &mut websocket, &reason).await;
    }

    for code in [1000u16, 1003, 1007, 1013, 3000, 4999] {
        let (mut peer, transport) = tokio::io::duplex(128);
        let mut websocket = websocket_over(transport);
        peer.write_all(&masked_frame(0x88, &code.to_be_bytes()))
            .await
            .unwrap();

        let mut application_data = [0u8; 1];
        assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn server_replies_without_status_to_short_close_like_xray() {
    for payload in [&[][..], &[0x01][..]] {
        let (mut peer, transport) = tokio::io::duplex(64);
        let mut websocket = websocket_over(transport);
        peer.write_all(&masked_frame(0x88, payload)).await.unwrap();

        let mut application_data = [0u8; 1];
        assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);

        let mut response = [0u8; 2];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x88, 0x00]);
    }
}

#[tokio::test]
async fn server_rejects_invalid_close_reason_utf8_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    let mut payload = 1000u16.to_be_bytes().to_vec();
    payload.push(0xff);
    peer.write_all(&masked_frame(0x88, &payload)).await.unwrap();

    assert_protocol_close(
        &mut peer,
        &mut websocket,
        "invalid utf8 payload in close frame",
    )
    .await;
}

#[tokio::test]
async fn server_rejects_invalid_fragmentation_sequence_like_xray() {
    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    peer.write_all(&masked_frame(0x80, b"x")).await.unwrap();
    assert_protocol_close(&mut peer, &mut websocket, "continuation after FIN").await;

    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    let mut frames = masked_frame(0x02, b"");
    frames.extend_from_slice(&masked_frame(0x82, b"x"));
    peer.write_all(&frames).await.unwrap();
    assert_protocol_close(&mut peer, &mut websocket, "data before FIN").await;
}

#[tokio::test]
async fn server_accepts_binary_fragmentation_sequence() {
    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    let mut frames = masked_frame(0x02, b"pi");
    frames.extend_from_slice(&masked_frame(0x80, b"ng"));
    peer.write_all(&frames).await.unwrap();

    let mut application_data = [0u8; 4];
    websocket.read_exact(&mut application_data).await.unwrap();
    assert_eq!(&application_data, b"ping");
}

#[tokio::test]
async fn server_accepts_text_frames_as_xray_byte_stream() {
    let (mut peer, transport) = tokio::io::duplex(128);
    let mut websocket = websocket_over(transport);
    let mut frames = masked_frame(0x01, b"pi");
    frames.extend_from_slice(&masked_frame(0x80, b"ng"));
    peer.write_all(&frames).await.unwrap();

    let mut application_data = [0u8; 4];
    websocket.read_exact(&mut application_data).await.unwrap();
    assert_eq!(&application_data, b"ping");
}

#[tokio::test]
async fn shutdown_sends_close_frame_before_transport_eof() {
    let (mut peer, transport) = tokio::io::duplex(64);
    let mut websocket = websocket_over(transport);

    websocket.shutdown().await.unwrap();

    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).await.unwrap();
    assert_eq!(wire, [0x88, 0x02, 0x03, 0xe8]);
}

#[tokio::test]
async fn received_close_echoes_xray_code_without_reason_before_read_eof() {
    let (mut peer, transport) = tokio::io::duplex(64);
    let mut websocket = websocket_over(transport);
    let close_payload = [0x03, 0xe9, b'b', b'y', b'e'];
    let mut frame = [0u8; 32];
    let frame_len = pack_frame(0x08, true, &close_payload, &mut frame);
    peer.write_all(&frame[..frame_len]).await.unwrap();

    let mut application_data = [0u8; 1];
    assert_eq!(websocket.read(&mut application_data).await.unwrap(), 0);

    let mut response = [0u8; 4];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x88, 0x02, 0x03, 0xe9]);

    websocket.shutdown().await.unwrap();
    let mut extra = [0u8; 1];
    assert_eq!(peer.read(&mut extra).await.unwrap(), 0);
}

#[tokio::test]
async fn repeated_shutdown_does_not_send_duplicate_close_frames() {
    let (mut peer, transport) = tokio::io::duplex(64);
    let mut websocket = websocket_over(transport);

    websocket.shutdown().await.unwrap();
    websocket.shutdown().await.unwrap();

    let mut wire = Vec::new();
    peer.read_to_end(&mut wire).await.unwrap();
    assert_eq!(wire, [0x88, 0x02, 0x03, 0xe8]);
}
