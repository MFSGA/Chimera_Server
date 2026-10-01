use std::{
    convert::Infallible,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http_body_util::{Empty, Full};
use hyper::{
    HeaderMap, Request, Response, client::conn::http2 as client_http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};

use super::{
    GrpcKeepalive, GrpcPeerContext, GrpcSetupTimeoutIo, GrpcStreamTaskGuard,
    PROTOBUF_MAX_FIELD_NUMBER, decode_grpc_message, decode_grpc_message_view,
    encode_grpc_message, encode_varint, grpc_content_type,
    grpc_content_type_is_valid, grpc_deadline_exceeded_response,
    grpc_duplicate_host_error, grpc_duplicate_host_response, grpc_encode_message,
    grpc_http2_builder, grpc_invalid_base64_offset,
    grpc_invalid_content_type_response, grpc_logical_addrs, grpc_logical_peer_addr,
    grpc_malformed_binary_metadata, grpc_malformed_binary_metadata_response,
    grpc_malformed_timeout_response, grpc_method_not_allowed_response,
    grpc_service_paths, grpc_stream_response, grpc_timeout_duration,
    grpc_unimplemented_path_response, grpc_unsupported_encoding,
    grpc_upload_status_from_error,
};

#[tokio::test]
async fn grpc_setup_timeout_expires_before_http2_handshake() {
    let (_client, server) = tokio::io::duplex(64);
    let mut server =
        GrpcSetupTimeoutIo::new(server, Instant::now() + Duration::from_millis(20));

    let error = server.read_u8().await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn grpc_setup_timeout_includes_initial_settings_frame() {
    let (mut client, server) = tokio::io::duplex(128);
    let mut server =
        GrpcSetupTimeoutIo::new(server, Instant::now() + Duration::from_millis(30));
    let reader = tokio::spawn(async move {
        let mut setup = [0u8; 33];
        server.read_exact(&mut setup).await.unwrap();
        server.read_u8().await
    });

    client
        .write_all(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x06\x04\x00\x00\x00\x00\x00",
        )
        .await
        .unwrap();

    let error = reader.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn grpc_setup_timeout_clears_after_preface_and_settings() {
    let (mut client, server) = tokio::io::duplex(128);
    let deadline = Instant::now() + Duration::from_millis(40);
    let mut server = GrpcSetupTimeoutIo::new(server, deadline);
    let reader = tokio::spawn(async move {
        let mut setup = [0u8; 33];
        server.read_exact(&mut setup).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        server.read_u8().await.unwrap()
    });

    let mut setup = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    setup.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    client.write_all(&setup).await.unwrap();
    tokio::time::sleep(Duration::from_millis(70)).await;
    client.write_u8(0x7f).await.unwrap();

    assert_eq!(reader.await.unwrap(), 0x7f);
}

#[tokio::test]
async fn grpc_server_does_not_advertise_hyper_stream_limit_like_xray_v26_2_6() {
    let (mut client, server) = tokio::io::duplex(4096);
    let builder = grpc_http2_builder(GrpcKeepalive {
        idle_timeout: 0,
        health_check_timeout: 0,
    });
    let server = tokio::spawn(async move {
        let service = service_fn(|_| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        });
        builder
            .serve_connection(TokioIo::new(server), service)
            .await
    });

    let mut header = [0u8; 9];
    client.read_exact(&mut header).await.unwrap();
    let payload_len = (usize::from(header[0]) << 16)
        | (usize::from(header[1]) << 8)
        | usize::from(header[2]);
    assert_eq!(header[3], 0x04, "first HTTP/2 frame must be SETTINGS");
    let mut payload = vec![0u8; payload_len];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload.len() % 6, 0);
    assert!(
        payload
            .as_chunks::<6>()
            .0
            .iter()
            .all(|setting| u16::from_be_bytes([setting[0], setting[1]]) != 0x03),
        "Xray/grpc-go does not advertise SETTINGS_MAX_CONCURRENT_STREAMS by default"
    );

    drop(client);
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn grpc_server_uses_xray_default_flow_control_windows() {
    let (mut client, server) = tokio::io::duplex(4096);
    let builder = grpc_http2_builder(GrpcKeepalive {
        idle_timeout: 0,
        health_check_timeout: 0,
    });
    let server = tokio::spawn(async move {
        let service = service_fn(|_| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        });
        builder
            .serve_connection(TokioIo::new(server), service)
            .await
    });

    let mut header = [0u8; 9];
    client.read_exact(&mut header).await.unwrap();
    let payload_len = (usize::from(header[0]) << 16)
        | (usize::from(header[1]) << 8)
        | usize::from(header[2]);
    assert_eq!(header[3], 0x04, "first HTTP/2 frame must be SETTINGS");
    let mut payload = vec![0u8; payload_len];
    client.read_exact(&mut payload).await.unwrap();
    for setting in payload.as_chunks::<6>().0 {
        if u16::from_be_bytes([setting[0], setting[1]]) == 0x04 {
            assert_eq!(
                u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]),
                65_535,
                "Hyper may advertise the RFC-default stream window explicitly"
            );
        }
    }

    let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    client.write_all(&preface).await.unwrap();

    let next = tokio::time::timeout(Duration::from_millis(100), async {
        let mut frame = [0u8; 9];
        loop {
            client.read_exact(&mut frame).await.unwrap();
            let payload_len = (usize::from(frame[0]) << 16)
                | (usize::from(frame[1]) << 8)
                | usize::from(frame[2]);
            let mut payload = vec![0u8; payload_len];
            client.read_exact(&mut payload).await.unwrap();
            if frame[3] != 0x04 || frame[4] & 0x01 == 0 {
                return frame[3];
            }
        }
    })
    .await;
    assert!(
        next.is_err(),
        "Xray/grpc-go does not send an initial connection WINDOW_UPDATE"
    );

    drop(client);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn grpc_server_accepts_xray_sized_metadata_headers() {
    let (client, server) = tokio::io::duplex(128 * 1024);
    let builder = grpc_http2_builder(GrpcKeepalive {
        idle_timeout: 0,
        health_check_timeout: 0,
    });
    let server = tokio::spawn(async move {
        let service = service_fn(|_| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
        });
        builder
            .serve_connection(TokioIo::new(server), service)
            .await
    });
    let (mut sender, connection) = client_http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(client))
        .await
        .unwrap();
    let client = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri("http://localhost/GunService/Tun")
        .header("content-type", "application/grpc")
        .header("x-large-metadata", "x".repeat(40 * 1024))
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);

    drop(sender);
    client.abort();
    server.abort();
}

#[tokio::test]
async fn grpc_server_rejects_http1_like_xray_v26_2_6() {
    let (mut client, server) = tokio::io::duplex(4096);
    let builder = grpc_http2_builder(GrpcKeepalive {
        idle_timeout: 0,
        health_check_timeout: 0,
    });
    let server = tokio::spawn(async move {
        let service = service_fn(|_| async {
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                b"unexpected HTTP/1 response",
            ))))
        });
        builder
            .serve_connection(TokioIo::new(server), service)
            .await
    });

    client
            .write_all(
                b"POST /svc/Tun HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert!(server.await.unwrap().is_err());
    assert!(
        !response.starts_with(b"HTTP/1.1 200"),
        "gRPC transport must stay HTTP/2-only"
    );
}

#[test]
fn grpc_server_exposes_tun_and_tun_multi_like_xray_v26_2_6() {
    let (tun, tun_multi) = grpc_service_paths("GunService");
    assert_eq!(tun, "/GunService/Tun");
    assert_eq!(tun_multi, "/GunService/TunMulti");
}

#[test]
fn grpc_custom_service_paths_match_xray_v26_2_6() {
    let (tun, tun_multi) = grpc_service_paths("");
    assert_eq!(tun, "//Tun");
    assert_eq!(tun_multi, "//TunMulti");

    let (tun, tun_multi) =
        grpc_service_paths("/my/sample path/tun service|multi service");
    assert_eq!(tun, "/my/sample%20path/tun%20service");
    assert_eq!(tun_multi, "/my/sample%20path/multi%20service");

    let (tun, tun_multi) = grpc_service_paths("hello/world!");
    assert_eq!(tun, "/hello%2Fworld%21/Tun");
    assert_eq!(tun_multi, "/hello%2Fworld%21/TunMulti");
}

#[test]
fn grpc_duplicate_host_validation_matches_xray_v26_2_6() {
    let uri: hyper::Uri = "http://proxy.example/NoService/Tun".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.append(hyper::header::HOST, "a.example".parse().unwrap());
    assert_eq!(grpc_duplicate_host_error(&headers, &uri), None);

    headers.append(hyper::header::HOST, "b.example".parse().unwrap());
    let message = grpc_duplicate_host_error(&headers, &uri)
        .expect("duplicate Host headers must be rejected before gRPC dispatch");
    assert_eq!(
        message,
        "num values of :authority: 1, num values of host: 2, both must only have 1 value as per HTTP/2 spec"
    );
    let response = grpc_duplicate_host_response(&message);
    assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["content-type"], "application/grpc");
    assert_eq!(response.headers()["grpc-status"], "13");
    assert_eq!(response.headers()["grpc-message"], message);
}

#[test]
fn grpc_content_type_validation_matches_xray_v26_2_6() {
    for valid in [
        "application/grpc",
        "application/grpc+proto",
        "application/grpc+xml",
        "application/grpc; charset=utf-8",
    ] {
        assert!(grpc_content_type_is_valid(valid), "{valid}");
    }
    for invalid in [
        "",
        "application/grpcfoo",
        "application/grpcx+proto",
        "application/grpc ",
        "application/grpc/",
        "APPLICATION/GRPC",
        "text/plain",
    ] {
        assert!(!grpc_content_type_is_valid(invalid), "{invalid}");
    }

    let mut headers = HeaderMap::new();
    headers.append("content-type", "text/plain".parse().unwrap());
    headers.append("content-type", "application/grpc".parse().unwrap());
    assert_eq!(grpc_content_type(&headers), Ok("application/grpc"));

    let mut headers = HeaderMap::new();
    headers.append("content-type", "application/grpc".parse().unwrap());
    headers.append("content-type", "application/grpcfoo".parse().unwrap());
    assert_eq!(grpc_content_type(&headers), Ok("application/grpc"));

    let mut headers = HeaderMap::new();
    headers.append("content-type", "text/plain".parse().unwrap());
    headers.append("content-type", "application/grpcfoo".parse().unwrap());
    assert_eq!(
        grpc_content_type(&headers),
        Err("application/grpcfoo".into())
    );

    let response = grpc_invalid_content_type_response("application/grpcfoo");
    assert_eq!(response.status(), hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(response.headers()["content-type"], "application/grpc");
    assert_eq!(response.headers()["grpc-status"], "3");
    assert_eq!(
        response.headers()["grpc-message"],
        "invalid gRPC request content-type \"application/grpcfoo\""
    );

    let response = grpc_invalid_content_type_response("application/grpc%foo");
    assert_eq!(
        response.headers()["grpc-message"],
        "invalid gRPC request content-type \"application/grpc%25foo\""
    );
}

#[test]
fn grpc_binary_metadata_validation_matches_xray_v26_2_6() {
    for valid in [b"".as_slice(), b"AQI=", b"AQI", b"AB", b"AB=="] {
        assert_eq!(grpc_invalid_base64_offset(valid), None, "{valid:?}");
    }
    for (invalid, offset) in [
        (b"A".as_slice(), 0),
        (b"A=".as_slice(), 1),
        (b"A===".as_slice(), 1),
        (b"AQI==".as_slice(), 3),
        (b"AQI*".as_slice(), 3),
        (b"!!!".as_slice(), 0),
    ] {
        assert_eq!(grpc_invalid_base64_offset(invalid), Some(offset));
    }

    let mut headers = HeaderMap::new();
    headers.insert("x-test-bin", "!!!".parse().unwrap());
    let message = grpc_malformed_binary_metadata(&headers)
        .expect("invalid binary metadata must be rejected");
    assert_eq!(
        message,
        "malformed binary metadata \"!!!\" in header \"x-test-bin\": illegal base64 data at input byte 0"
    );
    let response = grpc_malformed_binary_metadata_response(&message);
    assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["grpc-status"], "13");
    assert_eq!(response.headers()["grpc-message"], message);
}

#[test]
fn grpc_non_post_response_matches_xray_v26_2_6() {
    for method in [hyper::Method::GET, hyper::Method::PUT] {
        let response = grpc_method_not_allowed_response(&method);
        assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        assert_eq!(response.headers()["grpc-status"], "13");
        assert_eq!(
            response.headers()["grpc-message"],
            format!(
                "Received a HEADERS frame with :method \"{method}\" which should be POST"
            )
        );
    }
}

#[test]
fn grpc_unknown_service_and_method_match_xray_v26_2_6() {
    let tun_path = "/GunService/Tun";

    let response = grpc_unimplemented_path_response("/NoService/Tun", tun_path);
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "12");
    assert_eq!(
        response.headers()["grpc-message"],
        "unknown service NoService"
    );

    let response = grpc_unimplemented_path_response("/GunService/Nope", tun_path);
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "12");
    assert_eq!(
        response.headers()["grpc-message"],
        "unknown method Nope for service GunService"
    );

    let response = grpc_unimplemented_path_response("/No%25Service/Tun", tun_path);
    assert_eq!(response.headers()["grpc-status"], "12");
    assert_eq!(
        response.headers()["grpc-message"],
        "unknown service No%2525Service"
    );
}

#[test]
fn grpc_message_encoding_matches_grpc_go() {
    assert_eq!(grpc_encode_message("plain text"), "plain text");
    assert_eq!(grpc_encode_message("50% done"), "50%25 done");
    assert_eq!(grpc_encode_message("line\nbreak"), "line%0Abreak");
    assert_eq!(grpc_encode_message("é"), "%C3%A9");
}

#[test]
fn grpc_rejects_out_of_range_protobuf_field_numbers_like_xray_v26_2_6() {
    let encode_key = |field_number: usize| {
        let mut key = Vec::new();
        encode_varint(field_number << 3, &mut key);
        key
    };

    let mut max_field = encode_key(PROTOBUF_MAX_FIELD_NUMBER);
    max_field.push(1);
    max_field.extend_from_slice(&[0x0a, 0x02, b'o', b'k']);
    let mut frame = vec![0];
    frame.extend_from_slice(&(max_field.len() as u32).to_be_bytes());
    frame.extend_from_slice(&max_field);
    let mut buffer = BytesMut::from(frame.as_slice());
    assert_eq!(
        decode_grpc_message(&mut buffer, false).unwrap(),
        Some(vec![b"ok".to_vec()])
    );

    let mut too_large = encode_key(PROTOBUF_MAX_FIELD_NUMBER + 1);
    too_large.push(1);
    too_large.extend_from_slice(&[0x0a, 0x02, b'o', b'k']);
    let mut frame = vec![0];
    frame.extend_from_slice(&(too_large.len() as u32).to_be_bytes());
    frame.extend_from_slice(&too_large);
    let mut buffer = BytesMut::from(frame.as_slice());
    let error = decode_grpc_message(&mut buffer, false)
        .expect_err("protobuf field numbers above 2^29 - 1 must be rejected");
    let status = grpc_upload_status_from_error(&error)
        .expect("invalid protobuf field number must map to a status");
    assert_eq!(status.code, 13);
    assert_eq!(
        status.message,
        "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
    );
}

#[tokio::test]
async fn grpc_invalid_protobuf_reports_internal_like_xray_v26_2_6() {
    let protobuf = [0x00_u8];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let error = decode_grpc_message(&mut buffer, false)
        .expect_err("invalid protobuf wire format must be rejected");
    let status = grpc_upload_status_from_error(&error)
        .expect("invalid protobuf wire format must map to a status");
    assert_eq!(status.code, 13);
    assert_eq!(
        status.message,
        "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
    );

    let (transport_stream, handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    drop(handler_stream);
    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    status_tx.send(status).unwrap();
    drop(status_tx);

    let response = grpc_stream_response(
        transport_read,
        false,
        Arc::new(AtomicBool::new(false)),
        Some(status_rx),
        None,
    );
    let collected = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect invalid-protobuf response");
    let trailers = collected.trailers().expect("invalid-protobuf trailers");
    assert_eq!(trailers["grpc-status"], "13");
    assert_eq!(
        trailers["grpc-message"],
        "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
    );
}

#[test]
fn grpc_rejects_overflowing_protobuf_varints_like_xray_v26_2_6() {
    let protobuf = [
        0x10_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x0a,
        0x02, b'o', b'k',
    ];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());

    let error = decode_grpc_message(&mut buffer, false)
        .expect_err("protobuf varints wider than uint64 must be rejected");
    let status = grpc_upload_status_from_error(&error)
        .expect("overflowing protobuf varint must map to an internal status");
    assert_eq!(status.code, 13);
    assert_eq!(
        status.message,
        "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data"
    );

    let protobuf = [
        0x10_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x0a,
        0x02, b'o', b'k',
    ];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    assert_eq!(
        decode_grpc_message(&mut buffer, false).unwrap(),
        Some(vec![b"ok".to_vec()])
    );
}

#[tokio::test]
async fn grpc_truncated_message_reports_unexpected_eof_like_xray_v26_2_6() {
    let error = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "truncated gRPC message",
    );
    let status = grpc_upload_status_from_error(&error)
        .expect("truncated gRPC message must map to a status");
    assert_eq!(status.code, 13);
    assert_eq!(status.message, "unexpected EOF");

    let (transport_stream, handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    drop(handler_stream);
    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    status_tx.send(status).unwrap();
    drop(status_tx);

    let response = grpc_stream_response(
        transport_read,
        false,
        Arc::new(AtomicBool::new(false)),
        Some(status_rx),
        None,
    );
    let collected = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect truncated-message response");
    let trailers = collected.trailers().expect("truncated-message trailers");
    assert_eq!(trailers["grpc-status"], "13");
    assert_eq!(trailers["grpc-message"], "unexpected EOF");
}

#[tokio::test]
async fn grpc_compressed_flag_reports_internal_like_xray_v26_2_6() {
    let mut buffer = BytesMut::from(&[1_u8, 0, 0, 0, 0][..]);
    let error = decode_grpc_message(&mut buffer, false).expect_err(
        "compressed gRPC message must be rejected without a decompressor",
    );
    let status = grpc_upload_status_from_error(&error)
        .expect("compressed gRPC message must map to a status");
    assert_eq!(status.code, 13);
    assert_eq!(
        status.message,
        "grpc: compressed flag set with identity or empty encoding"
    );

    let (transport_stream, handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    drop(handler_stream);
    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    status_tx.send(status).unwrap();
    drop(status_tx);

    let response = grpc_stream_response(
        transport_read,
        false,
        Arc::new(AtomicBool::new(false)),
        Some(status_rx),
        None,
    );
    let collected = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect compressed-message response");
    let trailers = collected.trailers().expect("compressed-message trailers");
    assert_eq!(trailers["grpc-status"], "13");
    assert_eq!(
        trailers["grpc-message"],
        "grpc: compressed flag set with identity or empty encoding"
    );
}

#[tokio::test]
async fn grpc_invalid_payload_format_reports_internal_like_xray_v26_2_6() {
    for format in [2_u8, u8::MAX] {
        let mut buffer = BytesMut::from(&[format, 0, 0, 0, 0][..]);
        let error = decode_grpc_message(&mut buffer, false)
            .expect_err("unsupported gRPC payload format must be rejected");
        let status = grpc_upload_status_from_error(&error)
            .expect("unsupported gRPC payload format must map to a status");
        assert_eq!(status.code, 13);
        assert_eq!(
            status.message,
            format!("grpc: received unexpected payload format {format}")
        );
    }
}

#[tokio::test]
async fn grpc_oversized_message_reports_resource_exhausted_like_xray_v26_2_6() {
    let mut buffer = BytesMut::from(&[0_u8, 0, 0x40, 0, 1][..]);
    let error = decode_grpc_message(&mut buffer, false)
        .expect_err("4 MiB + 1 gRPC message must be rejected");
    let status = grpc_upload_status_from_error(&error)
        .expect("oversized gRPC message must map to a status");
    assert_eq!(status.code, 8);
    assert_eq!(
        status.message,
        "grpc: received message larger than max (4194305 vs. 4194304)"
    );

    let (transport_stream, handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    drop(handler_stream);
    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();
    status_tx.send(status).unwrap();
    drop(status_tx);

    let response = grpc_stream_response(
        transport_read,
        false,
        Arc::new(AtomicBool::new(false)),
        Some(status_rx),
        None,
    );
    let collected = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect resource exhausted response");
    let trailers = collected.trailers().expect("resource exhausted trailers");
    assert_eq!(trailers["grpc-status"], "8");
    assert_eq!(
        trailers["grpc-message"],
        "grpc: received message larger than max (4194305 vs. 4194304)"
    );
}

#[tokio::test]
async fn grpc_success_metadata_matches_xray_v26_2_6() {
    let (transport_stream, handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    drop(handler_stream);

    let response = grpc_stream_response(
        transport_read,
        false,
        Arc::new(AtomicBool::new(false)),
        None,
        None,
    );
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/grpc");
    assert!(!response.headers().contains_key("grpc-encoding"));
    assert!(!response.headers().contains_key("grpc-accept-encoding"));

    let collected = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect gRPC response");
    let trailers = collected.trailers().expect("gRPC success trailers");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(trailers["grpc-message"], "");
}

#[tokio::test]
async fn dropping_grpc_response_aborts_logical_stream_tasks() {
    let (transport_stream, _handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    let upload_task = tokio::spawn(futures::future::pending::<()>());
    let stream_task = tokio::spawn(futures::future::pending::<()>());
    let upload_abort = upload_task.abort_handle();
    let stream_abort = stream_task.abort_handle();
    let guard = GrpcStreamTaskGuard {
        upload_abort,
        stream_abort,
        deadline_abort: None,
    };

    let response = grpc_stream_response(
        transport_read,
        false,
        Arc::new(AtomicBool::new(false)),
        None,
        Some(guard),
    );
    drop(response);

    assert!(
        upload_task
            .await
            .expect_err("upload task must be aborted")
            .is_cancelled()
    );
    assert!(
        stream_task
            .await
            .expect_err("logical stream task must be aborted")
            .is_cancelled()
    );
}

#[tokio::test]
async fn grpc_deadline_ends_stream_without_success_trailers() {
    let (transport_stream, handler_stream) = tokio::io::duplex(64);
    let (transport_read, _transport_write) = tokio::io::split(transport_stream);
    drop(handler_stream);
    let timed_out = Arc::new(AtomicBool::new(true));

    let response =
        grpc_stream_response(transport_read, false, timed_out, None, None);
    let error = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect_err("expired gRPC stream must end with a body error");
    assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
}

#[test]
fn grpc_timeout_parser_matches_grpc_go_syntax() {
    let mut headers = HeaderMap::new();
    assert_eq!(grpc_timeout_duration(&headers).unwrap(), None);

    headers.insert("grpc-timeout", "1S".parse().unwrap());
    assert_eq!(
        grpc_timeout_duration(&headers).unwrap(),
        Some(std::time::Duration::from_secs(1))
    );

    headers.insert("grpc-timeout", "250m".parse().unwrap());
    assert_eq!(
        grpc_timeout_duration(&headers).unwrap(),
        Some(std::time::Duration::from_millis(250))
    );

    headers.insert("grpc-timeout", "nope".parse().unwrap());
    let message = grpc_timeout_duration(&headers).unwrap_err();
    assert_eq!(
        message,
        "malformed grpc-timeout: transport: timeout unit is not recognized: \"nope\""
    );
    let response = grpc_malformed_timeout_response(&message);
    assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["grpc-status"], "13");
    assert_eq!(response.headers()["grpc-message"], message);

    headers.insert("grpc-timeout", "xS".parse().unwrap());
    let message = grpc_timeout_duration(&headers).unwrap_err();
    assert_eq!(
        message,
        "malformed grpc-timeout: strconv.ParseUint: parsing \"x\": invalid syntax"
    );
    let response = grpc_malformed_timeout_response(&message);
    assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["grpc-status"], "13");
    assert_eq!(response.headers()["grpc-message"], message);
}

#[test]
fn grpc_expired_deadline_uses_xray_status() {
    let response = grpc_deadline_exceeded_response();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "4");
    assert_eq!(
        response.headers()["grpc-message"],
        "context deadline exceeded"
    );
}

#[test]
fn grpc_duplicate_timeouts_validate_all_values_but_use_first_like_xray_v26_2_6() {
    let mut headers = HeaderMap::new();
    headers.append("grpc-timeout", "1S".parse().unwrap());
    headers.append("grpc-timeout", "2S".parse().unwrap());
    assert_eq!(
        grpc_timeout_duration(&headers).unwrap(),
        Some(std::time::Duration::from_secs(1))
    );

    headers.append("grpc-timeout", "nope".parse().unwrap());
    assert_eq!(
        grpc_timeout_duration(&headers).unwrap_err(),
        "malformed grpc-timeout: transport: timeout unit is not recognized: \"nope\""
    );
}

#[test]
fn grpc_rejects_non_identity_encoding_like_xray_v26_2_6() {
    let mut headers = HeaderMap::new();
    assert_eq!(grpc_unsupported_encoding(&headers), None);

    headers.insert("grpc-encoding", "identity".parse().unwrap());
    assert_eq!(grpc_unsupported_encoding(&headers), None);

    headers.insert("grpc-encoding", "".parse().unwrap());
    assert_eq!(grpc_unsupported_encoding(&headers), None);

    headers.insert("grpc-encoding", "gzip".parse().unwrap());
    assert_eq!(grpc_unsupported_encoding(&headers), Some("gzip"));

    headers.insert("grpc-encoding", "deflate".parse().unwrap());
    assert_eq!(grpc_unsupported_encoding(&headers), Some("deflate"));

    headers.clear();
    headers.append("grpc-encoding", "identity".parse().unwrap());
    headers.append("grpc-encoding", "gzip".parse().unwrap());
    assert_eq!(grpc_unsupported_encoding(&headers), Some("gzip"));

    headers.clear();
    headers.append("grpc-encoding", "gzip".parse().unwrap());
    headers.append("grpc-encoding", "identity".parse().unwrap());
    assert_eq!(grpc_unsupported_encoding(&headers), None);
}

#[test]
fn grpc_trusted_x_forwarded_for_matches_current_xray() {
    let peer_addr = "127.0.0.1:34567".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "203.0.113.9, 198.51.100.2".parse().unwrap(),
    );
    assert_eq!(grpc_logical_peer_addr(&headers, peer_addr, &[]), peer_addr);
    assert_eq!(
        grpc_logical_peer_addr(&headers, peer_addr, &["X-Trusted-CDN".to_string()]),
        peer_addr
    );

    headers.insert("x-trusted-cdn", "".parse().unwrap());
    assert_eq!(
        grpc_logical_peer_addr(&headers, peer_addr, &["X-Trusted-CDN".to_string()]),
        "203.0.113.9:0".parse().unwrap()
    );

    assert_eq!(
        grpc_logical_peer_addr(
            &headers,
            peer_addr,
            &["X-Forwarded-For".to_string()]
        ),
        "203.0.113.9:0".parse().unwrap()
    );

    headers.insert("x-real-ip", "192.0.2.10".parse().unwrap());
    headers.remove("x-forwarded-for");
    assert_eq!(
        grpc_logical_peer_addr(&headers, peer_addr, &["X-Trusted-CDN".to_string()]),
        peer_addr
    );
}

#[test]
fn grpc_logical_addrs_preserve_accepted_local_addr() {
    let peer_addr = "127.0.0.1:34567".parse().unwrap();
    let local_addr = "127.0.0.1:8443".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    headers.insert("x-trusted-cdn", "".parse().unwrap());
    let context = GrpcPeerContext {
        peer_addr,
        local_addr,
        trusted_x_forwarded_for: Arc::new(vec!["X-Trusted-CDN".to_string()]),
        sniffing: None,
    };

    let (logical_peer_addr, logical_local_addr) =
        grpc_logical_addrs(&headers, &context);

    assert_eq!(logical_peer_addr, "203.0.113.9:0".parse().unwrap());
    assert_eq!(logical_local_addr, local_addr);
}

#[test]
fn hunk_round_trip_handles_large_payload() {
    let payload = (0..70_000).map(|value| value as u8).collect::<Vec<_>>();
    let encoded = encode_grpc_message(&payload, false);
    let mut buffer = BytesMut::from(encoded.as_ref());
    let decoded = decode_grpc_message(&mut buffer, false)
        .expect("decode Hunk")
        .expect("complete Hunk");
    assert_eq!(decoded, vec![payload]);
    assert!(buffer.is_empty());
}

#[test]
fn grpc_message_view_reuses_frame_backing_memory() {
    let protobuf = [0x0a, 0x05, b'h', b'e', b'l', b'l', b'o'];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let message_ptr = buffer[5..].as_ptr();

    let decoded = decode_grpc_message_view(&mut buffer, false)
        .expect("decode Hunk view")
        .expect("complete Hunk view");

    assert_eq!(decoded.data.as_ptr(), message_ptr);
    assert_eq!(decoded.payloads, vec![2..7]);
    assert_eq!(&decoded.data[decoded.payloads[0].clone()], b"hello");
    assert!(buffer.is_empty());
}

#[test]
fn multi_hunk_decodes_repeated_data_fields_in_order() {
    let protobuf = [
        0x0a, 0x05, b'h', b'e', b'l', b'l', b'o', 0x0a, 0x05, b'w', b'o', b'r',
        b'l', b'd',
    ];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let decoded = decode_grpc_message(&mut buffer, true)
        .expect("decode MultiHunk")
        .expect("complete MultiHunk");
    assert_eq!(decoded, vec![b"hello".to_vec(), b"world".to_vec()]);
    assert!(buffer.is_empty());
}

#[test]
fn hunk_decoder_matches_protobuf_unknown_and_duplicate_field_semantics() {
    let protobuf = [
        0x10, 0x01, // unknown varint field 2
        0x0a, 0x05, b'f', b'i', b'r', b's', b't', 0x1a, 0x03, b'x', b'y',
        b'z', // unknown bytes field 3
        0x0a, 0x04, b'l', b'a', b's', b't',
    ];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let decoded = decode_grpc_message(&mut buffer, false)
        .expect("decode Hunk with protobuf-compatible unknown fields")
        .expect("complete Hunk");
    assert_eq!(decoded, vec![b"last".to_vec()]);
    assert!(buffer.is_empty());
}

#[test]
fn hunk_skips_unknown_group_fields_like_xray_v26_2_6() {
    let protobuf = [
        0x13, // unknown field 2, start group
        0x18, 0x01, // nested unknown varint field 3
        0x14, // field 2, end group
        0x0a, 0x02, b'o', b'k',
    ];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let decoded = decode_grpc_message(&mut buffer, false)
        .expect("unknown protobuf group is skipped by generated decoder")
        .expect("complete Hunk");
    assert_eq!(decoded, vec![b"ok".to_vec()]);
    assert!(buffer.is_empty());
}

#[test]
fn hunk_ignores_known_data_field_with_wrong_wire_type_like_xray_v26_2_6() {
    let protobuf = [0x08_u8, 0x01];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let decoded = decode_grpc_message(&mut buffer, false)
        .expect("wrong-wire data field is skipped by generated protobuf decoder")
        .expect("complete Hunk");
    assert_eq!(decoded, vec![Vec::<u8>::new()]);
    assert!(buffer.is_empty());
}

#[test]
fn multi_hunk_ignores_unknown_fields_and_keeps_all_data_fields() {
    let protobuf = [
        0x0a, 0x03, b'o', b'n', b'e', 0x2d, 0x01, 0x02, 0x03,
        0x04, // unknown fixed32 field 5
        0x0a, 0x03, b't', b'w', b'o',
    ];
    let mut frame = vec![0];
    frame.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    frame.extend_from_slice(&protobuf);
    let mut buffer = BytesMut::from(frame.as_slice());
    let decoded = decode_grpc_message(&mut buffer, true)
        .expect("decode MultiHunk with protobuf-compatible unknown fields")
        .expect("complete MultiHunk");
    assert_eq!(decoded, vec![b"one".to_vec(), b"two".to_vec()]);
    assert!(buffer.is_empty());
}

#[test]
fn hunk_decoder_waits_for_complete_frame() {
    let encoded = encode_grpc_message(b"hello", false);
    let mut buffer = BytesMut::from(&encoded[..4]);
    assert!(decode_grpc_message(&mut buffer, false).unwrap().is_none());
}
