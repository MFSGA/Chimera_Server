use std::{path::Path, sync::Arc, time::Duration};

use bytes::BytesMut;
use tokio::{
    io::AsyncReadExt,
    net::UdpSocket,
    time::{sleep, timeout},
};

use super::*;
use crate::{
    runtime::{OutboundSummary, RuntimeState},
    traffic::{TrafficSnapshot, active_connections, snapshot},
    util::rustls_util::create_server_config,
};

const TEST_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb2273";
const TEST_PASSWORD: &str = "tuic-test-password";
const TEST_INBOUND: &str = "tuic-e2e-in";
const TEST_OUTBOUND: &str = "tuic-e2e-out";

#[derive(Debug)]
struct AcceptTestServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptTestServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[tokio::test]
async fn udp_stream_and_datagram_roundtrips_record_stats() {
    let payloads = [b"TUIC datagram".as_slice(), b"TUIC stream".as_slice()];
    let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo_socket.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 256];
        for _ in 0..2 {
            let (len, peer) = echo_socket.recv_from(&mut buf).await.unwrap();
            echo_socket.send_to(&buf[..len], peer).await.unwrap();
        }
    });

    let (server_task, endpoint, connection) = start_test_connection().await;
    authenticate(&connection).await;
    let before = snapshot();

    assert_datagram_roundtrip(&connection, echo_addr, payloads[0]).await;
    assert_stream_roundtrip(&connection, echo_addr, payloads[1]).await;

    assert!(active_connections().iter().any(|entry| {
        entry.inbound_tag.as_deref() == Some(TEST_INBOUND)
            && entry.identity.as_deref() == Some(TEST_UUID)
    }));
    let expected_bytes = payloads.iter().map(|payload| payload.len() as u64).sum();
    let after = wait_for_stats(&before, expected_bytes).await;
    assert_all_stat_deltas(&before, &after, expected_bytes);

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    server_task.abort();
    echo_task.await.unwrap();
}

async fn start_test_connection() -> (
    tokio::task::JoinHandle<std::io::Result<()>>,
    quinn::Endpoint,
    quinn::Connection,
) {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_addr = probe.local_addr().unwrap();
    drop(probe);

    let cert_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cert");
    let cert_bytes = std::fs::read(cert_dir.join("cert.pem")).unwrap();
    let key_bytes = std::fs::read(cert_dir.join("key.pem")).unwrap();
    let server_config = Arc::new(create_server_config(
        &cert_bytes,
        &key_bytes,
        &["h3".into()],
        &[],
    ));
    let runtime = RuntimeState::new(
        Vec::new(),
        vec![OutboundSummary {
            tag: TEST_OUTBOUND.into(),
            protocol: "freedom".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }],
    );
    let server_task = tokio::spawn(run_tuic_server(
        server_addr,
        server_config,
        TuicServerConfig {
            uuid: TEST_UUID.into(),
            password: TEST_PASSWORD.into(),
            zero_rtt_handshake: false,
        },
        TEST_INBOUND.into(),
        runtime,
    ));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptTestServerCert))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));
    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config);

    let connection = timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(connecting) = endpoint.connect(server_addr, "localhost")
                && let Ok(connection) = connecting.await
            {
                return connection;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("connect TUIC test client");

    (server_task, endpoint, connection)
}

async fn authenticate(connection: &quinn::Connection) {
    let uuid = uuid::Uuid::parse_str(TEST_UUID).unwrap().into_bytes();
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, &uuid, TEST_PASSWORD.as_bytes())
        .unwrap();
    let mut auth = connection.open_uni().await.unwrap();
    auth.write_all(&[TUIC_VERSION, COMMAND_TYPE_AUTHENTICATE])
        .await
        .unwrap();
    auth.write_all(&uuid).await.unwrap();
    auth.write_all(&token).await.unwrap();
    auth.finish().unwrap();
}

async fn assert_datagram_roundtrip(
    connection: &quinn::Connection,
    target: SocketAddr,
    payload: &[u8],
) {
    let mut packet = BytesMut::new();
    packet.extend_from_slice(&[TUIC_VERSION, COMMAND_TYPE_PACKET, 0, 7, 0, 1, 1, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&serialize_socket_addr(&target));
    packet.extend_from_slice(payload);
    connection.send_datagram(packet.freeze()).unwrap();

    let response = timeout(Duration::from_secs(2), connection.read_datagram())
        .await
        .unwrap()
        .unwrap();
    let payload_offset = match response[10] {
        0x01 => 17,
        0x02 => 29,
        address_type => panic!("unexpected TUIC address type {address_type}"),
    };
    assert_eq!(&response[payload_offset..], payload);
}

async fn assert_stream_roundtrip(
    connection: &quinn::Connection,
    target: SocketAddr,
    payload: &[u8],
) {
    let mut packet = connection.open_uni().await.unwrap();
    packet
        .write_all(&[TUIC_VERSION, COMMAND_TYPE_PACKET, 0, 8, 0, 1, 1, 0])
        .await
        .unwrap();
    packet
        .write_all(&(payload.len() as u16).to_be_bytes())
        .await
        .unwrap();
    packet
        .write_all(&serialize_socket_addr(&target))
        .await
        .unwrap();
    packet.write_all(payload).await.unwrap();
    packet.finish().unwrap();

    let mut response = timeout(Duration::from_secs(2), connection.accept_uni())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.read_u16().await.unwrap(), 8);
    assert_eq!(response.read_u16().await.unwrap(), 0);
    assert_eq!(response.read_u8().await.unwrap(), 1);
    assert_eq!(response.read_u8().await.unwrap(), 0);
    assert_eq!(response.read_u16().await.unwrap() as usize, payload.len());
    assert_eq!(
        read_address(&mut response).await.unwrap(),
        Some(NetLocation::from_ip_addr(target.ip(), target.port()))
    );
    let mut echoed = vec![0u8; payload.len()];
    response.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
}

async fn wait_for_stats(before: &TrafficSnapshot, expected: u64) -> TrafficSnapshot {
    timeout(Duration::from_secs(1), async {
        loop {
            let current = snapshot();
            let before_upload = before
                .per_outbound
                .get(TEST_OUTBOUND)
                .map(|totals| totals.upload_bytes)
                .unwrap_or_default();
            let current_upload = current
                .per_outbound
                .get(TEST_OUTBOUND)
                .map(|totals| totals.upload_bytes)
                .unwrap_or_default();
            if current_upload.saturating_sub(before_upload) == expected {
                return current;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("TUIC stats update")
}

fn assert_all_stat_deltas(
    before: &TrafficSnapshot,
    after: &TrafficSnapshot,
    expected: u64,
) {
    assert_stat_delta(
        &before.per_outbound,
        &after.per_outbound,
        &TEST_OUTBOUND.to_string(),
        expected,
    );
    assert_stat_delta(
        &before.per_inbound,
        &after.per_inbound,
        &TEST_INBOUND.to_string(),
        expected,
    );
    assert_stat_delta(
        &before.per_inbound_user,
        &after.per_inbound_user,
        &(TEST_INBOUND.to_string(), TEST_UUID.to_string()),
        expected,
    );
}

fn assert_stat_delta<K>(
    before: &std::collections::HashMap<K, crate::traffic::TransferTotals>,
    after: &std::collections::HashMap<K, crate::traffic::TransferTotals>,
    key: &K,
    expected: u64,
) where
    K: Eq + std::hash::Hash,
{
    let before = before.get(key).cloned().unwrap_or_default();
    let after = after.get(key).cloned().unwrap_or_default();
    assert_eq!(after.upload_bytes - before.upload_bytes, expected);
    assert_eq!(after.download_bytes - before.download_bytes, expected);
}
