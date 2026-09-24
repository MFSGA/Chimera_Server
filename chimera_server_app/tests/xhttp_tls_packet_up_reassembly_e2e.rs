mod xhttp_support;

use std::{
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use h2::client;
use http::Request;
use rustls::{
    ClientConfig, RootCertStore, crypto::CryptoProvider, pki_types::ServerName,
};
use rustls_pemfile::certs;
use serde_json::json;
use tokio::{net::TcpStream, sync::oneshot, time::timeout};
use tokio_rustls::TlsConnector;
use xhttp_support::{
    TEST_UUID, create_test_dir, free_localhost_port, serial_xray_guard_async,
    start_chimera, start_tcp_echo_server, start_xray, wait_for_tcp, workspace_root,
    write_json, xray_binary,
};

const XHTTP_PATH: &str = "/xhttp-v1/";
const VALID_PADDING: &str = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const SESSION_ID: &str = "packet-up-reassembly-session";
static RUSTLS_PROVIDER: std::sync::Once = std::sync::Once::new();

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_tls_h2_packet_up_reassembles_out_of_order_requests_like_xray() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping XHTTP TLS/H2 packet-up reassembly test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    install_rustls_provider();
    let _serial = serial_xray_guard_async().await;
    let work_dir = create_test_dir("tls-packet-up-reassembly");
    let (cert_path, key_path) = generate_test_certificate(&work_dir);
    let target_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_packet_up_config(&chimera_config, chimera_port, &cert_path, &key_path);
    write_packet_up_config(&xray_config, xray_port, &cert_path, &key_path);

    let mut xray_process = start_xray(&workspace, &work_dir, &xray_config);
    let xray_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_port));
    wait_for_tcp(xray_addr);
    let xray_payload = probe_reassembly(xray_addr, &cert_path, target_addr).await;
    xray_process.assert_running();

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    let chimera_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port));
    wait_for_tcp(chimera_addr);
    let chimera_payload =
        probe_reassembly(chimera_addr, &cert_path, target_addr).await;
    chimera.assert_running();

    assert_eq!(chimera_payload, xray_payload);
    assert_eq!(chimera_payload, b"AB");
}

async fn probe_reassembly(
    server_addr: SocketAddr,
    cert_path: &Path,
    target_addr: SocketAddr,
) -> Vec<u8> {
    let downlink_cert_path = cert_path.to_owned();
    let (ready_sender, ready_receiver) = oneshot::channel();
    let downlink = tokio::spawn(async move {
        raw_h2_downlink(server_addr, &downlink_cert_path, ready_sender).await
    });
    ready_receiver
        .await
        .expect("packet-up downlink response headers");

    let first_connection =
        send_packet(server_addr, cert_path, 1, Bytes::from_static(b"B")).await;
    let mut first_packet = build_vless_request(target_addr);
    first_packet.push(b'A');
    let second_connection =
        send_packet(server_addr, cert_path, 0, Bytes::from(first_packet)).await;
    let payload = downlink.await.expect("packet-up downlink task");
    first_connection.abort();
    second_connection.abort();
    payload
}

async fn send_packet(
    server_addr: SocketAddr,
    cert_path: &Path,
    sequence: u64,
    payload: Bytes,
) -> tokio::task::JoinHandle<Result<(), h2::Error>> {
    let (mut sender, connection) = connect_h2(server_addr, cert_path).await;
    let connection_task = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost{XHTTP_PATH}?x_padding={VALID_PADDING}&x_seq={sequence}"
        ))
        .header("X-Session", SESSION_ID)
        .header("content-length", payload.len())
        .body(())
        .expect("build packet-up request");
    let (response_future, mut request_body) = sender
        .send_request(request, false)
        .expect("send packet-up request headers");
    request_body
        .send_data(payload, true)
        .expect("send packet-up request payload");
    let response = timeout(Duration::from_secs(5), response_future)
        .await
        .expect("packet-up response timeout")
        .expect("receive packet-up response");
    assert_eq!(response.status(), http::StatusCode::OK);
    drain_response(response.into_body()).await;
    connection_task
}

async fn raw_h2_downlink(
    server_addr: SocketAddr,
    cert_path: &Path,
    ready_sender: oneshot::Sender<()>,
) -> Vec<u8> {
    let (mut sender, connection) = connect_h2(server_addr, cert_path).await;
    let connection_task = tokio::spawn(connection);
    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "https://localhost{XHTTP_PATH}?x_padding={VALID_PADDING}"
        ))
        .header("X-Session", SESSION_ID)
        .body(())
        .expect("build packet-up downlink request");
    let (response_future, _) = sender
        .send_request(request, true)
        .expect("send packet-up downlink request");
    let response = timeout(Duration::from_secs(5), response_future)
        .await
        .expect("packet-up downlink response timeout")
        .expect("receive packet-up downlink response");
    assert_eq!(response.status(), http::StatusCode::OK);
    let _ = ready_sender.send(());

    let mut body = response.into_body();
    let mut received = Vec::new();
    while received.len() < 4 {
        let chunk = match timeout(Duration::from_secs(5), body.data()).await {
            Ok(Some(chunk)) => chunk.expect("read packet-up downlink body"),
            Ok(None) => break,
            Err(_) => panic!(
                "packet-up downlink body timeout after {} bytes: {received:?}",
                received.len()
            ),
        };
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release packet-up downlink capacity");
        received.extend_from_slice(&chunk);
    }
    connection_task.abort();
    assert!(
        received.starts_with(&[0, 0]),
        "missing VLESS response header"
    );
    received.split_off(2)
}

async fn connect_h2(
    server_addr: SocketAddr,
    cert_path: &Path,
) -> (
    client::SendRequest<Bytes>,
    client::Connection<tokio_rustls::client::TlsStream<TcpStream>, Bytes>,
) {
    let tcp = TcpStream::connect(server_addr)
        .await
        .expect("connect raw XHTTP/2 packet-up client");
    let connector = TlsConnector::from(Arc::new(tls_client_config(cert_path)));
    let server_name = ServerName::try_from("localhost")
        .expect("packet-up reassembly server name")
        .to_owned();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("complete packet-up reassembly TLS handshake");
    client::handshake(tls)
        .await
        .expect("complete packet-up reassembly HTTP/2 handshake")
}

async fn drain_response(mut body: h2::RecvStream) {
    while let Some(chunk) = timeout(Duration::from_secs(5), body.data())
        .await
        .expect("packet-up response body timeout")
    {
        let chunk = chunk.expect("read packet-up response body");
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release packet-up response capacity");
    }
}

fn write_packet_up_config(
    path: &Path,
    port: u16,
    cert_path: &Path,
    key_path: &Path,
) {
    write_json(
        path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "tag": "xhttp-tls-packet-up-reassembly",
                "settings": {
                    "clients": [{"id": TEST_UUID}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": XHTTP_PATH,
                        "mode": "packet-up",
                        "noGRPCHeader": false,
                        "noSSEHeader": false,
                        "xPaddingBytes": 100,
                        "scMaxEachPostBytes": 4096,
                        "scMaxBufferedPosts": 8,
                        "sessionIDPlacement": "header",
                        "sessionIDKey": "X-Session",
                        "seqPlacement": "query",
                        "seqKey": "x_seq",
                        "uplinkDataPlacement": "body"
                    },
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": ["h2"],
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"finalRules": [{"action": "allow"}]}
            }]
        }),
    );
}

fn build_vless_request(target_addr: SocketAddr) -> Vec<u8> {
    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            panic!("packet-up reassembly uses an IPv4 target")
        }
    };
    let mut request = Vec::with_capacity(64);
    request.push(0);
    request.extend_from_slice(&parse_uuid(TEST_UUID));
    request.push(0);
    request.push(1);
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    request.push(1);
    request.extend_from_slice(&ip.octets());
    request
}

fn parse_uuid(value: &str) -> [u8; 16] {
    let compact = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>();
    assert_eq!(compact.len(), 32);
    let mut parsed = [0u8; 16];
    let (pairs, remainder) = compact.as_chunks::<2>();
    assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        parsed[index] = (hex(pair[0]) << 4) | hex(pair[1]);
    }
    parsed
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid UUID hex digit"),
    }
}

fn generate_test_certificate(
    work_dir: &Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("generate packet-up reassembly test key");
    let cert = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("build packet-up reassembly certificate params")
        .self_signed(&signing_key)
        .expect("generate packet-up reassembly certificate");
    let cert_path = work_dir.join("cert.pem");
    let key_path = work_dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())
        .expect("write packet-up reassembly certificate");
    std::fs::write(&key_path, signing_key.serialize_pem())
        .expect("write packet-up reassembly private key");
    (cert_path, key_path)
}

fn tls_client_config(cert_path: &Path) -> ClientConfig {
    let cert_file =
        File::open(cert_path).expect("open packet-up reassembly certificate");
    let mut roots = RootCertStore::empty();
    for certificate in certs(&mut BufReader::new(cert_file)) {
        roots
            .add(certificate.expect("parse packet-up reassembly certificate"))
            .expect("add packet-up reassembly certificate root");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
}
