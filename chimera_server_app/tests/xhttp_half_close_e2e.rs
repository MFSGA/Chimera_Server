mod xhttp_support;

use std::{
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Once},
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
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use xhttp_support::{
    TEST_UUID, create_test_dir, free_localhost_port, serial_xray_guard_async,
    start_chimera, start_tcp_half_close_server, start_xray, wait_for_tcp,
    workspace_root, write_json, xray_binary,
};

const XHTTP_PATH: &str = "/xhttp-v1/";
const HALF_CLOSE_PAYLOAD: &[u8] = b"raw-h2-half-close";
const REQUEST_PADDING: &str = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
static RUSTLS_PROVIDER: Once = Once::new();

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_tls_h2_half_close_matches_xray() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping raw XHTTP/2 half-close test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    install_rustls_provider();
    let _serial = serial_xray_guard_async().await;
    let work_dir = create_test_dir("raw-h2-half-close");
    let (cert_path, key_path) = generate_test_certificate(&work_dir);
    let target_addr = start_tcp_half_close_server();
    let chimera_port = free_localhost_port();
    let xray_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_xhttp_config(&chimera_config, chimera_port, &cert_path, &key_path);
    write_xhttp_config(&xray_config, xray_port, &cert_path, &key_path);

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    let chimera_response = raw_h2_half_close(
        SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)),
        target_addr,
        &cert_path,
    )
    .await;
    chimera.assert_running();

    let mut xray_process = start_xray(&workspace, &work_dir, &xray_config);
    let xray_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_port));
    wait_for_tcp(xray_addr);
    let xray_response = raw_h2_half_close(xray_addr, target_addr, &cert_path).await;
    xray_process.assert_running();

    assert_eq!(chimera_response, xray_response);
    assert!(chimera_response.is_empty());
}

async fn raw_h2_half_close(
    server_addr: SocketAddr,
    target_addr: SocketAddr,
    cert_path: &Path,
) -> Vec<u8> {
    let tcp = TcpStream::connect(server_addr)
        .await
        .expect("connect raw XHTTP/2 client");
    let client_config = tls_client_config(cert_path);
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost")
        .expect("raw XHTTP/2 server name")
        .to_owned();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("complete raw XHTTP/2 TLS handshake");
    let (mut sender, connection) = client::handshake(tls)
        .await
        .expect("complete raw XHTTP/2 handshake");
    let connection_task = tokio::spawn(connection);

    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost{XHTTP_PATH}?x_padding={REQUEST_PADDING}"
        ))
        .body(())
        .expect("build raw XHTTP/2 request");
    let (response_future, mut request_body) = sender
        .send_request(request, false)
        .expect("send raw XHTTP/2 request headers");
    request_body
        .send_data(Bytes::from(build_vless_request(target_addr)), false)
        .expect("send raw VLESS request header");
    request_body
        .send_data(Bytes::from_static(HALF_CLOSE_PAYLOAD), true)
        .expect("send raw XHTTP/2 END_STREAM");

    let response = timeout(Duration::from_secs(5), response_future)
        .await
        .expect("raw XHTTP/2 response timeout")
        .expect("receive raw XHTTP/2 response");
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut response_body = response.into_body();
    let mut received = Vec::new();
    while let Some(chunk) = timeout(Duration::from_secs(5), response_body.data())
        .await
        .expect("raw XHTTP/2 response body timeout")
    {
        let chunk = chunk.expect("read raw XHTTP/2 response body");
        response_body
            .flow_control()
            .release_capacity(chunk.len())
            .expect("release raw XHTTP/2 response capacity");
        received.extend_from_slice(&chunk);
    }
    connection_task.abort();

    assert!(
        received.starts_with(&[0, 0]),
        "missing VLESS response header"
    );
    received.split_off(2)
}

fn build_vless_request(target_addr: SocketAddr) -> Vec<u8> {
    let target_ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => panic!("raw XHTTP/2 test uses an IPv4 target"),
    };
    let mut request = Vec::with_capacity(64);
    request.push(0);
    request.extend_from_slice(&parse_uuid(TEST_UUID));
    request.push(0);
    request.push(1);
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    request.push(1);
    request.extend_from_slice(&target_ip.octets());
    request
}

fn parse_uuid(value: &str) -> [u8; 16] {
    let compact = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>();
    assert_eq!(compact.len(), 32, "test UUID must contain 32 hex digits");
    let mut parsed = [0u8; 16];
    let (pairs, remainder) = compact.as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "test UUID must contain complete bytes"
    );
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
        _ => panic!("invalid test UUID hex digit"),
    }
}

fn write_xhttp_config(path: &Path, port: u16, cert_path: &Path, key_path: &Path) {
    write_json(
        path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "vless",
                "tag": "raw-h2-half-close",
                "settings": {
                    "clients": [{"id": TEST_UUID}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "tls",
                    "xhttpSettings": {
                        "path": XHTTP_PATH,
                        "mode": "stream-one",
                        "noGRPCHeader": false,
                        "noSSEHeader": false
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
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
}

fn generate_test_certificate(
    work_dir: &Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("generate raw XHTTP/2 RSA key");
    let cert = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("build raw XHTTP/2 certificate params")
        .self_signed(&signing_key)
        .expect("generate raw XHTTP/2 test certificate");
    let cert_path = work_dir.join("cert.pem");
    let key_path = work_dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write raw XHTTP/2 certificate");
    std::fs::write(&key_path, signing_key.serialize_pem())
        .expect("write raw XHTTP/2 private key");
    (cert_path, key_path)
}

fn tls_client_config(cert_path: &Path) -> ClientConfig {
    let cert_file = File::open(cert_path).expect("open raw XHTTP/2 certificate");
    let mut roots = RootCertStore::empty();
    for certificate in certs(&mut BufReader::new(cert_file)) {
        roots
            .add(certificate.expect("parse raw XHTTP/2 certificate"))
            .expect("add raw XHTTP/2 certificate root");
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
