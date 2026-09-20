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
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use xhttp_support::{
    TEST_UUID, create_test_dir, free_localhost_port, serial_xray_guard,
    start_chimera, start_xray, wait_for_tcp, workspace_root, write_json,
    xray_binary,
};

const XHTTP_PATH: &str = "/xhttp-v1/";
const VALID_PADDING: &str = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const PACKET_LIMIT: usize = 8;
static RUSTLS_PROVIDER: std::sync::Once = std::sync::Once::new();

#[derive(Clone, Copy)]
enum PacketProbe {
    InvalidSequence,
    OversizedBody,
    InvalidPadding,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_tls_h2_packet_up_errors_match_xray_and_survive() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping XHTTP TLS/H2 packet-up error test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    install_rustls_provider();
    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("tls-packet-up-errors");
    let (cert_path, key_path) = generate_test_certificate(&work_dir);
    let chimera_port = free_localhost_port();
    let xray_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_packet_up_config(&chimera_config, chimera_port, &cert_path, &key_path);
    write_packet_up_config(&xray_config, xray_port, &cert_path, &key_path);

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    let chimera_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port));
    wait_for_tcp(chimera_addr);
    let chimera_statuses = probe_server(chimera_addr, &cert_path).await;
    chimera.assert_running();

    let mut xray_process = start_xray(&workspace, &work_dir, &xray_config);
    let xray_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_port));
    wait_for_tcp(xray_addr);
    let xray_statuses = probe_server(xray_addr, &cert_path).await;
    xray_process.assert_running();

    assert_eq!(chimera_statuses, xray_statuses);
    assert_eq!(chimera_statuses, [500, 413, 400]);
}

async fn probe_server(server_addr: SocketAddr, cert_path: &Path) -> [u16; 3] {
    let invalid_sequence = raw_h2_packet_status(
        server_addr,
        cert_path,
        Some(PacketProbe::InvalidSequence),
    )
    .await;
    let oversized_body = raw_h2_packet_status(
        server_addr,
        cert_path,
        Some(PacketProbe::OversizedBody),
    )
    .await;
    let invalid_padding = raw_h2_packet_status(
        server_addr,
        cert_path,
        Some(PacketProbe::InvalidPadding),
    )
    .await;
    let valid = raw_h2_packet_status(server_addr, cert_path, None).await;
    assert_eq!(
        valid, 200,
        "valid packet-up request must survive error probes"
    );
    [invalid_sequence, oversized_body, invalid_padding]
}

async fn raw_h2_packet_status(
    server_addr: SocketAddr,
    cert_path: &Path,
    probe: Option<PacketProbe>,
) -> u16 {
    let tcp = TcpStream::connect(server_addr)
        .await
        .expect("connect raw XHTTP/2 packet-up client");
    let connector = TlsConnector::from(Arc::new(tls_client_config(cert_path)));
    let server_name = ServerName::try_from("localhost")
        .expect("raw XHTTP/2 packet-up server name")
        .to_owned();
    let tls = connector
        .connect(server_name, tcp)
        .await
        .expect("complete raw XHTTP/2 packet-up TLS handshake");
    let (mut sender, connection) = client::handshake(tls)
        .await
        .expect("complete raw XHTTP/2 packet-up handshake");
    let connection_task = tokio::spawn(async move { connection.await });

    let (padding, sequence) = match probe {
        Some(PacketProbe::InvalidSequence) => (VALID_PADDING, "NaN"),
        Some(PacketProbe::InvalidPadding) => ("X", "0"),
        Some(PacketProbe::OversizedBody) | None => (VALID_PADDING, "0"),
    };
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost{XHTTP_PATH}?x_padding={padding}&x_seq={sequence}"
        ))
        .header("X-Session", "packet-up-error-session")
        .body(())
        .expect("build raw XHTTP/2 packet-up request");
    let has_body = matches!(probe, Some(PacketProbe::OversizedBody));
    let (response_future, mut request_body) = sender
        .send_request(request, !has_body)
        .expect("send raw XHTTP/2 packet-up request");
    if has_body {
        request_body
            .send_data(Bytes::from(vec![b'x'; PACKET_LIMIT + 1]), true)
            .expect("send oversized raw XHTTP/2 packet-up body");
    }

    let response = timeout(Duration::from_secs(5), response_future)
        .await
        .expect("raw XHTTP/2 packet-up response timeout")
        .expect("receive raw XHTTP/2 packet-up response");
    let status = response.status().as_u16();
    let mut response_body = response.into_body();
    while let Some(chunk) = timeout(Duration::from_secs(5), response_body.data())
        .await
        .expect("raw XHTTP/2 packet-up response body timeout")
    {
        let chunk = chunk.expect("read raw XHTTP/2 packet-up response body");
        response_body
            .flow_control()
            .release_capacity(chunk.len())
            .expect("release raw XHTTP/2 packet-up response capacity");
    }
    connection_task.abort();
    status
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
                "tag": "xhttp-tls-packet-up-errors",
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
                        "scMaxEachPostBytes": PACKET_LIMIT,
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
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
}

fn generate_test_certificate(
    work_dir: &Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("generate XHTTP packet-up error test key");
    let cert = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("build XHTTP packet-up error test certificate params")
        .self_signed(&signing_key)
        .expect("generate XHTTP packet-up error test certificate");
    let cert_path = work_dir.join("cert.pem");
    let key_path = work_dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())
        .expect("write XHTTP packet-up error certificate");
    std::fs::write(&key_path, signing_key.serialize_pem())
        .expect("write XHTTP packet-up error private key");
    (cert_path, key_path)
}

fn tls_client_config(cert_path: &Path) -> ClientConfig {
    let cert_file =
        File::open(cert_path).expect("open XHTTP packet-up error certificate");
    let mut roots = RootCertStore::empty();
    for certificate in certs(&mut BufReader::new(cert_file)) {
        roots
            .add(certificate.expect("parse XHTTP packet-up error certificate"))
            .expect("add XHTTP packet-up error certificate root");
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
