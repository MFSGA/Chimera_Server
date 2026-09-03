mod xhttp_support;

use std::{
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Once},
    time::Duration,
};

use aws_lc_rs::digest::{SHA256, digest};
use rustls::{ServerConfig as RustlsServerConfig, crypto::CryptoProvider};
use rustls_pemfile::{certs, private_key};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use xhttp_support::{
    TEST_UUID, assert_socks5_echo, create_test_dir, deterministic_payload,
    free_localhost_port, serial_xray_guard, start_chimera, start_tcp_echo_server,
    start_xray, wait_for_tcp, workspace_root, write_json, xray_binary,
};

const REALITY_PRIVATE_KEY: &str = "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI";
const REALITY_PUBLIC_KEY: &str = "lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg";
const REALITY_SHORT_ID: &str = "4ac97aaf8b9b0356";
const REALITY_SERVER_NAME: &str = "www.apple.com";
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Clone, Copy)]
enum SecurityCase {
    None,
    Tls,
    Http3,
    Reality,
}

impl SecurityCase {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Http3 => "h3",
            Self::Reality => "reality",
        }
    }

    fn mode(self) -> &'static str {
        match self {
            Self::None => "packet-up",
            Self::Tls | Self::Http3 => "stream-one",
            Self::Reality => "stream-up",
        }
    }
}

async fn run_security_case(case: SecurityCase) {
    let workspace = workspace_root();
    let work_dir = create_test_dir(&format!("security-{}", case.name()));
    let (cert_path, key_path) = generate_test_certificate(&work_dir);
    let reality_dest = match case {
        SecurityCase::Reality => Some(start_tls13_dest(&cert_path, &key_path).await),
        _ => None,
    };
    let _serial = serial_xray_guard();
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera.json");
    let xray_config_path = work_dir.join("xray.json");
    let pinned_cert = first_cert_sha256_hex(&cert_path);
    let xhttp_settings = json!({
        "path": "/xhttp",
        "mode": case.mode(),
        "noGRPCHeader": true,
        "noSSEHeader": false,
        "scMinPostsIntervalMs": {"from": 1, "to": 1},
        "sessionIDPlacement": "header",
        "sessionIDKey": "X-Security-Session",
        "seqPlacement": "query",
        "seqKey": "x_security_seq",
        "uplinkDataPlacement": "body"
    });
    let mut xray_xhttp_settings = json!({
        "path": "/xhttp",
        "mode": case.mode(),
        "noGRPCHeader": true,
        "sessionPlacement": "header",
        "sessionKey": "X-Security-Session",
        "sessionIDPlacement": "header",
        "sessionIDKey": "X-Security-Session",
        "seqPlacement": "query",
        "seqKey": "x_security_seq",
        "uplinkDataPlacement": "body"
    });
    if matches!(case, SecurityCase::Http3) {
        xray_xhttp_settings["headers"] = json!({
            "X-H3-Large-Header": "a".repeat(16 * 1024)
        });
    }

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": format!("xhttp-security-{}", case.name()),
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": format!("{}@xhttp.security", case.name())
                    }],
                    "decryption": "none"
                },
                "streamSettings": chimera_stream_settings(
                    case,
                    xhttp_settings,
                    &cert_path,
                    &key_path,
                    reality_dest,
                )
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
    write_json(
        &xray_config_path,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "tag": "socks-in",
                "settings": {"auth": "noauth"}
            }],
            "outbounds": [{
                "tag": "to-chimera",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": chimera_port,
                        "users": [{"id": TEST_UUID, "encryption": "none"}]
                    }]
                },
                "streamSettings": xray_stream_settings(
                    case,
                    xray_xhttp_settings,
                    &pinned_cert,
                )
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    if matches!(case, SecurityCase::Http3) {
        std::thread::sleep(Duration::from_millis(250));
    } else {
        wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    }
    chimera.assert_running();
    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    wait_for_tcp(socks_addr);
    xray.assert_running();

    assert_socks5_echo(
        socks_addr,
        echo_addr,
        format!("XHTTP {} security", case.name()).as_bytes(),
    );
    assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
}

fn chimera_stream_settings(
    case: SecurityCase,
    xhttp_settings: Value,
    cert_path: &Path,
    key_path: &Path,
    reality_dest: Option<SocketAddr>,
) -> Value {
    match case {
        SecurityCase::None => json!({
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": xhttp_settings
        }),
        SecurityCase::Tls | SecurityCase::Http3 => json!({
            "network": "xhttp",
            "security": "tls",
            "xhttpSettings": xhttp_settings,
            "finalmask": if matches!(case, SecurityCase::Http3) {
                json!({
                    "quicParams": {
                        "congestion": "force-brutal",
                        "brutalUp": "8 mbps",
                        "maxIdleTimeout": 45,
                        "maxIncomingStreams": 64,
                        "initStreamReceiveWindow": 32768,
                        "maxStreamReceiveWindow": 65536,
                        "initConnectionReceiveWindow": 131072,
                        "maxConnectionReceiveWindow": 262144,
                        "disablePathMTUDiscovery": true
                    }
                })
            } else {
                Value::Null
            },
            "tlsSettings": {
                "serverName": "localhost",
                "alpn": if matches!(case, SecurityCase::Http3) {
                    json!(["h3"])
                } else {
                    json!(["h2", "http/1.1"])
                },
                "certificates": [{
                    "certificateFile": cert_path,
                    "keyFile": key_path
                }]
            }
        }),
        SecurityCase::Reality => json!({
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": xhttp_settings,
            "realitySettings": {
                "dest": reality_dest.expect("REALITY destination").to_string(),
                "serverNames": [REALITY_SERVER_NAME],
                "privateKey": REALITY_PRIVATE_KEY,
                "shortIds": [REALITY_SHORT_ID],
                "maxTimeDiff": 0,
                "minClientVer": "26.2.6"
            }
        }),
    }
}

fn xray_stream_settings(
    case: SecurityCase,
    xhttp_settings: Value,
    pinned_cert: &str,
) -> Value {
    match case {
        SecurityCase::None => json!({
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": xhttp_settings
        }),
        SecurityCase::Tls | SecurityCase::Http3 => json!({
            "network": "xhttp",
            "security": "tls",
            "xhttpSettings": xhttp_settings,
            "tlsSettings": {
                "serverName": "localhost",
                "pinnedPeerCertSha256": pinned_cert,
                "alpn": if matches!(case, SecurityCase::Http3) {
                    json!(["h3"])
                } else {
                    json!(["h2", "http/1.1"])
                }
            }
        }),
        SecurityCase::Reality => json!({
            "network": "xhttp",
            "security": "reality",
            "xhttpSettings": xhttp_settings,
            "realitySettings": {
                "serverName": REALITY_SERVER_NAME,
                "fingerprint": "chrome",
                "publicKey": REALITY_PUBLIC_KEY,
                "shortId": REALITY_SHORT_ID
            }
        }),
    }
}

async fn run_xray_security_case(case: SecurityCase) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping XHTTP {} Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            case.name(),
            xray.display()
        );
        return;
    }
    run_security_case(case).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_security_none() {
    run_xray_security_case(SecurityCase::None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_security_tls() {
    run_xray_security_case(SecurityCase::Tls).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_security_http3() {
    run_xray_security_case(SecurityCase::Http3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_security_reality() {
    run_xray_security_case(SecurityCase::Reality).await;
}

async fn start_tls13_dest(cert_path: &Path, key_path: &Path) -> SocketAddr {
    install_rustls_provider();
    let acceptor =
        TlsAcceptor::from(Arc::new(tls_server_config(cert_path, key_path)));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind REALITY TLS destination");
    let addr = listener
        .local_addr()
        .expect("REALITY TLS destination address");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    addr
}

fn generate_test_certificate(
    work_dir: &Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("generate XHTTP security RSA key");
    let cert = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("build XHTTP security certificate params")
        .self_signed(&signing_key)
        .expect("generate XHTTP security test certificate");
    let cert_path = work_dir.join("cert.pem");
    let key_path = work_dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write XHTTP test certificate");
    std::fs::write(&key_path, signing_key.serialize_pem())
        .expect("write XHTTP test private key");
    (cert_path, key_path)
}

fn tls_server_config(cert_path: &Path, key_path: &Path) -> RustlsServerConfig {
    let cert_file = File::open(cert_path).expect("open TLS cert");
    let key_file = File::open(key_path).expect("open TLS key");
    let cert_chain = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse TLS certificates");
    let key = private_key(&mut BufReader::new(key_file))
        .expect("parse TLS private key")
        .expect("TLS private key present");
    RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("build TLS server config")
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
}

fn first_cert_sha256_hex(cert_path: &Path) -> String {
    let cert_file = File::open(cert_path).expect("open pinned certificate");
    let first_cert = certs(&mut BufReader::new(cert_file))
        .next()
        .expect("certificate present")
        .expect("parse certificate");
    let bytes = digest(&SHA256, first_cert.as_ref());
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
