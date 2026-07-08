use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Once,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::digest::{SHA256, digest};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as RustlsError,
    ServerConfig as RustlsServerConfig, SignatureScheme,
    client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rustls_pemfile::{certs, private_key};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb2273";
const REALITY_PRIVATE_KEY: &str = "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI";
const REALITY_PUBLIC_KEY: &str = "lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg";
const REALITY_SHORT_ID: &str = "4ac97aaf8b9b0356";
const REALITY_SERVER_NAME: &str = "www.apple.com";
const HYSTERIA_AUTH: &str = "hysteria-auth-token";
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Debug)]
struct AcceptTestServerCert;

impl ServerCertVerifier for AcceptTestServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

#[derive(Debug)]
struct ChildGuard {
    name: &'static str,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl ChildGuard {
    fn spawn(
        name: &'static str,
        command: &Path,
        args: &[&str],
        work_dir: &Path,
    ) -> io::Result<Self> {
        let stdout_path = work_dir.join(format!("{name}.stdout.log"));
        let stderr_path = work_dir.join(format!("{name}.stderr.log"));
        let child = Command::new(command)
            .args(args)
            .stdout(Stdio::from(File::create(&stdout_path)?))
            .stderr(Stdio::from(File::create(&stderr_path)?))
            .spawn()?;
        Ok(Self {
            name,
            child,
            stdout_path,
            stderr_path,
        })
    }

    fn assert_running(&mut self) {
        match self.child.try_wait() {
            Ok(Some(status)) => panic!(
                "{} exited early with {status}; stdout={} stderr={}",
                self.name,
                read_lossy(&self.stdout_path),
                read_lossy(&self.stderr_path)
            ),
            Ok(None) => {}
            Err(err) => panic!("failed to poll {}: {err}", self.name),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and ./xray as client for tcp+reality+vision"]
async fn xray_client_can_proxy_tcp_through_chimera_reality_vision() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("reality-vision");
    let echo_addr = start_tcp_echo_server();
    let domain_echo_addr = start_tcp_echo_server_v6();
    let tls_echo_addr = start_tls_echo_server(&workspace).await;
    let reality_dest_addr = start_tls13_dest(&workspace).await;
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();

    let chimera_config_path = work_dir.join("chimera-reality-vision.json");
    let xray_config_path = work_dir.join("xray-reality-vision-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-reality-vision",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "flow": "xtls-rprx-vision",
                        "email": "vision@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": format!("127.0.0.1:{}", reality_dest_addr.port()),
                        "serverNames": [REALITY_SERVER_NAME],
                        "privateKey": REALITY_PRIVATE_KEY,
                        "shortIds": [REALITY_SHORT_ID],
                        "maxTimeDiff": 0
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
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
                        "users": [{
                            "id": TEST_UUID,
                            "encryption": "none",
                            "flow": "xtls-rprx-vision"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": REALITY_SERVER_NAME,
                        "fingerprint": "chrome",
                        "publicKey": REALITY_PUBLIC_KEY,
                        "shortId": REALITY_SHORT_ID
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)));
    xray.assert_running();

    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    assert_socks5_echo(socks_addr, echo_addr, b"reality-vision through xray client");
    assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
    assert_socks5_domain_echo(
        socks_addr,
        "localhost",
        domain_echo_addr.port(),
        b"reality-vision domain target",
    );
    assert_tls_echo_through_socks(
        socks_addr,
        tls_echo_addr,
        b"real tls application data through reality vision",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and a plain TLS client for REALITY fallback"]
async fn plain_tls_client_falls_back_to_reality_dest_on_sni_mismatch() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("reality-fallback-sni");
    let reality_dest_addr = start_tls13_dest(&workspace).await;
    let chimera_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera-reality-fallback-sni.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-reality-fallback-sni",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "fallback@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": format!("127.0.0.1:{}", reality_dest_addr.port()),
                        "serverNames": [REALITY_SERVER_NAME],
                        "privateKey": REALITY_PRIVATE_KEY,
                        "shortIds": [REALITY_SHORT_ID],
                        "maxTimeDiff": 0
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();

    assert_tls_handshake_to_localhost(
        &workspace,
        SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and ./xray as client with wrong REALITY shortId"]
async fn xray_client_with_wrong_reality_short_id_falls_back_to_dest() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("reality-fallback-shortid");
    let (reality_dest_addr, dest_accepts) =
        start_tls13_dest_with_counter(&workspace).await;
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera-reality-fallback-shortid.json");
    let xray_config_path = work_dir.join("xray-reality-wrong-shortid-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-reality-fallback-shortid",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "fallback-shortid@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": format!("127.0.0.1:{}", reality_dest_addr.port()),
                        "serverNames": [REALITY_SERVER_NAME],
                        "privateKey": REALITY_PRIVATE_KEY,
                        "shortIds": [REALITY_SHORT_ID],
                        "maxTimeDiff": 0
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
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
                        "users": [{
                            "id": TEST_UUID,
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": REALITY_SERVER_NAME,
                        "fingerprint": "chrome",
                        "publicKey": REALITY_PUBLIC_KEY,
                        "shortId": "1111111111111111"
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)));
    xray.assert_running();

    assert_socks5_echo_does_not_succeed(
        SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, free_localhost_port())),
    );
    wait_for_counter(&dest_accepts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and ./xray as client with wrong REALITY SNI"]
async fn xray_client_with_wrong_reality_sni_falls_back_to_dest() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("reality-fallback-sni-xray");
    let (reality_dest_addr, dest_accepts) =
        start_tls13_dest_with_counter(&workspace).await;
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path =
        work_dir.join("chimera-reality-fallback-sni-xray.json");
    let xray_config_path = work_dir.join("xray-reality-wrong-sni-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-reality-fallback-sni-xray",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "fallback-sni@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": format!("127.0.0.1:{}", reality_dest_addr.port()),
                        "serverNames": [REALITY_SERVER_NAME],
                        "privateKey": REALITY_PRIVATE_KEY,
                        "shortIds": [REALITY_SHORT_ID],
                        "maxTimeDiff": 0
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
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
                        "users": [{
                            "id": TEST_UUID,
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "wrong.example.test",
                        "fingerprint": "chrome",
                        "publicKey": REALITY_PUBLIC_KEY,
                        "shortId": REALITY_SHORT_ID
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)));
    xray.assert_running();

    assert_socks5_echo_does_not_succeed(
        SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, free_localhost_port())),
    );
    wait_for_counter(&dest_accepts, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and ./xray as client for hysteria2"]
async fn xray_client_can_proxy_tcp_through_chimera_hysteria2() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("hysteria2");
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);

    let chimera_config_path = work_dir.join("chimera-hysteria2.json");
    let xray_config_path = work_dir.join("xray-hysteria2-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "hysteria",
                "tag": "chimera-hysteria2",
                "settings": {
                    "version": 2,
                    "clients": [{
                        "auth": HYSTERIA_AUTH,
                        "email": "hy@example.test"
                    }]
                },
                "streamSettings": {
                    "network": "quic",
                    "security": "tls",
                    "hysteriaSettings": {
                        "version": 2,
                        "up": "10 mbps",
                        "down": "10 mbps"
                    },
                    "tlsSettings": {
                        "alpn": ["h3"],
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
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
                "protocol": "hysteria",
                "settings": {
                    "version": 2,
                    "address": "127.0.0.1",
                    "port": chimera_port
                },
                "streamSettings": {
                    "network": "hysteria",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": pinned_peer_cert_sha256,
                        "alpn": ["h3"]
                    },
                    "hysteriaSettings": {
                        "version": 2,
                        "auth": HYSTERIA_AUTH
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)));
    xray.assert_running();

    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    assert_socks5_echo_async(
        socks_addr,
        echo_addr,
        b"hysteria2 through xray client",
    )
    .await;
    assert_socks5_echo_async(socks_addr, echo_addr, b"hysteria2 second roundtrip")
        .await;
    assert_socks5_echo_async(
        socks_addr,
        echo_addr,
        &deterministic_payload(32 * 1024),
    )
    .await;
}

fn workspace_root() -> PathBuf {
    for ancestor in Path::new(env!("CARGO_MANIFEST_DIR")).ancestors() {
        if ancestor.join("xray").is_file()
            && ancestor.join("cert/cert.pem").is_file()
        {
            return ancestor.to_path_buf();
        }
    }
    panic!(
        "failed to find workspace root containing xray and cert/cert.pem from {}",
        env!("CARGO_MANIFEST_DIR")
    );
}

fn create_test_dir(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis();
    let dir = env::temp_dir().join(format!(
        "chimera-xray-client-{name}-{}-{now}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create test directory");
    dir
}

fn write_json(path: &Path, value: serde_json::Value) {
    let content = serde_json::to_string_pretty(&value).expect("serialize json");
    fs::write(path, content).expect("write json config");
}

fn first_cert_sha256_hex(cert_path: &Path) -> String {
    let cert_file = File::open(cert_path).expect("open pinned cert");
    let first_cert = certs(&mut BufReader::new(cert_file))
        .next()
        .expect("at least one cert in pem")
        .expect("parse first cert");
    to_lower_hex(digest(&SHA256, first_cert.as_ref()).as_ref())
}

fn to_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write hex");
    }
    out
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
}

fn start_chimera(workspace: &Path, work_dir: &Path, config: &Path) -> ChildGuard {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_chimera_server_app"));
    ChildGuard::spawn(
        "chimera",
        &binary,
        &[
            "--config",
            config.to_str().expect("config utf8"),
            "--format",
            "json",
        ],
        work_dir,
    )
    .unwrap_or_else(|err| {
        panic!(
            "failed to start chimera from {} in {}: {err}",
            binary.display(),
            workspace.display()
        )
    })
}

fn start_xray(workspace: &Path, work_dir: &Path, config: &Path) -> ChildGuard {
    let binary = env::var_os("XRAY_BIN")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                workspace.join(path)
            }
        })
        .unwrap_or_else(|| workspace.join("xray"));
    ChildGuard::spawn(
        "xray",
        &binary,
        &["run", "-c", config.to_str().expect("config utf8")],
        work_dir,
    )
    .unwrap_or_else(|err| {
        panic!("failed to start xray from {}: {err}", binary.display())
    })
}

fn start_tcp_echo_server() -> SocketAddr {
    start_tcp_echo_server_on(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
}

fn start_tcp_echo_server_v6() -> SocketAddr {
    start_tcp_echo_server_on(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
}

fn start_tcp_echo_server_on(bind_addr: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind(bind_addr).expect("bind echo server");
    let addr = listener.local_addr().expect("echo addr");
    thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

async fn assert_tls_handshake_to_localhost(_workspace: &Path, addr: SocketAddr) {
    let connector = TlsConnector::from(Arc::new(tls_test_client_config()));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect fallback target through chimera");
    let server_name =
        ServerName::try_from("localhost").expect("valid fallback server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("fallback TLS handshake should complete");
    tls.shutdown().await.expect("shutdown fallback TLS stream");
}

async fn start_tls13_dest(workspace: &Path) -> SocketAddr {
    start_tls13_dest_with_counter(workspace).await.0
}

async fn start_tls_echo_server(workspace: &Path) -> SocketAddr {
    install_rustls_provider();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config(workspace)));
    let listener =
        TokioTcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind tls echo server");
    let addr = listener.local_addr().expect("tls echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            if tls.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

async fn start_tls13_dest_with_counter(
    workspace: &Path,
) -> (SocketAddr, Arc<AtomicUsize>) {
    install_rustls_provider();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config(workspace)));
    let listener =
        TokioTcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind tls dest");
    let addr = listener.local_addr().expect("tls dest addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            accepted_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    (addr, accepted)
}

fn tls_server_config(workspace: &Path) -> RustlsServerConfig {
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let cert_file = File::open(&cert_path).expect("open tls cert");
    let key_file = File::open(&key_path).expect("open tls key");
    let cert_chain = certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse tls certs");
    let key = private_key(&mut BufReader::new(key_file))
        .expect("parse tls private key")
        .expect("tls private key present");
    RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("build tls server config")
}

fn tls_test_client_config() -> RustlsClientConfig {
    install_rustls_provider();
    RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptTestServerCert))
        .with_no_client_auth()
}

async fn assert_socks5_echo_async(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) {
    let mut stream = connect_socks5_tcp(socks_addr, target_addr).await;
    stream
        .write_all(payload)
        .await
        .expect("write async tunneled payload");
    stream.flush().await.expect("flush async tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut echoed))
        .await
        .expect("async tunneled echo timeout")
        .expect("read async tunneled echo response");
    assert_eq!(echoed, payload);
}

async fn assert_tls_echo_through_socks(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) {
    let tcp = connect_socks5_tcp(socks_addr, target_addr).await;
    let connector = TlsConnector::from(Arc::new(tls_test_client_config()));
    let server_name =
        ServerName::try_from("localhost").expect("valid TLS echo server name");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS echo handshake through socks");
    tls.write_all(payload)
        .await
        .expect("write TLS echo payload");
    tls.flush().await.expect("flush TLS echo payload");
    let mut echoed = vec![0u8; payload.len()];
    tls.read_exact(&mut echoed)
        .await
        .expect("read TLS echo payload");
    assert_eq!(echoed, payload);
    tls.shutdown().await.expect("shutdown TLS echo stream");
}

async fn connect_socks5_tcp(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(socks_addr)
        .await
        .expect("connect xray socks inbound");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("socks hello");
    let mut hello = [0u8; 2];
    stream
        .read_exact(&mut hello)
        .await
        .expect("socks hello response");
    assert_eq!(hello, [0x05, 0x00], "SOCKS no-auth negotiation failed");

    let mut request = vec![0x05, 0x01, 0x00];
    match target_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .expect("socks connect request");

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .expect("socks connect response header");
    assert_eq!(header[0], 0x05);
    assert_eq!(header[1], 0x00, "SOCKS connect failed: {header:02x?}");
    read_async_socks_bound_address_tail(&mut stream, header[3]).await;
    stream
}

async fn read_async_socks_bound_address_tail(
    stream: &mut tokio::net::TcpStream,
    atyp: u8,
) {
    match atyp {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.expect("socks ipv4 tail");
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.expect("socks domain len");
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .await
                .expect("socks domain tail");
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await.expect("socks ipv6 tail");
        }
        atyp => panic!("unsupported SOCKS address type {atyp:#x}"),
    }
}

fn assert_socks5_echo(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) {
    let mut request = vec![0x05, 0x01, 0x00];
    match target_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let port = target_addr.port().to_be_bytes();
            request.extend_from_slice(&[
                0x05,
                0x01,
                0x00,
                0x01,
                ip.octets()[0],
                ip.octets()[1],
                ip.octets()[2],
                ip.octets()[3],
                port[0],
                port[1],
            ]);
        }
        std::net::IpAddr::V6(ip) => {
            let port = target_addr.port().to_be_bytes();
            request.extend_from_slice(&[0x05, 0x01, 0x00, 0x04]);
            request.extend_from_slice(&ip.octets());
            request.extend_from_slice(&port);
        }
    }
    assert_socks5_request_echo(socks_addr, &request, payload);
}

fn assert_socks5_echo_does_not_succeed(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
) {
    let mut stream = TcpStream::connect_timeout(&socks_addr, IO_TIMEOUT)
        .expect("connect xray socks inbound");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set write timeout");

    stream.write_all(&[0x05, 0x01, 0x00]).expect("socks hello");
    let mut hello = [0u8; 2];
    stream.read_exact(&mut hello).expect("socks hello response");
    assert_eq!(hello, [0x05, 0x00], "SOCKS no-auth negotiation failed");

    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("test only uses ipv4 target"),
    };
    let port = target_addr.port().to_be_bytes();
    stream
        .write_all(&[
            0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
        ])
        .expect("socks connect request");

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .expect("socks response header");
    assert_eq!(header[0], 0x05);
    if header[1] != 0x00 {
        return;
    }
    read_socks_bound_address_tail(&mut stream, header[3])
        .expect("socks success response tail");

    let payload = b"wrong short id must not echo";
    stream.write_all(payload).expect("write tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    match stream.read_exact(&mut echoed) {
        Ok(()) => assert_ne!(echoed, payload, "unexpected successful tunneled echo"),
        Err(_) => {}
    }
}

fn assert_socks5_domain_echo(
    socks_addr: SocketAddr,
    domain: &str,
    port: u16,
    payload: &[u8],
) {
    let domain = domain.as_bytes();
    assert!(domain.len() <= u8::MAX as usize);
    let mut request =
        vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&port.to_be_bytes());
    assert_socks5_request_echo(socks_addr, &request, payload);
}

fn assert_socks5_request_echo(
    socks_addr: SocketAddr,
    request: &[u8],
    payload: &[u8],
) {
    let mut stream = TcpStream::connect_timeout(&socks_addr, IO_TIMEOUT)
        .expect("connect xray socks inbound");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set write timeout");

    stream.write_all(&request[..3]).expect("socks hello");
    let mut hello = [0u8; 2];
    stream.read_exact(&mut hello).expect("socks hello response");
    assert_eq!(hello, [0x05, 0x00], "SOCKS no-auth negotiation failed");

    stream
        .write_all(&request[3..])
        .expect("socks connect request");
    read_socks_connect_response(&mut stream).expect("socks connect response");

    stream.write_all(payload).expect("write tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    read_exact_with_deadline(&mut stream, &mut echoed)
        .expect("read tunneled echo response");
    assert_eq!(echoed, payload);
}

fn read_exact_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> io::Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut read = 0;
    while read < buf.len() {
        match stream.read(&mut buf[read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF while reading tunneled data",
                ));
            }
            Ok(n) => read += n,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && Instant::now() < deadline =>
            {
                thread::sleep(CONNECT_RETRY_INTERVAL);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| (idx.wrapping_mul(31).wrapping_add(17) % 251) as u8)
        .collect()
}

fn read_socks_connect_response(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS connect failed: header={header:02x?}"),
        ));
    }
    read_socks_bound_address_tail(stream, header[3])
}

fn read_socks_bound_address_tail(
    stream: &mut TcpStream,
    atyp: u8,
) -> io::Result<()> {
    match atyp {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest)?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest)?;
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS address type {atyp:#x}"),
            ));
        }
    }
    Ok(())
}

fn wait_for_tcp(addr: SocketAddr) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, CONNECT_RETRY_INTERVAL).is_ok() {
            return;
        }
        thread::sleep(CONNECT_RETRY_INTERVAL);
    }
    panic!("timed out waiting for TCP listener at {addr}");
}

fn wait_for_counter(counter: &AtomicUsize, expected: usize) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        thread::sleep(CONNECT_RETRY_INTERVAL);
    }
    panic!(
        "timed out waiting for counter to reach {expected}; got {}",
        counter.load(Ordering::SeqCst)
    );
}

fn free_localhost_port() -> u16 {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral local addr")
        .port()
}

fn read_lossy(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| format!("<failed to read {}: {err}>", path.display()))
}
