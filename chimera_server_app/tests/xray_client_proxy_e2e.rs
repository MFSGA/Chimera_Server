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
        mpsc,
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
    net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket},
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
#[ignore = "starts Chimera and verifies unauthenticated VLESS fallback replay"]
async fn unauthenticated_plain_tcp_reaches_vless_fallback() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("vless-fallback");
    let default_fallback_addr = start_tcp_marker_echo_server(b"default:");
    let path_fallback_addr = start_tcp_marker_echo_server(b"path:");
    let proxy_v1_addr = start_proxy_protocol_marker_echo_server(1, b"proxy-v1:");
    let proxy_v2_addr = start_proxy_protocol_marker_echo_server(2, b"proxy-v2:");
    let chimera_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera-vless-fallback.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-vless-fallback",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "fallback@example.test"
                    }],
                    "decryption": "none",
                    "fallbacks": [{
                        "dest": default_fallback_addr.to_string()
                    }, {
                        "path": "/fallback",
                        "dest": path_fallback_addr.to_string()
                    }, {
                        "path": "/proxy-v1",
                        "dest": proxy_v1_addr.to_string(),
                        "xver": 1
                    }, {
                        "path": "/proxy-v2",
                        "dest": proxy_v2_addr.to_string(),
                        "xver": 2
                    }]
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    let chimera_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port));
    wait_for_tcp(chimera_addr);
    chimera.assert_running();

    for (path, marker) in [
        ("/fallback?query=1", b"path:".as_slice()),
        ("/proxy-v1", b"proxy-v1:".as_slice()),
        ("/proxy-v2", b"proxy-v2:".as_slice()),
        ("/other", b"default:".as_slice()),
    ] {
        let payload = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let mut stream =
            TcpStream::connect(chimera_addr).expect("connect VLESS fallback");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("set fallback read timeout");
        stream
            .write_all(payload.as_bytes())
            .expect("write fallback payload");
        let mut response = vec![0u8; marker.len() + payload.len()];
        stream
            .read_exact(&mut response)
            .expect("read fallback marker and replay response");
        let mut expected = marker.to_vec();
        expected.extend_from_slice(payload.as_bytes());
        assert_eq!(response, expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and verifies TLS Vision VLESS fallback replay"]
async fn unauthenticated_tls_payload_reaches_vless_vision_fallback() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("vless-tls-vision-fallback");
    let default_fallback_addr = start_tcp_marker_echo_server(b"default:");
    let name_fallback_addr = start_tcp_marker_echo_server(b"name:");
    let alpn_fallback_addr = start_tcp_marker_echo_server(b"alpn:");
    let path_fallback_addr = start_tcp_marker_echo_server(b"path:");
    let chimera_port = free_localhost_port();
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let chimera_config_path =
        work_dir.join("chimera-vless-tls-vision-fallback.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-vless-tls-vision-fallback",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "vision-fallback@example.test",
                        "flow": "xtls-rprx-vision"
                    }],
                    "decryption": "none",
                    "fallbacks": [{
                        "dest": default_fallback_addr.to_string()
                    }, {
                        "name": "localhost",
                        "dest": name_fallback_addr.to_string()
                    }, {
                        "name": "localhost",
                        "alpn": "h2",
                        "dest": alpn_fallback_addr.to_string()
                    }, {
                        "name": "localhost",
                        "alpn": "h2",
                        "path": "/vision-fallback",
                        "dest": path_fallback_addr.to_string()
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": ["h2", "http/1.1"],
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

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    let chimera_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port));
    wait_for_tcp(chimera_addr);
    chimera.assert_running();

    for (server_name, use_h2, path, marker) in [
        (
            "localhost",
            true,
            "/vision-fallback?query=1",
            b"path:".as_slice(),
        ),
        ("localhost", true, "/other", b"alpn:".as_slice()),
        ("localhost", false, "/other", b"name:".as_slice()),
        ("other.test", false, "/other", b"default:".as_slice()),
    ] {
        let mut client_config = tls_test_client_config();
        if use_h2 {
            client_config.alpn_protocols = vec![b"h2".to_vec()];
        }
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp = tokio::net::TcpStream::connect(chimera_addr)
            .await
            .expect("connect TLS VLESS fallback");
        let server_name = ServerName::try_from(server_name).unwrap();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("establish outer TLS");
        let payload = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        tls.write_all(payload.as_bytes())
            .await
            .expect("write fallback request");
        tls.flush().await.expect("flush fallback request");
        let mut response = vec![0u8; marker.len() + payload.len()];
        tls.read_exact(&mut response)
            .await
            .expect("read TLS fallback marker and replay response");
        let mut expected = marker.to_vec();
        expected.extend_from_slice(payload.as_bytes());
        assert_eq!(response, expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and verifies Trojan TLS fallback selection"]
async fn unauthenticated_tls_payload_reaches_trojan_fallback_rules() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("trojan-tls-fallback");
    let default_addr = start_tcp_marker_echo_server(b"default:");
    let name_addr = start_tcp_marker_echo_server(b"name:");
    let alpn_addr = start_proxy_protocol_marker_echo_server(1, b"alpn-v1:");
    let path_addr = start_proxy_protocol_marker_echo_server(2, b"path-v2:");
    let chimera_port = free_localhost_port();
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let config_path = work_dir.join("chimera-trojan-tls-fallback.json");

    write_json(
        &config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "trojan",
                "tag": "chimera-trojan-tls-fallback",
                "settings": {
                    "clients": [{
                        "password": "trojan-fallback-password",
                        "email": "trojan-fallback@example.test"
                    }],
                    "fallbacks": [{
                        "dest": default_addr.to_string()
                    }, {
                        "name": "localhost",
                        "dest": name_addr.to_string()
                    }, {
                        "name": "localhost",
                        "alpn": "h2",
                        "dest": alpn_addr.to_string(),
                        "xver": 1
                    }, {
                        "name": "localhost",
                        "alpn": "h2",
                        "path": "/trojan-fallback",
                        "dest": path_addr.to_string(),
                        "xver": 2
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "alpn": ["h2", "http/1.1"],
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

    let mut chimera = start_chimera(&workspace, &work_dir, &config_path);
    let chimera_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port));
    wait_for_tcp(chimera_addr);
    chimera.assert_running();

    for (server_name, use_h2, path, marker) in [
        (
            "localhost",
            true,
            "/trojan-fallback?query=1",
            b"path-v2:".as_slice(),
        ),
        ("localhost", true, "/other", b"alpn-v1:".as_slice()),
        ("localhost", false, "/other", b"name:".as_slice()),
        ("other.test", false, "/other", b"default:".as_slice()),
    ] {
        let mut client_config = tls_test_client_config();
        if use_h2 {
            client_config.alpn_protocols = vec![b"h2".to_vec()];
        }
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp = tokio::net::TcpStream::connect(chimera_addr)
            .await
            .expect("connect Trojan TLS fallback");
        let server_name = ServerName::try_from(server_name).unwrap();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("establish Trojan outer TLS");
        let payload = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        tls.write_all(payload.as_bytes())
            .await
            .expect("write Trojan fallback request");
        tls.flush().await.expect("flush Trojan fallback request");
        let mut response = vec![0u8; marker.len() + payload.len()];
        tls.read_exact(&mut response)
            .await
            .expect("read Trojan fallback marker and replay response");
        let mut expected = marker.to_vec();
        expected.extend_from_slice(payload.as_bytes());
        assert_eq!(response, expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and ./xray as client for tcp+tls+vision"]
async fn xray_client_can_proxy_tcp_through_chimera_tls_vision() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("tls-vision");
    let echo_addr = start_tcp_echo_server();
    let tls_echo_addr = start_tls_echo_server(&workspace).await;
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);

    let chimera_config_path = work_dir.join("chimera-tls-vision.json");
    let xray_config_path = work_dir.join("xray-tls-vision-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-tls-vision",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "flow": "xtls-rprx-vision",
                        "email": "tls-vision@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
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
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": pinned_peer_cert_sha256
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
    assert_socks5_echo(socks_addr, echo_addr, b"tls-vision through xray client");
    assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
    assert_tls_echo_through_socks(
        socks_addr,
        tls_echo_addr,
        b"real tls application data through tls vision direct",
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
#[ignore = "starts Chimera HTTP and Mixed inbounds"]
async fn http_and_mixed_inbounds_proxy_tcp() {
    let workspace = workspace_root();
    let echo_addr = start_tcp_echo_server();
    let (absolute_target, absolute_request) = start_http_capture_server();
    let (transparent_target, transparent_request) = start_http_capture_server();

    let http_work_dir = create_test_dir("http-inbound");
    let http_port = free_localhost_port();
    let transparent_http_port = free_localhost_port();
    let http_config_path = http_work_dir.join("chimera-http.json");
    write_json(
        &http_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": http_port,
                "protocol": "http",
                "tag": "http-in",
                "settings": {
                    "accounts": [{
                        "user": "alice",
                        "pass": "secret"
                    }]
                }
            }, {
                "listen": "127.0.0.1",
                "port": transparent_http_port,
                "protocol": "http",
                "tag": "http-transparent-in",
                "settings": {
                    "allowTransparent": true
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        }),
    );
    let mut http = start_chimera(&workspace, &http_work_dir, &http_config_path);
    let http_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, http_port));
    let transparent_http_addr =
        SocketAddr::from((Ipv4Addr::LOCALHOST, transparent_http_port));
    wait_for_tcp(http_addr);
    wait_for_tcp(transparent_http_addr);
    http.assert_running();
    assert_http_connect_echo(
        http_addr,
        echo_addr,
        Some("YWxpY2U6c2VjcmV0"),
        b"HTTP CONNECT through Chimera",
    );
    assert_http_forward_response(
        http_addr,
        &format!(
            "GET http://{absolute_target}/absolute?q=1 HTTP/1.1\r\n\
             Host: {absolute_target}\r\n\
             Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\
             Proxy-Connection: keep-alive\r\n\r\n"
        ),
    );
    let absolute_request = absolute_request
        .recv_timeout(IO_TIMEOUT)
        .expect("capture absolute-form forwarded request");
    assert!(absolute_request.starts_with("GET /absolute?q=1 HTTP/1.1\r\n"));
    assert!(!absolute_request.to_ascii_lowercase().contains("proxy-"));
    assert!(absolute_request.contains("Connection: close\r\n"));

    assert_http_forward_response(
        transparent_http_addr,
        &format!("GET /transparent HTTP/1.1\r\nHost: {transparent_target}\r\n\r\n"),
    );
    let transparent_request = transparent_request
        .recv_timeout(IO_TIMEOUT)
        .expect("capture transparent forwarded request");
    assert!(transparent_request.starts_with("GET /transparent HTTP/1.1\r\n"));
    assert!(
        transparent_request.contains(&format!("Host: {transparent_target}\r\n"))
    );
    drop(http);

    let mixed_work_dir = create_test_dir("mixed-inbound");
    let mixed_port = free_localhost_port();
    let mixed_config_path = mixed_work_dir.join("chimera-mixed.json");
    write_json(
        &mixed_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": mixed_port,
                "protocol": "mixed",
                "tag": "mixed-in",
                "settings": {
                    "auth": "noauth",
                    "udp": false
                }
            }],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }]
        }),
    );
    let mut mixed = start_chimera(&workspace, &mixed_work_dir, &mixed_config_path);
    let mixed_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, mixed_port));
    wait_for_tcp(mixed_addr);
    mixed.assert_running();
    assert_http_connect_echo(
        mixed_addr,
        echo_addr,
        None,
        b"HTTP through mixed inbound",
    );
    assert_socks5_echo(mixed_addr, echo_addr, b"SOCKS5 through mixed inbound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and ./xray for legacy Shadowsocks AEAD TCP"]
async fn xray_client_can_proxy_tcp_through_chimera_shadowsocks() {
    let workspace = workspace_root();
    let echo_addr = start_tcp_echo_server();
    let udp_echo_addr = start_udp_echo_server().await;

    for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
        let work_dir = create_test_dir(&format!("shadowsocks-{method}"));
        let chimera_port = free_localhost_port();
        let xray_socks_port = free_localhost_port();
        let chimera_config_path = work_dir.join("chimera-shadowsocks.json");
        let xray_config_path = work_dir.join("xray-shadowsocks-client.json");

        write_json(
            &chimera_config_path,
            json!({
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": chimera_port,
                    "protocol": "shadowsocks",
                    "tag": format!("chimera-ss-{method}"),
                    "settings": {
                        "method": method,
                        "password": "chimera-shadow-password",
                        "email": format!("{method}@example.test"),
                        "network": "tcp,udp"
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
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-chimera",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": "127.0.0.1",
                            "port": chimera_port,
                            "method": method,
                            "password": "chimera-shadow-password"
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none"
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
        assert_socks5_echo(
            socks_addr,
            echo_addr,
            format!("Shadowsocks {method} through Xray").as_bytes(),
        );
        assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
        assert_socks5_udp_echo(
            socks_addr,
            udp_echo_addr,
            format!("Shadowsocks UDP {method}").as_bytes(),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts one multi-user Chimera Shadowsocks inbound and two Xray clients"]
async fn xray_clients_can_use_multiple_legacy_shadowsocks_users() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("shadowsocks-multi-user");
    let echo_addr = start_tcp_echo_server();
    let udp_echo_addr = start_udp_echo_server().await;
    let chimera_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera-shadowsocks-multi.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "shadowsocks",
                "tag": "chimera-ss-multi",
                "settings": {
                    "clients": [{
                        "method": "aes-128-gcm",
                        "password": "multi-user-aes-password",
                        "email": "aes-user@example.test"
                    }, {
                        "method": "chacha20-ietf-poly1305",
                        "password": "multi-user-chacha-password",
                        "email": "chacha-user@example.test"
                    }],
                    "network": "tcp,udp"
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

    for (method, password) in [
        ("aes-128-gcm", "multi-user-aes-password"),
        ("chacha20-ietf-poly1305", "multi-user-chacha-password"),
    ] {
        let client_dir = create_test_dir(&format!("ss-multi-client-{method}"));
        let xray_socks_port = free_localhost_port();
        let xray_config_path = client_dir.join("xray-client.json");
        write_json(
            &xray_config_path,
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": xray_socks_port,
                    "protocol": "socks",
                    "tag": "socks-in",
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-chimera",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": "127.0.0.1",
                            "port": chimera_port,
                            "method": method,
                            "password": password
                        }]
                    }
                }]
            }),
        );

        let mut xray = start_xray(&workspace, &client_dir, &xray_config_path);
        let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
        wait_for_tcp(socks_addr);
        xray.assert_running();
        assert_socks5_echo(
            socks_addr,
            echo_addr,
            format!("multi-user {method}").as_bytes(),
        );
        assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
        assert_socks5_udp_echo(
            socks_addr,
            udp_echo_addr,
            format!("multi-user UDP {method}").as_bytes(),
        )
        .await;
        drop(xray);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts one multi-user Shadowsocks 2022 EIH inbound and two Xray clients"]
async fn xray_clients_can_use_shadowsocks_2022_eih_users() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("shadowsocks-2022-eih");
    let echo_addr = start_tcp_echo_server();
    let udp_echo_addr = start_udp_echo_server().await;
    let chimera_port = free_localhost_port();
    let server_psk = "AAECAwQFBgcICQoLDA0ODw==";
    let users = [
        ("EBESExQVFhcYGRobHB0eHw==", "eih-a@example.test"),
        ("ICEiIyQlJicoKSorLC0uLw==", "eih-b@example.test"),
    ];
    let chimera_config_path = work_dir.join("chimera-shadowsocks-eih.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "shadowsocks",
                "tag": "chimera-ss-2022-eih",
                "settings": {
                    "method": "2022-blake3-aes-128-gcm",
                    "password": server_psk,
                    "clients": users
                        .iter()
                        .map(|(password, email)| json!({
                            "password": password,
                            "email": email
                        }))
                        .collect::<Vec<_>>(),
                    "network": "tcp,udp"
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

    for (index, (user_psk, _email)) in users.iter().enumerate() {
        let client_dir = create_test_dir(&format!("ss-2022-eih-client-{index}"));
        let xray_socks_port = free_localhost_port();
        let xray_config_path = client_dir.join("xray-client.json");
        write_json(
            &xray_config_path,
            json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": xray_socks_port,
                    "protocol": "socks",
                    "tag": "socks-in",
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-chimera",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": "127.0.0.1",
                            "port": chimera_port,
                            "method": "2022-blake3-aes-128-gcm",
                            "password": format!("{server_psk}:{user_psk}")
                        }]
                    }
                }]
            }),
        );

        let mut xray = start_xray(&workspace, &client_dir, &xray_config_path);
        let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
        wait_for_tcp(socks_addr);
        xray.assert_running();
        assert_socks5_echo(
            socks_addr,
            echo_addr,
            format!("EIH TCP user {index}").as_bytes(),
        );
        assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
        assert_socks5_udp_echo(
            socks_addr,
            udp_echo_addr,
            format!("EIH UDP user {index}").as_bytes(),
        )
        .await;
        drop(xray);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and ./xray for Shadowsocks 2022 TCP and AES UDP"]
async fn xray_client_can_proxy_tcp_and_aes_udp_through_chimera_shadowsocks_2022() {
    let workspace = workspace_root();
    let echo_addr = start_tcp_echo_server();
    let udp_echo_addr = start_udp_echo_server().await;

    for (method, key) in [
        ("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="),
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
    ] {
        let supports_udp = true;
        let network = "tcp,udp";
        let work_dir = create_test_dir(&format!("shadowsocks-2022-{method}"));
        let chimera_port = free_localhost_port();
        let xray_socks_port = free_localhost_port();
        let chimera_config_path = work_dir.join("chimera-shadowsocks-2022.json");
        let xray_config_path = work_dir.join("xray-shadowsocks-2022-client.json");

        write_json(
            &chimera_config_path,
            json!({
                "inbounds": [{
                    "listen": "127.0.0.1",
                    "port": chimera_port,
                    "protocol": "shadowsocks",
                    "tag": format!("chimera-ss-2022-{method}"),
                    "settings": {
                        "method": method,
                        "password": key,
                        "email": format!("{method}@example.test"),
                        "network": network
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
                    "settings": {"auth": "noauth", "udp": true}
                }],
                "outbounds": [{
                    "tag": "to-chimera",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": "127.0.0.1",
                            "port": chimera_port,
                            "method": method,
                            "password": key
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none"
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
        assert_socks5_echo(
            socks_addr,
            echo_addr,
            format!("Shadowsocks 2022 {method} through Xray").as_bytes(),
        );
        assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
        if supports_udp {
            assert_socks5_udp_echo(
                socks_addr,
                udp_echo_addr,
                format!("Shadowsocks 2022 UDP {method}").as_bytes(),
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and ./xray for VLESS gRPC h2c"]
async fn xray_client_can_proxy_tcp_through_chimera_grpc() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("grpc-vless");
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera-grpc.json");
    let xray_config_path = work_dir.join("xray-grpc-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-grpc-vless",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "grpc@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "none",
                    "grpcSettings": {
                        "serviceName": "chimera.GunService"
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
                    "network": "grpc",
                    "security": "none",
                    "grpcSettings": {
                        "serviceName": "chimera.GunService"
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();
    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    wait_for_tcp(socks_addr);
    xray.assert_running();
    assert_socks5_echo(socks_addr, echo_addr, b"VLESS gRPC h2c through Xray");
    assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera and ./xray for VLESS HTTPUpgrade"]
async fn xray_client_can_proxy_tcp_through_chimera_httpupgrade() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("httpupgrade-vless");
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera-httpupgrade.json");
    let xray_config_path = work_dir.join("xray-httpupgrade-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": "chimera-httpupgrade-vless",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": "httpupgrade@example.test"
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "httpupgrade",
                    "security": "none",
                    "httpupgradeSettings": {
                        "host": "localhost",
                        "path": "/upgrade"
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
                    "network": "httpupgrade",
                    "security": "none",
                    "httpupgradeSettings": {
                        "host": "localhost",
                        "path": "/upgrade"
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();
    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    wait_for_tcp(socks_addr);
    xray.assert_running();
    assert_socks5_echo(socks_addr, echo_addr, b"VLESS HTTPUpgrade through Xray");
    assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts Chimera as server and ./xray as client for hysteria2"]
async fn xray_client_can_proxy_tcp_and_udp_through_chimera_hysteria2() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("hysteria2");
    let echo_addr = start_tcp_echo_server();
    let udp_echo_addr = start_udp_echo_server().await;
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
                    "finalmask": {
                        "quicParams": {
                            "congestion": "brutal",
                            "brutalUp": "10 mbps",
                            "brutalDown": "10 mbps",
                            "initStreamReceiveWindow": 32768,
                            "maxStreamReceiveWindow": 65536,
                            "initConnectionReceiveWindow": 131072,
                            "maxConnectionReceiveWindow": 262144,
                            "disablePathMTUDiscovery": true
                        }
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
                "settings": {"auth": "noauth", "udp": true}
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
                    },
                    "finalmask": {
                        "quicParams": {
                            "congestion": "brutal",
                            "brutalUp": "10 mbps",
                            "brutalDown": "10 mbps"
                        }
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
    assert_socks5_udp_echo(
        socks_addr,
        udp_echo_addr,
        b"hysteria2 UDP through xray client",
    )
    .await;
}

#[test]
#[ignore = "starts Chimera and ./xray to validate Hysteria2 UUID route auth"]
fn xray_hysteria2_uuid_auth_routes_by_embedded_vless_route() {
    const BASE_AUTH: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const ROUTED_AUTH: &str = "00112233-4455-abcd-8899-aabbccddeeff";

    let workspace = workspace_root();
    let work_dir = create_test_dir("hysteria2-uuid-route");
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);

    let chimera_config_path = work_dir.join("chimera-hysteria2-uuid-route.json");
    let xray_config_path = work_dir.join("xray-hysteria2-uuid-route-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "hysteria",
                "tag": "chimera-hysteria2-uuid-route",
                "settings": {
                    "version": 2,
                    "clients": [{
                        "auth": BASE_AUTH,
                        "email": "uuid-route@example.test"
                    }]
                },
                "streamSettings": {
                    "network": "quic",
                    "security": "tls",
                    "hysteriaSettings": {"version": 2},
                    "tlsSettings": {
                        "alpn": ["h3"],
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }
            }],
            "outbounds": [
                {"tag": "blocked", "protocol": "blackhole"},
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "vlessRoute": 43981,
                    "outboundTag": "direct"
                }]
            }
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
                "settings": {"auth": "noauth"}
            }],
            "outbounds": [{
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
                        "auth": ROUTED_AUTH
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    wait_for_tcp(socks_addr);
    xray.assert_running();

    assert_socks5_echo(socks_addr, echo_addr, b"hysteria2 UUID route through Xray");
}

#[test]
#[ignore = "starts Chimera as server and ./xray with invalid hysteria2 auth"]
fn xray_client_rejects_invalid_hysteria2_auth_without_tunnel() {
    let workspace = workspace_root();
    let work_dir = create_test_dir("hysteria2-auth-reject");
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let cert_path = workspace.join("cert/cert.pem");
    let key_path = workspace.join("cert/key.pem");
    let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);

    let chimera_config_path = work_dir.join("chimera-hysteria2-auth-reject.json");
    let xray_config_path = work_dir.join("xray-hysteria2-auth-reject-client.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "hysteria",
                "tag": "chimera-hysteria2-auth-reject",
                "settings": {
                    "version": 2,
                    "clients": [{"auth": HYSTERIA_AUTH}]
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
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
    write_json(
        &xray_config_path,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth"}
            }],
            "outbounds": [{
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
                        "auth": "wrong-hysteria-auth-token"
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

    assert_socks5_echo_does_not_succeed(
        SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)),
        echo_addr,
    );

    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let logs = format!(
            "{}\n{}",
            read_lossy(&xray.stdout_path),
            read_lossy(&xray.stderr_path)
        );
        if logs.contains("proxy/hysteria: failed to find an available destination")
            && logs.contains("transport/internet/hysteria: auth failed")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Xray did not report Hysteria2 authentication failure; logs={logs}"
        );
        thread::sleep(CONNECT_RETRY_INTERVAL);
    }
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

fn start_http_capture_server() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind HTTP capture server");
    let addr = listener.local_addr().expect("HTTP capture addr");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut request = Vec::with_capacity(1024);
        while !request.ends_with(b"\r\n\r\n") && request.len() < 32 * 1024 {
            let mut byte = [0u8; 1];
            if stream.read_exact(&mut byte).is_err() {
                return;
            }
            request.push(byte[0]);
        }
        let request = String::from_utf8_lossy(&request).into_owned();
        let _ = sender.send(request);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
    });
    (addr, receiver)
}

fn start_tcp_marker_echo_server(marker: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind marker echo server");
    let addr = listener.local_addr().expect("marker echo addr");
    thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            thread::spawn(move || {
                let mut first = true;
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if first {
                                first = false;
                                if stream.write_all(marker).is_err() {
                                    break;
                                }
                            }
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

fn start_proxy_protocol_marker_echo_server(
    version: u8,
    marker: &'static [u8],
) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind PROXY protocol echo server");
    let addr = listener.local_addr().expect("PROXY protocol echo addr");
    thread::spawn(move || {
        for stream in listener.incoming().take(16) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            thread::spawn(move || {
                match version {
                    1 => {
                        let mut header = Vec::with_capacity(96);
                        while header.len() < 108 {
                            let mut byte = [0u8; 1];
                            if stream.read_exact(&mut byte).is_err() {
                                return;
                            }
                            header.push(byte[0]);
                            if header.ends_with(b"\r\n") {
                                break;
                            }
                        }
                        let Ok(header) = std::str::from_utf8(&header) else {
                            return;
                        };
                        assert!(
                            header.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 ")
                        );
                    }
                    2 => {
                        let mut header = [0u8; 16];
                        if stream.read_exact(&mut header).is_err() {
                            return;
                        }
                        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
                        assert_eq!(header[12], 0x21);
                        assert_eq!(header[13], 0x11);
                        let address_len =
                            u16::from_be_bytes([header[14], header[15]]) as usize;
                        let mut address = vec![0u8; address_len];
                        if stream.read_exact(&mut address).is_err() {
                            return;
                        }
                        assert_eq!(address_len, 12);
                        assert_eq!(&address[..4], &[127, 0, 0, 1]);
                        assert_eq!(&address[4..8], &[127, 0, 0, 1]);
                    }
                    other => {
                        panic!("unsupported test PROXY protocol version {other}")
                    }
                }

                let mut first = true;
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if first {
                                first = false;
                                if stream.write_all(marker).is_err() {
                                    break;
                                }
                            }
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

async fn start_udp_echo_server() -> SocketAddr {
    let socket = TokioUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind UDP echo server");
    let addr = socket.local_addr().expect("UDP echo addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..len], peer).await.is_err() {
                break;
            }
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

async fn assert_socks5_udp_echo(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) {
    let mut control = tokio::net::TcpStream::connect(socks_addr)
        .await
        .expect("connect xray SOCKS UDP control");
    control
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("SOCKS UDP hello");
    let mut hello = [0u8; 2];
    control
        .read_exact(&mut hello)
        .await
        .expect("SOCKS UDP hello response");
    assert_eq!(hello, [0x05, 0x00]);

    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .expect("SOCKS UDP associate request");
    let mut header = [0u8; 4];
    control
        .read_exact(&mut header)
        .await
        .expect("SOCKS UDP associate response");
    assert_eq!(header[1], 0x00, "SOCKS UDP associate failed");
    let mut relay_addr =
        read_async_socks_bound_address(&mut control, header[3]).await;
    if relay_addr.ip().is_unspecified() {
        relay_addr.set_ip(socks_addr.ip());
    }

    let udp = TokioUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind SOCKS UDP client");
    let target_ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => panic!("SOCKS UDP E2E target must be IPv4"),
    };
    let mut request = vec![0x00, 0x00, 0x00, 0x01];
    request.extend_from_slice(&target_ip.octets());
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    request.extend_from_slice(payload);
    udp.send_to(&request, relay_addr)
        .await
        .expect("send SOCKS UDP payload");

    let mut response = vec![0u8; payload.len() + 64];
    let (len, _) = tokio::time::timeout(IO_TIMEOUT, udp.recv_from(&mut response))
        .await
        .expect("SOCKS UDP echo timeout")
        .expect("receive SOCKS UDP echo");
    let payload_offset = socks_udp_payload_offset(&response[..len]);
    assert_eq!(&response[payload_offset..len], payload);
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
    let _ = read_async_socks_bound_address(&mut stream, header[3]).await;
    stream
}

async fn read_async_socks_bound_address(
    stream: &mut tokio::net::TcpStream,
    atyp: u8,
) -> SocketAddr {
    let ip = match atyp {
        0x01 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await.expect("socks ipv4");
            std::net::IpAddr::V4(Ipv4Addr::from(bytes))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.expect("socks domain len");
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await.expect("socks domain");
            let domain = String::from_utf8(domain).expect("socks domain utf8");
            tokio::net::lookup_host((domain.as_str(), 0))
                .await
                .expect("resolve socks bound domain")
                .next()
                .expect("socks bound domain address")
                .ip()
        }
        0x04 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await.expect("socks ipv6");
            std::net::IpAddr::V6(Ipv6Addr::from(bytes))
        }
        atyp => panic!("unsupported SOCKS address type {atyp:#x}"),
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .expect("socks bound port");
    SocketAddr::new(ip, u16::from_be_bytes(port))
}

fn socks_udp_payload_offset(packet: &[u8]) -> usize {
    assert!(packet.len() >= 4, "SOCKS UDP packet too short");
    assert_eq!(&packet[..3], &[0x00, 0x00, 0x00]);
    match packet[3] {
        0x01 => 10,
        0x03 => 7 + packet.get(4).copied().unwrap_or_default() as usize,
        0x04 => 22,
        atyp => panic!("unsupported SOCKS UDP address type {atyp:#x}"),
    }
}

fn assert_http_forward_response(proxy_addr: SocketAddr, request: &str) {
    let mut stream = TcpStream::connect_timeout(&proxy_addr, IO_TIMEOUT)
        .expect("connect HTTP forward proxy inbound");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set HTTP forward read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set HTTP forward write timeout");
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP forward request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read HTTP forward response");
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("ok"), "{response}");
}

fn assert_http_connect_echo(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    proxy_authorization: Option<&str>,
    payload: &[u8],
) {
    let mut stream = TcpStream::connect_timeout(&proxy_addr, IO_TIMEOUT)
        .expect("connect HTTP proxy inbound");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set HTTP proxy read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set HTTP proxy write timeout");

    let mut request =
        format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n");
    if let Some(value) = proxy_authorization {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP CONNECT request");

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("read HTTP CONNECT response");
        response.push(byte[0]);
        assert!(response.len() <= 4096, "HTTP CONNECT response too large");
    }
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200"),
        "unexpected HTTP CONNECT response: {response}"
    );

    stream
        .write_all(payload)
        .expect("write HTTP CONNECT tunnel payload");
    let mut echoed = vec![0u8; payload.len()];
    stream
        .read_exact(&mut echoed)
        .expect("read HTTP CONNECT tunnel echo");
    assert_eq!(echoed, payload);
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
    if let Ok(()) = stream.read_exact(&mut echoed) {
        assert_ne!(echoed, payload, "unexpected successful tunneled echo");
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
        return Err(io::Error::other(format!(
            "SOCKS connect failed: header={header:02x?}"
        )));
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
