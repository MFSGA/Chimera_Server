use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Once},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::digest::{SHA256, digest};
use rustls::{ServerConfig as RustlsServerConfig, crypto::CryptoProvider};
use rustls_pemfile::{certs, private_key};
use serde_json::json;
use tokio::net::TcpListener as TokioTcpListener;
use tokio_rustls::TlsAcceptor;

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
                        "dest": format!("localhost:{}", reality_dest_addr.port()),
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

    assert_socks5_echo(
        SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)),
        echo_addr,
        b"reality-vision through xray client",
    );
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

    assert_socks5_echo(
        SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port)),
        echo_addr,
        b"hysteria2 through xray client",
    );
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
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo addr");
    thread::spawn(move || {
        for stream in listener.incoming().take(8) {
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

async fn start_tls13_dest(workspace: &Path) -> SocketAddr {
    install_rustls_provider();
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
    let tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("build tls server config");
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener =
        TokioTcpListener::bind(SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 0)))
            .await
            .expect("bind tls dest");
    let addr = listener.local_addr().expect("tls dest addr");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    addr
}

fn assert_socks5_echo(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
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

    stream.write_all(&[0x05, 0x01, 0x00]).expect("socks hello");
    let mut hello = [0u8; 2];
    stream.read_exact(&mut hello).expect("socks hello response");
    assert_eq!(hello, [0x05, 0x00], "SOCKS no-auth negotiation failed");

    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("test only uses ipv4 echo target"),
    };
    let port = target_addr.port().to_be_bytes();
    stream
        .write_all(&[
            0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
        ])
        .expect("socks connect request");
    read_socks_connect_response(&mut stream).expect("socks connect response");

    stream.write_all(payload).expect("write tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    stream
        .read_exact(&mut echoed)
        .expect("read tunneled echo response");
    assert_eq!(echoed, payload);
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
    match header[3] {
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
