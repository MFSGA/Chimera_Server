#![allow(dead_code)]

use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Once,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
    sync::{Mutex, MutexGuard},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const TEST_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb2273";
pub const WRONG_UUID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
pub const REALITY_PRIVATE_KEY: &str = "dnprBfWdJgo5yaGClSaZ12TZW-SiD988YmjDKOhXLKI";
pub const REALITY_PUBLIC_KEY: &str = "lpaMu0U01fKbRO9mgkSiOArWZz4V0TRW7pR543Pm9Xg";
pub const WRONG_REALITY_PUBLIC_KEY: &str =
    "YMN7dhY3BslQZ0LY8Fzb65vVgV6MY_QgVjQ9JOxV8gI";
pub const REALITY_SHORT_ID: &str = "4ac97aaf8b9b0356";
pub const REALITY_SERVER_NAME: &str = "www.apple.com";
pub const CURRENT_XRAY_VERSION: &str = "26.2.6";
pub const CHIMERA_CLIENT_REALITY_VERSION: &str = "1.8.0";

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(8);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);
static XRAY_TEST_LOCK: Mutex<()> = Mutex::const_new(());
static RUSTLS_PROVIDER: Once = Once::new();

#[derive(Debug, Clone)]
pub struct VisionServerOptions {
    pub min_client_ver: Option<String>,
    pub max_client_ver: Option<String>,
    pub server_names: Vec<String>,
    pub short_ids: Vec<String>,
    pub user_id: String,
    pub user_flow: Option<String>,
}

impl Default for VisionServerOptions {
    fn default() -> Self {
        Self {
            min_client_ver: Some(CURRENT_XRAY_VERSION.to_string()),
            max_client_ver: None,
            server_names: vec![REALITY_SERVER_NAME.to_string()],
            short_ids: vec![REALITY_SHORT_ID.to_string()],
            user_id: TEST_UUID.to_string(),
            user_flow: Some("xtls-rprx-vision".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VisionClientOptions {
    pub server_name: String,
    pub short_id: String,
    pub public_key: String,
    pub user_id: String,
    pub flow: Option<String>,
    pub fingerprint: String,
}

impl Default for VisionClientOptions {
    fn default() -> Self {
        Self {
            server_name: REALITY_SERVER_NAME.to_string(),
            short_id: REALITY_SHORT_ID.to_string(),
            public_key: REALITY_PUBLIC_KEY.to_string(),
            user_id: TEST_UUID.to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            fingerprint: "chrome".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct ChildGuard {
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
            .env("RUST_LOG", "debug")
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

    pub fn assert_running(&mut self) {
        match self.child.try_wait() {
            Ok(Some(status)) => panic!(
                "{} exited early with {status}; stdout={} stderr={}",
                self.name,
                self.stdout(),
                self.stderr(),
            ),
            Ok(None) => {}
            Err(error) => panic!("failed to poll {}: {error}", self.name),
        }
    }

    pub fn stdout(&self) -> String {
        read_lossy(&self.stdout_path)
    }

    pub fn stderr(&self) -> String {
        read_lossy(&self.stderr_path)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct VisionHarness {
    pub socks_addr: SocketAddr,
    pub dest_accepts: Arc<AtomicUsize>,
    pub chimera: ChildGuard,
    pub xray: ChildGuard,
    pub work_dir: PathBuf,
}

pub struct XrayReferenceHarness {
    pub socks_addr: SocketAddr,
    pub server: ChildGuard,
    pub client: ChildGuard,
    pub work_dir: PathBuf,
}

pub struct ChimeraClientHarness {
    pub socks_addr: SocketAddr,
    pub dest_accepts: Arc<AtomicUsize>,
    pub server: ChildGuard,
    pub client: ChildGuard,
    pub work_dir: PathBuf,
}

impl VisionHarness {
    pub fn assert_running(&mut self) {
        self.chimera.assert_running();
        self.xray.assert_running();
    }
}

impl ChimeraClientHarness {
    pub fn assert_running(&mut self) {
        self.server.assert_running();
        self.client.assert_running();
    }
}

pub async fn serial_guard() -> MutexGuard<'static, ()> {
    XRAY_TEST_LOCK.lock().await
}

pub async fn start_vision_harness(
    name: &str,
    server: VisionServerOptions,
    client: VisionClientOptions,
) -> VisionHarness {
    let workspace = workspace_root();
    let work_dir = create_test_dir(name);
    let (reality_dest_addr, dest_accepts) = start_tls13_dest(&workspace).await;
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera.json");
    let xray_config_path = work_dir.join("xray.json");

    let mut server_user = Map::new();
    server_user.insert("id".into(), Value::String(server.user_id));
    server_user.insert(
        "email".into(),
        Value::String(format!("{name}@reality-vision.test")),
    );
    if let Some(flow) = server.user_flow {
        server_user.insert("flow".into(), Value::String(flow));
    }

    let mut reality_settings = Map::new();
    reality_settings.insert(
        "dest".into(),
        Value::String(format!("127.0.0.1:{}", reality_dest_addr.port())),
    );
    reality_settings.insert(
        "serverNames".into(),
        Value::Array(server.server_names.into_iter().map(Value::String).collect()),
    );
    reality_settings.insert(
        "privateKey".into(),
        Value::String(REALITY_PRIVATE_KEY.to_string()),
    );
    reality_settings.insert(
        "shortIds".into(),
        Value::Array(server.short_ids.into_iter().map(Value::String).collect()),
    );
    reality_settings.insert("maxTimeDiff".into(), Value::from(0));
    if let Some(version) = server.min_client_ver {
        reality_settings.insert("minClientVer".into(), Value::String(version));
    }
    if let Some(version) = server.max_client_ver {
        reality_settings.insert("maxClientVer".into(), Value::String(version));
    }

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": format!("reality-vision-{name}"),
                "settings": {
                    "clients": [Value::Object(server_user)],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": Value::Object(reality_settings)
                }
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );

    let mut client_user = Map::new();
    client_user.insert("id".into(), Value::String(client.user_id));
    client_user.insert("encryption".into(), Value::String("none".into()));
    if let Some(flow) = client.flow {
        client_user.insert("flow".into(), Value::String(flow));
    }

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
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": chimera_port,
                        "users": [Value::Object(client_user)]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": client.server_name,
                        "fingerprint": client.fingerprint,
                        "publicKey": client.public_key,
                        "shortId": client.short_id
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

    VisionHarness {
        socks_addr,
        dest_accepts,
        chimera,
        xray,
        work_dir,
    }
}

pub async fn start_chimera_client_harness(
    name: &str,
    server: VisionServerOptions,
    client: VisionClientOptions,
) -> ChimeraClientHarness {
    let workspace = workspace_root();
    let work_dir = create_test_dir(&format!("chimera-client-{name}"));
    let (reality_dest_addr, dest_accepts) = start_tls13_dest(&workspace).await;
    let server_port = free_localhost_port();
    let socks_port = free_localhost_port();
    let server_config_path = work_dir.join("chimera-server.json");
    let client_config_path = work_dir.join("chimera-client.yaml");

    let mut server_user = Map::new();
    server_user.insert("id".into(), Value::String(server.user_id));
    server_user.insert(
        "email".into(),
        Value::String(format!("{name}@chimera-client.test")),
    );
    if let Some(flow) = server.user_flow {
        server_user.insert("flow".into(), Value::String(flow));
    }

    let mut reality_settings = Map::new();
    reality_settings.insert(
        "dest".into(),
        Value::String(format!("127.0.0.1:{}", reality_dest_addr.port())),
    );
    reality_settings.insert(
        "serverNames".into(),
        Value::Array(server.server_names.into_iter().map(Value::String).collect()),
    );
    reality_settings.insert(
        "privateKey".into(),
        Value::String(REALITY_PRIVATE_KEY.to_string()),
    );
    reality_settings.insert(
        "shortIds".into(),
        Value::Array(server.short_ids.into_iter().map(Value::String).collect()),
    );
    reality_settings.insert("maxTimeDiff".into(), Value::from(0));
    if let Some(version) = server.min_client_ver {
        reality_settings.insert("minClientVer".into(), Value::String(version));
    }
    if let Some(version) = server.max_client_ver {
        reality_settings.insert("maxClientVer".into(), Value::String(version));
    }

    write_json(
        &server_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "tag": format!("chimera-client-reality-vision-{name}"),
                "settings": {
                    "clients": [Value::Object(server_user)],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": Value::Object(reality_settings)
                }
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );

    let flow_line = client
        .flow
        .as_deref()
        .map(|flow| format!("    flow: '{}'\n", yaml_single_quote(flow)))
        .unwrap_or_default();
    let client_config = format!(
        r#"socks-port: {socks_port}
bind-address: 127.0.0.1
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: false
proxies:
  - name: to-chimera
    type: vless
    server: 127.0.0.1
    port: {server_port}
    uuid: '{}'
    network: tcp
    udp: true
    tls: true
{flow_line}    servername: '{}'
    client-fingerprint: '{}'
    reality-opts:
      public-key: '{}'
      short-id: '{}'
rules:
  - MATCH,to-chimera
"#,
        yaml_single_quote(&client.user_id),
        yaml_single_quote(&client.server_name),
        yaml_single_quote(&client.fingerprint),
        yaml_single_quote(&client.public_key),
        yaml_single_quote(&client.short_id),
    );
    fs::write(&client_config_path, client_config)
        .expect("write Chimera Client YAML config");

    let mut server_process =
        start_chimera(&workspace, &work_dir, &server_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, server_port)));
    server_process.assert_running();

    let mut client_process =
        start_chimera_client(&workspace, &work_dir, &client_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    wait_for_tcp(socks_addr);
    client_process.assert_running();

    ChimeraClientHarness {
        socks_addr,
        dest_accepts,
        server: server_process,
        client: client_process,
        work_dir,
    }
}

pub async fn start_xray_reference_harness(name: &str) -> XrayReferenceHarness {
    let workspace = workspace_root();
    let work_dir = create_test_dir(&format!("xray-reference-{name}"));
    let (reality_dest_addr, _) = start_tls13_dest(&workspace).await;
    let server_port = free_localhost_port();
    let socks_port = free_localhost_port();
    let server_config_path = work_dir.join("xray-server.json");
    let client_config_path = work_dir.join("xray-client.json");

    write_json(
        &server_config_path,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": server_port,
                "protocol": "vless",
                "tag": "reality-vision-server",
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "flow": "xtls-rprx-vision",
                        "email": "xray-reference@example.test"
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
                        "shortIds": [REALITY_SHORT_ID]
                    }
                }
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
    write_json(
        &client_config_path,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "tag": "socks-in",
                "settings": {"auth": "noauth"}
            }],
            "outbounds": [{
                "tag": "to-reference",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
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

    let mut server =
        start_xray_named("xray-server", &workspace, &work_dir, &server_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, server_port)));
    server.assert_running();
    let mut client =
        start_xray_named("xray-client", &workspace, &work_dir, &client_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    wait_for_tcp(socks_addr);
    client.assert_running();

    XrayReferenceHarness {
        socks_addr,
        server,
        client,
        work_dir,
    }
}

pub fn workspace_root() -> PathBuf {
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

pub fn create_test_dir(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "chimera-reality-vision-{name}-{}-{now}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create reality vision test directory");
    dir
}

fn write_json(path: &Path, value: Value) {
    let content = serde_json::to_string_pretty(&value).expect("serialize JSON");
    fs::write(path, content).expect("write JSON config");
}

fn yaml_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn start_chimera(workspace: &Path, work_dir: &Path, config: &Path) -> ChildGuard {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_chimera_server_app"));
    ChildGuard::spawn(
        "chimera",
        &binary,
        &[
            "--config",
            config.to_str().expect("config path utf8"),
            "--format",
            "json",
        ],
        work_dir,
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to start Chimera from {} in {}: {error}",
            binary.display(),
            workspace.display()
        )
    })
}

fn start_chimera_client(
    workspace: &Path,
    work_dir: &Path,
    config: &Path,
) -> ChildGuard {
    let binary = env::var_os("CHIMERA_CLIENT_BIN")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                workspace.join(path)
            }
        })
        .unwrap_or_else(|| {
            workspace
                .parent()
                .expect("server workspace parent")
                .join("Chimera_Client/target/debug/clash-rs")
        });
    if !binary.is_file() {
        panic!(
            "Chimera Client binary not found at {}; build it with `cargo build -p clash-rs` or set CHIMERA_CLIENT_BIN",
            binary.display()
        );
    }
    ChildGuard::spawn(
        "chimera-client",
        &binary,
        &[
            "--directory",
            work_dir.to_str().expect("work directory utf8"),
            "--config",
            config
                .file_name()
                .and_then(|name| name.to_str())
                .expect("client config file name utf8"),
            "--compatibility=false",
        ],
        work_dir,
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to start Chimera Client from {}: {error}",
            binary.display()
        )
    })
}

fn start_xray(workspace: &Path, work_dir: &Path, config: &Path) -> ChildGuard {
    start_xray_named("xray", workspace, work_dir, config)
}

fn start_xray_named(
    name: &'static str,
    workspace: &Path,
    work_dir: &Path,
    config: &Path,
) -> ChildGuard {
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
        name,
        &binary,
        &["run", "-c", config.to_str().expect("config path utf8")],
        work_dir,
    )
    .unwrap_or_else(|error| {
        panic!("failed to start Xray from {}: {error}", binary.display())
    })
}

pub fn start_tcp_echo_server() -> SocketAddr {
    start_tcp_echo_server_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind TCP echo server")
}

pub fn try_start_tcp_echo_server_v6() -> Option<SocketAddr> {
    start_tcp_echo_server_on(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).ok()
}

fn start_tcp_echo_server_on(bind_addr: SocketAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(bind_addr)?;
    let addr = listener.local_addr().expect("TCP echo address");
    thread::spawn(move || {
        for stream in listener.incoming().take(256) {
            let Ok(mut stream) = stream else {
                continue;
            };
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(length) => {
                            if stream.write_all(&buffer[..length]).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Ok(addr)
}

pub fn start_half_close_server() -> SocketAddr {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind half-close server");
    let addr = listener.local_addr().expect("half-close address");
    thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else {
                continue;
            };
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut payload = Vec::new();
                if stream.read_to_end(&mut payload).is_ok() {
                    let response = format!("received:{}", payload.len());
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.shutdown(Shutdown::Write);
                }
            });
        }
    });
    addr
}

pub async fn start_tls_echo_server() -> SocketAddr {
    let workspace = workspace_root();
    install_rustls_provider();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config(&workspace)));
    let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind TLS echo server");
    let addr = listener.local_addr().expect("TLS echo address");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    match tls.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(length) => {
                            if tls.write_all(&buffer[..length]).await.is_err()
                                || tls.flush().await.is_err()
                            {
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

async fn start_tls13_dest(workspace: &Path) -> (SocketAddr, Arc<AtomicUsize>) {
    install_rustls_provider();
    let acceptor = TlsAcceptor::from(Arc::new(tls_server_config(workspace)));
    let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind REALITY TLS 1.3 destination");
    let addr = listener.local_addr().expect("REALITY destination address");
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut byte = [0u8; 1];
                let _ = tls.read(&mut byte).await;
            });
        }
    });
    (addr, accepts)
}

pub fn assert_socks5_echo(
    socks_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) {
    let mut stream = connect_socks5(socks_addr, SocksTarget::Socket(target))
        .expect("connect target through Xray SOCKS");
    stream.write_all(payload).expect("write tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    read_exact_with_deadline(&mut stream, &mut echoed).expect("read tunneled echo");
    assert_payload_matches(&echoed, payload, "TCP echo");
}

pub fn assert_socks5_domain_echo(
    socks_addr: SocketAddr,
    domain: &str,
    port: u16,
    payload: &[u8],
) {
    let mut stream =
        connect_socks5(socks_addr, SocksTarget::Domain(domain.to_string(), port))
            .expect("connect domain target through Xray SOCKS");
    stream
        .write_all(payload)
        .expect("write domain tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    read_exact_with_deadline(&mut stream, &mut echoed)
        .expect("read domain tunneled echo");
    assert_payload_matches(&echoed, payload, "domain echo");
}

pub async fn assert_tls_echo_through_socks(
    socks_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) {
    assert_tls_echo_through_socks_with_config(
        socks_addr,
        target,
        payload,
        tls_test_client_config(),
    )
    .await;
}

pub async fn assert_tls13_only_echo_through_socks(
    socks_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) {
    assert_tls_echo_through_socks_with_config(
        socks_addr,
        target,
        payload,
        tls13_only_test_client_config(),
    )
    .await;
}

async fn assert_tls_echo_through_socks_with_config(
    socks_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
    config: RustlsClientConfig,
) {
    let stream = connect_socks5_async(socks_addr, target)
        .await
        .expect("connect TLS target through Xray SOCKS");
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("localhost").expect("TLS server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake through REALITY Vision");
    tls.write_all(payload)
        .await
        .expect("write TLS application data");
    tls.flush().await.expect("flush TLS application data");
    let mut echoed = vec![0u8; payload.len()];
    tls.read_exact(&mut echoed)
        .await
        .expect("read TLS application data echo");
    assert_payload_matches(&echoed, payload, "TLS application-data echo");
}

fn assert_payload_matches(actual: &[u8], expected: &[u8], label: &str) {
    if actual == expected {
        return;
    }
    let mismatch = actual
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
        .unwrap_or_else(|| actual.len().min(expected.len()));
    let actual_byte = actual.get(mismatch).copied();
    let expected_byte = expected.get(mismatch).copied();
    let probe_len = actual.len().min(expected.len()).min(64);
    let matching_shift = if probe_len == 0 {
        None
    } else {
        (0..expected.len().saturating_sub(probe_len)).find(|offset| {
            actual[..probe_len] == expected[*offset..*offset + probe_len]
        })
    };
    panic!(
        "{label} mismatch at byte {mismatch}: actual={actual_byte:02x?}, expected={expected_byte:02x?}, matching_shift={matching_shift:?}, actual_prefix={:02x?}, expected_prefix={:02x?}, actual_len={}, expected_len={}",
        &actual[..actual.len().min(16)],
        &expected[..expected.len().min(16)],
        actual.len(),
        expected.len(),
    );
}

pub fn probe_half_close(
    socks_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut stream = connect_socks5(socks_addr, SocksTarget::Socket(target))?;
    stream.write_all(payload)?;
    stream.shutdown(Shutdown::Write)?;
    let expected = format!("received:{}", payload.len());
    let mut response = vec![0u8; expected.len()];
    read_exact_with_deadline(&mut stream, &mut response)?;
    if response != expected.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected half-close response: {response:?}"),
        ));
    }
    Ok(response)
}

pub fn assert_half_close(
    socks_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) {
    probe_half_close(socks_addr, target, payload).expect("half-close roundtrip");
}

pub fn assert_socks5_proxy_fails(socks_addr: SocketAddr, target: SocketAddr) {
    let mut stream = match connect_socks5(socks_addr, SocksTarget::Socket(target)) {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let payload = b"must-not-echo-through-invalid-reality-vision";
    if stream.write_all(payload).is_err() {
        return;
    }
    let mut echoed = vec![0u8; payload.len()];
    if let Ok(()) = read_exact_with_deadline(&mut stream, &mut echoed) {
        assert_ne!(echoed, payload, "invalid setup unexpectedly proxied data");
    }
}

pub fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index.wrapping_mul(31).wrapping_add(17) % 251) as u8)
        .collect()
}

pub fn wait_for_counter(counter: &AtomicUsize, expected: usize) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        thread::sleep(RETRY_INTERVAL);
    }
    panic!(
        "timed out waiting for counter {expected}; current={}",
        counter.load(Ordering::SeqCst)
    );
}

pub fn wait_for_log(child: &ChildGuard, needle: &str) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        let logs = format!("{}\n{}", child.stdout(), child.stderr());
        if logs.contains(needle) {
            return;
        }
        thread::sleep(RETRY_INTERVAL);
    }
    panic!(
        "timed out waiting for log {needle:?}; stdout={} stderr={}",
        child.stdout(),
        child.stderr()
    );
}

#[derive(Debug)]
enum SocksTarget {
    Socket(SocketAddr),
    Domain(String, u16),
}

fn connect_socks5(
    socks_addr: SocketAddr,
    target: SocksTarget,
) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&socks_addr, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "SOCKS greeting failed: {greeting:02x?}"
        )));
    }
    let request = socks_connect_request(target)?;
    stream.write_all(&request)?;
    read_socks_connect_response(&mut stream)?;
    Ok(stream)
}

async fn connect_socks5_async(
    socks_addr: SocketAddr,
    target: SocketAddr,
) -> io::Result<tokio::net::TcpStream> {
    let mut stream = tokio::net::TcpStream::connect(socks_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "SOCKS greeting failed: {greeting:02x?}"
        )));
    }
    let request = socks_connect_request(SocksTarget::Socket(target))?;
    stream.write_all(&request).await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS connect failed: {header:02x?}"
        )));
    }
    match header[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail).await?;
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut tail = vec![0u8; length[0] as usize + 2];
            stream.read_exact(&mut tail).await?;
        }
        0x04 => {
            let mut tail = [0u8; 18];
            stream.read_exact(&mut tail).await?;
        }
        address_type => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS address type {address_type:#x}"),
            ));
        }
    }
    Ok(stream)
}

fn socks_connect_request(target: SocksTarget) -> io::Result<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];
    match target {
        SocksTarget::Socket(SocketAddr::V4(addr)) => {
            request.push(0x01);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksTarget::Socket(SocketAddr::V6(addr)) => {
            request.push(0x04);
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksTarget::Domain(domain, port) => {
            if domain.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain too long",
                ));
            }
            request.push(0x03);
            request.push(domain.len() as u8);
            request.extend_from_slice(domain.as_bytes());
            request.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(request)
}

fn read_socks_connect_response(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS connect failed: {header:02x?}"
        )));
    }
    match header[3] {
        0x01 => {
            let mut tail = [0u8; 6];
            stream.read_exact(&mut tail)?;
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut tail = vec![0u8; length[0] as usize + 2];
            stream.read_exact(&mut tail)?;
        }
        0x04 => {
            let mut tail = [0u8; 18];
            stream.read_exact(&mut tail)?;
        }
        address_type => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS address type {address_type:#x}"),
            ));
        }
    }
    Ok(())
}

fn read_exact_with_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
) -> io::Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut read = 0;
    while read < buffer.len() {
        match stream.read(&mut buffer[read..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(length) => read += length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && Instant::now() < deadline =>
            {
                thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn wait_for_tcp(addr: SocketAddr) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, RETRY_INTERVAL).is_ok() {
            return;
        }
        thread::sleep(RETRY_INTERVAL);
    }
    panic!("timed out waiting for TCP listener at {addr}");
}

fn free_localhost_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral local address")
        .port()
}

fn install_rustls_provider() {
    RUSTLS_PROVIDER.call_once(|| {
        let _ = CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
}

fn tls_server_config(workspace: &Path) -> RustlsServerConfig {
    let cert_file =
        File::open(workspace.join("cert/cert.pem")).expect("open TLS certificate");
    let key_file =
        File::open(workspace.join("cert/key.pem")).expect("open TLS private key");
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

fn tls_test_client_config() -> RustlsClientConfig {
    install_rustls_provider();
    RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptTestServerCert))
        .with_no_client_auth()
}

fn tls13_only_test_client_config() -> RustlsClientConfig {
    install_rustls_provider();
    RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptTestServerCert))
        .with_no_client_auth()
}

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

fn read_lossy(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| {
        format!("<failed to read {}: {error}>", path.display())
    })
}
