use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

fn trace_step(step: impl AsRef<str>) {
    eprintln!("[socks-external-e2e] {}", step.as_ref());
}

fn global_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct ServerProcess {
    child: Child,
    workdir: PathBuf,
    log_path: PathBuf,
}

impl ServerProcess {
    fn spawn(config_content: &str) -> io::Result<Self> {
        let workdir = unique_test_dir()?;
        trace_step(format!(
            "spawn server with temporary workspace {}",
            workdir.display()
        ));
        fs::write(workdir.join("config.json5"), config_content)?;

        let log_path = workdir.join("server.log");
        let stdout_file = File::create(&log_path)?;
        let stderr_file = stdout_file.try_clone()?;

        let child = Command::new(env!("CARGO_BIN_EXE_chimera_server_app"))
            .current_dir(&workdir)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()?;
        trace_step(format!(
            "server spawned pid={} log={}",
            child.id(),
            log_path.display()
        ));

        Ok(Self {
            child,
            workdir,
            log_path,
        })
    }

    fn wait_until_ready(&mut self, socks_addr: SocketAddr) -> io::Result<()> {
        trace_step(format!("waiting for socks listener {}", socks_addr));
        let deadline = Instant::now() + STARTUP_TIMEOUT;

        loop {
            if let Some(status) = self.child.try_wait()? {
                let logs = self.logs();
                return Err(io::Error::other(format!(
                    "chimera exited early with status {status}; logs:\n{logs}"
                )));
            }

            if let Ok(stream) = TcpStream::connect_timeout(&socks_addr, IO_TIMEOUT) {
                drop(stream);
                trace_step(format!("socks listener {} is ready", socks_addr));
                return Ok(());
            }

            if Instant::now() >= deadline {
                let logs = self.logs();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timeout waiting for socks listener {socks_addr}; logs:\n{logs}"
                    ),
                ));
            }

            thread::sleep(CONNECT_RETRY_INTERVAL);
        }
    }

    fn logs(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_else(|err| {
            format!(
                "(failed to read logs from {}: {err})",
                self.log_path.display()
            )
        })
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        trace_step(format!(
            "teardown server pid={} workspace={}",
            self.child.id(),
            self.workdir.display()
        ));
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

fn unique_test_dir() -> io::Result<PathBuf> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let pid = std::process::id();
    let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("chimera-socks-e2e-{pid}-{millis}-{test_id}"));
    fs::create_dir_all(&path)?;
    trace_step(format!("allocated temporary test dir {}", path.display()));
    Ok(path)
}

fn free_localhost_port() -> io::Result<u16> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    trace_step(format!("allocated localhost tcp port {}", port));
    Ok(port)
}

fn spawn_echo_server() -> io::Result<(SocketAddrV4, thread::JoinHandle<()>)> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let addr = match listener.local_addr()? {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "echo listener unexpectedly bound to ipv6",
            ));
        }
    };
    trace_step(format!("echo server listening on {}", addr));

    let handle = thread::spawn(move || {
        eprintln!("[socks-external-e2e] echo loop thread started for {}", addr);
        let accept_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    eprintln!(
                        "[socks-external-e2e] echo server accepted stream from {:?}",
                        stream.peer_addr()
                    );
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                    let mut buf = [0u8; 1024];

                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => return,
                            Ok(n) => {
                                eprintln!(
                                    "[socks-external-e2e] echo server forwarding {} bytes back",
                                    n
                                );
                                if stream.write_all(&buf[..n]).is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return,
            }
        }
    });

    Ok((addr, handle))
}

fn socks_roundtrip_noauth(
    socks_addr: SocketAddrV4,
    target_addr: SocketAddrV4,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    trace_step(format!(
        "starting noauth socks roundtrip via {} to {} payload_len={}",
        socks_addr,
        target_addr,
        payload.len()
    ));
    let mut stream = TcpStream::connect(socks_addr)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    stream.write_all(&[0x05, 0x01, 0x00])?;
    trace_step("sent method negotiation request: noauth");
    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response)?;
    trace_step(format!("received method response {:?}", method_response));
    if method_response != [0x05, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected method response: {method_response:?}"),
        ));
    }

    write_connect_request(&mut stream, target_addr)?;
    trace_step("connect request accepted, sending payload");

    stream.write_all(payload)?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed)?;
    trace_step(format!("received echoed payload of {} bytes", echoed.len()));
    Ok(echoed)
}

fn socks_roundtrip_password(
    socks_addr: SocketAddrV4,
    target_addr: SocketAddrV4,
    username: &str,
    password: &str,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    trace_step(format!(
        "starting password socks roundtrip via {} to {} user={} payload_len={}",
        socks_addr,
        target_addr,
        username,
        payload.len()
    ));
    let mut stream = TcpStream::connect(socks_addr)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    stream.write_all(&[0x05, 0x01, 0x02])?;
    trace_step("sent method negotiation request: password auth");
    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response)?;
    trace_step(format!("received method response {:?}", method_response));
    if method_response != [0x05, 0x02] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected method response: {method_response:?}"),
        ));
    }

    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "username/password too long for socks5 auth",
        ));
    }

    let mut auth_request = Vec::with_capacity(3 + username.len() + password.len());
    auth_request.push(0x01);
    auth_request.push(username.len() as u8);
    auth_request.extend_from_slice(username.as_bytes());
    auth_request.push(password.len() as u8);
    auth_request.extend_from_slice(password.as_bytes());
    stream.write_all(&auth_request)?;
    trace_step("sent username/password auth payload");

    let mut auth_response = [0u8; 2];
    stream.read_exact(&mut auth_response)?;
    trace_step(format!("received auth response {:?}", auth_response));
    if auth_response != [0x01, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected auth response: {auth_response:?}"),
        ));
    }

    write_connect_request(&mut stream, target_addr)?;
    trace_step("connect request accepted, sending payload");

    stream.write_all(payload)?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed)?;
    trace_step(format!("received echoed payload of {} bytes", echoed.len()));
    Ok(echoed)
}

fn write_connect_request(
    stream: &mut TcpStream,
    target_addr: SocketAddrV4,
) -> io::Result<()> {
    trace_step(format!("sending connect request to {}", target_addr));
    let ip = target_addr.ip().octets();
    let port = target_addr.port().to_be_bytes();
    let request = [
        0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
    ];
    stream.write_all(&request)?;

    let mut response = [0u8; 10];
    stream.read_exact(&mut response)?;
    trace_step(format!("received connect response {:?}", response));
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(io::Error::other(format!(
            "unexpected connect response: {response:?}"
        )));
    }

    Ok(())
}

#[test]
fn socks_noauth_external_roundtrip() {
    trace_step("==== test socks_noauth_external_roundtrip start ====");
    let _guard = global_test_lock()
        .lock()
        .expect("failed to acquire test lock");
    let (echo_addr, echo_handle) =
        spawn_echo_server().expect("failed to start echo server");
    let socks_port = free_localhost_port().expect("failed to allocate socks port");
    let socks_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);

    let config = format!(
        r#"{{
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {socks_port},
      "protocol": "socks",
      "settings": {{
        "auth": "noauth"
      }},
      "tag": "socks-noauth"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "freedom",
      "tag": "direct"
    }}
  ]
}}"#
    );
    trace_step(format!(
        "generated noauth config for socks_addr={} target_echo={}",
        socks_addr, echo_addr
    ));

    let mut server =
        ServerProcess::spawn(&config).expect("failed to spawn chimera process");
    server
        .wait_until_ready(SocketAddr::V4(socks_addr))
        .unwrap_or_else(|err| panic!("chimera not ready: {err}"));

    let payload = b"chimera-socks-noauth-e2e";
    trace_step(format!("test payload={}", String::from_utf8_lossy(payload)));
    let echoed = socks_roundtrip_noauth(socks_addr, echo_addr, payload)
        .unwrap_or_else(|err| {
            panic!("noauth roundtrip failed: {err}; logs:\n{}", server.logs())
        });
    assert_eq!(echoed, payload);
    trace_step("assertion passed: noauth echoed payload matches input");

    drop(server);
    let _ = echo_handle.join();
    trace_step("==== test socks_noauth_external_roundtrip done ====");
}

#[test]
fn socks_password_external_roundtrip() {
    trace_step("==== test socks_password_external_roundtrip start ====");
    let _guard = global_test_lock()
        .lock()
        .expect("failed to acquire test lock");
    let (echo_addr, echo_handle) =
        spawn_echo_server().expect("failed to start echo server");
    let socks_port = free_localhost_port().expect("failed to allocate socks port");
    let socks_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port);

    let username = "e2e-user";
    let password = "e2e-pass";
    let config = format!(
        r#"{{
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {socks_port},
      "protocol": "socks",
      "settings": {{
        "auth": "password",
        "accounts": [
          {{
            "user": "{username}",
            "pass": "{password}"
          }}
        ]
      }},
      "tag": "socks-password"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "freedom",
      "tag": "direct"
    }}
  ]
}}"#
    );
    trace_step(format!(
        "generated password config for socks_addr={} target_echo={} user={}",
        socks_addr, echo_addr, username
    ));

    let mut server =
        ServerProcess::spawn(&config).expect("failed to spawn chimera process");
    server
        .wait_until_ready(SocketAddr::V4(socks_addr))
        .unwrap_or_else(|err| panic!("chimera not ready: {err}"));

    let payload = b"chimera-socks-password-e2e";
    trace_step(format!("test payload={}", String::from_utf8_lossy(payload)));
    let echoed =
        socks_roundtrip_password(socks_addr, echo_addr, username, password, payload)
            .unwrap_or_else(|err| {
                panic!("password roundtrip failed: {err}; logs:\n{}", server.logs())
            });
    assert_eq!(echoed, payload);
    trace_step("assertion passed: password echoed payload matches input");

    drop(server);
    let _ = echo_handle.join();
    trace_step("==== test socks_password_external_roundtrip done ====");
}
