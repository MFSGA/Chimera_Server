#![allow(dead_code)]

use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, MutexGuard},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const TEST_UUID: &str = "3ac9b383-75a1-431c-8184-106c80eb2273";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
static XRAY_TEST_LOCK: Mutex<()> = Mutex::new(());

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
                read_lossy(&self.stdout_path),
                read_lossy(&self.stderr_path)
            ),
            Ok(None) => {}
            Err(error) => panic!("failed to poll {}: {error}", self.name),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn serial_xray_guard() -> MutexGuard<'static, ()> {
    XRAY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn workspace_root() -> PathBuf {
    for ancestor in Path::new(env!("CARGO_MANIFEST_DIR")).ancestors() {
        if ancestor.join("Cargo.toml").is_file()
            && ancestor.join("chimera_server_app/Cargo.toml").is_file()
        {
            return ancestor.to_path_buf();
        }
    }
    panic!(
        "failed to find Chimera workspace root from {}",
        env!("CARGO_MANIFEST_DIR")
    );
}

pub fn create_test_dir(name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = env::temp_dir()
        .join(format!("chimera-xhttp-{name}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).expect("create XHTTP test directory");
    dir
}

pub fn write_json(path: &Path, value: serde_json::Value) {
    let content = serde_json::to_string_pretty(&value).expect("serialize JSON");
    fs::write(path, content).expect("write JSON config");
}

pub fn start_chimera(
    workspace: &Path,
    work_dir: &Path,
    config: &Path,
) -> ChildGuard {
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
            "failed to start chimera from {} in {}: {error}",
            binary.display(),
            workspace.display()
        )
    })
}

pub fn start_xray(workspace: &Path, work_dir: &Path, config: &Path) -> ChildGuard {
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
        &["run", "-c", config.to_str().expect("config path utf8")],
        work_dir,
    )
    .unwrap_or_else(|error| {
        panic!("failed to start xray from {}: {error}", binary.display())
    })
}

pub fn start_tcp_echo_server() -> SocketAddr {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind TCP echo server");
    let addr = listener.local_addr().expect("TCP echo address");
    thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            thread::spawn(move || {
                let mut buffer = [0u8; 4096];
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
    addr
}

pub fn assert_socks5_echo(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    payload: &[u8],
) {
    let mut stream = TcpStream::connect_timeout(&socks_addr, IO_TIMEOUT)
        .expect("connect Xray SOCKS inbound");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set SOCKS read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set SOCKS write timeout");

    stream
        .write_all(&[0x05, 0x01, 0x00])
        .expect("SOCKS greeting");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .expect("SOCKS greeting response");
    assert_eq!(greeting, [0x05, 0x00]);

    let ip = match target_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("XHTTP matrix uses an IPv4 echo target"),
    };
    let port = target_addr.port().to_be_bytes();
    stream
        .write_all(&[
            0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
        ])
        .expect("SOCKS connect request");
    read_socks_connect_response(&mut stream).expect("SOCKS connect response");

    stream.write_all(payload).expect("write tunneled payload");
    let mut echoed = vec![0u8; payload.len()];
    read_exact_with_deadline(&mut stream, &mut echoed)
        .expect("read tunneled echo response");
    assert_eq!(echoed, payload);
}

pub fn deterministic_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index.wrapping_mul(31).wrapping_add(17) % 251) as u8)
        .collect()
}

pub fn wait_for_tcp(addr: SocketAddr) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, CONNECT_RETRY_INTERVAL).is_ok() {
            return;
        }
        thread::sleep(CONNECT_RETRY_INTERVAL);
    }
    panic!("timed out waiting for TCP listener at {addr}");
}

pub fn free_localhost_port() -> u16 {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral local address")
        .port()
}

#[derive(Debug)]
pub struct HttpHead {
    pub status: u16,
    pub headers: HashMap<String, String>,
}

pub fn open_http_request(addr: SocketAddr, request: &[u8]) -> (TcpStream, HttpHead) {
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .expect("connect XHTTP listener");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set HTTP read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set HTTP write timeout");
    stream.write_all(request).expect("write HTTP request");
    let head = read_http_head(&mut stream);
    (stream, head)
}

pub fn send_http_request(addr: SocketAddr, request: &[u8]) -> HttpHead {
    open_http_request(addr, request).1
}

fn read_http_head(stream: &mut TcpStream) -> HttpHead {
    let mut bytes = Vec::with_capacity(1024);
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .expect("read HTTP response head");
        bytes.push(byte[0]);
        assert!(bytes.len() <= 64 * 1024, "HTTP response head too large");
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("HTTP response status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| {
            (name.trim().to_ascii_lowercase(), value.trim().to_string())
        })
        .collect();
    HttpHead { status, headers }
}

fn read_socks_connect_response(stream: &mut TcpStream) -> io::Result<()> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS connect failed: header={header:02x?}"
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
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF while reading tunneled data",
                ));
            }
            Ok(length) => read += length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && Instant::now() < deadline =>
            {
                thread::sleep(CONNECT_RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_lossy(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| {
        format!("<failed to read {}: {error}>", path.display())
    })
}
