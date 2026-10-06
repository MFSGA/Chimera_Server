#![cfg(any(feature = "full", feature = "vless-reverse"))]

mod xhttp_support;

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use xhttp_support::{
    TEST_UUID, create_test_dir, free_localhost_port, serial_xray_guard,
    start_chimera, start_xray, wait_for_tcp, workspace_root, write_json,
    xray_binary,
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const UNKNOWN_COMMAND: u8 = 0xff;
const VALID_PAYLOAD: &[u8] = b"valid request after unknown command";
const TEST_UUID_BYTES: [u8; 16] = [
    0x3a, 0xc9, 0xb3, 0x83, 0x75, 0xa1, 0x43, 0x1c, 0x81, 0x84, 0x10, 0x6c, 0x80,
    0xeb, 0x22, 0x73,
];
const REVERSE_TEST_UUID: &str = "e041e73e-a0a0-49f5-9754-6401aa621fb7";
const REVERSE_TEST_UUID_BYTES: [u8; 16] = [
    0xe0, 0x41, 0xe7, 0x3e, 0xa0, 0xa0, 0x49, 0xf5, 0x97, 0x54, 0x64, 0x01, 0xaa,
    0x62, 0x1f, 0xb7,
];

struct EchoTarget {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}

#[test]
fn chimera_and_xray_reject_unknown_vless_command_without_dialing_target() {
    let workspace = workspace_root();
    let reference_xray = xray_binary(&workspace);

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-invalid-command");
    let chimera_port = free_localhost_port();
    let chimera_target = start_echo_target();
    let chimera_config = work_dir.join("chimera.json");
    write_json(
        &chimera_config,
        chimera_server_config(chimera_port, chimera_target.addr),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    let chimera_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port));
    wait_for_tcp(chimera_addr);
    chimera.assert_running();

    assert_unknown_command_is_rejected(
        chimera_addr,
        REVERSE_TEST_UUID_BYTES,
        chimera_target.addr,
    );
    assert_target_not_dialed(&chimera_target, "Chimera");

    let mut xray_case = if reference_xray.is_file() {
        let xray_port = free_localhost_port();
        let xray_target = start_echo_target();
        let xray_config = work_dir.join("xray.json");
        write_json(
            &xray_config,
            xray_server_config(xray_port, xray_target.addr),
        );
        let xray = start_xray(&workspace, &work_dir, &xray_config);
        let xray_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_port));
        wait_for_tcp(xray_addr);
        Some((xray_addr, xray_target, xray))
    } else {
        eprintln!(
            "Xray comparison skipped because {} is unavailable; Chimera network regression still runs",
            reference_xray.display()
        );
        None
    };
    if let Some((xray_addr, xray_target, xray)) = xray_case.as_mut() {
        xray.assert_running();
        assert_unknown_command_is_rejected(
            *xray_addr,
            REVERSE_TEST_UUID_BYTES,
            xray_target.addr,
        );
        assert_target_not_dialed(xray_target, "Xray 26.9.9");
    }

    // The same listeners must continue to serve a valid request after the
    // malformed command has been rejected.
    assert_valid_vless_echo("Chimera", chimera_addr, chimera_target.addr);
    assert_eq!(chimera_target.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(
        chimera_target.bytes.load(Ordering::SeqCst),
        VALID_PAYLOAD.len()
    );
    chimera.assert_running();
    if let Some((xray_addr, xray_target, xray)) = xray_case.as_mut() {
        assert_valid_vless_echo("Xray 26.9.9", *xray_addr, xray_target.addr);
        assert_eq!(xray_target.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(
            xray_target.bytes.load(Ordering::SeqCst),
            VALID_PAYLOAD.len()
        );
        xray.assert_running();
    }
}

fn chimera_server_config(port: u16, target: SocketAddr) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "tag": "invalid-command-vless",
            "settings": {
                "clients": [
                    {"id": TEST_UUID, "email": "valid@example.test"},
                    {
                        "id": REVERSE_TEST_UUID,
                        "email": "reverse@example.test",
                        "reverse": {"tag": "test-reverse"}
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {"network": "tcp"}
        }],
        "outbounds": [{
            "tag": "direct",
            "protocol": "freedom",
            "settings": {"finalRules": [{
                "action": "allow",
                "network": "tcp",
                "port": target.port(),
                "ip": ["127.0.0.1/32"]
            }]}
        }],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["invalid-command-vless"],
                "network": "tcp",
                "outboundTag": "direct"
            }]
        }
    })
}

fn xray_server_config(port: u16, target: SocketAddr) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "tag": "invalid-command-vless",
            "settings": {
                "clients": [
                    {"id": TEST_UUID, "email": "valid@example.test"},
                    {
                        "id": REVERSE_TEST_UUID,
                        "email": "reverse@example.test",
                        "reverse": {"tag": "test-reverse"}
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {"network": "tcp", "security": "none"}
        }],
        "outbounds": [{
            "tag": "direct",
            "protocol": "freedom",
            "settings": {"finalRules": [{
                "action": "allow",
                "network": "tcp",
                "port": target.port(),
                "ip": ["127.0.0.1/32"]
            }]}
        }]
    })
}

fn start_echo_target() -> EchoTarget {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind VLESS command test target");
    let addr = listener
        .local_addr()
        .expect("read VLESS command test target address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let accepted_worker = accepted.clone();
    let bytes_worker = bytes.clone();

    thread::spawn(move || {
        // One valid follow-up request is expected. If the unknown command
        // reaches the target first, the test observes it before this worker
        // exits and reports the regression.
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        accepted_worker.fetch_add(1, Ordering::SeqCst);
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut buffer = [0u8; 512];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(length) => {
                    bytes_worker.fetch_add(length, Ordering::SeqCst);
                    if stream.write_all(&buffer[..length]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    EchoTarget {
        addr,
        accepted,
        bytes,
    }
}

fn assert_unknown_command_is_rejected(
    server: SocketAddr,
    user_id: [u8; 16],
    target: SocketAddr,
) {
    let mut stream = TcpStream::connect_timeout(&server, IO_TIMEOUT)
        .expect("connect to VLESS listener for invalid command");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set invalid-command read timeout");
    stream
        .write_all(&vless_request(user_id, UNKNOWN_COMMAND, target))
        .expect("write authenticated VLESS request with unknown command");

    let mut response = [0u8; 2];
    match stream.read(&mut response) {
        Ok(0) => {}
        Ok(length) => panic!(
            "unknown VLESS command unexpectedly received {length} response bytes: {response:?}"
        ),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Err(error) => {
            panic!("unknown VLESS command was not closed promptly: {error}")
        }
    }
}

fn assert_target_not_dialed(target: &EchoTarget, server_name: &str) {
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        0,
        "{server_name} dialed a target for an unknown VLESS command"
    );
    assert_eq!(
        target.bytes.load(Ordering::SeqCst),
        0,
        "{server_name} forwarded bytes for an unknown VLESS command"
    );
}

fn assert_valid_vless_echo(
    server_name: &str,
    server: SocketAddr,
    target: SocketAddr,
) {
    let mut stream = TcpStream::connect_timeout(&server, IO_TIMEOUT)
        .expect("connect to VLESS listener for valid follow-up");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set valid-request read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set valid-request write timeout");
    let mut request = vless_request(TEST_UUID_BYTES, 1, target);
    request.extend_from_slice(VALID_PAYLOAD);
    stream
        .write_all(&request)
        .expect("write valid VLESS TCP request and initial payload");

    let mut response_header = [0u8; 2];
    stream
        .read_exact(&mut response_header)
        .unwrap_or_else(|error| {
            panic!("{server_name} did not return a valid VLESS response after invalid command: {error}")
        });
    assert_eq!(response_header, [0, 0]);

    let mut response = vec![0u8; VALID_PAYLOAD.len()];
    stream
        .read_exact(&mut response)
        .expect("read VLESS echo response");
    assert_eq!(response, VALID_PAYLOAD);
}

fn vless_request(user_id: [u8; 16], command: u8, target: SocketAddr) -> Vec<u8> {
    let mut request = Vec::with_capacity(26);
    request.push(0);
    request.extend_from_slice(&user_id);
    request.push(0); // No addons.
    request.push(command);
    request.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            request.push(3);
            request.extend_from_slice(&address.octets());
        }
    }
    request
}
