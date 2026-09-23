mod xhttp_support;

use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use aws_lc_rs::digest::{SHA256, digest};
use rustls_pemfile::certs;
use serde_json::json;
use xhttp_support::{
    TEST_UUID, create_test_dir, free_localhost_port, serial_xray_guard,
    start_chimera, start_xray, wait_for_tcp, workspace_root, write_json,
    xray_binary,
};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const REVERSE_READY_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Copy)]
enum ReverseSecurity {
    Raw,
    Tls,
    Websocket,
}

impl ReverseSecurity {
    fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Tls => "tls",
            Self::Websocket => "websocket",
        }
    }
}

#[test]
fn xray_bridge_round_trips_public_dokodemo_tcp_over_raw_vless_reverse() {
    run_reverse_interop(ReverseSecurity::Raw);
}

#[test]
fn xray_bridge_round_trips_public_dokodemo_tcp_over_tls_vless_reverse() {
    run_reverse_interop(ReverseSecurity::Tls);
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_raw_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Raw, None);
}

#[test]
fn chimera_bridge_preserves_reverse_source_for_freedom_proxy_protocol() {
    run_chimera_bridge_proxy_protocol_interop();
}

#[test]
fn chimera_bridge_preserves_reverse_routing_user_over_raw_vless_reverse() {
    run_chimera_bridge_interop(
        ReverseSecurity::Raw,
        Some("reverse-routing@example.test"),
    );
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_tls_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Tls, None);
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_over_websocket_vless_reverse() {
    run_chimera_bridge_interop(ReverseSecurity::Websocket, None);
}

#[test]
fn chimera_bridge_sniffs_http_host_over_raw_vless_reverse() {
    run_chimera_bridge_sniffing_interop(
        "http-override",
        "192.0.2.1",
        json!({"enabled": true, "destOverride": ["http"]}),
        b"GET /sniff HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn chimera_bridge_sniffs_tls_sni_over_raw_vless_reverse() {
    let payload = tls_client_hello_payload("localhost");
    run_chimera_bridge_sniffing_interop(
        "tls-override",
        "192.0.2.1",
        json!({"enabled": true, "destOverride": ["tls"]}),
        &payload,
    );
}

#[test]
fn chimera_bridge_reverse_sniffing_route_only_keeps_original_target() {
    run_chimera_bridge_sniffing_interop(
        "http-route-only",
        "127.0.0.1",
        json!({
            "enabled": true,
            "destOverride": ["http"],
            "routeOnly": true
        }),
        b"GET /sniff HTTP/1.1\r\nHost: route-only.test\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn chimera_bridge_reverse_sniffing_honors_domain_exclusions() {
    run_chimera_bridge_sniffing_interop(
        "http-domain-excluded",
        "127.0.0.1",
        json!({
            "enabled": true,
            "destOverride": ["http"],
            "domainsExcluded": ["full:excluded.test"]
        }),
        b"GET /sniff HTTP/1.1\r\nHost: excluded.test\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn chimera_bridge_reverse_sniffing_honors_ip_exclusions() {
    run_chimera_bridge_sniffing_interop(
        "http-ip-excluded",
        "127.0.0.1",
        json!({
            "enabled": true,
            "destOverride": ["http"],
            "ipsExcluded": ["127.0.0.0/8"]
        }),
        b"GET /sniff HTTP/1.1\r\nHost: ip-excluded.test\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn xray_bridge_round_trips_public_dokodemo_udp_over_raw_vless_reverse() {
    run_reverse_udp_interop();
}

#[test]
fn chimera_bridge_round_trips_public_xray_portal_udp_over_raw_vless_reverse() {
    run_chimera_bridge_udp_interop();
}

fn run_chimera_bridge_sniffing_interop(
    name: &str,
    original_target: &str,
    sniffing: serde_json::Value,
    payload: &[u8],
) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse sniffing Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir =
        create_test_dir(&format!("vless-reverse-chimera-bridge-sniff-http-{name}"));
    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-sniff@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-http",
                    "settings": {
                        "address": original_target,
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-http"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {
                            "tag": "bridge-in",
                            "sniffing": sniffing
                        }
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom"
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    assert_reverse_echo_with_retry(
        SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)),
        payload,
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_chimera_bridge_udp_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse UDP Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-chimera-bridge-udp-raw");
    let (echo_addr, echoed_bytes) = start_observed_udp_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_udp_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-udp@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-udp",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "udp",
                        "followRedirect": false
                    }
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-udp"],
                    "network": "udp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom"
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "udp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    // Exercise the same supervised retry path as the TCP fixture.
    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    xray.assert_running();

    assert_reverse_udp_echo_with_retry(
        SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)),
        b"chimera bridge through xray reverse portal udp",
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_reverse_udp_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse UDP Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-xray-bridge-udp-raw");
    let (echo_addr, echoed_bytes) = start_observed_udp_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_udp_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "xray-bridge-udp@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-udp",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "udp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "udp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-udp"],
                    "network": "udp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "finalRules": [{
                            "action": "allow",
                            "network": "udp",
                            "ip": ["127.0.0.0/8"]
                        }]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "udp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    xray.assert_running();

    assert_reverse_udp_echo_with_retry(
        SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)),
        b"xray bridge through chimera reverse portal udp",
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_chimera_bridge_proxy_protocol_interop() {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse PROXY protocol Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir("vless-reverse-chimera-bridge-proxy-protocol");
    let (echo_addr, captured_source) = start_proxy_protocol_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge-proxy@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-proxy",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-proxy"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": {"network": "tcp", "security": "none"}
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {"proxyProtocol": 1}
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    let payload = b"reverse proxy protocol source";
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let successful_source = loop {
        match reverse_echo_once_with_source(public_addr, payload) {
            Ok(source) => break source,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                panic!(
                    "VLESS Reverse PROXY protocol worker did not become usable at {public_addr}: {error}"
                );
            }
        }
    };

    assert_eq!(
        *captured_source
            .lock()
            .expect("PROXY protocol capture lock poisoned"),
        Some(successful_source),
        "Chimera freedom proxyProtocol must preserve the Xray Portal public source"
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_chimera_bridge_interop(
    security: ReverseSecurity,
    routing_user: Option<&str>,
) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let case_suffix = if routing_user.is_some() {
        "-routing-user"
    } else {
        ""
    };
    let work_dir = create_test_dir(&format!(
        "vless-reverse-chimera-bridge-{}{}",
        security.name(),
        case_suffix
    ));
    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    let (xray_stream, chimera_stream) = match security {
        ReverseSecurity::Raw => (
            json!({"network": "tcp", "security": "none"}),
            json!({"network": "tcp", "security": "none"}),
        ),
        ReverseSecurity::Tls => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            (
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }),
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "disableSystemRoot": true,
                        "certificates": [{
                            "certificateFile": cert_path,
                            "usage": "verify"
                        }]
                    }
                }),
            )
        }
        ReverseSecurity::Websocket => (
            json!({
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/reverse"}
            }),
            json!({
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/reverse"}
            }),
        ),
    };

    let reverse_bridge_outbound = json!({
        "tag": "reverse-bridge",
        "protocol": "vless",
        "settings": {
            "address": "127.0.0.1",
            "port": reverse_port,
            "id": TEST_UUID,
            "email": routing_user.unwrap_or(""),
            "encryption": "none",
            "reverse": {"tag": "bridge-in"}
        },
        "streamSettings": chimera_stream
    });
    let (mut chimera_outbounds, chimera_routing_rules) =
        if let Some(routing_user) = routing_user {
            (
                vec![
                    json!({"tag": "default-block", "protocol": "blackhole"}),
                    json!({"tag": "direct", "protocol": "freedom"}),
                ],
                vec![json!({
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "user": [routing_user],
                    "network": "tcp",
                    "outboundTag": "direct"
                })],
            )
        } else {
            (
                vec![json!({"tag": "direct", "protocol": "freedom"})],
                vec![json!({
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                })],
            )
        };
    chimera_outbounds.insert(0, reverse_bridge_outbound);

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "chimera-bridge@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": xray_stream
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-echo",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-echo"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [],
            "outbounds": chimera_outbounds,
            "routing": {
                "rules": chimera_routing_rules
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    chimera.assert_running();

    // Xray waits two seconds before its first Reverse monitor tick. Start
    // Chimera first and let that first dial fail so the successful path also
    // proves periodic retry rather than only startup ordering.
    std::thread::sleep(Duration::from_millis(2300));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    xray.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    let first_payload = format!(
        "chimera bridge through xray reverse portal ({})",
        security.name()
    );
    assert_reverse_echo_with_retry(
        public_addr,
        first_payload.as_bytes(),
        &echoed_bytes,
    );

    // Kill the Portal side and bring it back on the same ports. The physical
    // Reverse worker must observe EOF and the monitor must create a new worker.
    drop(xray);
    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(public_addr);
    xray.assert_running();

    let reconnect_payload = format!(
        "chimera bridge reconnect through xray reverse portal ({})",
        security.name()
    );
    assert_reverse_echo_with_retry(
        public_addr,
        reconnect_payload.as_bytes(),
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn run_reverse_interop(security: ReverseSecurity) {
    let workspace = workspace_root();
    let xray = xray_binary(&workspace);
    if !xray.is_file() {
        eprintln!(
            "skipping VLESS Reverse Xray interoperability test because {} is unavailable; set XRAY_BIN to enable it",
            xray.display()
        );
        return;
    }

    let _serial = serial_xray_guard();
    let work_dir = create_test_dir(&format!("vless-reverse-{}", security.name()));
    let (echo_addr, echoed_bytes) = start_observed_echo_server();
    let reverse_port = free_localhost_port();
    let public_port = free_localhost_port();
    let chimera_config = work_dir.join("chimera.json");
    let xray_config = work_dir.join("xray.json");

    let (chimera_stream, xray_stream) = match security {
        ReverseSecurity::Raw => (
            json!({
                "network": "tcp",
                "security": "none"
            }),
            json!({
                "network": "tcp",
                "security": "none"
            }),
        ),
        ReverseSecurity::Tls => {
            let (cert_path, key_path) = generate_test_certificate(&work_dir);
            let pinned_peer_cert_sha256 = first_cert_sha256_hex(&cert_path);
            (
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "certificates": [{
                            "certificateFile": cert_path,
                            "keyFile": key_path
                        }]
                    }
                }),
                json!({
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "localhost",
                        "pinnedPeerCertSha256": pinned_peer_cert_sha256
                    }
                }),
            )
        }
        ReverseSecurity::Websocket => {
            unreachable!("Portal-side WebSocket is not exercised here")
        }
    };

    write_json(
        &chimera_config,
        json!({
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": reverse_port,
                    "protocol": "vless",
                    "tag": "reverse-vless-in",
                    "settings": {
                        "clients": [{
                            "id": TEST_UUID,
                            "email": "reverse-bridge@example.test",
                            "reverse": {"tag": "reverse-out"}
                        }],
                        "decryption": "none"
                    },
                    "streamSettings": chimera_stream
                },
                {
                    "listen": "127.0.0.1",
                    "port": public_port,
                    "protocol": "dokodemo-door",
                    "tag": "public-echo",
                    "settings": {
                        "address": echo_addr.ip().to_string(),
                        "port": echo_addr.port(),
                        "network": "tcp",
                        "followRedirect": false
                    },
                    "streamSettings": {"network": "tcp"}
                }
            ],
            "outbounds": [{
                "tag": "direct",
                "protocol": "freedom"
            }],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["public-echo"],
                    "network": "tcp",
                    "outboundTag": "reverse-out"
                }]
            }
        }),
    );

    write_json(
        &xray_config,
        json!({
            "log": {"loglevel": "debug"},
            "outbounds": [
                {
                    "tag": "reverse-bridge",
                    "protocol": "vless",
                    "settings": {
                        "address": "127.0.0.1",
                        "port": reverse_port,
                        "id": TEST_UUID,
                        "encryption": "none",
                        "reverse": {"tag": "bridge-in"}
                    },
                    "streamSettings": xray_stream
                },
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        // Current Xray applies a default private-IP block to
                        // traffic originating from a VLESS inbound. The echo
                        // target is intentionally loopback, so allow it
                        // explicitly for this interoperability fixture.
                        "finalRules": [{
                            "action": "allow",
                            "network": "tcp",
                            "ip": ["127.0.0.0/8"]
                        }]
                    }
                }
            ],
            "routing": {
                "rules": [{
                    "type": "field",
                    "inboundTag": ["bridge-in"],
                    "network": "tcp",
                    "outboundTag": "direct"
                }]
            }
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, reverse_port)));
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, public_port)));
    chimera.assert_running();

    let mut xray = start_xray(&workspace, &work_dir, &xray_config);
    xray.assert_running();

    let public_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, public_port));
    assert_reverse_echo_with_retry(
        public_addr,
        format!(
            "xray bridge through chimera reverse portal ({})",
            security.name()
        )
        .as_bytes(),
        &echoed_bytes,
    );

    chimera.assert_running();
    xray.assert_running();
}

fn tls_client_hello_payload(server_name: &str) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default TLS protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let server_name =
        rustls::pki_types::ServerName::try_from(server_name.to_string())
            .expect("valid TLS sniffing server name");
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), server_name)
            .expect("create TLS sniffing client");
    let mut payload = Vec::new();
    connection
        .write_tls(&mut payload)
        .expect("serialize TLS ClientHello");
    assert!(!payload.is_empty(), "TLS ClientHello must not be empty");
    payload
}

fn free_localhost_udp_port() -> u16 {
    let socket =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind temporary UDP port");
    socket
        .local_addr()
        .expect("temporary UDP local address")
        .port()
}

fn assert_reverse_udp_echo_with_retry(
    public_addr: SocketAddr,
    payload: &[u8],
    echoed_bytes: &AtomicUsize,
) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let mut last_error = None;

    while Instant::now() < deadline {
        match reverse_udp_echo_once(public_addr, payload) {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    panic!(
        "VLESS Reverse UDP worker did not become usable at {public_addr}; target received {} bytes: {}",
        echoed_bytes.load(Ordering::SeqCst),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no UDP exchange completed".to_string())
    );
}

fn start_observed_udp_echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind observed Reverse UDP echo server");
    socket
        .set_read_timeout(Some(REVERSE_READY_TIMEOUT))
        .expect("set Reverse UDP echo timeout");
    let address = socket
        .local_addr()
        .expect("observed Reverse UDP echo address");
    let received = Arc::new(AtomicUsize::new(0));
    let received_worker = received.clone();

    std::thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        for _ in 0..32 {
            let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                break;
            };
            received_worker.fetch_add(length, Ordering::SeqCst);
            let _ = socket.send_to(&buffer[..length], peer);
        }
    });

    (address, received)
}

fn reverse_udp_echo_once(
    public_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.send_to(payload, public_addr)?;

    let mut response = vec![0u8; payload.len().max(1)];
    let (length, source) = socket.recv_from(&mut response)?;
    if source != public_addr {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Reverse UDP reply came from unexpected source {source}"),
        ));
    }
    response.truncate(length);
    if response != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse UDP echo payload mismatch",
        ));
    }

    Ok(())
}

fn assert_reverse_echo_with_retry(
    public_addr: SocketAddr,
    payload: &[u8],
    echoed_bytes: &AtomicUsize,
) {
    let deadline = Instant::now() + REVERSE_READY_TIMEOUT;
    let mut last_error = None;

    while Instant::now() < deadline {
        match reverse_echo_once(public_addr, payload) {
            Ok(()) => return,
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    panic!(
        "VLESS Reverse worker did not become usable at {public_addr}; target received {} bytes: {}",
        echoed_bytes.load(Ordering::SeqCst),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no connection attempt completed".to_string())
    );
}

fn start_proxy_protocol_echo_server() -> (SocketAddr, Arc<Mutex<Option<SocketAddr>>>)
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind Reverse PROXY protocol echo server");
    let address = listener
        .local_addr()
        .expect("Reverse PROXY protocol echo address");
    let captured_source = Arc::new(Mutex::new(None));
    let captured_worker = Arc::clone(&captured_source);

    std::thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let captured_source = Arc::clone(&captured_worker);
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

                let mut header = Vec::with_capacity(108);
                let mut byte = [0u8; 1];
                while header.len() < 108 {
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
                let fields =
                    header.trim_end().split_whitespace().collect::<Vec<_>>();
                if fields.len() != 6 || fields[0] != "PROXY" || fields[1] != "TCP4" {
                    return;
                }
                let Ok(source_ip) = fields[2].parse::<std::net::IpAddr>() else {
                    return;
                };
                let Ok(source_port) = fields[4].parse::<u16>() else {
                    return;
                };
                *captured_source
                    .lock()
                    .expect("PROXY protocol capture lock poisoned") =
                    Some(SocketAddr::new(source_ip, source_port));

                let mut payload = [0u8; 4096];
                if let Ok(length) = stream.read(&mut payload)
                    && length != 0
                {
                    let _ = stream.write_all(&payload[..length]);
                }
            });
        }
    });

    (address, captured_source)
}

fn reverse_echo_once_with_source(
    public_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<SocketAddr> {
    let mut stream = TcpStream::connect_timeout(&public_addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let source = stream.local_addr()?;
    stream.write_all(payload)?;

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response)?;
    if response != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse PROXY protocol echo payload mismatch",
        ));
    }
    Ok(source)
}

fn start_observed_echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind observed Reverse echo server");
    let address = listener
        .local_addr()
        .expect("observed Reverse echo address");
    let received = Arc::new(AtomicUsize::new(0));
    let received_worker = received.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming().take(32) {
            let Ok(mut stream) = stream else {
                continue;
            };
            let received = received_worker.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let mut buffer = [0u8; 4096];
                if let Ok(length) = stream.read(&mut buffer)
                    && length != 0
                {
                    received.fetch_add(length, Ordering::SeqCst);
                    let _ = stream.write_all(&buffer[..length]);
                }
            });
        }
    });

    (address, received)
}

fn reverse_echo_once(
    public_addr: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&public_addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(payload)?;

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response)?;
    if response != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Reverse echo payload mismatch",
        ));
    }
    Ok(())
}

fn generate_test_certificate(work_dir: &Path) -> (PathBuf, PathBuf) {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .expect("generate VLESS Reverse interoperability RSA key");
    let cert = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("build VLESS Reverse certificate params")
        .self_signed(&signing_key)
        .expect("generate VLESS Reverse test certificate");
    let cert_path = work_dir.join("cert.pem");
    let key_path = work_dir.join("key.pem");
    fs::write(&cert_path, cert.pem())
        .expect("write VLESS Reverse interoperability certificate");
    fs::write(&key_path, signing_key.serialize_pem())
        .expect("write VLESS Reverse interoperability private key");
    (cert_path, key_path)
}

fn first_cert_sha256_hex(cert_path: &Path) -> String {
    let cert_file =
        File::open(cert_path).expect("open VLESS Reverse pinned certificate");
    let first_cert = certs(&mut BufReader::new(cert_file))
        .next()
        .expect("VLESS Reverse certificate present")
        .expect("parse VLESS Reverse certificate");
    let bytes = digest(&SHA256, first_cert.as_ref());
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
