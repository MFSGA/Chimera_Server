use std::net::IpAddr;

use crate::routing_state::RoutingInput;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessMetadata {
    pid: u32,
    name: String,
    path: String,
}

pub(crate) async fn enrich_routing_input(input: &mut RoutingInput) {
    if input.process_id != 0
        || !input.process_name.is_empty()
        || !input.process_path.is_empty()
    {
        return;
    }
    let Some(source_ip) = input.source_ips.iter().find_map(|value| decode_ip(value))
    else {
        return;
    };
    let Ok(source_port) = u16::try_from(input.source_port) else {
        return;
    };
    if source_port == 0 || !matches!(input.network, 2 | 3) {
        return;
    }
    let network = input.network;
    let metadata = tokio::task::spawn_blocking(move || {
        find_process(network, source_ip, source_port)
    })
    .await
    .ok()
    .flatten();
    let Some(metadata) = metadata else {
        return;
    };
    input.process_id = metadata.pid;
    input.process_name = metadata.name;
    input.process_path = metadata.path;
}

fn decode_ip(input: &[u8]) -> Option<IpAddr> {
    match input {
        [a, b, c, d] => Some(IpAddr::from([*a, *b, *c, *d])),
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => Some(IpAddr::from([
            *a, *b, *c, *d, *e, *f, *g, *h, *i, *j, *k, *l, *m, *n, *o, *p,
        ])),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn find_process(
    network: i32,
    source_ip: IpAddr,
    source_port: u16,
) -> Option<ProcessMetadata> {
    let proc_file = match (network, source_ip) {
        (2, IpAddr::V4(_)) => "/proc/net/tcp",
        (2, IpAddr::V6(_)) => "/proc/net/tcp6",
        (3, IpAddr::V4(_)) => "/proc/net/udp",
        (3, IpAddr::V6(_)) => "/proc/net/udp6",
        _ => return None,
    };
    let address = format_proc_address(source_ip, source_port);
    let inode = find_socket_inode(proc_file, &address)?;
    find_process_by_inode(&inode)
}

#[cfg(not(target_os = "linux"))]
fn find_process(
    _network: i32,
    _source_ip: IpAddr,
    _source_port: u16,
) -> Option<ProcessMetadata> {
    None
}

#[cfg(target_os = "linux")]
fn format_proc_address(ip: IpAddr, port: u16) -> String {
    let bytes = match ip {
        IpAddr::V4(ip) => {
            let mut bytes = ip.octets().to_vec();
            bytes.reverse();
            bytes
        }
        IpAddr::V6(ip) => {
            let mut bytes = ip.octets().to_vec();
            for word in bytes.as_chunks_mut::<4>().0 {
                word.reverse();
            }
            bytes
        }
    };
    let mut encoded = String::with_capacity(bytes.len() * 2 + 5);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02X}");
    }
    use std::fmt::Write as _;
    let _ = write!(encoded, ":{port:04X}");
    encoded
}

#[cfg(target_os = "linux")]
fn find_socket_inode(path: &str, address: &str) -> Option<String> {
    use std::io::BufRead as _;

    let file = std::fs::File::open(path).ok()?;
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 10 && fields[1].eq_ignore_ascii_case(address) {
            return Some(fields[9].to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_process_by_inode(inode: &str) -> Option<ProcessMetadata> {
    let expected = format!("socket:[{inode}]");
    for process in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(file_type) = process.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let pid_text = process.file_name();
        let Some(pid_text) = pid_text.to_str() else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        let fd_dir = process.path().join("fd");
        let Ok(entries) = std::fs::read_dir(fd_dir) else {
            continue;
        };
        let owns_socket = entries.flatten().any(|entry| {
            std::fs::read_link(entry.path())
                .ok()
                .is_some_and(|target| target == std::path::Path::new(&expected))
        });
        if !owns_socket {
            continue;
        }
        let path = std::fs::read_link(process.path().join("exe")).ok()?;
        let name = path.file_name()?.to_string_lossy().into_owned();
        return Some(ProcessMetadata {
            pid,
            name,
            path: path.to_string_lossy().replace('\\', "/"),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_address_matches_linux_ipv4_layout() {
        assert_eq!(
            format_proc_address("127.0.0.1".parse().unwrap(), 1080),
            "0100007F:0438"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_address_matches_linux_ipv6_word_layout() {
        assert_eq!(
            format_proc_address("::1".parse().unwrap(), 1080),
            "00000000000000000000000001000000:0438"
        );
        assert_eq!(
            format_proc_address("2001:db8::1".parse().unwrap(), 443),
            "B80D0120000000000000000001000000:01BB"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_current_process_for_an_open_tcp_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind process lookup listener");
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap())
            .expect("connect process lookup client");
        let (_server, _) = listener.accept().expect("accept process lookup client");
        let source = client.local_addr().expect("read client local address");

        let metadata = find_process(2, source.ip(), source.port())
            .expect("current process socket should be discoverable");

        assert_eq!(metadata.pid, std::process::id());
        assert!(!metadata.name.is_empty());
        assert!(!metadata.path.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_current_process_for_an_open_ipv6_tcp_socket() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            return;
        };
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap())
            .expect("connect IPv6 process lookup client");
        let (_server, _) = listener
            .accept()
            .expect("accept IPv6 process lookup client");
        let source = client.local_addr().expect("read IPv6 client local address");

        let metadata = find_process(2, source.ip(), source.port())
            .expect("current IPv6 process socket should be discoverable");

        assert_eq!(metadata.pid, std::process::id());
        assert!(!metadata.name.is_empty());
        assert!(!metadata.path.is_empty());
    }
}
