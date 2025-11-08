use std::net::SocketAddr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::debug;

#[inline]
pub fn new_tcp_socket(
    bind_interface: Option<String>,
    is_ipv6: bool,
) -> std::io::Result<tokio::net::TcpSocket> {
    let tcp_socket = if is_ipv6 {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };

    if let Some(_b) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tcp_socket.bind_device(Some(_b.as_bytes()))?;

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not find to device, unsupported platform.")
    }

    Ok(tcp_socket)
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    debug!("new_socket2_udp_socket");
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        panic!("Cannot support reuse sockets");
    }

    debug!("new_socket2_udp_socket 2");
    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    debug!("new_socket2_udp_socket 3");
    if let Some(bind_address) = bind_address {
        debug!("new_socket2_udp_socket 4 {:?}", bind_address);
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}
