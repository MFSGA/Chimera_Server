use std::{net::SocketAddr, sync::Arc};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use tokio::net::UdpSocket;

#[cfg(target_os = "linux")]
use crate::util::socket::enable_udp_original_destination;
use crate::{
    address::BindLocation, config::server_config::TcpSocketPolicy,
    util::socket::new_socket2_udp_socket,
};

mod listener;
pub(crate) use listener::start_udp_server;

pub(crate) fn bind_location_to_socket_addr(
    bind_location: &BindLocation,
) -> std::io::Result<SocketAddr> {
    match bind_location {
        BindLocation::Address(location) => location.to_socket_addr(),
    }
}

pub(crate) fn create_udp_listener(
    bind_addr: SocketAddr,
    policy: Option<&TcpSocketPolicy>,
    force_original_destination: bool,
) -> std::io::Result<Arc<UdpSocket>> {
    let bind_interface = policy.and_then(|policy| policy.bind_interface.clone());
    let socket =
        new_socket2_udp_socket(bind_addr.is_ipv6(), bind_interface, None, true)?;

    if policy.is_some_and(|policy| policy.ipv6_only) {
        if !bind_addr.is_ipv6() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sockopt.v6only requires an IPv6 UDP listener",
            ));
        }
        socket.set_only_v6(true)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(policy) = policy {
        let fd = socket.as_raw_fd();
        if let Some(mark) = policy.mark {
            crate::util::socket::configure_socket_mark(fd, mark)?;
        }
        if policy.transparent {
            crate::util::socket::configure_ip_transparent(fd)?;
        }
        crate::util::socket::configure_custom_sockopt(
            fd,
            if bind_addr.is_ipv6() { "udp6" } else { "udp4" },
            &policy.custom_sockopt,
        )?;
    }

    #[cfg(not(target_os = "linux"))]
    if policy.is_some_and(|policy| {
        policy.mark.is_some()
            || policy.transparent
            || !policy.custom_sockopt.is_empty()
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "configured inbound UDP listener socket options are unsupported on this platform",
        ));
    }

    let receive_original_destination = force_original_destination
        || policy.is_some_and(|policy| policy.receive_original_destination);
    if receive_original_destination {
        #[cfg(target_os = "linux")]
        enable_udp_original_destination(&socket, bind_addr.is_ipv6())?;
        #[cfg(not(target_os = "linux"))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP original destination is supported only on Linux",
        ));
    }

    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(Arc::new(UdpSocket::from_std(socket)?))
}
