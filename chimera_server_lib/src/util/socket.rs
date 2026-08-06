use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::{
    io,
    mem::{self, MaybeUninit},
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, RawFd},
    ptr,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

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
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux"
        ))]
        tcp_socket.bind_device(Some(_b.as_bytes()))?;

        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux"
        )))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "binding a TCP socket to an interface is not supported on this platform",
        ));
    }

    Ok(tcp_socket)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn configure_tcp_keepalive(
    fd: std::os::fd::RawFd,
    idle_secs: i32,
    interval_secs: i32,
) -> std::io::Result<()> {
    let enabled = i32::from(idle_secs > 0 || interval_secs > 0);
    set_socket_option_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, enabled)?;
    if enabled == 0 {
        return Ok(());
    }
    if idle_secs > 0 {
        set_socket_option_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, idle_secs)?;
    }
    if interval_secs > 0 {
        set_socket_option_int(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            interval_secs,
        )?;
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn set_socket_option_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    // SAFETY: `fd` is borrowed for this call and `value` is a valid integer
    // socket-option payload for the full duration of `setsockopt`.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    new_socket2_udp_socket_with_buffer_size(
        is_ipv6,
        bind_interface,
        bind_address,
        reuse_port,
        None,
    )
}

pub fn new_socket2_udp_socket_with_buffer_size(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    // Set socket buffer sizes if specified.
    // This helps prevent packet drops during bursts for high-throughput connections.
    if let Some(size) = buffer_size {
        // Ignore errors - kernel may cap the value
        let _ = socket.set_recv_buffer_size(size);
        let _ = socket.set_send_buffer_size(size);
    }

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP reuse-port is not supported on this platform",
        ));
    }

    if let Some(ref _interface) = bind_interface {
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux"
        ))]
        socket.bind_device(Some(_interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux"
        )))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "binding a UDP socket to an interface is not supported on this platform",
        ));
    }

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

#[cfg(target_os = "linux")]
pub fn enable_udp_original_destination(
    socket: &Socket,
    is_ipv6: bool,
) -> io::Result<()> {
    let (level, option) = if is_ipv6 {
        (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR)
    } else {
        (libc::SOL_IP, libc::IP_RECVORIGDSTADDR)
    };
    let enabled: libc::c_int = 1;
    // SAFETY: the file descriptor belongs to `socket`; `enabled` is a valid
    // integer socket-option payload for the duration of this call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            ptr::from_ref(&enabled).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn recv_udp_with_original_destination(
    socket: &tokio::net::UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    socket
        .async_io(tokio::io::Interest::READABLE, || {
            recv_udp_with_original_destination_once(socket.as_raw_fd(), buffer)
        })
        .await
}

#[cfg(target_os = "linux")]
fn recv_udp_with_original_destination_once(
    fd: RawFd,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut control = [MaybeUninit::<u8>::uninit(); 128];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = ptr::from_mut(&mut source).cast();
    message.msg_namelen =
        mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_iov = ptr::from_mut(&mut iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() as _;

    // SAFETY: all pointers in `message` refer to live writable storage above.
    let length = unsafe { libc::recvmsg(fd, &mut message, 0) };
    if length == -1 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP original-destination control message was truncated",
        ));
    }

    let source_addr = socket_addr_from_storage(&source, message.msg_namelen)?;
    let original_destination = original_destination_from_message(&message)?;
    Ok((length as usize, source_addr, original_destination))
}

#[cfg(target_os = "linux")]
fn socket_addr_from_storage(
    storage: &libc::sockaddr_storage,
    length: libc::socklen_t,
) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET if length as usize >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: family and length establish a valid sockaddr_in layout.
            let address =
                unsafe { &*(ptr::from_ref(storage).cast::<libc::sockaddr_in>()) };
            Ok(socket_addr_from_v4(address))
        }
        libc::AF_INET6
            if length as usize >= mem::size_of::<libc::sockaddr_in6>() =>
        {
            // SAFETY: family and length establish a valid sockaddr_in6 layout.
            let address =
                unsafe { &*(ptr::from_ref(storage).cast::<libc::sockaddr_in6>()) };
            Ok(socket_addr_from_v6(address))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("UDP recvmsg returned unsupported address family {family}"),
        )),
    }
}

#[cfg(target_os = "linux")]
fn original_destination_from_message(
    message: &libc::msghdr,
) -> io::Result<SocketAddr> {
    // SAFETY: CMSG_LEN only performs alignment arithmetic for these fixed
    // payload sizes and does not dereference pointers.
    let (ipv4_control_len, ipv6_control_len) = unsafe {
        (
            libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in>() as u32) as usize,
            libc::CMSG_LEN(mem::size_of::<libc::sockaddr_in6>() as u32) as usize,
        )
    };
    // SAFETY: `message` was populated by recvmsg and remains valid while its
    // control buffer is alive in the caller.
    let mut control = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !control.is_null() {
        // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR only return headers within message.
        let header = unsafe { &*control };
        if header.cmsg_level == libc::SOL_IP
            && header.cmsg_type == libc::IP_ORIGDSTADDR
            && (header.cmsg_len as usize) >= ipv4_control_len
        {
            // SAFETY: the length check guarantees a complete sockaddr_in.
            let address = unsafe {
                ptr::read_unaligned(
                    libc::CMSG_DATA(control).cast::<libc::sockaddr_in>(),
                )
            };
            return Ok(socket_addr_from_v4(&address));
        }
        if header.cmsg_level == libc::SOL_IPV6
            && header.cmsg_type == libc::IPV6_ORIGDSTADDR
            && (header.cmsg_len as usize) >= ipv6_control_len
        {
            // SAFETY: the length check guarantees a complete sockaddr_in6.
            let address = unsafe {
                ptr::read_unaligned(
                    libc::CMSG_DATA(control).cast::<libc::sockaddr_in6>(),
                )
            };
            return Ok(socket_addr_from_v6(&address));
        }
        // SAFETY: `control` came from this message and remains within it.
        control = unsafe { libc::CMSG_NXTHDR(message, control) };
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "UDP original destination is unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn socket_addr_from_v4(address: &libc::sockaddr_in) -> SocketAddr {
    SocketAddr::new(
        Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)).into(),
        u16::from_be(address.sin_port),
    )
}

#[cfg(target_os = "linux")]
fn socket_addr_from_v6(address: &libc::sockaddr_in6) -> SocketAddr {
    SocketAddr::V6(std::net::SocketAddrV6::new(
        Ipv6Addr::from(address.sin6_addr.s6_addr),
        u16::from_be(address.sin6_port),
        address.sin6_flowinfo,
        address.sin6_scope_id,
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod original_destination_tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use tokio::{net::UdpSocket, time::timeout};

    use super::*;

    fn tokio_udp_socket(socket: Socket) -> UdpSocket {
        let socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(socket).expect("convert nonblocking UDP socket")
    }

    #[tokio::test]
    async fn recvmsg_returns_source_and_original_destination() {
        let socket = new_socket2_udp_socket(
            false,
            None,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            false,
        )
        .expect("bind original-destination UDP socket");
        enable_udp_original_destination(&socket, false)
            .expect("enable IP_RECVORIGDSTADDR");
        let listener_addr = socket
            .local_addr()
            .expect("read UDP listener address")
            .as_socket()
            .expect("UDP listener must use IP address");
        let listener = tokio_udp_socket(socket);
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP client");
        let client_addr = client.local_addr().expect("read UDP client address");
        client
            .send_to(b"original-dst", listener_addr)
            .await
            .expect("send UDP test datagram");

        let mut buffer = [0u8; 64];
        let (length, source, original_destination) = timeout(
            Duration::from_secs(1),
            recv_udp_with_original_destination(&listener, &mut buffer),
        )
        .await
        .expect("original-destination receive timed out")
        .expect("receive UDP original destination");

        assert_eq!(&buffer[..length], b"original-dst");
        assert_eq!(source, client_addr);
        assert_eq!(original_destination, listener_addr);
    }

    #[tokio::test]
    async fn recvmsg_returns_ipv6_original_destination() {
        let socket = match new_socket2_udp_socket(
            true,
            None,
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))),
            false,
        ) {
            Ok(socket) => socket,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return;
            }
            Err(error) => panic!("bind IPv6 original-destination socket: {error}"),
        };
        enable_udp_original_destination(&socket, true)
            .expect("enable IPV6_RECVORIGDSTADDR");
        let listener_addr = socket
            .local_addr()
            .expect("read IPv6 UDP listener address")
            .as_socket()
            .expect("IPv6 UDP listener must use IP address");
        let listener = tokio_udp_socket(socket);
        let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .expect("bind IPv6 UDP client");
        let client_addr = client.local_addr().expect("read IPv6 UDP client address");
        client
            .send_to(b"ipv6-original-dst", listener_addr)
            .await
            .expect("send IPv6 UDP test datagram");

        let mut buffer = [0u8; 64];
        let (length, source, original_destination) = timeout(
            Duration::from_secs(1),
            recv_udp_with_original_destination(&listener, &mut buffer),
        )
        .await
        .expect("IPv6 original-destination receive timed out")
        .expect("receive IPv6 UDP original destination");

        assert_eq!(&buffer[..length], b"ipv6-original-dst");
        assert_eq!(source, client_addr);
        assert_eq!(original_destination, listener_addr);
    }

    #[tokio::test]
    async fn recvmsg_without_socket_option_reports_missing_original_destination() {
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP socket without original-destination option");
        let listener_addr =
            listener.local_addr().expect("read UDP listener address");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind UDP client");
        client
            .send_to(b"no-option", listener_addr)
            .await
            .expect("send UDP test datagram");

        let mut buffer = [0u8; 64];
        let error = timeout(
            Duration::from_secs(1),
            recv_udp_with_original_destination(&listener, &mut buffer),
        )
        .await
        .expect("missing-option receive timed out")
        .expect_err("missing original-destination option must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }
}
