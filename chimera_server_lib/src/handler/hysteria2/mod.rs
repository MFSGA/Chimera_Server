#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

use socket2::SockAddr;

// use congestion::BrutalConfig;
use congestion::BrutalConfig;
use connection::process_hysteria2_connection;

#[cfg(target_os = "linux")]
use crate::util::socket::{
    configure_ip_transparent, configure_socket_mark, enable_udp_original_destination,
};
use crate::{
    config::server_config::{Hysteria2QuicParams, Hysteria2ServerConfig},
    runtime::RuntimeState,
    util::socket::new_socket2_udp_socket_with_buffer_size,
};

mod congestion;
pub mod connection;

const MAX_QUIC_ENDPOINTS: usize = 1;
const DEFAULT_MAX_IDLE_TIMEOUT_SECS: u64 = 30;
const SHOES_MAX_INCOMING_BIDI_STREAMS: u64 = 4096;
const SHOES_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Hysteria2ListenerOptions {
    pub(crate) socket_mark: Option<i32>,
    pub(crate) transparent: bool,
    pub(crate) receive_original_destination: bool,
    pub(crate) ipv6_only: bool,
}

fn create_hysteria2_listener_socket(
    bind_address: SocketAddr,
    options: Hysteria2ListenerOptions,
) -> std::io::Result<socket2::Socket> {
    let socket = new_socket2_udp_socket_with_buffer_size(
        bind_address.is_ipv6(),
        None,
        None,
        true,
        Some(8_625_000),
    )?;

    #[cfg(target_os = "linux")]
    if let Some(mark) = options.socket_mark {
        configure_socket_mark(socket.as_raw_fd(), mark)?;
    }

    #[cfg(not(target_os = "linux"))]
    if options.socket_mark.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hysteria2 socket mark is currently supported only on Linux",
        ));
    }

    #[cfg(target_os = "linux")]
    if options.transparent {
        configure_ip_transparent(socket.as_raw_fd())?;
    }

    #[cfg(not(target_os = "linux"))]
    if options.transparent {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hysteria2 transparent socket is currently supported only on Linux",
        ));
    }

    #[cfg(target_os = "linux")]
    if options.receive_original_destination {
        enable_udp_original_destination(&socket, bind_address.is_ipv6())?;
    }

    #[cfg(not(target_os = "linux"))]
    if options.receive_original_destination {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hysteria2 original destination is currently supported only on Linux",
        ));
    }

    if options.ipv6_only {
        socket.set_only_v6(true)?;
    }

    socket.bind(&SockAddr::from(bind_address))?;
    Ok(socket)
}

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    config: Hysteria2ServerConfig,
    listener_options: Hysteria2ListenerOptions,
    inbound_tag: String,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let resolver = runtime.resolver();

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
        server_config.try_into().map_err(std::io::Error::other)?;

    let quic_server_config = Arc::new(quic_server_config);

    let endpoints_len = MAX_QUIC_ENDPOINTS;
    let config = Arc::new(config);

    let mut join_handles = Vec::with_capacity(endpoints_len);

    for _ in 0..endpoints_len {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let config = config.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();

        let base_transport = build_transport_config(&config.quic_params)?;
        let mut base_server_config =
            quinn::ServerConfig::with_crypto(quic_server_config);
        base_server_config.transport_config(Arc::new(base_transport));

        let socket2_socket =
            create_hysteria2_listener_socket(bind_address, listener_options)?;

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(base_server_config.clone()),
            socket2_socket.into(),
            Arc::new(quinn::TokioRuntime),
        )?;

        let join_handle = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let cloned_resolver = resolver.clone();
                let config = config.clone();
                let inbound_tag = inbound_tag.clone();
                let runtime = runtime.clone();
                let tx_bps = Arc::new(AtomicU64::new(0));

                let mut transport = match build_transport_config(&config.quic_params)
                {
                    Ok(transport) => transport,
                    Err(err) => {
                        tracing::error!(
                            "Failed to configure hysteria2 transport: {}",
                            err
                        );
                        return;
                    }
                };

                transport.congestion_controller_factory(Arc::new(
                    BrutalConfig::new(tx_bps.clone()),
                ));

                let mut server_config = base_server_config.clone();
                server_config.transport_config(Arc::new(transport));

                tokio::spawn(async move {
                    let connecting =
                        match incoming.accept_with(Arc::new(server_config)) {
                            Ok(connecting) => connecting,
                            Err(err) => {
                                tracing::error!(
                                    "Failed to accept hysteria2 connection: {}",
                                    err
                                );
                                return;
                            }
                        };

                    let connection = match connecting.await {
                        Ok(connection) => connection,
                        Err(err) => {
                            tracing::error!(
                                "Failed to establish hysteria2 connection: {}",
                                err
                            );
                            return;
                        }
                    };

                    if let Err(e) = process_hysteria2_connection(
                        cloned_resolver,
                        config,
                        tx_bps,
                        connection,
                        Arc::new(inbound_tag),
                        runtime,
                    )
                    .await
                    {
                        tracing::error!("Connection ended with error: {}", e);
                    }
                });
            }
        });
        join_handles.push(join_handle);
    }

    for join_handle in join_handles {
        join_handle.await.map_err(std::io::Error::other)?;
    }
    Ok(())
}

fn configured_max_idle_timeout(params: &Hysteria2QuicParams) -> Duration {
    Duration::from_secs(if params.max_idle_timeout == 0 {
        DEFAULT_MAX_IDLE_TIMEOUT_SECS
    } else {
        params.max_idle_timeout
    })
}

fn configured_max_incoming_streams(
    params: &Hysteria2QuicParams,
) -> std::io::Result<quinn::VarInt> {
    let value = if params.max_incoming_streams == 0 {
        SHOES_MAX_INCOMING_BIDI_STREAMS
    } else {
        params.max_incoming_streams
    };
    quinn::VarInt::from_u64(value)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
}

fn configured_mtu_discovery(
    params: &Hysteria2QuicParams,
) -> Option<quinn::MtuDiscoveryConfig> {
    (!params.disable_path_mtu_discovery).then(quinn::MtuDiscoveryConfig::default)
}

fn build_transport_config(
    params: &Hysteria2QuicParams,
) -> std::io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = configured_max_idle_timeout(params)
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let max_incoming_streams = configured_max_incoming_streams(params)?;
    let mtu_discovery = configured_mtu_discovery(params);
    transport
        .max_concurrent_bidi_streams(max_incoming_streams)
        // Hysteria2 uses HTTP/3, so keep enough uni streams for QPACK/control updates.
        .max_concurrent_uni_streams(1024_u32.into())
        .max_idle_timeout(Some(idle_timeout))
        // Xray validates keepAlivePeriod but its Hysteria2 server listener does
        // not apply it. Keep Shoes' fixed server keepalive behavior here.
        .keep_alive_interval(Some(SHOES_KEEP_ALIVE_INTERVAL))
        .send_window(16 * 1024 * 1024)
        .receive_window((20u32 * 1024 * 1024).into())
        .stream_receive_window((8u32 * 1024 * 1024).into())
        .initial_mtu(1200)
        .min_mtu(1200)
        .mtu_discovery_config(mtu_discovery)
        .enable_segmentation_offload(true)
        .initial_rtt(Duration::from_millis(100));
    Ok(transport)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        os::fd::AsRawFd,
    };

    use super::*;

    #[test]
    fn quic_idle_timeout_uses_xray_default_and_override() {
        assert_eq!(
            configured_max_idle_timeout(&Hysteria2QuicParams::default()),
            Duration::from_secs(30)
        );
        assert_eq!(
            configured_max_idle_timeout(&Hysteria2QuicParams {
                max_idle_timeout: 7,
                keep_alive_period: 11,
                ..Hysteria2QuicParams::default()
            }),
            Duration::from_secs(7)
        );
    }

    #[test]
    fn quic_stream_limit_and_mtu_discovery_apply_explicit_params() {
        let default = Hysteria2QuicParams::default();
        assert_eq!(
            configured_max_incoming_streams(&default)
                .expect("default stream limit")
                .into_inner(),
            4096
        );
        assert!(configured_mtu_discovery(&default).is_some());

        let configured = Hysteria2QuicParams {
            max_incoming_streams: 8,
            disable_path_mtu_discovery: true,
            ..Hysteria2QuicParams::default()
        };
        assert_eq!(
            configured_max_incoming_streams(&configured)
                .expect("configured stream limit")
                .into_inner(),
            8
        );
        assert!(configured_mtu_discovery(&configured).is_none());
    }

    #[test]
    fn marked_listener_applies_so_mark() {
        let socket = match create_hysteria2_listener_socket(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Hysteria2ListenerOptions {
                socket_mark: Some(255),
                ..Hysteria2ListenerOptions::default()
            },
        ) {
            Ok(socket) => socket,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EPERM | libc::EACCES)
                ) =>
            {
                return;
            }
            Err(error) => panic!("create marked hysteria2 listener: {error}"),
        };

        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(value, 255);
    }

    #[test]
    fn transparent_listener_applies_ip_transparent() {
        let socket = match create_hysteria2_listener_socket(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Hysteria2ListenerOptions {
                transparent: true,
                ..Hysteria2ListenerOptions::default()
            },
        ) {
            Ok(socket) => socket,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EPERM | libc::EACCES)
                ) =>
            {
                return;
            }
            Err(error) => panic!("create transparent hysteria2 listener: {error}"),
        };

        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(value, 1);
    }

    #[test]
    fn original_destination_listener_applies_recv_origdstaddr() {
        let socket = create_hysteria2_listener_socket(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            Hysteria2ListenerOptions {
                receive_original_destination: true,
                ..Hysteria2ListenerOptions::default()
            },
        )
        .expect("create original-destination hysteria2 listener");
        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(value, 1);
    }

    #[test]
    fn ipv6_only_listener_applies_ipv6_v6only() {
        let socket = create_hysteria2_listener_socket(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            Hysteria2ListenerOptions {
                ipv6_only: true,
                ..Hysteria2ListenerOptions::default()
            },
        )
        .expect("create IPv6-only hysteria2 listener");

        let mut value = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: `value` and `length` are valid writable getsockopt buffers.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(value, 1);
    }
}
