use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

use congestion::BrutalConfig;
use connection::{build_xray_proxy_transport, process_hysteria2_connection};
use quinn::congestion::{BbrConfig, NewRenoConfig};

use crate::{
    config::server_config::Hysteria2ServerConfig,
    resolver::{NativeResolver, Resolver},
    runtime::RuntimeState,
    util::socket::new_socket2_udp_socket_with_buffer_size,
};

mod congestion;
pub mod connection;

const MAX_QUIC_ENDPOINTS: usize = 1;
const SHOES_MAX_INCOMING_UNI_STREAMS: u32 = 1024;
const XRAY_MAX_INCOMING_UNI_STREAMS: u32 = 100;
const SHOES_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const SHOES_SEND_WINDOW: u64 = 16 * 1024 * 1024;
const SHOES_INITIAL_RTT: Duration = Duration::from_millis(100);
const SHOES_UDP_SOCKET_BUFFER_SIZE: usize = 8_625_000;
const SHOES_INITIAL_MTU: u16 = 1200;
const XRAY_INITIAL_MTU: u16 = 1280;
const XRAY_ASSUME_PEER_MAX_DATAGRAM_FRAME_SIZE: u32 = 1200;
const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
const DEFAULT_CONNECTION_RECEIVE_WINDOW: u64 = 20 * 1024 * 1024;

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    config: Hysteria2ServerConfig,
    inbound_tag: String,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig =
        server_config.try_into().map_err(std::io::Error::other)?;

    let quic_server_config = Arc::new(quic_server_config);
    let xray_proxy_transport =
        build_xray_proxy_transport(config.xray_masquerade_proxy.as_ref())?;

    let endpoints_len = MAX_QUIC_ENDPOINTS;
    let config = Arc::new(config);

    let mut join_handles = Vec::with_capacity(endpoints_len);

    for _ in 0..endpoints_len {
        let quic_server_config = quic_server_config.clone();
        let resolver = resolver.clone();
        let config = config.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();
        let xray_proxy_transport = xray_proxy_transport.clone();

        let base_transport = build_transport_config(config.as_ref())?;
        let mut base_server_config =
            quinn::ServerConfig::with_crypto(quic_server_config);
        // Xray disables its QUIC path manager, while shoes leaves Quinn's
        // default migration support enabled.
        base_server_config
            .migration(configured_server_migration(config.xray_compat));
        base_server_config.transport_config(Arc::new(base_transport));

        let socket2_socket = new_socket2_udp_socket_with_buffer_size(
            bind_address.is_ipv6(),
            None,
            Some(bind_address),
            false,
            configured_udp_socket_buffer_size(config.xray_compat),
        )?;

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
                let xray_proxy_transport = xray_proxy_transport.clone();
                let tx_bps = Arc::new(AtomicU64::new(0));

                let mut transport = match build_transport_config(config.as_ref()) {
                    Ok(transport) => transport,
                    Err(err) => {
                        tracing::error!(
                            "Failed to configure hysteria2 transport: {}",
                            err
                        );
                        return;
                    }
                };

                match configured_congestion_mode(
                    config.xray_compat,
                    config.xray_congestion.as_deref(),
                ) {
                    CongestionMode::Cubic => {}
                    CongestionMode::Reno => {
                        transport.congestion_controller_factory(Arc::new(
                            NewRenoConfig::default(),
                        ));
                    }
                    CongestionMode::Brutal => {
                        transport.congestion_controller_factory(Arc::new(
                            BrutalConfig::new(tx_bps.clone()),
                        ));
                    }
                    CongestionMode::Bbr => {
                        transport.congestion_controller_factory(Arc::new(
                            BbrConfig::default(),
                        ));
                    }
                }

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
                        xray_proxy_transport,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CongestionMode {
    Cubic,
    Bbr,
    Reno,
    Brutal,
}

fn configured_congestion_mode(
    xray_compat: bool,
    mode: Option<&str>,
) -> CongestionMode {
    match mode {
        Some("reno") => CongestionMode::Reno,
        Some("") | Some("brutal") | Some("force-brutal") => CongestionMode::Brutal,
        Some("bbr") => CongestionMode::Bbr,
        None if xray_compat => CongestionMode::Bbr,
        None => CongestionMode::Cubic,
        Some(_) => unreachable!("validated Xray congestion mode"),
    }
}

fn build_transport_config(
    config: &Hysteria2ServerConfig,
) -> std::io::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = Duration::from_secs(configured_max_idle_timeout_secs(
        config.xray_max_idle_timeout_secs,
    ))
    .try_into()
    .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let max_bidi_streams =
        quinn::VarInt::from_u64(configured_max_incoming_bidi_streams(
            config.xray_compat,
            config.xray_max_incoming_streams,
        ))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let max_uni_streams = configured_max_incoming_uni_streams(config.xray_compat);
    let keep_alive_interval = configured_keep_alive_interval(
        config.xray_compat,
        config.xray_keep_alive_period_secs,
    );
    // Quinn has a single static receive window rather than quic-go's separate
    // initial/max auto-tuned windows. Apply Xray's max values as the closest
    // runtime equivalent; the initial values remain validated/preserved in config.
    let stream_receive_window = configured_receive_window(
        config.xray_max_stream_receive_window,
        DEFAULT_STREAM_RECEIVE_WINDOW,
    )?;
    let connection_receive_window = configured_receive_window(
        config.xray_max_connection_receive_window,
        DEFAULT_CONNECTION_RECEIVE_WINDOW,
    )?;
    if let Some(send_window) = configured_send_window(config.xray_compat) {
        transport.send_window(send_window);
    }
    if let Some(initial_rtt) = configured_initial_rtt(config.xray_compat) {
        transport.initial_rtt(initial_rtt);
    }
    transport.max_datagram_frame_size(configured_max_datagram_frame_size(
        config.xray_compat,
    ));
    transport.assume_peer_max_datagram_frame_size(
        configured_assume_peer_max_datagram_frame_size(config.xray_compat),
    );
    transport
        .max_concurrent_bidi_streams(max_bidi_streams)
        .max_concurrent_uni_streams(max_uni_streams)
        .keep_alive_interval(keep_alive_interval)
        .stream_receive_window(stream_receive_window)
        .receive_window(connection_receive_window)
        .initial_mtu(configured_initial_mtu(config.xray_compat))
        .min_mtu(SHOES_INITIAL_MTU)
        .mtu_discovery_config(configured_mtu_discovery(
            config.xray_disable_path_mtu_discovery,
        ))
        .max_idle_timeout(Some(idle_timeout));
    Ok(transport)
}

fn configured_server_migration(xray_compat: bool) -> bool {
    !xray_compat
}

fn configured_max_idle_timeout_secs(configured: Option<u64>) -> u64 {
    configured.unwrap_or(30)
}

fn configured_max_incoming_bidi_streams(
    xray_compat: bool,
    configured: Option<u64>,
) -> u64 {
    configured.unwrap_or(if xray_compat { 1024 } else { 4096 })
}

fn configured_max_incoming_uni_streams(xray_compat: bool) -> quinn::VarInt {
    if xray_compat {
        XRAY_MAX_INCOMING_UNI_STREAMS.into()
    } else {
        SHOES_MAX_INCOMING_UNI_STREAMS.into()
    }
}

fn configured_keep_alive_interval(
    xray_compat: bool,
    configured: Option<u64>,
) -> Option<Duration> {
    if xray_compat {
        configured
            .filter(|period| *period != 0)
            .map(Duration::from_secs)
    } else {
        Some(SHOES_KEEP_ALIVE_INTERVAL)
    }
}

fn configured_send_window(xray_compat: bool) -> Option<u64> {
    (!xray_compat).then_some(SHOES_SEND_WINDOW)
}

fn configured_initial_rtt(xray_compat: bool) -> Option<Duration> {
    (!xray_compat).then_some(SHOES_INITIAL_RTT)
}

fn configured_udp_socket_buffer_size(xray_compat: bool) -> Option<usize> {
    (!xray_compat).then_some(SHOES_UDP_SOCKET_BUFFER_SIZE)
}

fn configured_max_datagram_frame_size(xray_compat: bool) -> Option<quinn::VarInt> {
    xray_compat.then_some(XRAY_ASSUME_PEER_MAX_DATAGRAM_FRAME_SIZE.into())
}

fn configured_assume_peer_max_datagram_frame_size(
    xray_compat: bool,
) -> Option<quinn::VarInt> {
    xray_compat.then_some(XRAY_ASSUME_PEER_MAX_DATAGRAM_FRAME_SIZE.into())
}

fn configured_mtu_discovery(
    disable_path_mtu_discovery: Option<bool>,
) -> Option<quinn::MtuDiscoveryConfig> {
    let platform_supports_path_mtu_discovery = cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    ));
    if disable_path_mtu_discovery == Some(true)
        || !platform_supports_path_mtu_discovery
    {
        None
    } else {
        Some(quinn::MtuDiscoveryConfig::default())
    }
}

fn configured_initial_mtu(xray_compat: bool) -> u16 {
    if xray_compat {
        XRAY_INITIAL_MTU
    } else {
        SHOES_INITIAL_MTU
    }
}

fn configured_receive_window(
    value: Option<u64>,
    default: u64,
) -> std::io::Result<quinn::VarInt> {
    let value = value.filter(|value| *value != 0).unwrap_or(default);
    quinn::VarInt::from_u64(value)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        CongestionMode, DEFAULT_CONNECTION_RECEIVE_WINDOW,
        DEFAULT_STREAM_RECEIVE_WINDOW, SHOES_INITIAL_MTU, SHOES_INITIAL_RTT,
        SHOES_KEEP_ALIVE_INTERVAL, SHOES_MAX_INCOMING_UNI_STREAMS,
        SHOES_SEND_WINDOW, SHOES_UDP_SOCKET_BUFFER_SIZE,
        XRAY_ASSUME_PEER_MAX_DATAGRAM_FRAME_SIZE, XRAY_INITIAL_MTU,
        XRAY_MAX_INCOMING_UNI_STREAMS,
        configured_assume_peer_max_datagram_frame_size, configured_congestion_mode,
        configured_initial_mtu, configured_initial_rtt,
        configured_keep_alive_interval, configured_max_datagram_frame_size,
        configured_max_idle_timeout_secs, configured_max_incoming_bidi_streams,
        configured_max_incoming_uni_streams, configured_mtu_discovery,
        configured_receive_window, configured_send_window,
        configured_server_migration, configured_udp_socket_buffer_size,
    };

    #[test]
    fn server_migration_matches_xray_and_shoes() {
        assert!(configured_server_migration(false));
        assert!(!configured_server_migration(true));
    }

    #[test]
    fn transport_defaults_follow_protocol_mode_without_finalmask() {
        assert_eq!(configured_max_idle_timeout_secs(None), 30);
        assert_eq!(configured_max_idle_timeout_secs(Some(45)), 45);
        assert_eq!(configured_max_incoming_bidi_streams(false, None), 4096);
        assert_eq!(configured_max_incoming_bidi_streams(true, None), 1024);
        assert_eq!(configured_max_incoming_bidi_streams(true, Some(2048)), 2048);
    }

    #[test]
    fn max_incoming_uni_streams_follow_protocol_mode() {
        assert_eq!(
            configured_max_incoming_uni_streams(false).into_inner(),
            u64::from(SHOES_MAX_INCOMING_UNI_STREAMS)
        );
        assert_eq!(
            configured_max_incoming_uni_streams(true).into_inner(),
            u64::from(XRAY_MAX_INCOMING_UNI_STREAMS)
        );
    }

    #[test]
    fn shoes_transport_tuning_is_disabled_for_xray_compatibility() {
        assert_eq!(
            configured_keep_alive_interval(false, None),
            Some(SHOES_KEEP_ALIVE_INTERVAL)
        );
        assert_eq!(configured_keep_alive_interval(true, None), None);
        assert_eq!(configured_send_window(false), Some(SHOES_SEND_WINDOW));
        assert_eq!(configured_send_window(true), None);
        assert_eq!(configured_initial_rtt(false), Some(SHOES_INITIAL_RTT));
        assert_eq!(configured_initial_rtt(true), None);
        assert_eq!(
            configured_udp_socket_buffer_size(false),
            Some(SHOES_UDP_SOCKET_BUFFER_SIZE)
        );
        assert_eq!(configured_udp_socket_buffer_size(true), None);
    }

    #[test]
    fn xray_keep_alive_period_matches_configured_value() {
        assert_eq!(configured_keep_alive_interval(true, Some(0)), None);
        assert_eq!(
            configured_keep_alive_interval(true, Some(12)),
            Some(Duration::from_secs(12))
        );
    }

    #[test]
    fn xray_compat_uses_xray_datagram_frame_size() {
        assert_eq!(configured_max_datagram_frame_size(false), None);
        assert_eq!(
            configured_max_datagram_frame_size(true)
                .expect(
                    "Xray compatibility must advertise Xray's DATAGRAM frame size"
                )
                .into_inner(),
            u64::from(XRAY_ASSUME_PEER_MAX_DATAGRAM_FRAME_SIZE)
        );
        assert_eq!(configured_assume_peer_max_datagram_frame_size(false), None);
        assert_eq!(
            configured_assume_peer_max_datagram_frame_size(true)
                .expect("Xray compatibility must assume peer DATAGRAM support")
                .into_inner(),
            u64::from(XRAY_ASSUME_PEER_MAX_DATAGRAM_FRAME_SIZE)
        );
    }

    #[test]
    fn path_mtu_discovery_matches_xray_disable_flag() {
        assert!(configured_mtu_discovery(None).is_some());
        assert!(configured_mtu_discovery(Some(false)).is_some());
        assert!(configured_mtu_discovery(Some(true)).is_none());
    }

    #[test]
    fn initial_mtu_matches_protocol_mode() {
        assert_eq!(configured_initial_mtu(false), SHOES_INITIAL_MTU);
        assert_eq!(configured_initial_mtu(true), XRAY_INITIAL_MTU);
    }

    #[test]
    fn congestion_mode_matches_xray_and_shoes_defaults() {
        assert_eq!(
            configured_congestion_mode(false, None),
            CongestionMode::Cubic
        );
        assert_eq!(configured_congestion_mode(true, None), CongestionMode::Bbr);
        assert_eq!(
            configured_congestion_mode(true, Some("bbr")),
            CongestionMode::Bbr
        );
        assert_eq!(
            configured_congestion_mode(true, Some("reno")),
            CongestionMode::Reno
        );
        assert_eq!(
            configured_congestion_mode(true, Some("")),
            CongestionMode::Brutal
        );
        assert_eq!(
            configured_congestion_mode(true, Some("brutal")),
            CongestionMode::Brutal
        );
        assert_eq!(
            configured_congestion_mode(true, Some("force-brutal")),
            CongestionMode::Brutal
        );
    }

    #[test]
    fn receive_windows_use_xray_max_values_and_shared_defaults() {
        assert_eq!(
            configured_receive_window(None, DEFAULT_STREAM_RECEIVE_WINDOW)
                .expect("default stream window")
                .into_inner(),
            DEFAULT_STREAM_RECEIVE_WINDOW
        );
        assert_eq!(
            configured_receive_window(Some(0), DEFAULT_CONNECTION_RECEIVE_WINDOW)
                .expect("zero connection window uses default")
                .into_inner(),
            DEFAULT_CONNECTION_RECEIVE_WINDOW
        );
        assert_eq!(
            configured_receive_window(Some(65_536), DEFAULT_STREAM_RECEIVE_WINDOW)
                .expect("explicit stream window")
                .into_inner(),
            65_536
        );
        assert_eq!(
            configured_receive_window(
                Some(262_144),
                DEFAULT_CONNECTION_RECEIVE_WINDOW
            )
            .expect("explicit connection window")
            .into_inner(),
            262_144
        );
    }
}
