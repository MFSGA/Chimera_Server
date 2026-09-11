use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(feature = "shadowsocks")]
use tokio::time::timeout;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::{Instant, sleep},
};
use tracing::{debug, error, info, warn};

use crate::util::socket::new_socket2_udp_socket;
#[cfg(target_os = "linux")]
use crate::util::socket::{
    enable_udp_original_destination, recv_udp_with_original_destination,
};
#[cfg(feature = "shadowsocks")]
use crate::{
    handler::shadowsocks::ShadowsocksUdpCodec,
    outbound::{
        DirectOutboundAction, InboundRoutingMetadata, OutboundRoutingContext,
        select_direct_outbound_for_location,
    },
};

#[cfg(feature = "trojan")]
use crate::{
    handler::trojan_udp::TrojanUdpStream, outbound::connect_trojan_udp_via_outbound,
};

use crate::{
    address::{Address, BindLocation, NetLocation},
    config::server_config::{
        DokodemoDoorConfig, ServerConfig, ServerProxyConfig, TcpSocketPolicy,
    },
    resolver::{NativeResolver, Resolver, resolve_single_address},
    routing_process::enrich_routing_input,
    routing_state::RoutingInput,
    runtime::{DataPlaneRuntime, OutboundSummary, RuntimeState},
    traffic::{TrafficContext, record_transfer, record_transfer_ref},
};

#[cfg(feature = "trojan")]
use super::targeted_session::shutdown_targeted_message;
use super::{
    UDP_BUFFER_SIZE, UDP_SESSION_CHANNEL_CAPACITY, UDP_SESSION_IDLE_TIMEOUT,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum UdpOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
    Trojan { outbound: OutboundSummary },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    outbound_tag: Option<String>,
}

#[cfg(feature = "trojan")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DokodemoTrojanUdpSessionKey {
    client_addr: SocketAddr,
    target: NetLocation,
    outbound_tag: String,
}

struct DokodemoUdpDatagram {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: NetLocation,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct UdpRelayState {
    server_socket: Arc<UdpSocket>,
    sessions: Mutex<HashMap<UdpSessionKey, mpsc::Sender<Vec<u8>>>>,
    #[cfg(feature = "trojan")]
    trojan_sessions:
        Mutex<HashMap<DokodemoTrojanUdpSessionKey, mpsc::Sender<Vec<u8>>>>,
}

impl UdpRelayState {
    fn new(server_socket: Arc<UdpSocket>) -> Self {
        Self {
            server_socket,
            sessions: Mutex::new(HashMap::new()),
            #[cfg(feature = "trojan")]
            trojan_sessions: Mutex::new(HashMap::new()),
        }
    }
}

pub async fn start_udp_server(
    config: ServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        tcp_socket_policy,
        ..
    } = config;

    let dokodemo_config = match protocol {
        #[cfg(feature = "shadowsocks")]
        ServerProxyConfig::Shadowsocks { users, identity } => {
            return start_shadowsocks_udp_server(
                bind_location,
                tag,
                users,
                identity,
                tcp_socket_policy,
                runtime.data_plane(),
            )
            .await;
        }
        ServerProxyConfig::DokodemoDoor { config } => config,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport=udp supports dokodemo-door and shadowsocks in this stage (got {other})"
                ),
            ));
        }
    };

    #[cfg(not(target_os = "linux"))]
    if dokodemo_config.follow_redirect {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dokodemo-door UDP followRedirect is supported only on Linux",
        ));
    }

    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let target_addr = if dokodemo_config.follow_redirect {
        None
    } else {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        Some(resolve_single_address(&resolver, &dokodemo_config.target).await?)
    };

    if dokodemo_config.follow_redirect {
        info!(
            "Starting DokodemoDoor UDP server at {} with followRedirect",
            bind_location
        );
    } else {
        info!(
            "Starting DokodemoDoor UDP server at {} forwarding to {}",
            bind_location, dokodemo_config.target
        );
    }

    let socket = create_udp_listener(
        bind_addr,
        tcp_socket_policy.as_ref(),
        dokodemo_config.follow_redirect,
    )?;
    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_dokodemo_udp_server(
            socket,
            dokodemo_config,
            target_addr,
            tag,
            runtime.data_plane(),
        )
        .await
        {
            error!("UDP server stopped with error: {}", err);
        }
    })))
}

pub(super) fn bind_location_to_socket_addr(
    bind_location: &BindLocation,
) -> std::io::Result<SocketAddr> {
    match bind_location {
        BindLocation::Address(location) => location.to_socket_addr(),
    }
}

pub(super) fn create_udp_listener(
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

#[cfg(feature = "shadowsocks")]
async fn start_shadowsocks_udp_server(
    bind_location: BindLocation,
    inbound_tag: String,
    users: Vec<crate::config::server_config::ShadowsocksUser>,
    identity: Option<crate::config::server_config::ShadowsocksServerIdentity>,
    socket_policy: Option<TcpSocketPolicy>,
    runtime: DataPlaneRuntime,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let socket = create_udp_listener(bind_addr, socket_policy.as_ref(), false)?;
    let codec = Arc::new(ShadowsocksUdpCodec::new(users, identity)?);
    info!("Starting Shadowsocks UDP server at {}", bind_location);

    Ok(Some(tokio::spawn(run_shadowsocks_udp_server(
        socket,
        codec,
        inbound_tag,
        runtime,
    ))))
}

#[cfg(feature = "shadowsocks")]
pub(super) async fn run_shadowsocks_udp_server(
    socket: Arc<UdpSocket>,
    codec: Arc<ShadowsocksUdpCodec>,
    inbound_tag: String,
    runtime: DataPlaneRuntime,
) {
    let runtime_users = runtime.shadowsocks_user_store(&inbound_tag);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut buffer = vec![0u8; UDP_BUFFER_SIZE];
    loop {
        let (len, client_addr) = match socket.recv_from(&mut buffer).await {
            Ok(value) => value,
            Err(error) => {
                error!("Shadowsocks UDP receive failed: {error}");
                break;
            }
        };
        let packet = buffer[..len].to_vec();
        let socket = socket.clone();
        let codec = runtime_users
            .as_ref()
            .map(|store| Arc::new(store.udp_codec(codec.as_ref())))
            .unwrap_or_else(|| codec.clone());
        let task_runtime = runtime.clone();
        let resolver = resolver.clone();
        let inbound_tag = inbound_tag.clone();
        runtime.spawn_inbound_connection(async move {
            if let Err(error) = relay_shadowsocks_udp_packet(
                socket,
                codec,
                resolver,
                task_runtime,
                inbound_tag,
                client_addr,
                packet,
            )
            .await
            {
                debug!(
                    "Shadowsocks UDP packet from {} failed: {}",
                    client_addr, error
                );
            }
        });
    }
}

#[cfg(feature = "shadowsocks")]
pub(super) async fn relay_shadowsocks_udp_packet(
    server_socket: Arc<UdpSocket>,
    codec: Arc<ShadowsocksUdpCodec>,
    resolver: Arc<dyn Resolver>,
    runtime: DataPlaneRuntime,
    inbound_tag: String,
    client_addr: SocketAddr,
    packet: Vec<u8>,
) -> std::io::Result<()> {
    let request = codec.decrypt_packet(&packet)?;
    let (outbound_action, target_addr) = select_direct_outbound_for_location(
        &resolver,
        &request.target_location,
        &runtime,
        OutboundRoutingContext::new(
            &inbound_tag,
            &request.identity,
            client_addr,
            3,
            "udp",
            InboundRoutingMetadata {
                local_addr: server_socket.local_addr().ok(),
                ..InboundRoutingMetadata::default()
            },
        ),
    )
    .await?;
    let mut traffic_context = TrafficContext::new("shadowsocks")
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_addr.ip())
        .with_user_level(request.user_level);
    if !request.identity.is_empty() {
        traffic_context = traffic_context.with_identity(request.identity.clone());
    }
    runtime.apply_traffic_stats_policy(&mut traffic_context);

    match outbound_action {
        DirectOutboundAction::Blackhole { tag } => {
            traffic_context = traffic_context.with_outbound_tag(tag);
            record_transfer(Some(traffic_context), request.payload.len() as u64, 0);
            Ok(())
        }
        DirectOutboundAction::Freedom { tag } => {
            if let Some(tag) = tag {
                traffic_context = traffic_context.with_outbound_tag(tag);
            }
            let target_addr = target_addr.ok_or_else(|| {
                std::io::Error::other(
                    "Shadowsocks UDP freedom route did not resolve target",
                )
            })?;
            let bind_addr = if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let outbound = UdpSocket::bind(bind_addr).await?;
            let sent = outbound.send_to(&request.payload, target_addr).await?;
            record_transfer_ref(Some(&traffic_context), sent as u64, 0);

            let mut response = vec![0u8; UDP_BUFFER_SIZE];
            let (response_len, response_addr) =
                timeout(UDP_SESSION_IDLE_TIMEOUT, outbound.recv_from(&mut response))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Shadowsocks UDP response timed out",
                        )
                    })??;
            let source =
                NetLocation::from_ip_addr(response_addr.ip(), response_addr.port());
            let encrypted = codec.encrypt_packet(
                &request,
                &source,
                &response[..response_len],
            )?;
            server_socket.send_to(&encrypted, client_addr).await?;
            record_transfer(Some(traffic_context), 0, response_len as u64);
            Ok(())
        }
        DirectOutboundAction::Trojan { outbound } => {
            #[cfg(feature = "trojan")]
            {
                traffic_context =
                    traffic_context.with_outbound_tag(outbound.tag.clone());
                let mut proxy = connect_trojan_udp_via_outbound(
                    &resolver,
                    &request.target_location,
                    &runtime,
                    &outbound,
                )
                .await?;
                proxy
                    .send_to(&request.target_location, &request.payload)
                    .await?;
                record_transfer_ref(
                    Some(&traffic_context),
                    request.payload.len() as u64,
                    0,
                );

                let mut response = vec![0u8; UDP_BUFFER_SIZE];
                let (source, response_len) = timeout(
                    UDP_SESSION_IDLE_TIMEOUT,
                    proxy.recv_from(&mut response),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Shadowsocks Trojan UDP response timed out",
                    )
                })??;
                let encrypted = codec.encrypt_packet(
                    &request,
                    &source,
                    &response[..response_len],
                )?;
                server_socket.send_to(&encrypted, client_addr).await?;
                record_transfer(Some(traffic_context), 0, response_len as u64);
                let _ = shutdown_targeted_message(&mut proxy).await;
                Ok(())
            }
            #[cfg(not(feature = "trojan"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "Trojan outbound {} requires the trojan feature",
                        outbound.tag
                    ),
                ))
            }
        }
        DirectOutboundAction::Socks { outbound }
        | DirectOutboundAction::Vless { outbound } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("TCP proxy outbound {} cannot be used for UDP", outbound.tag),
        )),
    }
}

pub(super) async fn run_dokodemo_udp_server(
    socket: Arc<UdpSocket>,
    config: DokodemoDoorConfig,
    target_addr: impl Into<Option<SocketAddr>> + Send,
    inbound_tag: String,
    runtime: DataPlaneRuntime,
) -> std::io::Result<()> {
    let target_addr = target_addr.into();
    let relay_state = Arc::new(UdpRelayState::new(socket));
    let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let (len, client_addr, datagram_target, target_location) =
            if config.follow_redirect {
                #[cfg(target_os = "linux")]
                {
                    let (len, client_addr, original_destination) =
                        recv_udp_with_original_destination(
                            &relay_state.server_socket,
                            &mut recv_buf,
                        )
                        .await?;
                    (
                        len,
                        client_addr,
                        original_destination,
                        NetLocation::from_ip_addr(
                            original_destination.ip(),
                            original_destination.port(),
                        ),
                    )
                }
                #[cfg(not(target_os = "linux"))]
                unreachable!("non-Linux followRedirect returned before receive loop")
            } else {
                let (len, client_addr) =
                    relay_state.server_socket.recv_from(&mut recv_buf).await?;
                let target_addr = target_addr.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "dokodemo-door UDP fixed target is unavailable",
                    )
                })?;
                (len, client_addr, target_addr, config.target.clone())
            };
        let payload = recv_buf[..len].to_vec();
        let inbound_tag = inbound_tag.clone();
        let task_runtime = runtime.clone();
        let relay_state = relay_state.clone();

        runtime.spawn_inbound_connection(async move {
            if let Err(err) = relay_dokodemo_udp_datagram(
                relay_state,
                inbound_tag,
                config.user_level,
                task_runtime,
                DokodemoUdpDatagram {
                    client_addr,
                    target_addr: datagram_target,
                    target_location,
                    payload,
                },
            )
            .await
            {
                debug!(
                    "dokodemo-door udp relay for {} ended with error: {}",
                    client_addr, err
                );
            }
        });
    }
}

async fn relay_dokodemo_udp_datagram(
    relay_state: Arc<UdpRelayState>,
    inbound_tag: String,
    user_level: u32,
    runtime: DataPlaneRuntime,
    datagram: DokodemoUdpDatagram,
) -> std::io::Result<()> {
    let DokodemoUdpDatagram {
        client_addr,
        target_addr,
        target_location,
        payload,
    } = datagram;
    let outbound_action = select_udp_outbound(
        &runtime,
        &inbound_tag,
        client_addr,
        relay_state.server_socket.local_addr().ok(),
        target_addr,
        &target_location,
    )
    .await?;

    let mut traffic_context = TrafficContext::new("dokodemo-door")
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_addr.ip())
        .with_user_level(user_level);
    runtime.apply_traffic_stats_policy(&mut traffic_context);

    match outbound_action {
        UdpOutboundAction::Blackhole { tag } => {
            let traffic_context = traffic_context.with_outbound_tag(tag.clone());
            debug!(
                "dokodemo-door udp packet from {} to {} dropped by blackhole outbound {}",
                client_addr, target_location, tag
            );
            record_transfer(Some(traffic_context), payload.len() as u64, 0);
            Ok(())
        }
        UdpOutboundAction::Freedom { tag } => {
            let traffic_context = match &tag {
                Some(tag) => traffic_context.with_outbound_tag(tag.clone()),
                None => traffic_context,
            };
            let key = UdpSessionKey {
                client_addr,
                target_addr,
                outbound_tag: tag.clone(),
            };
            let sender = freedom_udp_session_sender(
                relay_state,
                key,
                target_location,
                tag,
                traffic_context,
                &runtime,
            )
            .await?;

            sender.send(payload).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dokodemo-door udp session closed before payload was sent",
                )
            })
        }
        UdpOutboundAction::Trojan { outbound } => {
            #[cfg(feature = "trojan")]
            {
                let traffic_context =
                    traffic_context.with_outbound_tag(outbound.tag.clone());
                let key = DokodemoTrojanUdpSessionKey {
                    client_addr,
                    target: target_location,
                    outbound_tag: outbound.tag.clone(),
                };
                let sender = trojan_dokodemo_udp_session_sender(
                    relay_state,
                    key,
                    outbound,
                    runtime,
                    traffic_context,
                )
                .await?;
                sender.send(payload).await.map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "dokodemo-door Trojan UDP session closed before payload was sent",
                    )
                })
            }
            #[cfg(not(feature = "trojan"))]
            {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "Trojan outbound {} requires the trojan feature",
                        outbound.tag
                    ),
                ))
            }
        }
    }
}

#[cfg(feature = "trojan")]
async fn trojan_dokodemo_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: DokodemoTrojanUdpSessionKey,
    outbound: OutboundSummary,
    runtime: DataPlaneRuntime,
    traffic_context: TrafficContext,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    if let Some(sender) = relay_state
        .trojan_sessions
        .lock()
        .await
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        return Ok(sender);
    }

    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut proxy =
        connect_trojan_udp_via_outbound(&resolver, &key.target, &runtime, &outbound)
            .await?;
    let (sender, receiver) = mpsc::channel(UDP_SESSION_CHANNEL_CAPACITY);

    let mut sessions = relay_state.trojan_sessions.lock().await;
    if let Some(existing) = sessions
        .get(&key)
        .filter(|sender| !sender.is_closed())
        .cloned()
    {
        drop(sessions);
        let _ = shutdown_targeted_message(&mut proxy).await;
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    runtime.spawn_inbound_connection(run_trojan_dokodemo_udp_session(
        relay_state,
        key,
        traffic_context,
        proxy,
        receiver,
    ));
    Ok(sender)
}

#[cfg(feature = "trojan")]
async fn run_trojan_dokodemo_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: DokodemoTrojanUdpSessionKey,
    traffic_context: TrafficContext,
    mut proxy: TrojanUdpStream,
    mut receiver: mpsc::Receiver<Vec<u8>>,
) {
    let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
    let mut idle = Box::pin(sleep(UDP_SESSION_IDLE_TIMEOUT));

    loop {
        tokio::select! {
            _ = idle.as_mut() => {
                debug!(
                    "dokodemo-door Trojan UDP session {} -> {} via {} expired after {:?}",
                    key.client_addr,
                    key.target,
                    key.outbound_tag,
                    UDP_SESSION_IDLE_TIMEOUT
                );
                break;
            }
            maybe_payload = receiver.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                match proxy.send_to(&key.target, &payload).await {
                    Ok(()) => {
                        record_transfer_ref(
                            Some(&traffic_context),
                            payload.len() as u64,
                            0,
                        );
                        idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
                    }
                    Err(error) => {
                        debug!(
                            "dokodemo-door Trojan UDP send {} -> {} via {} failed: {}",
                            key.client_addr,
                            key.target,
                            key.outbound_tag,
                            error
                        );
                        break;
                    }
                }
            }
            response = proxy.recv_from(&mut response_buf) => {
                let (_source, response_len) = match response {
                    Ok(response) => response,
                    Err(error) => {
                        debug!(
                            "dokodemo-door Trojan UDP receive from {} via {} failed: {}",
                            key.target,
                            key.outbound_tag,
                            error
                        );
                        break;
                    }
                };
                match relay_state
                    .server_socket
                    .send_to(&response_buf[..response_len], key.client_addr)
                    .await
                {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
                    }
                    Err(error) => {
                        debug!(
                            "dokodemo-door Trojan UDP response to {} via {} failed: {}",
                            key.client_addr,
                            key.outbound_tag,
                            error
                        );
                        break;
                    }
                }
            }
        }
    }

    let _ = shutdown_targeted_message(&mut proxy).await;
    relay_state.trojan_sessions.lock().await.remove(&key);
}

async fn freedom_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
    runtime: &DataPlaneRuntime,
) -> std::io::Result<mpsc::Sender<Vec<u8>>> {
    if let Some(sender) = relay_state.sessions.lock().await.get(&key).cloned() {
        return Ok(sender);
    }

    let bind_addr = if key.target_addr.is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let outbound_socket = UdpSocket::bind(bind_addr).await?;
    let (sender, receiver) = mpsc::channel(UDP_SESSION_CHANNEL_CAPACITY);

    let mut sessions = relay_state.sessions.lock().await;
    if let Some(existing) = sessions.get(&key).cloned() {
        return Ok(existing);
    }
    sessions.insert(key.clone(), sender.clone());
    drop(sessions);

    runtime.spawn_inbound_connection(run_freedom_udp_session(
        relay_state,
        key,
        target_location,
        outbound_tag,
        traffic_context,
        outbound_socket,
        receiver,
    ));

    Ok(sender)
}

async fn run_freedom_udp_session(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
    outbound_socket: UdpSocket,
    mut receiver: mpsc::Receiver<Vec<u8>>,
) {
    let outbound_label = outbound_tag.as_deref().unwrap_or("implicit-freedom");
    let mut idle = Box::pin(sleep(UDP_SESSION_IDLE_TIMEOUT));

    loop {
        let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
        tokio::select! {
            _ = idle.as_mut() => {
                debug!(
                    "dokodemo-door udp session {} -> {} via {} expired after {:?}",
                    key.client_addr,
                    target_location,
                    outbound_label,
                    UDP_SESSION_IDLE_TIMEOUT
                );
                break;
            }
            maybe_payload = receiver.recv() => {
                let Some(payload) = maybe_payload else {
                    break;
                };
                match outbound_socket.send_to(&payload, key.target_addr).await {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), sent as u64, 0);
                        idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
                    }
                    Err(err) => {
                        debug!(
                            "dokodemo-door udp send {} -> {} via {} failed: {}",
                            key.client_addr,
                            target_location,
                            outbound_label,
                            err
                        );
                        break;
                    }
                }
            }
            response = outbound_socket.recv_from(&mut response_buf) => {
                let (response_len, response_addr) = match response {
                    Ok(result) => result,
                    Err(err) => {
                        debug!(
                            "dokodemo-door udp recv from {} via {} failed: {}",
                            target_location,
                            outbound_label,
                            err
                        );
                        break;
                    }
                };

                if response_addr != key.target_addr {
                    warn!(
                        "dokodemo-door udp ignored response from unexpected {} for target {}",
                        response_addr,
                        target_location
                    );
                    continue;
                }

                let response = &response_buf[..response_len];
                match relay_state.server_socket.send_to(response, key.client_addr).await {
                    Ok(sent) => {
                        record_transfer_ref(Some(&traffic_context), 0, sent as u64);
                        idle.as_mut().reset(Instant::now() + UDP_SESSION_IDLE_TIMEOUT);
                        debug!(
                            "dokodemo-door udp relay {} <- {} via {} forwarded {} bytes",
                            key.client_addr,
                            target_location,
                            outbound_label,
                            sent
                        );
                    }
                    Err(err) => {
                        debug!(
                            "dokodemo-door udp response to {} from {} via {} failed: {}",
                            key.client_addr,
                            target_location,
                            outbound_label,
                            err
                        );
                        break;
                    }
                }
            }
        }
    }

    relay_state.sessions.lock().await.remove(&key);
}

pub(super) async fn select_udp_outbound(
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    client_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> std::io::Result<UdpOutboundAction> {
    let mut route_input = RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network: 3,
        source_ips: vec![encode_ip(client_addr.ip())],
        target_ips: vec![encode_ip(target_addr.ip())],
        source_port: client_addr.port() as u32,
        target_port: target_addr.port() as u32,
        target_domain: target_domain(target_location),
        local_ips: local_addr
            .map(|address| vec![encode_ip(address.ip())])
            .unwrap_or_default(),
        local_port: local_addr.map_or(0, |address| address.port() as u32),
        ..RoutingInput::default()
    };
    if runtime.routing_needs_process_lookup(&route_input) {
        enrich_routing_input(&mut route_input).await;
    }

    let selected =
        runtime
            .select_outbound_checked(&route_input)
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
            })?;

    let Some(outbound) = selected else {
        return Ok(UdpOutboundAction::Freedom { tag: None });
    };

    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(UdpOutboundAction::Freedom {
            tag: Some(outbound.tag),
        }),
        "blackhole" => Ok(UdpOutboundAction::Blackhole { tag: outbound.tag }),
        "trojan" => Ok(UdpOutboundAction::Trojan { outbound }),
        protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "udp outbound {} uses unsupported protocol {}",
                outbound.tag, protocol
            ),
        )),
    }
}

fn encode_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn target_domain(target_location: &NetLocation) -> String {
    match target_location.address() {
        Address::Hostname(hostname) => hostname.clone(),
        _ => String::new(),
    }
}
