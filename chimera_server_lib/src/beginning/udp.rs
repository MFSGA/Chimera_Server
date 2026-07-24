use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::{Instant, sleep},
};
use tracing::{debug, error, info, warn};

use crate::{
    address::{Address, BindLocation, NetLocation},
    config::server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
    resolver::{NativeResolver, Resolver, resolve_single_address},
    routing_state::RoutingInput,
    runtime::RuntimeState,
    traffic::{TrafficContext, record_transfer},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_CHANNEL_CAPACITY: usize = 64;
// Keep UDP routing intentionally limited to direct and drop outbounds for now.

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    outbound_tag: Option<String>,
}

#[derive(Debug)]
struct UdpRelayState {
    server_socket: Arc<UdpSocket>,
    sessions: Mutex<HashMap<UdpSessionKey, mpsc::Sender<Vec<u8>>>>,
}

impl UdpRelayState {
    fn new(server_socket: Arc<UdpSocket>) -> Self {
        Self {
            server_socket,
            sessions: Mutex::new(HashMap::new()),
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
        ..
    } = config;

    let dokodemo_config = match protocol {
        ServerProxyConfig::DokodemoDoor { config } => config,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "transport=udp only supports dokodemo-door in this stage (got {other})"
                ),
            ));
        }
    };

    if dokodemo_config.follow_redirect {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dokodemo-door followRedirect is not supported for udp transport",
        ));
    }

    let bind_addr = bind_location_to_socket_addr(&bind_location)?;
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target_addr =
        resolve_single_address(&resolver, &dokodemo_config.target).await?;

    info!(
        "Starting DokodemoDoor UDP server at {} forwarding to {}",
        bind_location, dokodemo_config.target
    );

    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    Ok(Some(tokio::spawn(async move {
        if let Err(err) = run_dokodemo_udp_server(
            socket,
            dokodemo_config,
            target_addr,
            tag,
            runtime,
        )
        .await
        {
            error!("UDP server stopped with error: {}", err);
        }
    })))
}

fn bind_location_to_socket_addr(
    bind_location: &BindLocation,
) -> std::io::Result<SocketAddr> {
    match bind_location {
        BindLocation::Address(location) => location.to_socket_addr(),
    }
}

async fn run_dokodemo_udp_server(
    socket: Arc<UdpSocket>,
    config: DokodemoDoorConfig,
    target_addr: SocketAddr,
    inbound_tag: String,
    runtime: RuntimeState,
) -> std::io::Result<()> {
    let relay_state = Arc::new(UdpRelayState::new(socket));
    let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let (len, client_addr) =
            relay_state.server_socket.recv_from(&mut recv_buf).await?;
        let payload = recv_buf[..len].to_vec();
        let target_location = config.target.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();
        let relay_state = relay_state.clone();

        tokio::spawn(async move {
            if let Err(err) = relay_dokodemo_udp_datagram(
                relay_state,
                client_addr,
                target_addr,
                target_location,
                inbound_tag,
                runtime,
                payload,
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
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: NetLocation,
    inbound_tag: String,
    runtime: RuntimeState,
    payload: Vec<u8>,
) -> std::io::Result<()> {
    let outbound_action = select_udp_outbound(
        &runtime,
        &inbound_tag,
        client_addr,
        target_addr,
        &target_location,
    )?;

    let traffic_context = TrafficContext::new("dokodemo-door")
        .with_inbound_tag(inbound_tag)
        .with_client_ip(client_addr.ip());

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
            )
            .await?;

            sender.send(payload).await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "dokodemo-door udp session closed before payload was sent",
                )
            })
        }
    }
}

async fn freedom_udp_session_sender(
    relay_state: Arc<UdpRelayState>,
    key: UdpSessionKey,
    target_location: NetLocation,
    outbound_tag: Option<String>,
    traffic_context: TrafficContext,
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

    tokio::spawn(run_freedom_udp_session(
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
                        record_transfer(Some(traffic_context.clone()), sent as u64, 0);
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
                        record_transfer(Some(traffic_context.clone()), 0, sent as u64);
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

fn select_udp_outbound(
    runtime: &RuntimeState,
    inbound_tag: &str,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> std::io::Result<UdpOutboundAction> {
    let route_input = RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network: 3,
        source_ips: vec![encode_ip(client_addr.ip())],
        target_ips: vec![encode_ip(target_addr.ip())],
        source_port: client_addr.port() as u32,
        target_port: target_addr.port() as u32,
        target_domain: target_domain(target_location),
        ..RoutingInput::default()
    };

    let selected = runtime.select_outbound(&route_input);

    let Some(outbound) = selected else {
        return Ok(UdpOutboundAction::Freedom { tag: None });
    };

    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(UdpOutboundAction::Freedom {
            tag: Some(outbound.tag),
        }),
        "blackhole" => Ok(UdpOutboundAction::Blackhole { tag: outbound.tag }),
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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use tokio::{net::UdpSocket, time::timeout};

    use crate::{
        address::{Address, NetLocation},
        config::{
            rule::{NetworkListConfig, RoutingConfig, RuleConfig},
            server_config::DokodemoDoorConfig,
        },
        routing_state::RoutingState,
        runtime::OutboundSummary,
    };

    use super::*;

    fn runtime_with_outbounds(outbounds: Vec<OutboundSummary>) -> RuntimeState {
        RuntimeState::new(Vec::new(), outbounds)
    }

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[tokio::test]
    async fn dokodemo_udp_relay_forwards_datagrams() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo socket");
        let echo_addr = echo_socket.local_addr().expect("echo addr");
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, peer) =
                echo_socket.recv_from(&mut buf).await.expect("echo recv");
            echo_socket
                .send_to(&buf[..len], peer)
                .await
                .expect("echo send");
        });

        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dokodemo socket"),
        );
        let server_addr = server_socket.local_addr().expect("dokodemo addr");
        let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
        let server_task = tokio::spawn(run_dokodemo_udp_server(
            server_socket,
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
            },
            echo_addr,
            "dokodemo-udp-test".into(),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
        ));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        client
            .send_to(b"ping", server_addr)
            .await
            .expect("client send");

        let mut response = [0u8; 32];
        let (len, _peer) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("relay response timeout")
                .expect("client receive");
        assert_eq!(&response[..len], b"ping");

        echo_task.await.expect("echo task finished");
        server_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_udp_reuses_session_for_same_flow() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo socket");
        let echo_addr = echo_socket.local_addr().expect("echo addr");
        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            for _ in 0..2 {
                let (len, peer) =
                    echo_socket.recv_from(&mut buf).await.expect("echo recv");
                peer_tx.send(peer).await.expect("record peer");
                echo_socket
                    .send_to(&buf[..len], peer)
                    .await
                    .expect("echo send");
            }
        });

        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dokodemo socket"),
        );
        let server_addr = server_socket.local_addr().expect("dokodemo addr");
        let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
        let server_task = tokio::spawn(run_dokodemo_udp_server(
            server_socket,
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
            },
            echo_addr,
            "dokodemo-udp-test".into(),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
        ));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        let mut response = [0u8; 32];

        client
            .send_to(b"one", server_addr)
            .await
            .expect("client send one");
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("relay response one timeout")
                .expect("client receive one");
        assert_eq!(&response[..len], b"one");

        client
            .send_to(b"two", server_addr)
            .await
            .expect("client send two");
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("relay response two timeout")
                .expect("client receive two");
        assert_eq!(&response[..len], b"two");

        let first_peer = peer_rx.recv().await.expect("first outbound peer");
        let second_peer = peer_rx.recv().await.expect("second outbound peer");
        assert_eq!(first_peer, second_peer);

        echo_task.await.expect("echo task finished");
        server_task.abort();
    }

    #[tokio::test]
    async fn dokodemo_udp_session_forwards_multiple_responses() {
        let echo_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo socket");
        let echo_addr = echo_socket.local_addr().expect("echo addr");
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (_len, peer) =
                echo_socket.recv_from(&mut buf).await.expect("echo recv");
            echo_socket
                .send_to(b"first", peer)
                .await
                .expect("send first");
            echo_socket
                .send_to(b"second", peer)
                .await
                .expect("send second");
        });

        let server_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind dokodemo socket"),
        );
        let server_addr = server_socket.local_addr().expect("dokodemo addr");
        let target = NetLocation::from_ip_addr(echo_addr.ip(), echo_addr.port());
        let server_task = tokio::spawn(run_dokodemo_udp_server(
            server_socket,
            DokodemoDoorConfig {
                target: target.clone(),
                follow_redirect: false,
            },
            echo_addr,
            "dokodemo-udp-test".into(),
            runtime_with_outbounds(vec![outbound("direct", "freedom")]),
        ));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client socket");
        client
            .send_to(b"request", server_addr)
            .await
            .expect("client send");

        let mut response = [0u8; 32];
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("first relay response timeout")
                .expect("client receive first");
        assert_eq!(&response[..len], b"first");
        let (len, _) =
            timeout(Duration::from_secs(5), client.recv_from(&mut response))
                .await
                .expect("second relay response timeout")
                .expect("client receive second");
        assert_eq!(&response[..len], b"second");

        echo_task.await.expect("echo task finished");
        server_task.abort();
    }

    #[test]
    fn udp_routing_selects_blackhole_outbound() {
        let runtime = runtime_with_outbounds(vec![
            outbound("direct", "freedom"),
            outbound("blocked", "blackhole"),
        ]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["dokodemo-udp".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("routing should build"),
        );

        let action = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect("outbound selection should succeed");

        assert_eq!(
            action,
            UdpOutboundAction::Blackhole {
                tag: "blocked".into()
            }
        );
    }

    #[test]
    fn udp_routing_defaults_to_first_outbound() {
        let runtime = runtime_with_outbounds(vec![outbound("direct", "freedom")]);

        let action = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect("outbound selection should succeed");

        assert_eq!(
            action,
            UdpOutboundAction::Freedom {
                tag: Some("direct".into())
            }
        );
    }

    #[test]
    fn udp_routing_rejects_unsupported_outbound_protocol() {
        let runtime = runtime_with_outbounds(vec![outbound("proxy", "vmess")]);

        let err = select_udp_outbound(
            &runtime,
            "dokodemo-udp",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 12345)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            &NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        )
        .expect_err("unsupported udp outbound protocol should fail");

        assert!(
            err.to_string()
                .contains("udp outbound proxy uses unsupported protocol vmess")
        );
    }

    #[test]
    fn udp_bind_location_converts_ip_address() {
        let bind_location = BindLocation::Address(NetLocation::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            1080,
        ));

        let socket_addr = bind_location_to_socket_addr(&bind_location)
            .expect("ip bind should convert to socket address");
        assert_eq!(socket_addr.port(), 1080);
    }
}
