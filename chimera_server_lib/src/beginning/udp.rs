use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tracing::{debug, error, info, warn};

use crate::{
    address::{Address, BindLocation, NetLocation},
    config::server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
    resolver::{NativeResolver, Resolver, resolve_single_address},
    routing_state::RoutingInput,
    runtime::{OutboundSummary, RuntimeState},
    traffic::{TrafficContext, record_transfer},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;
const UDP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
// Keep the first UDP routing step intentionally limited to direct and drop outbounds.

#[derive(Debug, Clone, PartialEq, Eq)]
enum UdpOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
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
    let mut recv_buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let (len, client_addr) = socket.recv_from(&mut recv_buf).await?;
        let payload = recv_buf[..len].to_vec();
        let server_socket = socket.clone();
        let target_location = config.target.clone();
        let inbound_tag = inbound_tag.clone();
        let runtime = runtime.clone();

        tokio::spawn(async move {
            if let Err(err) = relay_dokodemo_udp_datagram(
                server_socket,
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
    server_socket: Arc<UdpSocket>,
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

    let traffic_context = Some(
        TrafficContext::new("dokodemo-door")
            .with_inbound_tag(inbound_tag)
            .with_client_ip(client_addr.ip()),
    );

    match outbound_action {
        UdpOutboundAction::Blackhole { tag } => {
            debug!(
                "dokodemo-door udp packet from {} to {} dropped by blackhole outbound {}",
                client_addr, target_location, tag
            );
            record_transfer(traffic_context, payload.len() as u64, 0);
            Ok(())
        }
        UdpOutboundAction::Freedom { tag } => {
            let bind_addr = if target_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let outbound_socket = UdpSocket::bind(bind_addr).await?;

            outbound_socket.send_to(&payload, target_addr).await?;

            let mut response_buf = vec![0u8; UDP_BUFFER_SIZE];
            let (response_len, response_addr) = match timeout(
                UDP_RESPONSE_TIMEOUT,
                outbound_socket.recv_from(&mut response_buf),
            )
            .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    warn!(
                        "dokodemo-door udp response from {} timed out for client {}",
                        target_location, client_addr
                    );
                    return Ok(());
                }
            };

            let response = &response_buf[..response_len];
            server_socket.send_to(response, client_addr).await?;

            record_transfer(
                traffic_context,
                payload.len() as u64,
                response_len as u64,
            );

            debug!(
                "dokodemo-door udp relay {} -> {} -> {} via {} completed: upload {} bytes, download {} bytes",
                client_addr,
                target_location,
                response_addr,
                tag.as_deref().unwrap_or("implicit-freedom"),
                payload.len(),
                response_len
            );

            Ok(())
        }
    }
}

fn select_udp_outbound(
    runtime: &RuntimeState,
    inbound_tag: &str,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> std::io::Result<UdpOutboundAction> {
    let outbounds = runtime.outbounds();
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

    let selected = runtime
        .routing()
        .route(&route_input, &outbounds, &HashMap::new())
        .and_then(|route| outbound_by_tag(&outbounds, &route.outbound_tag))
        .or_else(|| outbounds.first().cloned());

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

fn outbound_by_tag(
    outbounds: &[OutboundSummary],
    tag: &str,
) -> Option<OutboundSummary> {
    outbounds
        .iter()
        .find(|outbound| outbound.tag == tag)
        .cloned()
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
            Transport,
            rule::{NetworkListConfig, RoutingConfig, RuleConfig},
            server_config::{DokodemoDoorConfig, ServerConfig, ServerProxyConfig},
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
