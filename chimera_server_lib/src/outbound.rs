use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use tracing::warn;

use crate::{
    address::{Address, NetLocation},
    resolver::{Resolver, resolve_single_address},
    routing_process::enrich_routing_input,
    routing_state::{OutboundObservation, RoutingInput},
    runtime::RuntimeState,
    util::socket::new_tcp_socket,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
}

pub(crate) struct TcpOutboundConnection {
    pub stream: tokio::net::TcpStream,
    pub outbound_tag: Option<String>,
}

pub(crate) async fn connect_tcp_outbound(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &RuntimeState,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
) -> std::io::Result<Option<TcpOutboundConnection>> {
    let target_addr = resolve_single_address(resolver, remote_location).await?;
    let mut route_input = connection_routing_input(
        inbound_tag,
        user,
        2,
        source_addr,
        target_addr,
        remote_location,
    );
    if runtime.routing().requires_process_lookup() {
        enrich_routing_input(&mut route_input).await;
    }

    let outbound_tag = match select_direct_outbound(runtime, &route_input, "tcp")? {
        DirectOutboundAction::Freedom { tag } => tag,
        DirectOutboundAction::Blackhole { .. } => return Ok(None),
    };

    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let started = Instant::now();
    let attempted_at = unix_time_secs();
    let stream = match tcp_socket.connect(target_addr).await {
        Ok(stream) => {
            if let Some(tag) = outbound_tag.as_deref() {
                runtime.record_outbound_observation(
                    tag,
                    OutboundObservation {
                        alive: true,
                        delay_ms: started.elapsed().as_millis().min(i64::MAX as u128)
                            as i64,
                        last_seen_time: attempted_at,
                        last_try_time: attempted_at,
                        ..OutboundObservation::default()
                    },
                );
            }
            stream
        }
        Err(error) => {
            if let Some(tag) = outbound_tag.as_deref() {
                runtime.record_outbound_observation(
                    tag,
                    OutboundObservation {
                        alive: false,
                        delay_ms: started.elapsed().as_millis().min(i64::MAX as u128)
                            as i64,
                        last_error_reason: error.to_string(),
                        last_try_time: attempted_at,
                        ..OutboundObservation::default()
                    },
                );
            }
            return Err(error);
        }
    };
    if let Err(err) = stream.set_nodelay(true) {
        warn!("Failed to set TCP no-delay on client socket: {}", err);
    }

    Ok(Some(TcpOutboundConnection {
        stream,
        outbound_tag,
    }))
}

pub(crate) fn connection_routing_input(
    inbound_tag: &str,
    user: &str,
    network: i32,
    source_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> RoutingInput {
    RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network,
        source_ips: vec![encode_ip(source_addr.ip())],
        target_ips: vec![encode_ip(target_addr.ip())],
        source_port: source_addr.port() as u32,
        target_port: target_addr.port() as u32,
        target_domain: match target_location.address() {
            Address::Hostname(hostname) => hostname.clone(),
            _ => String::new(),
        },
        user: user.to_string(),
        ..RoutingInput::default()
    }
}

pub(crate) fn select_direct_outbound(
    runtime: &RuntimeState,
    input: &RoutingInput,
    network_name: &str,
) -> std::io::Result<DirectOutboundAction> {
    let Some(outbound) =
        runtime.select_outbound_checked(input).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })?
    else {
        return Ok(DirectOutboundAction::Freedom { tag: None });
    };

    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(DirectOutboundAction::Freedom {
            tag: Some(outbound.tag),
        }),
        "blackhole" => Ok(DirectOutboundAction::Blackhole { tag: outbound.tag }),
        protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} outbound {} uses unsupported protocol {}",
                network_name, outbound.tag, protocol
            ),
        )),
    }
}

fn unix_time_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn encode_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::rule::{BalancerConfig, RoutingConfig, RuleConfig},
        resolver::NativeResolver,
        routing_state::RoutingState,
        runtime::OutboundSummary,
    };

    fn outbound(tag: &str, protocol: &str) -> OutboundSummary {
        OutboundSummary {
            tag: tag.into(),
            protocol: protocol.into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
        }
    }

    #[test]
    fn direct_outbound_defaults_to_implicit_freedom() {
        let runtime = RuntimeState::new(Vec::new(), Vec::new());

        assert_eq!(
            select_direct_outbound(&runtime, &RoutingInput::default(), "tcp")
                .unwrap(),
            DirectOutboundAction::Freedom { tag: None }
        );
    }

    #[test]
    fn direct_outbound_rejects_unsupported_protocol() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("proxy", "vmess")]);

        let err = select_direct_outbound(&runtime, &RoutingInput::default(), "tcp")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "tcp outbound proxy uses unsupported protocol vmess"
        );
    }

    #[test]
    fn direct_outbound_rejects_missing_routed_outbound() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    outbound_tag: Some("missing".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("missing outbound routing rule should compile"),
        );

        let error = select_direct_outbound(
            &runtime,
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            "tcp",
        )
        .expect_err("missing routed outbound must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("missing outbound missing"));
    }

    #[test]
    fn direct_outbound_rejects_empty_balancer_without_falling_back() {
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["test".into()],
                    balancer_tag: Some("empty".into()),
                    ..RuleConfig::default()
                }],
                balancers: vec![BalancerConfig {
                    tag: "empty".into(),
                    outbound_selector: vec!["missing-prefix".into()],
                    strategy: Default::default(),
                    fallback_tag: None,
                }],
                ..RoutingConfig::default()
            }))
            .expect("empty balancer routing rule should compile"),
        );

        let error = select_direct_outbound(
            &runtime,
            &RoutingInput {
                inbound_tag: "test".into(),
                ..RoutingInput::default()
            },
            "tcp",
        )
        .expect_err("empty routed balancer must fail closed");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("balancer empty has no available outbound")
        );
    }

    #[test]
    fn direct_outbound_routes_by_authenticated_user() {
        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    user: vec!["alice".into()],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .unwrap(),
        );
        let input = connection_routing_input(
            "quic-in",
            "alice",
            2,
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            &NetLocation::from_str("example.com:443", None).unwrap(),
        );

        assert_eq!(
            select_direct_outbound(&runtime, &input, "tcp").unwrap(),
            DirectOutboundAction::Blackhole {
                tag: "blocked".into()
            }
        );
        assert_eq!(input.source_port, 12345);
        assert_eq!(input.target_domain, "example.com");
    }

    #[tokio::test]
    async fn tcp_outbound_records_successful_observation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind observed target");
        let target_addr = listener.local_addr().expect("observed target address");
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "observed-in",
            "",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .expect("observed connection should succeed");
        assert!(connection.is_some());

        let observations = runtime.outbound_observations();
        let status = observations.get("direct").expect("observation missing");
        assert!(status.alive);
        assert!(status.last_seen_time > 0);
        assert_eq!(status.last_error_reason, "");
    }

    #[tokio::test]
    async fn tcp_outbound_records_failed_observation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve failed target port");
        let target_addr = listener.local_addr().expect("failed target address");
        drop(listener);
        let runtime =
            RuntimeState::new(Vec::new(), vec![outbound("direct", "freedom")]);
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        if connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "observed-in",
            "",
            "127.0.0.1:12345".parse().unwrap(),
        )
        .await
        .is_ok()
        {
            panic!("connection to released port should fail");
        }

        let observations = runtime.outbound_observations();
        let status = observations
            .get("direct")
            .expect("failure observation missing");
        assert!(!status.alive);
        assert!(status.last_try_time > 0);
        assert!(!status.last_error_reason.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tcp_outbound_routes_by_local_process() {
        let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process routing inbound listener");
        let client = tokio::net::TcpStream::connect(
            inbound_listener.local_addr().expect("inbound address"),
        );
        let (client, accepted) = tokio::join!(client, inbound_listener.accept());
        let _client = client.expect("connect local process client");
        let (_accepted, source_addr) =
            accepted.expect("accept local process client");
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process routing target");
        let target_addr = target_listener.local_addr().expect("target address");
        let process_name = std::env::current_exe()
            .expect("current executable")
            .file_name()
            .expect("current executable name")
            .to_string_lossy()
            .into_owned();

        let runtime = RuntimeState::new(
            Vec::new(),
            vec![
                outbound("direct", "freedom"),
                outbound("blocked", "blackhole"),
            ],
        );
        runtime.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    process: vec![process_name],
                    outbound_tag: Some("blocked".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("process routing should build"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let target = NetLocation::from_ip_addr(target_addr.ip(), target_addr.port());

        let connection = connect_tcp_outbound(
            &resolver,
            &target,
            &runtime,
            "process-in",
            "",
            source_addr,
        )
        .await
        .expect("process-routed outbound selection should succeed");

        assert!(
            connection.is_none(),
            "process route should select blackhole"
        );
    }
}
