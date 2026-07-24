use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tracing::warn;

use crate::{
    address::{Address, NetLocation},
    resolver::{Resolver, resolve_single_address},
    routing_state::RoutingInput,
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
    let route_input = connection_routing_input(
        inbound_tag,
        user,
        2,
        source_addr,
        target_addr,
        remote_location,
    );

    let outbound_tag = match select_direct_outbound(runtime, &route_input, "tcp")? {
        DirectOutboundAction::Freedom { tag } => tag,
        DirectOutboundAction::Blackhole { .. } => return Ok(None),
    };

    let tcp_socket = new_tcp_socket(None, target_addr.is_ipv6())?;
    let stream = tcp_socket.connect(target_addr).await?;
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
    let Some(outbound) = runtime.select_outbound(input) else {
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
        config::rule::{RoutingConfig, RuleConfig},
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
}
