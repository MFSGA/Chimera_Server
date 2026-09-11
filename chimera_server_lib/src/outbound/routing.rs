use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use crate::{
    address::{Address, NetLocation},
    resolver::{Resolver, resolve_single_address},
    routing_process::enrich_routing_input,
    routing_state::{DomainStrategy, RoutingInput},
    runtime::{DataPlaneRuntime, OutboundSummary},
};

const USER_DOMAIN_ACCESS_BLACKHOLE_TAG: &str = "user-domain-access";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectOutboundAction {
    Freedom { tag: Option<String> },
    Blackhole { tag: String },
    Socks { outbound: OutboundSummary },
    Vless { outbound: OutboundSummary },
    Trojan { outbound: OutboundSummary },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct InboundRoutingMetadata {
    pub local_addr: Option<SocketAddr>,
    pub vless_route: u32,
    pub sniffed_protocol: Option<String>,
    pub route_target_domain: Option<String>,
    pub attributes: HashMap<String, String>,
}

pub(crate) struct OutboundRoutingContext<'a> {
    pub inbound_tag: &'a str,
    pub user: &'a str,
    pub source_addr: SocketAddr,
    pub network: i32,
    pub network_name: &'a str,
    pub metadata: InboundRoutingMetadata,
}

impl<'a> OutboundRoutingContext<'a> {
    pub fn new(
        inbound_tag: &'a str,
        user: &'a str,
        source_addr: SocketAddr,
        network: i32,
        network_name: &'a str,
        metadata: InboundRoutingMetadata,
    ) -> Self {
        Self {
            inbound_tag,
            user,
            source_addr,
            network,
            network_name,
            metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TcpRoutePlan {
    Freedom {
        target_addr: SocketAddr,
        outbound_tag: Option<String>,
    },
    Socks {
        target: NetLocation,
        outbound: OutboundSummary,
    },
    Vless {
        target: NetLocation,
        outbound: OutboundSummary,
    },
    Trojan {
        target: NetLocation,
        outbound: OutboundSummary,
    },
}

pub(crate) fn apply_routing_metadata(
    mut input: RoutingInput,
    metadata: InboundRoutingMetadata,
) -> RoutingInput {
    input.vless_route = metadata.vless_route;
    if let Some(local_addr) = metadata.local_addr {
        input.local_ips = vec![encode_ip(local_addr.ip())];
        input.local_port = local_addr.port() as u32;
    }
    if let Some(domain) = metadata.route_target_domain {
        input.target_domain = domain;
    }
    if let Some(protocol) = metadata.sniffed_protocol {
        input.protocol = protocol;
    }
    input.attributes = metadata.attributes;
    input
}

pub(super) async fn plan_tcp_route(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &DataPlaneRuntime,
    inbound_tag: &str,
    user: &str,
    source_addr: SocketAddr,
    routing_metadata: InboundRoutingMetadata,
) -> std::io::Result<Option<TcpRoutePlan>> {
    let (action, target_addr) = select_direct_outbound_for_location(
        resolver,
        remote_location,
        runtime,
        OutboundRoutingContext::new(
            inbound_tag,
            user,
            source_addr,
            2,
            "tcp",
            routing_metadata,
        ),
    )
    .await?;
    match action {
        DirectOutboundAction::Blackhole { .. } => Ok(None),
        DirectOutboundAction::Freedom { tag } => Ok(Some(TcpRoutePlan::Freedom {
            target_addr: target_addr.ok_or_else(|| {
                std::io::Error::other("TCP freedom route did not resolve target")
            })?,
            outbound_tag: tag,
        })),
        DirectOutboundAction::Socks { outbound } => Ok(Some(TcpRoutePlan::Socks {
            target: remote_location.clone(),
            outbound,
        })),
        DirectOutboundAction::Vless { outbound } => Ok(Some(TcpRoutePlan::Vless {
            target: remote_location.clone(),
            outbound,
        })),
        DirectOutboundAction::Trojan { outbound } => {
            Ok(Some(TcpRoutePlan::Trojan {
                target: remote_location.clone(),
                outbound,
            }))
        }
    }
}

pub(crate) async fn select_direct_outbound_for_location(
    resolver: &Arc<dyn Resolver>,
    remote_location: &NetLocation,
    runtime: &DataPlaneRuntime,
    context: OutboundRoutingContext<'_>,
) -> std::io::Result<(DirectOutboundAction, Option<SocketAddr>)> {
    let mut route_input = apply_routing_metadata(
        unresolved_connection_routing_input(
            context.inbound_tag,
            context.user,
            context.network,
            context.source_addr,
            remote_location,
        ),
        context.metadata,
    );
    if !runtime
        .allows_user_domain_access(&route_input.user, &route_input.target_domain)
    {
        return Ok((
            DirectOutboundAction::Blackhole {
                tag: USER_DOMAIN_ACCESS_BLACKHOLE_TAG.to_string(),
            },
            None,
        ));
    }

    let routing_location =
        routing_resolution_location(&route_input, remote_location);
    let domain_strategy = runtime.routing_domain_strategy();
    let mut resolved_for_routing = None;

    if runtime.routing_needs_target_ip_resolution(&route_input) {
        let addresses = resolve_all_addresses(resolver, &routing_location).await?;
        route_input.target_ips = encode_target_ips(&addresses);
        resolved_for_routing = Some(addresses);
    }
    route_input = enrich_route_input_if_needed(runtime, route_input).await;

    let selected = if domain_strategy == DomainStrategy::IpIfNonMatch
        && !route_input.target_domain.is_empty()
        && route_input.target_ips.is_empty()
    {
        match runtime
            .match_outbound_checked(&route_input)
            .map_err(invalid_routing_error)?
        {
            Some(outbound) => Some(outbound),
            None => {
                let addresses =
                    resolve_all_addresses(resolver, &routing_location).await?;
                route_input.target_ips = encode_target_ips(&addresses);
                resolved_for_routing = Some(addresses);
                route_input =
                    enrich_route_input_if_needed(runtime, route_input).await;
                runtime
                    .select_outbound_checked(&route_input)
                    .map_err(invalid_routing_error)?
            }
        }
    } else {
        runtime
            .select_outbound_checked(&route_input)
            .map_err(invalid_routing_error)?
    };

    let action = classify_selected_outbound(selected, context.network_name)?;
    match action {
        DirectOutboundAction::Blackhole { .. }
        | DirectOutboundAction::Socks { .. }
        | DirectOutboundAction::Vless { .. }
        | DirectOutboundAction::Trojan { .. } => Ok((action, None)),
        DirectOutboundAction::Freedom { .. } => {
            let target_addr = match remote_location.to_socket_addr_nonblocking() {
                Some(target_addr) => target_addr,
                None if routing_location == *remote_location => resolved_for_routing
                    .as_ref()
                    .and_then(|addresses| addresses.first().copied())
                    .unwrap_or(
                        resolve_single_address(resolver, remote_location).await?,
                    ),
                None => resolve_single_address(resolver, remote_location).await?,
            };
            Ok((action, Some(target_addr)))
        }
    }
}

fn invalid_routing_error(error: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
}

async fn resolve_all_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    let addresses = resolver.resolve_location(location).await?;
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("DNS lookup returned no addresses for {location}"),
        ));
    }
    Ok(addresses)
}

fn encode_target_ips(addresses: &[SocketAddr]) -> Vec<Vec<u8>> {
    addresses
        .iter()
        .map(|address| encode_ip(address.ip()))
        .collect()
}

fn routing_resolution_location(
    input: &RoutingInput,
    remote_location: &NetLocation,
) -> NetLocation {
    if remote_location.address().is_hostname()
        && !input.target_domain.is_empty()
        && remote_location.address().hostname() != Some(input.target_domain.as_str())
    {
        return NetLocation::new(
            Address::Hostname(input.target_domain.clone()),
            remote_location.port(),
        );
    }
    remote_location.clone()
}

async fn enrich_route_input_if_needed(
    runtime: &DataPlaneRuntime,
    mut input: RoutingInput,
) -> RoutingInput {
    if runtime.routing_needs_process_lookup(&input) {
        enrich_routing_input(&mut input).await;
    }
    input
}

pub(crate) fn connection_routing_input(
    inbound_tag: &str,
    user: &str,
    network: i32,
    source_addr: SocketAddr,
    target_addr: SocketAddr,
    target_location: &NetLocation,
) -> RoutingInput {
    let mut input = unresolved_connection_routing_input(
        inbound_tag,
        user,
        network,
        source_addr,
        target_location,
    );
    input.target_ips = vec![encode_ip(target_addr.ip())];
    input
}

fn unresolved_connection_routing_input(
    inbound_tag: &str,
    user: &str,
    network: i32,
    source_addr: SocketAddr,
    target_location: &NetLocation,
) -> RoutingInput {
    RoutingInput {
        inbound_tag: inbound_tag.to_string(),
        network,
        source_ips: vec![encode_ip(source_addr.ip())],
        target_ips: target_location
            .to_socket_addr_nonblocking()
            .map(|address| vec![encode_ip(address.ip())])
            .unwrap_or_default(),
        source_port: source_addr.port() as u32,
        target_port: target_location.port() as u32,
        target_domain: match target_location.address() {
            Address::Hostname(hostname) => hostname.clone(),
            _ => String::new(),
        },
        user: user.to_string(),
        ..RoutingInput::default()
    }
}

pub(crate) fn select_direct_outbound(
    runtime: &DataPlaneRuntime,
    input: &RoutingInput,
    network_name: &str,
) -> std::io::Result<DirectOutboundAction> {
    if !runtime.allows_user_domain_access(&input.user, &input.target_domain) {
        return Ok(DirectOutboundAction::Blackhole {
            tag: USER_DOMAIN_ACCESS_BLACKHOLE_TAG.to_string(),
        });
    }

    let outbound = runtime
        .select_outbound_checked(input)
        .map_err(invalid_routing_error)?;
    classify_selected_outbound(outbound, network_name)
}

fn classify_selected_outbound(
    outbound: Option<OutboundSummary>,
    network_name: &str,
) -> std::io::Result<DirectOutboundAction> {
    let Some(outbound) = outbound else {
        return Ok(DirectOutboundAction::Freedom { tag: None });
    };
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(DirectOutboundAction::Freedom {
            tag: Some(outbound.tag),
        }),
        "blackhole" => Ok(DirectOutboundAction::Blackhole { tag: outbound.tag }),
        "socks" if network_name.eq_ignore_ascii_case("tcp") => {
            Ok(DirectOutboundAction::Socks { outbound })
        }
        "vless" if network_name.eq_ignore_ascii_case("tcp") => {
            Ok(DirectOutboundAction::Vless { outbound })
        }
        "trojan"
            if network_name.eq_ignore_ascii_case("tcp")
                || network_name.eq_ignore_ascii_case("udp") =>
        {
            Ok(DirectOutboundAction::Trojan { outbound })
        }
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
