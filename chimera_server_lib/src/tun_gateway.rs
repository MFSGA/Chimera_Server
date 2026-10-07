//! Linux site-to-site TUN ingress.
//!
//! This is a device-owned gateway service, not an Xray TUN inbound. It feeds
//! packets through watfaq-netstack, then sends accepted TCP and UDP flows
//! through Chimera's existing Dokodemo routing paths.

use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{Error, config::def::TunGatewayConfig};
use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::DokodemoDoorConfig,
    handler::{
        dokodemo::DokodemoDoorTcpHandler,
        tcp::tcp_handler::{TcpServerConnectionContext, TcpServerHandler},
    },
    runtime::DataPlaneRuntime,
    session::dispatcher::process_stream_with_context,
};
use futures::TryStreamExt;
use rtnetlink::{Handle as NetlinkHandle, RouteMessageBuilder};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use watfaq_netstack::{NetStack, Packet, TcpStream};

#[cfg(test)]
const NETSTACK_MTU: usize = 1500;
const MIN_TUN_GATEWAY_MTU: usize = 1280;
const MAX_TUN_GATEWAY_MTU: usize = 9000;
const NETSTACK_MAX_TCP_STREAMS: usize = 512;
const MAX_MANAGED_TUN_PREFIXES: usize = 128;
const DEFAULT_TUN_ROUTE_TABLE: u32 = 10_001;
const DEFAULT_TUN_ROUTE_RULE_PRIORITY: u32 = 10_001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpPrefix {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

impl IpPrefix {
    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4(network, prefix), IpAddr::V4(address)) => {
                let mask = u32::MAX << (32 - prefix);
                u32::from(network) == u32::from(address) & mask
            }
            (Self::V6(network, prefix), IpAddr::V6(address)) => {
                let mask = u128::MAX << (128 - prefix);
                u128::from(network) == u128::from(address) & mask
            }
            _ => false,
        }
    }

    fn family(self) -> u8 {
        match self {
            Self::V4(..) => 4,
            Self::V6(..) => 6,
        }
    }
}

fn parse_managed_prefix(value: &str, field: &str) -> Result<IpPrefix, String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("{field} entries must be IP CIDRs"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| format!("{field} entries must be IP CIDRs"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("{field} entries must use a valid prefix length"))?;
    match address {
        IpAddr::V4(address) if (1..=32).contains(&prefix) => {
            let mask = u32::MAX << (32 - prefix);
            Ok(IpPrefix::V4(
                Ipv4Addr::from(u32::from(address) & mask),
                prefix,
            ))
        }
        IpAddr::V6(address) if (1..=128).contains(&prefix) => {
            let mask = u128::MAX << (128 - prefix);
            Ok(IpPrefix::V6(
                Ipv6Addr::from(u128::from(address) & mask),
                prefix,
            ))
        }
        IpAddr::V4(_) => Err(format!(
            "{field} prefixes must be from 1 to 32; default routes are not supported"
        )),
        IpAddr::V6(_) => Err(format!(
            "{field} prefixes must be from 1 to 128; default routes are not supported"
        )),
    }
}

fn parse_managed_prefixes(
    values: &[String],
    field: &str,
) -> Result<Vec<IpPrefix>, String> {
    if values.len() > MAX_MANAGED_TUN_PREFIXES {
        return Err(format!(
            "tunGateway.{field} supports at most {MAX_MANAGED_TUN_PREFIXES} prefixes"
        ));
    }
    let mut seen = HashSet::with_capacity(values.len());
    values
        .iter()
        .map(|value| {
            let prefix =
                parse_managed_prefix(value, &format!("tunGateway.{field}"))?;
            if !seen.insert(prefix) {
                return Err(format!(
                    "tunGateway.{field} contains duplicate prefix {value}"
                ));
            }
            Ok(prefix)
        })
        .collect()
}

#[derive(Debug)]
struct TunDeviceCreateError {
    device_name: String,
    source: std::io::Error,
}

impl std::fmt::Display for TunDeviceCreateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "failed to create tunGateway device {}: {}",
            self.device_name, self.source
        )
    }
}

impl std::error::Error for TunDeviceCreateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TunGatewayPlan {
    name: String,
    address: Ipv4Addr,
    prefix_len: u8,
    ipv6_address: Option<(Ipv6Addr, u8)>,
    mtu: usize,
    routes: Vec<IpPrefix>,
    route_from: Vec<IpPrefix>,
    route_input_interface: Option<String>,
    route_table: u32,
    route_rule_priority: u32,
    inbound_tag: String,
    user_level: u32,
    max_tcp_connections: usize,
    max_udp_sessions: usize,
}

impl TryFrom<TunGatewayConfig> for TunGatewayPlan {
    type Error = String;

    fn try_from(config: TunGatewayConfig) -> Result<Self, Self::Error> {
        if config.name.is_empty()
            || config.name.len() > 15
            || !config
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(
                "tunGateway.name must contain 1-15 ASCII letters, digits, '.', '_' or '-'".into(),
            );
        }
        if config.inbound_tag.trim().is_empty() {
            return Err("tunGateway.inboundTag must not be empty".into());
        }
        let (address, prefix_len) = config
            .address
            .split_once('/')
            .ok_or_else(|| "tunGateway.address must be an IPv4 CIDR".to_string())?;
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|_| "tunGateway.address must be an IPv4 CIDR".to_string())?;
        let prefix_len = prefix_len.parse::<u8>().map_err(|_| {
            "tunGateway.address must use a prefix length from 1 to 32".to_string()
        })?;
        if !(1..=32).contains(&prefix_len) {
            return Err(
                "tunGateway.address must use a prefix length from 1 to 32".into()
            );
        }
        let ipv6_address = config
            .ipv6_address
            .as_deref()
            .map(parse_ipv6_interface_address)
            .transpose()?;
        if !(MIN_TUN_GATEWAY_MTU..=MAX_TUN_GATEWAY_MTU).contains(&config.mtu) {
            return Err(format!(
                "tunGateway.mtu must be from {MIN_TUN_GATEWAY_MTU} to {MAX_TUN_GATEWAY_MTU}"
            ));
        }
        let routes = parse_managed_prefixes(&config.routes, "routes")?;
        let route_from = parse_managed_prefixes(&config.route_from, "routeFrom")?;
        let route_input_interface = config.route_input_interface;
        if routes.is_empty() != route_from.is_empty() {
            return Err(
                "tunGateway.routes and tunGateway.routeFrom must both be configured"
                    .into(),
            );
        }
        let route_table = config.route_table.unwrap_or(DEFAULT_TUN_ROUTE_TABLE);
        let route_rule_priority = config
            .route_rule_priority
            .unwrap_or(DEFAULT_TUN_ROUTE_RULE_PRIORITY);
        if routes.is_empty()
            && (route_input_interface.is_some()
                || config.route_table.is_some()
                || config.route_rule_priority.is_some())
        {
            return Err(
                "tunGateway.routeInputInterface, routeTable and routeRulePriority require managed routes"
                    .into(),
            );
        }
        if !routes.is_empty() {
            let input_interface =
                route_input_interface.as_deref().ok_or_else(|| {
                    "tunGateway.routeInputInterface is required with managed routes"
                        .to_string()
                })?;
            if input_interface == config.name
                || input_interface.is_empty()
                || input_interface.len() > 15
                || !input_interface.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)
                })
            {
                return Err(
                    "tunGateway.routeInputInterface must name a different Linux interface using 1-15 ASCII letters, digits, '.', '_' or '-'"
                        .into(),
                );
            }
            if matches!(route_table, 0 | 253 | 254 | 255) {
                return Err(
                    "tunGateway.routeTable must not use a reserved Linux route table ID".into(),
                );
            }
            if matches!(route_rule_priority, 0 | 32_766 | 32_767) {
                return Err(
                    "tunGateway.routeRulePriority must not use a reserved Linux rule priority"
                        .into(),
                );
            }
            for route in &routes {
                if route.contains(IpAddr::V4(address))
                    || ipv6_address.is_some_and(|(address, _)| {
                        route.contains(IpAddr::V6(address))
                    })
                {
                    return Err(
                        "tunGateway.routes must not include the TUN interface address".into(),
                    );
                }
                if route.family() == 6 && ipv6_address.is_none() {
                    return Err(
                        "IPv6 tunGateway.routes require tunGateway.ipv6Address"
                            .into(),
                    );
                }
            }
            for source in &route_from {
                if source.contains(IpAddr::V4(address))
                    || ipv6_address
                        .is_some_and(|(address, _)| source.contains(address.into()))
                {
                    return Err(
                        "tunGateway.routeFrom must identify forwarded clients, not TUN interface addresses"
                            .into(),
                    );
                }
            }
            for family in [4, 6] {
                if routes.iter().any(|prefix| prefix.family() == family)
                    != route_from.iter().any(|prefix| prefix.family() == family)
                {
                    return Err(format!(
                        "tunGateway.routes and routeFrom must both include IPv{family} prefixes when that family is enabled"
                    ));
                }
            }
        }
        if !(1..=NETSTACK_MAX_TCP_STREAMS).contains(&config.max_tcp_connections) {
            return Err(format!(
                "tunGateway.maxTcpConnections must be from 1 to {NETSTACK_MAX_TCP_STREAMS}"
            ));
        }
        if !(1..=1024).contains(&config.max_udp_sessions) {
            return Err("tunGateway.maxUdpSessions must be from 1 to 1024".into());
        }

        Ok(Self {
            name: config.name,
            address,
            prefix_len,
            ipv6_address,
            mtu: config.mtu,
            routes,
            route_from,
            route_input_interface,
            route_table,
            route_rule_priority,
            inbound_tag: config.inbound_tag,
            user_level: config.user_level,
            max_tcp_connections: config.max_tcp_connections,
            max_udp_sessions: config.max_udp_sessions,
        })
    }
}

fn parse_ipv6_interface_address(value: &str) -> Result<(Ipv6Addr, u8), String> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| "tunGateway.ipv6Address must be an IPv6 CIDR".to_string())?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| "tunGateway.ipv6Address must be an IPv6 CIDR".to_string())?;
    let prefix_len = prefix_len.parse::<u8>().map_err(|_| {
        "tunGateway.ipv6Address must use a prefix length from 1 to 128".to_string()
    })?;
    if !(1..=128).contains(&prefix_len) {
        return Err(
            "tunGateway.ipv6Address must use a prefix length from 1 to 128".into(),
        );
    }
    Ok((address, prefix_len))
}

pub(crate) struct TunGatewayTask {
    pub(crate) task: JoinHandle<Result<(), Error>>,
    pub(crate) cancellation: CancellationToken,
}

pub(crate) async fn start_server(
    plan: TunGatewayPlan,
    runtime: DataPlaneRuntime,
) -> Result<TunGatewayTask, Error> {
    let mut config = tun::Configuration::default();
    config
        .tun_name(&plan.name)
        .address(plan.address)
        .netmask(prefix_netmask(plan.prefix_len))
        .mtu(plan.mtu as u16)
        .layer(tun::Layer::L3)
        .up();
    config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });

    let device = tun::create_as_async(&config).map_err(|error| {
        let error = std::io::Error::from(error);
        let error_kind = error.kind();
        tracing::error!(
            tun_name = %plan.name,
            error_kind = ?error_kind,
            raw_os_error = ?error.raw_os_error(),
            %error,
            "failed to create Linux site-to-site TUN device"
        );
        Error::Io(std::io::Error::new(
            error_kind,
            TunDeviceCreateError {
                device_name: plan.name.clone(),
                source: error,
            },
        ))
    })?;
    if let Some((address, prefix_len)) = plan.ipv6_address {
        configure_ipv6_tun_address(&plan.name, address, prefix_len)
            .await
            .map_err(|source| {
                tracing::error!(
                    tun_name = %plan.name,
                    ipv6_address = %format_args!("{address}/{prefix_len}"),
                    %source,
                    "failed to configure Linux site-to-site TUN IPv6 address"
                );
                Error::Io(std::io::Error::other(TunIpv6AddressConfigureError {
                    device_name: plan.name.clone(),
                    address,
                    prefix_len,
                    source,
                }))
            })?;
    }
    let managed_routing = install_tun_routing(&plan).await?;
    tracing::info!(
        tun_name = %plan.name,
        address = %format_args!("{}/{}", plan.address, plan.prefix_len),
        ipv6_address = plan
            .ipv6_address
            .map(|(address, prefix_len)| format!("{address}/{prefix_len}")),
        inbound_tag = %plan.inbound_tag,
        mtu = plan.mtu,
        max_tcp_connections = plan.max_tcp_connections,
        managed_routes = plan.routes.len(),
        route_source_prefixes = plan.route_from.len(),
        route_table = plan.route_table,
        route_rule_priority = plan.route_rule_priority,
        "starting Linux site-to-site TUN gateway"
    );
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(run_server_with_routing(
        device,
        plan,
        runtime,
        cancellation.clone(),
        managed_routing,
    ));
    Ok(TunGatewayTask { task, cancellation })
}

#[derive(Debug)]
struct TunIpv6AddressConfigureError {
    device_name: String,
    address: Ipv6Addr,
    prefix_len: u8,
    source: std::io::Error,
}

impl std::fmt::Display for TunIpv6AddressConfigureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "failed to configure tunGateway IPv6 address {}/{} on {}: {}",
            self.address, self.prefix_len, self.device_name, self.source
        )
    }
}

impl std::error::Error for TunIpv6AddressConfigureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

async fn configure_ipv6_tun_address(
    device_name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
) -> std::io::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    let configure_address = async {
        let mut links = handle
            .link()
            .get()
            .match_name(device_name.to_string())
            .execute();
        let link = links.try_next().await.map_err(std::io::Error::other)?;
        let link = link.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("TUN interface {device_name} was not found"),
            )
        })?;
        handle
            .address()
            .add(link.header.index, IpAddr::V6(address), prefix_len)
            .execute()
            .await
            .map_err(std::io::Error::other)
    };

    tokio::select! {
        result = configure_address => result,
        _ = connection => Err(std::io::Error::other(
            "Linux route-netlink connection ended before IPv6 address setup completed",
        )),
    }
}

struct AbortOnDropNetlinkTask(JoinHandle<()>);

impl Drop for AbortOnDropNetlinkTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ManagedTunRouting {
    handle: NetlinkHandle,
    _connection: AbortOnDropNetlinkTask,
    routes: Vec<rtnetlink::packet_route::route::RouteMessage>,
    rules: Vec<rtnetlink::packet_route::rule::RuleMessage>,
}

impl ManagedTunRouting {
    async fn remove(mut self) -> std::io::Result<()> {
        let mut first_error = None;
        for rule in self.rules.drain(..).rev() {
            if let Err(error) = self.handle.rule().del(rule).execute().await {
                tracing::warn!(%error, "failed to remove a managed TUN source-routing rule");
                first_error.get_or_insert_with(|| std::io::Error::other(error));
            }
        }
        for route in self.routes.drain(..).rev() {
            if let Err(error) = self.handle.route().del(route).execute().await {
                tracing::warn!(%error, "failed to remove a managed TUN route");
                first_error.get_or_insert_with(|| std::io::Error::other(error));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn build_tun_route(
    prefix: IpPrefix,
    interface_index: u32,
    table_id: u32,
) -> rtnetlink::packet_route::route::RouteMessage {
    use rtnetlink::packet_route::route::RouteScope;

    match prefix {
        IpPrefix::V4(network, length) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(network, length)
            .output_interface(interface_index)
            .table_id(table_id)
            .scope(RouteScope::Link)
            .build(),
        IpPrefix::V6(network, length) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(network, length)
            .output_interface(interface_index)
            .table_id(table_id)
            .scope(RouteScope::Link)
            .build(),
    }
}

fn build_tun_source_rule(
    prefix: IpPrefix,
    input_interface: &str,
    table_id: u32,
    priority: u32,
) -> rtnetlink::packet_route::rule::RuleMessage {
    use rtnetlink::packet_route::{AddressFamily, rule::RuleAction};

    let mut message = rtnetlink::packet_route::rule::RuleMessage::default();
    message.header.table = if table_id <= u8::MAX as u32 {
        table_id as u8
    } else {
        0
    };
    message.header.action = RuleAction::ToTable;
    message
        .attributes
        .push(rtnetlink::packet_route::rule::RuleAttribute::Priority(
            priority,
        ));
    message
        .attributes
        .push(rtnetlink::packet_route::rule::RuleAttribute::Iifname(
            input_interface.to_string(),
        ));
    if table_id > u8::MAX as u32 {
        message.attributes.push(
            rtnetlink::packet_route::rule::RuleAttribute::Table(table_id),
        );
    }
    match prefix {
        IpPrefix::V4(network, length) => {
            message.header.family = AddressFamily::Inet;
            message.header.src_len = length;
            message.attributes.push(
                rtnetlink::packet_route::rule::RuleAttribute::Source(network.into()),
            );
        }
        IpPrefix::V6(network, length) => {
            message.header.family = AddressFamily::Inet6;
            message.header.src_len = length;
            message.attributes.push(
                rtnetlink::packet_route::rule::RuleAttribute::Source(network.into()),
            );
        }
    }
    message
}

async fn install_tun_routing(
    plan: &TunGatewayPlan,
) -> Result<Option<ManagedTunRouting>, Error> {
    if plan.routes.is_empty() {
        return Ok(None);
    }

    let (connection, handle, _) = rtnetlink::new_connection().map_err(|source| {
        Error::Io(std::io::Error::other(format!(
            "failed to open route-netlink for tunGateway: {source}"
        )))
    })?;
    let connection = AbortOnDropNetlinkTask(tokio::spawn(connection));
    let mut links = handle.link().get().match_name(plan.name.clone()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|source| {
            Error::Io(std::io::Error::other(format!(
                "failed to find TUN interface {} for managed routes: {source}",
                plan.name
            )))
        })?
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "TUN interface {} was not found for managed routes",
                    plan.name
                ),
            ))
        })?;
    let input_interface =
        plan.route_input_interface.as_deref().ok_or_else(|| {
            Error::InvalidConfig(
                "tunGateway.routeInputInterface is required with managed routes"
                    .into(),
            )
        })?;
    let mut input_links = handle
        .link()
        .get()
        .match_name(input_interface.to_string())
        .execute();
    let input_link = input_links
        .try_next()
        .await
        .map_err(|source| {
            Error::Io(std::io::Error::other(format!(
                "failed to find tunGateway.routeInputInterface {input_interface}: {source}"
            )))
        })?;
    if input_link.is_none() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "tunGateway.routeInputInterface {input_interface} was not found"
            ),
        )));
    }
    let mut managed = ManagedTunRouting {
        handle,
        _connection: connection,
        routes: Vec::with_capacity(plan.routes.len()),
        rules: Vec::with_capacity(plan.route_from.len()),
    };

    if let Err(source) =
        verify_managed_route_table_is_empty(&managed.handle, plan.route_table).await
    {
        return Err(Error::Io(std::io::Error::other(format!(
            "tunGateway.routeTable {} must be empty before startup: {source}",
            plan.route_table
        ))));
    }

    for prefix in &plan.routes {
        let route = build_tun_route(*prefix, link.header.index, plan.route_table);
        if let Err(source) =
            managed.handle.route().add(route.clone()).execute().await
        {
            let error = Error::Io(std::io::Error::other(format!(
                "failed to install tunGateway route {prefix:?} in table {}: {source}",
                plan.route_table
            )));
            if let Err(cleanup_error) = managed.remove().await {
                tracing::error!(%cleanup_error, "failed to roll back partial TUN route setup");
            }
            return Err(error);
        }
        managed.routes.push(route);
    }

    if let Err(source) =
        verify_rule_priority_is_available(&managed.handle, plan.route_rule_priority)
            .await
    {
        let error = Error::Io(std::io::Error::other(format!(
            "tunGateway.routeRulePriority {} is already in use: {source}",
            plan.route_rule_priority
        )));
        if let Err(cleanup_error) = managed.remove().await {
            tracing::error!(%cleanup_error, "failed to roll back TUN routes after a rule-priority conflict");
        }
        return Err(error);
    }

    for prefix in &plan.route_from {
        let rule = build_tun_source_rule(
            *prefix,
            input_interface,
            plan.route_table,
            plan.route_rule_priority,
        );
        let mut add_rule = managed.handle.rule().add();
        *add_rule.message_mut() = rule.clone();
        if let Err(source) = add_rule.execute().await {
            let error = Error::Io(std::io::Error::other(format!(
                "failed to install tunGateway source rule {prefix:?} at priority {}: {source}",
                plan.route_rule_priority
            )));
            if let Err(cleanup_error) = managed.remove().await {
                tracing::error!(%cleanup_error, "failed to roll back partial TUN route setup");
            }
            return Err(error);
        }
        managed.rules.push(rule);
    }

    Ok(Some(managed))
}

async fn verify_managed_route_table_is_empty(
    handle: &NetlinkHandle,
    table_id: u32,
) -> Result<(), String> {
    use rtnetlink::RouteMessageBuilder;

    for route in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut routes = handle.route().get(route).execute();
        while let Some(route) =
            routes.try_next().await.map_err(|error| error.to_string())?
        {
            let route_table = route
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    rtnetlink::packet_route::route::RouteAttribute::Table(table) => {
                        Some(*table)
                    }
                    _ => None,
                })
                .unwrap_or(u32::from(route.header.table));
            if route_table == table_id {
                return Err("route table already contains a route".into());
            }
        }
    }
    Ok(())
}

async fn verify_rule_priority_is_available(
    handle: &NetlinkHandle,
    priority: u32,
) -> Result<(), String> {
    use rtnetlink::IpVersion;

    for version in [IpVersion::V4, IpVersion::V6] {
        let mut rules = handle.rule().get(version).execute();
        while let Some(rule) =
            rules.try_next().await.map_err(|error| error.to_string())?
        {
            let rule_priority =
                rule.attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        rtnetlink::packet_route::rule::RuleAttribute::Priority(
                            priority,
                        ) => Some(*priority),
                        _ => None,
                    });
            if rule_priority == Some(priority) {
                return Err(format!("rule priority {priority} is already in use"));
            }
        }
    }
    Ok(())
}

fn prefix_netmask(prefix_len: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::MAX << (32 - prefix_len))
}

#[cfg(test)]
async fn run_server<D: PacketDevice + 'static>(
    device: D,
    plan: TunGatewayPlan,
    runtime: DataPlaneRuntime,
    cancellation: CancellationToken,
) -> Result<(), Error> {
    run_server_with_routing(device, plan, runtime, cancellation, None).await
}

async fn run_server_with_routing<D: PacketDevice + 'static>(
    device: D,
    plan: TunGatewayPlan,
    runtime: DataPlaneRuntime,
    cancellation: CancellationToken,
    managed_routing: Option<ManagedTunRouting>,
) -> Result<(), Error> {
    use futures::{SinkExt, StreamExt};

    let (stack, mut tcp_listener, udp_socket) =
        NetStack::new_with_mtu(plan.mtu).map_err(Error::Io)?;
    let (mut packet_sink, mut packet_stream) = stack.split();
    let (mut udp_reader, udp_writer) = udp_socket.split();
    let udp_reply: NetstackUdpReply =
        Arc::new(move |payload, source, destination| {
            let mut writer = udp_writer.clone();
            Box::pin(async move {
                let len = payload.len();
                writer
                    .send(watfaq_netstack::UdpPacket::from((
                        watfaq_netstack::Packet::new(payload),
                        source,
                        destination,
                    )))
                    .await?;
                Ok(len)
            })
        });
    let udp_forwarder = crate::session::udp::dokodemo::TunUdpForwarder::new(
        plan.inbound_tag.clone(),
        plan.user_level,
        runtime.clone(),
        Arc::new(NetstackUdpReplySink::new(
            udp_reply,
            Some(SocketAddr::new(plan.address.into(), 0)),
            plan.ipv6_address
                .map(|(address, _)| SocketAddr::new(address.into(), 0)),
        )),
        plan.max_udp_sessions,
    );
    let tcp_slots = Arc::new(Semaphore::new(plan.max_tcp_connections));
    let udp_failures = AtomicUsize::new(0);
    let mut packet_buffer = vec![0; plan.mtu];
    let mut first_tcp_payload_packet_logged = false;

    let mut terminal_error = loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                tracing::debug!(inbound_tag = %plan.inbound_tag, "TUN gateway shutdown requested");
                break None;
            }
            result = device.recv(&mut packet_buffer) => {
                match result {
                    Ok(length) if length <= packet_buffer.len() => {
                        if !first_tcp_payload_packet_logged
                            && let Some(payload_bytes) =
                                tcp_application_payload_len(&packet_buffer[..length])
                            && payload_bytes > 0
                        {
                            tracing::debug!(
                                packet_bytes = length,
                                payload_bytes,
                                "TUN device received its first TCP application payload packet"
                            );
                            first_tcp_payload_packet_logged = true;
                        }
                        let packet = Packet::new(packet_buffer[..length].to_vec());
                        let Some(result) = await_or_cancel(
                            &cancellation,
                            packet_sink.send(packet),
                        )
                        .await else {
                            break None;
                        };
                        if let Err(error) = result {
                            tracing::error!(inbound_tag = %plan.inbound_tag, %error, "TUN packet stack stopped accepting packets");
                            break Some(Error::Io(std::io::Error::other(error)));
                        }
                    }
                    Ok(_) => {
                        tracing::warn!(inbound_tag = %plan.inbound_tag, "TUN returned a packet larger than its configured MTU");
                    }
                    Err(error) => {
                        tracing::error!(inbound_tag = %plan.inbound_tag, %error, "TUN device read failed");
                        break Some(Error::Io(error));
                    }
                }
            }
            packet = packet_stream.next() => {
                let Some(packet) = packet else {
                    tracing::error!(inbound_tag = %plan.inbound_tag, "TUN packet stack output closed");
                    break Some(Error::Io(std::io::Error::other(
                        "TUN packet stack output closed",
                    )));
                };
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        tracing::error!(inbound_tag = %plan.inbound_tag, %error, "TUN packet stack output failed");
                        break Some(Error::Io(std::io::Error::other(error)));
                    }
                };
                let Some(result) =
                    await_or_cancel(&cancellation, device.send(packet.data())).await
                else {
                    break None;
                };
                match result {
                    Ok(length) if length == packet.data().len() => {}
                    Ok(length) => {
                        tracing::warn!(inbound_tag = %plan.inbound_tag, written = length, expected = packet.data().len(), "TUN device performed a short packet write");
                        break Some(Error::Io(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            format!("TUN device wrote {length} of {} packet bytes", packet.data().len()),
                        )));
                    }
                    Err(error) => {
                        tracing::error!(inbound_tag = %plan.inbound_tag, %error, "TUN device write failed");
                        break Some(Error::Io(error));
                    }
                }
            }
            stream = tcp_listener.next() => {
                let Some(stream) = stream else {
                    tracing::error!(inbound_tag = %plan.inbound_tag, "TUN TCP listener stopped");
                    break Some(Error::Io(std::io::Error::other(
                        "TUN TCP listener stopped",
                    )));
                };
                let permit = match tcp_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(inbound_tag = %plan.inbound_tag, limit = plan.max_tcp_connections, "TUN TCP connection rejected at configured limit");
                        drop(stream);
                        continue;
                    }
                };
                let source = stream.local_addr();
                let target = stream.remote_addr();
                let connection_runtime = runtime.clone();
                let inbound_tag = plan.inbound_tag.clone();
                let user_level = plan.user_level;
                let handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(Box::new(
                    DokodemoDoorTcpHandler::new(
                        DokodemoDoorConfig {
                            target: NetLocation::from_ip_addr(target.ip(), target.port()),
                            follow_redirect: true,
                            user_level,
                        },
                        &inbound_tag,
                    ),
                ));
                let connection_context = TcpServerConnectionContext {
                    original_destination: Some(NetLocation::from_ip_addr(target.ip(), target.port())),
                    peer_addr: Some(source),
                    ..TcpServerConnectionContext::default()
                };
                let resolver = runtime.resolver();
                if !runtime.spawn_inbound_connection(async move {
                    let _permit = permit;
                    if let Err(error) = process_stream_with_context(
                        GatewayTcpStream {
                            stream,
                            first_read_logged: false,
                        },
                        handler,
                        resolver,
                        source,
                        connection_runtime,
                        connection_context,
                        None,
                    )
                    .await
                    {
                        tracing::debug!(peer = %source, %error, "TUN TCP flow ended");
                    }
                }) {
                    tracing::warn!(inbound_tag = %plan.inbound_tag, "TUN TCP connection rejected while server is draining");
                }
            }
            packet = udp_reader.recv() => {
                let Some(packet) = packet else {
                    tracing::error!(inbound_tag = %plan.inbound_tag, "TUN UDP packet reader stopped");
                    break Some(Error::Io(std::io::Error::other(
                        "TUN UDP packet reader stopped",
                    )));
                };
                let Some(result) =
                    await_or_cancel(&cancellation, udp_forwarder.forward(packet)).await
                else {
                    break None;
                };
                if let Err(error) = result {
                    let failures =
                        udp_failures.fetch_add(1, Ordering::Relaxed) + 1;
                    if failures.is_power_of_two() {
                        if error.kind() == std::io::ErrorKind::WouldBlock {
                            tracing::warn!(inbound_tag = %plan.inbound_tag, failures, limit = plan.max_udp_sessions, "TUN UDP sessions rejected at configured limit");
                        } else {
                            tracing::debug!(inbound_tag = %plan.inbound_tag, failures, %error, "TUN UDP datagrams could not be forwarded");
                        }
                    }
                }
            }
        }
    };

    // Join the netstack's internal packet engine before releasing the device.
    if let Err(error) = tcp_listener.shutdown().await {
        tracing::error!(
            inbound_tag = %plan.inbound_tag,
            %error,
            "TUN TCP packet engine failed to shut down cleanly"
        );
        if terminal_error.is_none() {
            terminal_error = Some(Error::Io(error));
        }
    }

    if let Some(managed_routing) = managed_routing
        && let Err(error) = managed_routing.remove().await
    {
        tracing::error!(
            inbound_tag = %plan.inbound_tag,
            %error,
            "failed to remove managed TUN routes during shutdown"
        );
        if terminal_error.is_none() {
            terminal_error = Some(Error::Io(error));
        }
    }

    terminal_error.map_or(Ok(()), Err)
}

async fn await_or_cancel<T>(
    cancellation: &CancellationToken,
    future: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        _ = cancellation.cancelled() => None,
        result = future => Some(result),
    }
}

type NetstackUdpReply = Arc<
    dyn Fn(
            Vec<u8>,
            SocketAddr,
            SocketAddr,
        ) -> futures::future::BoxFuture<'static, std::io::Result<usize>>
        + Send
        + Sync,
>;

struct NetstackUdpReplySink {
    local_ipv4_addr: Option<SocketAddr>,
    local_ipv6_addr: Option<SocketAddr>,
    reply: NetstackUdpReply,
}

impl NetstackUdpReplySink {
    fn new(
        reply: NetstackUdpReply,
        local_ipv4_addr: Option<SocketAddr>,
        local_ipv6_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            local_ipv4_addr,
            local_ipv6_addr,
            reply,
        }
    }
}

#[async_trait::async_trait]
impl crate::session::udp::dokodemo::UdpReplySink for NetstackUdpReplySink {
    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_ipv4_addr.or(self.local_ipv6_addr)
    }

    fn local_addr_for(&self, client_addr: SocketAddr) -> Option<SocketAddr> {
        if client_addr.is_ipv4() {
            self.local_ipv4_addr
        } else {
            self.local_ipv6_addr
        }
    }

    async fn send_response(
        &self,
        payload: &[u8],
        client_addr: SocketAddr,
        source_addr: SocketAddr,
    ) -> std::io::Result<usize> {
        (self.reply)(payload.to_vec(), source_addr, client_addr).await
    }
}

#[async_trait::async_trait]
trait PacketDevice: Send + Sync {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize>;
    async fn send(&self, buffer: &[u8]) -> std::io::Result<usize>;
}

#[async_trait::async_trait]
impl PacketDevice for tun::AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        tun::AsyncDevice::recv(self, buffer).await
    }

    async fn send(&self, buffer: &[u8]) -> std::io::Result<usize> {
        tun::AsyncDevice::send(self, buffer).await
    }
}

struct GatewayTcpStream {
    stream: TcpStream,
    first_read_logged: bool,
}

fn tcp_application_payload_len(packet: &[u8]) -> Option<usize> {
    let (ip_header_len, tcp_offset, packet_end) = match packet.first()? >> 4 {
        4 if packet.len() >= 20 && packet[9] == 6 => {
            let ip_header_len = usize::from(packet[0] & 0x0f) * 4;
            let packet_end = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if ip_header_len < 20 || packet_end > packet.len() {
                return None;
            }
            (ip_header_len, ip_header_len, packet_end)
        }
        6 if packet.len() >= 40 && packet[6] == 6 => {
            let packet_end =
                40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if packet_end > packet.len() {
                return None;
            }
            (40, 40, packet_end)
        }
        _ => return None,
    };
    let tcp_header_len = usize::from(*packet.get(tcp_offset + 12)? >> 4) * 4;
    let payload_offset = ip_header_len.checked_add(tcp_header_len)?;
    (tcp_header_len >= 20 && payload_offset <= packet_end)
        .then_some(packet_end - payload_offset)
}

impl AsyncRead for GatewayTcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let result = std::pin::Pin::new(&mut self.stream).poll_read(cx, buffer);
        if !self.first_read_logged
            && matches!(&result, std::task::Poll::Ready(Ok(())))
            && !buffer.filled().is_empty()
        {
            tracing::debug!(
                source = %self.stream.local_addr(),
                target = %self.stream.remote_addr(),
                payload_bytes = buffer.filled().len(),
                "TUN TCP stream received its first application payload"
            );
            self.first_read_logged = true;
        }
        result
    }
}

impl AsyncWrite for GatewayTcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for GatewayTcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}

impl AsyncStream for GatewayTcpStream {}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener as HostTcpListener,
        net::UdpSocket as HostUdpSocket,
        sync::{Mutex, mpsc, oneshot},
        time::timeout,
    };
    use tokio_util::sync::CancellationToken;

    use crate::runtime::{OutboundSummary, RuntimeState};
    #[cfg(feature = "vless-reverse")]
    use crate::{
        config::rule::{
            NetworkListConfig, PortListConfig, PortRangeConfig, RoutingConfig,
            RuleConfig,
        },
        handler::vless_reverse::{
            bridge_worker::{BridgeDispatchContext, MuxServerWorker},
            mux_frame::{FrameMetadata, FrameOption, SessionStatus},
            mux_io::{
                MuxFrame, XRAY_MUX_UDP_PACKET_SIZE, encode_frame,
                read_frame_with_source_and_local,
            },
            session_stream::ReverseSessionStream,
            site_policy::{
                SitePrefixMapConfig, SiteTargetAllowConfig, SiteToSiteConfig,
                SiteToSitePolicy,
            },
        },
        resolver::NativeResolver,
        routing_state::RoutingState,
        session::udp::{
            SessionUdpEvent, TargetedUdpSessionKey,
            dokodemo::{TunUdpForwarder, UdpReplySink},
            session_worker::{
                ReverseSessionUdpWorkerStart, expire_session_udp_worker,
                replace_reverse_session_udp_worker, terminate_session_udp_worker,
            },
        },
    };
    #[cfg(feature = "vless-reverse")]
    use bytes::Bytes;

    use super::*;

    fn config() -> TunGatewayConfig {
        TunGatewayConfig {
            name: "site-tun".into(),
            address: "10.254.0.1/24".into(),
            ipv6_address: None,
            mtu: NETSTACK_MTU,
            routes: Vec::new(),
            route_from: Vec::new(),
            route_input_interface: None,
            route_table: None,
            route_rule_priority: None,
            inbound_tag: "office-tun".into(),
            user_level: 2,
            max_tcp_connections: 32,
            max_udp_sessions: 128,
        }
    }

    #[cfg(feature = "vless-reverse")]
    struct ChannelUdpReplySink {
        local_addr: SocketAddr,
        responses: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    }

    #[cfg(feature = "vless-reverse")]
    #[async_trait::async_trait]
    impl UdpReplySink for ChannelUdpReplySink {
        fn local_addr(&self) -> Option<SocketAddr> {
            Some(self.local_addr)
        }

        async fn send_response(
            &self,
            payload: &[u8],
            client_addr: SocketAddr,
            source_addr: SocketAddr,
        ) -> std::io::Result<usize> {
            self.responses
                .send((payload.to_vec(), client_addr, source_addr))
                .await
                .map_err(std::io::Error::other)?;
            Ok(payload.len())
        }
    }

    #[cfg(feature = "vless-reverse")]
    fn loopback_site_policy(port: u16) -> SiteToSitePolicy {
        SiteToSitePolicy::compile(&SiteToSiteConfig {
            prefix_maps: vec![SitePrefixMapConfig {
                from: "10.200.1.20/32".into(),
                to: "127.0.0.1/32".into(),
            }],
            allow: vec![SiteTargetAllowConfig {
                network: vec!["tcp".into(), "udp".into()],
                ip: vec!["127.0.0.1/32".into()],
                ports: vec![port.to_string()],
            }],
        })
        .expect("compile loopback site-to-site policy")
    }

    #[cfg(feature = "vless-reverse")]
    fn overlapping_lan_site_policy(
        overlay_prefix: &str,
        port: u16,
    ) -> SiteToSitePolicy {
        SiteToSitePolicy::compile(&SiteToSiteConfig {
            prefix_maps: vec![SitePrefixMapConfig {
                from: overlay_prefix.into(),
                to: "127.0.0.0/24".into(),
            }],
            allow: vec![SiteTargetAllowConfig {
                network: vec!["tcp".into(), "udp".into()],
                ip: vec!["127.0.0.0/24".into()],
                ports: vec![port.to_string()],
            }],
        })
        .expect("compile overlapping-LAN site-to-site policy")
    }

    #[test]
    fn gateway_config_compiles_to_configured_netstack_mtu_and_tcp_limit() {
        let plan = TunGatewayPlan::try_from(config()).expect("valid TUN plan");
        assert_eq!(plan.name, "site-tun");
        assert_eq!(plan.address, Ipv4Addr::new(10, 254, 0, 1));
        assert_eq!(plan.prefix_len, 24);
        assert_eq!(plan.ipv6_address, None);
        assert_eq!(plan.max_tcp_connections, 32);
        assert_eq!(plan.max_udp_sessions, 128);
        assert_eq!(plan.mtu, NETSTACK_MTU);
    }

    #[test]
    fn gateway_config_defaults_to_bounded_tcp_and_udp_limits() {
        let config: TunGatewayConfig = serde_json::from_value(serde_json::json!({
            "name": "site-tun",
            "address": "10.254.0.1/24",
            "inboundTag": "office-tun"
        }))
        .expect("parse TUN gateway config with omitted optional limits");
        let plan = TunGatewayPlan::try_from(config).expect("valid TUN plan");

        assert_eq!(plan.max_tcp_connections, 64);
        assert_eq!(plan.max_udp_sessions, 256);
        assert_eq!(plan.mtu, 1500);
    }

    #[test]
    fn gateway_config_accepts_mtu_boundaries_and_rejects_out_of_range_values() {
        for mtu in [MIN_TUN_GATEWAY_MTU, MAX_TUN_GATEWAY_MTU] {
            let mut config = config();
            config.mtu = mtu;
            assert_eq!(TunGatewayPlan::try_from(config).unwrap().mtu, mtu);
        }

        for mtu in [0, MIN_TUN_GATEWAY_MTU - 1, MAX_TUN_GATEWAY_MTU + 1] {
            let mut config = config();
            config.mtu = mtu;
            let error = TunGatewayPlan::try_from(config).unwrap_err();
            assert!(error.contains("tunGateway.mtu"));
        }
    }

    #[test]
    fn gateway_config_accepts_optional_ipv6_interface_address() {
        let mut config = config();
        config.ipv6_address = Some("fd00:254::1/64".into());
        let plan =
            TunGatewayPlan::try_from(config).expect("valid dual-stack TUN plan");
        assert_eq!(
            plan.ipv6_address,
            Some(("fd00:254::1".parse().unwrap(), 64))
        );
    }

    #[test]
    fn gateway_config_rejects_invalid_optional_ipv6_interface_address() {
        for value in [
            "fd00:254::1",
            "10.254.0.2/24",
            "fd00:254::1/0",
            "fd00:254::1/129",
        ] {
            let mut config = config();
            config.ipv6_address = Some(value.into());
            assert!(
                TunGatewayPlan::try_from(config).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }

    #[test]
    fn gateway_config_rejects_invalid_device_and_resource_limits() {
        let mut invalid = config();
        invalid.name = "interface-name-too-long".into();
        assert!(TunGatewayPlan::try_from(invalid).is_err());

        let mut invalid = config();
        invalid.address = "2001:db8::1/64".into();
        assert!(TunGatewayPlan::try_from(invalid).is_err());

        let mut invalid = config();
        invalid.max_tcp_connections = NETSTACK_MAX_TCP_STREAMS + 1;
        assert!(TunGatewayPlan::try_from(invalid).is_err());

        let mut invalid = config();
        invalid.max_tcp_connections = 0;
        assert!(TunGatewayPlan::try_from(invalid).is_err());

        let mut invalid = config();
        invalid.max_udp_sessions = 0;
        assert!(TunGatewayPlan::try_from(invalid).is_err());

        let mut invalid = config();
        invalid.max_udp_sessions = 1025;
        assert!(TunGatewayPlan::try_from(invalid).is_err());
    }

    #[test]
    fn managed_tun_routes_require_source_prefixes_and_specific_routes() {
        let mut missing_source = config();
        missing_source.routes = vec!["10.44.0.0/24".into()];
        assert!(TunGatewayPlan::try_from(missing_source).is_err());

        let mut missing_input_interface = config();
        missing_input_interface.routes = vec!["10.44.0.0/24".into()];
        missing_input_interface.route_from = vec!["10.251.0.0/24".into()];
        assert!(TunGatewayPlan::try_from(missing_input_interface).is_err());

        let mut invalid_input_interface = config();
        invalid_input_interface.routes = vec!["10.44.0.0/24".into()];
        invalid_input_interface.route_from = vec!["10.251.0.0/24".into()];
        invalid_input_interface.route_input_interface =
            Some("office gateway".into());
        assert!(TunGatewayPlan::try_from(invalid_input_interface).is_err());

        let mut tun_as_input_interface = config();
        tun_as_input_interface.routes = vec!["10.44.0.0/24".into()];
        tun_as_input_interface.route_from = vec!["10.251.0.0/24".into()];
        tun_as_input_interface.route_input_interface = Some("site-tun".into());
        assert!(TunGatewayPlan::try_from(tun_as_input_interface).is_err());

        let mut default_route = config();
        default_route.routes = vec!["0.0.0.0/0".into()];
        default_route.route_from = vec!["10.251.0.0/24".into()];
        default_route.route_input_interface = Some("office-gw".into());
        assert!(TunGatewayPlan::try_from(default_route).is_err());

        let mut v6_without_address = config();
        v6_without_address.routes = vec!["2001:db8:44::/64".into()];
        v6_without_address.route_from = vec!["fd18:251::/64".into()];
        v6_without_address.route_input_interface = Some("office-gw".into());
        assert!(TunGatewayPlan::try_from(v6_without_address).is_err());

        let mut duplicate_prefix = config();
        duplicate_prefix.routes = vec!["10.44.0.1/24".into(), "10.44.0.0/24".into()];
        duplicate_prefix.route_from = vec!["10.251.0.0/24".into()];
        duplicate_prefix.route_input_interface = Some("office-gw".into());
        assert!(TunGatewayPlan::try_from(duplicate_prefix).is_err());

        let mut local_route = config();
        local_route.routes = vec!["10.254.0.0/24".into()];
        local_route.route_from = vec!["10.251.0.0/24".into()];
        local_route.route_input_interface = Some("office-gw".into());
        assert!(TunGatewayPlan::try_from(local_route).is_err());

        let mut local_v6_route = config();
        local_v6_route.ipv6_address = Some("fd00:254::1/64".into());
        local_v6_route.routes = vec!["fd00:254::/64".into()];
        local_v6_route.route_from = vec!["fd18:251::/64".into()];
        local_v6_route.route_input_interface = Some("office-gw".into());
        assert!(TunGatewayPlan::try_from(local_v6_route).is_err());

        let mut reserved_table = config();
        reserved_table.routes = vec!["10.44.0.0/24".into()];
        reserved_table.route_from = vec!["10.251.0.0/24".into()];
        reserved_table.route_input_interface = Some("office-gw".into());
        reserved_table.route_table = Some(254);
        assert!(TunGatewayPlan::try_from(reserved_table).is_err());

        let mut family_mismatch = config();
        family_mismatch.routes = vec!["10.44.0.0/24".into()];
        family_mismatch.route_from = vec!["fd18:251::/64".into()];
        family_mismatch.route_input_interface = Some("office-gw".into());
        assert!(TunGatewayPlan::try_from(family_mismatch).is_err());
    }

    #[test]
    fn managed_tun_routes_canonicalize_prefixes_and_keep_policy_separate() {
        let mut config = config();
        config.ipv6_address = Some("fd00:254::1/64".into());
        config.routes = vec!["10.44.0.19/24".into(), "2001:db8:44::20/64".into()];
        config.route_from = vec!["10.251.0.7/24".into(), "fd18:251::9/64".into()];
        config.route_input_interface = Some("office-gw".into());
        let plan =
            TunGatewayPlan::try_from(config).expect("valid source-scoped routes");
        assert_eq!(
            plan.routes[0],
            IpPrefix::V4(Ipv4Addr::new(10, 44, 0, 0), 24)
        );
        assert_eq!(
            plan.routes[1],
            IpPrefix::V6("2001:db8:44::".parse().unwrap(), 64)
        );
        assert_eq!(
            plan.route_from[0],
            IpPrefix::V4(Ipv4Addr::new(10, 251, 0, 0), 24)
        );
        assert_eq!(plan.route_table, DEFAULT_TUN_ROUTE_TABLE);
        assert_eq!(plan.route_rule_priority, DEFAULT_TUN_ROUTE_RULE_PRIORITY);
    }

    #[test]
    fn gateway_ipv4_netmask_matches_prefix() {
        assert_eq!(prefix_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[tokio::test]
    async fn gateway_cancellation_interrupts_a_pending_packet_operation() {
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            signal.cancel();
        });

        let result = timeout(
            Duration::from_secs(1),
            await_or_cancel(&cancellation, std::future::pending::<()>()),
        )
        .await
        .expect("packet operation did not observe cancellation");
        assert!(result.is_none());
    }

    struct MemoryTun {
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        outbound: mpsc::Sender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl PacketDevice for MemoryTun {
        async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let packet =
                self.inbound.lock().await.recv().await.ok_or_else(|| {
                    std::io::Error::other("memory TUN input closed")
                })?;
            if packet.len() > buffer.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "memory TUN packet exceeds MTU",
                ));
            }
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
            self.outbound
                .send(packet.to_vec())
                .await
                .map_err(|_| std::io::Error::other("memory TUN output closed"))?;
            Ok(packet.len())
        }
    }

    struct FailingTun;

    #[async_trait::async_trait]
    impl PacketDevice for FailingTun {
        async fn recv(&self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected TUN device read failure",
            ))
        }

        async fn send(&self, _buffer: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    struct DropAwareTun {
        started: Mutex<Option<oneshot::Sender<()>>>,
        dropped: Option<oneshot::Sender<()>>,
    }

    impl Drop for DropAwareTun {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(());
            }
        }
    }

    #[async_trait::async_trait]
    impl PacketDevice for DropAwareTun {
        async fn recv(&self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            if let Some(started) = self.started.lock().await.take() {
                let _ = started.send(());
            }
            std::future::pending().await
        }

        async fn send(&self, _buffer: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn cooperative_shutdown_joins_gateway_task_and_drops_device() {
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let device = DropAwareTun {
            started: Mutex::new(Some(started_tx)),
            dropped: Some(dropped_tx),
        };
        let cancellation = CancellationToken::new();
        let runtime_state = RuntimeState::new(Vec::new(), Vec::new());
        let task = tokio::spawn(run_server(
            device,
            TunGatewayPlan::try_from(config()).expect("valid gateway plan"),
            runtime_state.data_plane(),
            cancellation.clone(),
        ));

        timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("TUN device read did not start")
            .expect("TUN device dropped before read started");
        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("cooperative TUN shutdown did not finish")
            .expect("TUN service task panicked")
            .expect("cooperative TUN shutdown should complete cleanly");
        timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("TUN device was not dropped after task shutdown")
            .expect("TUN drop notification sender was lost");
    }

    #[tokio::test]
    async fn gateway_returns_tun_device_failure_to_service_supervisor() {
        let runtime_state = RuntimeState::new(Vec::new(), Vec::new());
        let error = run_server(
            FailingTun,
            TunGatewayPlan::try_from(config()).expect("valid TUN plan"),
            runtime_state.data_plane(),
            CancellationToken::new(),
        )
        .await
        .expect_err("failed TUN device reads must fail the gateway task");

        let Error::Io(error) = error else {
            panic!("TUN device failure must be returned as an I/O error");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(
            error
                .to_string()
                .contains("injected TUN device read failure")
        );
    }

    fn tcp_syn(source_port: u16, target: SocketAddr) -> Vec<u8> {
        let target_ip = match target.ip() {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => panic!("test echo listener must be IPv4"),
        };
        let mut packet = Vec::new();
        PacketBuilder::ipv4([10, 44, 0, 2], target_ip, 64)
            .tcp(source_port, target.port(), 100, u16::MAX)
            .syn()
            .write(&mut packet, &[])
            .expect("build test TCP SYN");
        packet
    }

    fn udp_datagram(
        source_port: u16,
        target: SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let target_ip = match target.ip() {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => panic!("test UDP target must be IPv4"),
        };
        let mut packet = Vec::new();
        PacketBuilder::ipv4([10, 44, 0, 2], target_ip, 64)
            .udp(source_port, target.port())
            .write(&mut packet, payload)
            .expect("build test UDP packet");
        packet
    }

    fn udp_datagram_ipv6(
        source_port: u16,
        target: SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let target_ip = match target.ip() {
            std::net::IpAddr::V6(address) => address.octets(),
            std::net::IpAddr::V4(_) => panic!("test UDP target must be IPv6"),
        };
        let source_ip = "fd00:254::2".parse::<Ipv6Addr>().expect("test IPv6 source");
        let mut packet = Vec::new();
        PacketBuilder::ipv6(source_ip.octets(), target_ip, 64)
            .udp(source_port, target.port())
            .write(&mut packet, payload)
            .expect("build test IPv6 UDP packet");
        packet
    }

    fn fragment_ipv4_packet(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        assert_eq!(packet[0] >> 4, 4, "expected IPv4 packet");
        assert!(header_len >= 20 && header_len <= packet.len());
        let fragment_payload = &packet[header_len..];
        let max_fragment_payload = ((mtu - header_len) / 8) * 8;
        assert!(max_fragment_payload > 0);

        let mut fragments = Vec::new();
        let mut offset = 0;
        while offset < fragment_payload.len() {
            let length = max_fragment_payload.min(fragment_payload.len() - offset);
            let more_fragments = offset + length < fragment_payload.len();
            let mut fragment = packet[..header_len].to_vec();
            fragment.extend_from_slice(&fragment_payload[offset..offset + length]);
            let total_len = fragment.len() as u16;
            fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
            let mut flags_offset = (offset / 8) as u16;
            if more_fragments {
                flags_offset |= 0x2000;
            }
            fragment[6..8].copy_from_slice(&flags_offset.to_be_bytes());
            update_ipv4_header_checksum(&mut fragment);
            fragments.push(fragment);
            offset += length;
        }
        fragments
    }

    #[cfg(feature = "vless-reverse")]
    fn ipv4_fragment_piece(
        packet: &[u8],
        identification: u16,
        offset: usize,
        length: usize,
        more_fragments: bool,
    ) -> Vec<u8> {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        assert_eq!(packet[0] >> 4, 4, "expected IPv4 packet");
        assert_eq!(offset % 8, 0, "IPv4 fragment offset uses 8-byte units");
        let payload = &packet[header_len..];
        assert!(offset + length <= payload.len());

        let mut fragment = packet[..header_len].to_vec();
        fragment.extend_from_slice(&payload[offset..offset + length]);
        let total_len = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
        fragment[4..6].copy_from_slice(&identification.to_be_bytes());
        let mut flags_offset = (offset / 8) as u16;
        if more_fragments {
            flags_offset |= 0x2000;
        }
        fragment[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        update_ipv4_header_checksum(&mut fragment);
        fragment
    }

    fn fragment_ipv6_packet(
        packet: &[u8],
        identification: u32,
        mtu: usize,
    ) -> Vec<Vec<u8>> {
        const IPV6_HEADER_LEN: usize = 40;
        let fragment_header_len = etherparse::Ipv6FragmentHeader::LEN;
        assert_eq!(packet[0] >> 4, 6, "expected IPv6 packet");
        assert_eq!(packet[6], etherparse::ip_number::UDP.0);
        assert!(packet.len() >= IPV6_HEADER_LEN);
        let fragment_payload = &packet[IPV6_HEADER_LEN..];
        let max_fragment_payload =
            ((mtu - IPV6_HEADER_LEN - fragment_header_len) / 8) * 8;
        assert!(max_fragment_payload > 0);

        let mut fragments = Vec::new();
        let mut offset = 0;
        while offset < fragment_payload.len() {
            let length = max_fragment_payload.min(fragment_payload.len() - offset);
            let more_fragments = offset + length < fragment_payload.len();
            let mut fragment = packet[..IPV6_HEADER_LEN].to_vec();
            fragment[4..6].copy_from_slice(
                &((fragment_header_len + length) as u16).to_be_bytes(),
            );
            fragment[6] = etherparse::ip_number::IPV6_FRAG.0;
            let fragment_header = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::UDP,
                etherparse::IpFragOffset::try_new((offset / 8) as u16)
                    .expect("IPv6 fragment offset is in range"),
                more_fragments,
                identification,
            );
            fragment.extend_from_slice(&fragment_header.to_bytes());
            fragment.extend_from_slice(&fragment_payload[offset..offset + length]);
            fragments.push(fragment);
            offset += length;
        }
        fragments
    }

    #[cfg(feature = "vless-reverse")]
    fn ipv6_fragment_piece(
        packet: &[u8],
        identification: u32,
        offset: usize,
        length: usize,
        more_fragments: bool,
    ) -> Vec<u8> {
        const IPV6_HEADER_LEN: usize = 40;
        let fragment_header_len = etherparse::Ipv6FragmentHeader::LEN;
        assert_eq!(packet[0] >> 4, 6, "expected IPv6 packet");
        assert_eq!(packet[6], etherparse::ip_number::UDP.0);
        assert_eq!(offset % 8, 0, "IPv6 fragment offset uses 8-byte units");
        let payload = &packet[IPV6_HEADER_LEN..];
        assert!(offset + length <= payload.len());

        let mut fragment = packet[..IPV6_HEADER_LEN].to_vec();
        fragment[4..6]
            .copy_from_slice(&((fragment_header_len + length) as u16).to_be_bytes());
        fragment[6] = etherparse::ip_number::IPV6_FRAG.0;
        let header = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::UDP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16)
                .expect("IPv6 fragment offset is in range"),
            more_fragments,
            identification,
        );
        fragment.extend_from_slice(&header.to_bytes());
        fragment.extend_from_slice(&payload[offset..offset + length]);
        fragment
    }

    #[cfg(feature = "vless-reverse")]
    fn set_ipv6_fragment_offset(packet: &mut [u8], byte_offset: u16) {
        const IPV6_HEADER_LEN: usize = 40;
        assert_eq!(byte_offset % 8, 0, "IPv6 fragment offset uses 8-byte units");
        let offset_flags = u16::from_be_bytes([
            packet[IPV6_HEADER_LEN + 2],
            packet[IPV6_HEADER_LEN + 3],
        ]);
        let offset_flags = (offset_flags & 0x0007) | ((byte_offset / 8) << 3);
        packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4]
            .copy_from_slice(&offset_flags.to_be_bytes());
    }

    #[cfg(feature = "vless-reverse")]
    fn set_ipv4_fragment_offset(packet: &mut [u8], byte_offset: u16) {
        assert_eq!(byte_offset % 8, 0, "IPv4 fragment offset uses 8-byte units");
        let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
        let flags_offset = (flags_offset & 0xe000) | (byte_offset / 8);
        packet[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        update_ipv4_header_checksum(packet);
    }

    fn update_ipv4_header_checksum(packet: &mut [u8]) {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        assert!(header_len >= 20 && header_len <= packet.len());
        packet[10..12].fill(0);
        let (words, remainder) = packet[..header_len].as_chunks::<2>();
        assert!(remainder.is_empty(), "IPv4 header has an even length");
        let checksum = words
            .iter()
            .fold(0u32, |sum, word| sum + u32::from(u16::from_be_bytes(*word)));
        let mut checksum = checksum;
        while checksum >> 16 != 0 {
            checksum = (checksum & 0xffff) + (checksum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
    }

    fn tcp_ack(
        source_port: u16,
        target: SocketAddr,
        sequence: u32,
        acknowledgment: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let target_ip = match target.ip() {
            std::net::IpAddr::V4(address) => address.octets(),
            std::net::IpAddr::V6(_) => panic!("test echo listener must be IPv4"),
        };
        let mut packet = Vec::new();
        let builder = PacketBuilder::ipv4([10, 44, 0, 2], target_ip, 64)
            .tcp(source_port, target.port(), sequence, u16::MAX)
            .ack(acknowledgment);
        if payload.is_empty() {
            builder.write(&mut packet, &[]).expect("build test TCP ACK");
        } else {
            builder
                .psh()
                .write(&mut packet, payload)
                .expect("build test TCP data packet");
        }
        packet
    }

    fn tcp_syn_ack_numbers(packet: &[u8]) -> Option<(u32, u32)> {
        let packet = SlicedPacket::from_ip(packet).ok()?;
        let Some(TransportSlice::Tcp(tcp)) = packet.transport else {
            return None;
        };
        (tcp.syn() && tcp.ack())
            .then_some((tcp.sequence_number(), tcp.acknowledgment_number()))
    }

    fn contains_tcp_payload(packet: &[u8], expected: &[u8]) -> bool {
        let Ok(packet) = SlicedPacket::from_ip(packet) else {
            return false;
        };
        let Some(TransportSlice::Tcp(tcp)) = packet.transport else {
            return false;
        };
        tcp.payload() == expected
    }

    fn contains_tcp_close(packet: &[u8]) -> bool {
        let Ok(packet) = SlicedPacket::from_ip(packet) else {
            return false;
        };
        let Some(TransportSlice::Tcp(tcp)) = packet.transport else {
            return false;
        };
        tcp.fin() || tcp.rst()
    }

    fn ipv4_udp_tuple(
        packet: &[u8],
    ) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>)> {
        let ip = etherparse::Ipv4HeaderSlice::from_slice(packet).ok()?;
        let packet = SlicedPacket::from_ip(packet).ok()?;
        let Some(TransportSlice::Udp(udp)) = packet.transport else {
            return None;
        };
        Some((
            ip.source_addr(),
            ip.destination_addr(),
            udp.source_port(),
            udp.destination_port(),
            udp.payload().to_vec(),
        ))
    }

    fn ipv6_udp_tuple(
        packet: &[u8],
    ) -> Option<(Ipv6Addr, Ipv6Addr, u16, u16, Vec<u8>)> {
        let ip = etherparse::Ipv6HeaderSlice::from_slice(packet).ok()?;
        let packet = SlicedPacket::from_ip(packet).ok()?;
        let Some(TransportSlice::Udp(udp)) = packet.transport else {
            return None;
        };
        Some((
            ip.source_addr(),
            ip.destination_addr(),
            udp.source_port(),
            udp.destination_port(),
            udp.payload().to_vec(),
        ))
    }

    async fn next_udp_payload(
        packets: &mut mpsc::Receiver<Vec<u8>>,
        expected: &[u8],
    ) -> (Ipv4Addr, Ipv4Addr, u16, u16) {
        timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if let Some((
                    source_ip,
                    destination_ip,
                    source,
                    destination,
                    payload,
                )) = ipv4_udp_tuple(&packet)
                    && payload == expected
                {
                    return (source_ip, destination_ip, source, destination);
                }
            }
        })
        .await
        .expect("TUN UDP response timed out")
    }

    async fn next_ipv6_udp_payload(
        packets: &mut mpsc::Receiver<Vec<u8>>,
        expected: &[u8],
    ) -> (Ipv6Addr, Ipv6Addr, u16, u16) {
        timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if let Some((
                    source_ip,
                    destination_ip,
                    source,
                    destination,
                    payload,
                )) = ipv6_udp_tuple(&packet)
                    && payload == expected
                {
                    return (source_ip, destination_ip, source, destination);
                }
            }
        })
        .await
        .expect("TUN IPv6 UDP response timed out")
    }

    async fn next_tcp_syn_ack(
        packets: &mut mpsc::Receiver<Vec<u8>>,
    ) -> (Vec<u8>, u32) {
        timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if let Some((sequence, _)) = tcp_syn_ack_numbers(&packet) {
                    return (packet, sequence);
                }
            }
        })
        .await
        .expect("TUN TCP SYN-ACK timed out")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_tcp_packet_enters_existing_dokodemo_dispatcher() {
        let echo_listener = HostTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local TCP echo listener");
        let echo_address = echo_listener.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener
                .accept()
                .await
                .expect("accept proxied gateway flow");
            let mut payload = [0; 4];
            stream
                .read_exact(&mut payload)
                .await
                .expect("read gateway payload");
            stream
                .write_all(&payload)
                .await
                .expect("write echo payload");
        });

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let plan = TunGatewayPlan::try_from(config()).expect("valid gateway plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime_state.data_plane(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_555;
        incoming
            .send(tcp_syn(CLIENT_PORT, echo_address))
            .await
            .expect("inject TCP SYN into memory TUN");
        let (_, server_sequence) = next_tcp_syn_ack(&mut packets).await;
        incoming
            .send(tcp_ack(
                CLIENT_PORT,
                echo_address,
                101,
                server_sequence.wrapping_add(1),
                b"ping",
            ))
            .await
            .expect("inject TCP payload into memory TUN");

        timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if contains_tcp_payload(&packet, b"ping") {
                    break;
                }
            }
        })
        .await
        .expect("TCP echo did not return through the TUN packet path");
        echo_task.await.expect("echo task failed");

        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_tcp_connection_limit_does_not_dial_excess_flow() {
        let target_listener = HostTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local TCP target");
        let target_address = target_listener.local_addr().expect("target address");
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (excess_dial_tx, mut excess_dial_rx) = oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (stream, _) = target_listener
                .accept()
                .await
                .expect("accept first TUN flow");
            accepted_tx.send(()).expect("report first accepted flow");
            tokio::select! {
                _ = release_rx => {}
                excess = target_listener.accept() => {
                    let _ = excess_dial_tx.send(excess.is_ok());
                }
            }
            drop(stream);
        });

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let mut gateway_config = config();
        gateway_config.max_tcp_connections = 1;
        let plan = TunGatewayPlan::try_from(gateway_config)
            .expect("valid single-connection TUN plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let cancellation = CancellationToken::new();
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime_state.data_plane(),
            cancellation.clone(),
        ));

        const FIRST_CLIENT_PORT: u16 = 45_555;
        incoming
            .send(tcp_syn(FIRST_CLIENT_PORT, target_address))
            .await
            .expect("inject first TCP SYN into memory TUN");
        let (_, first_server_sequence) = next_tcp_syn_ack(&mut packets).await;
        incoming
            .send(tcp_ack(
                FIRST_CLIENT_PORT,
                target_address,
                101,
                first_server_sequence.wrapping_add(1),
                &[],
            ))
            .await
            .expect("complete first TCP handshake");
        timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("first TUN flow did not reach target")
            .expect("target accept notification was lost");

        const EXCESS_CLIENT_PORT: u16 = 45_556;
        incoming
            .send(tcp_syn(EXCESS_CLIENT_PORT, target_address))
            .await
            .expect("inject excess TCP SYN into memory TUN");
        let (_, excess_server_sequence) = next_tcp_syn_ack(&mut packets).await;
        incoming
            .send(tcp_ack(
                EXCESS_CLIENT_PORT,
                target_address,
                101,
                excess_server_sequence.wrapping_add(1),
                &[],
            ))
            .await
            .expect("complete excess TCP handshake");

        assert!(
            timeout(Duration::from_millis(250), &mut excess_dial_rx)
                .await
                .is_err(),
            "excess flow must not dial the target"
        );

        release_tx
            .send(())
            .expect("release first target connection");
        target_task.await.expect("target task failed");
        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after cancellation")
            .expect("TUN service task panicked")
            .expect("cooperative TUN shutdown should complete cleanly");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_udp_packet_uses_existing_dokodemo_freedom_session() {
        let echo_socket = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local UDP echo socket");
        let echo_address = echo_socket.local_addr().expect("UDP echo address");
        let large_payload = vec![0x6b; 16 * 1024];
        let expected_large_payload = large_payload.clone();
        let echo_task = tokio::spawn(async move {
            let mut payload = vec![0; expected_large_payload.len()];
            for expected in [b"ping".as_slice(), expected_large_payload.as_slice()] {
                let (len, peer) = echo_socket
                    .recv_from(&mut payload)
                    .await
                    .expect("receive gateway UDP datagram");
                assert_eq!(&payload[..len], expected);
                echo_socket
                    .send_to(&payload[..len], peer)
                    .await
                    .expect("send UDP echo response");
            }
        });

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let plan = TunGatewayPlan::try_from(config()).expect("valid gateway plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime_state.data_plane(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_557;
        incoming
            .send(udp_datagram(CLIENT_PORT, echo_address, b"ping"))
            .await
            .expect("inject UDP datagram into memory TUN");
        assert_eq!(
            next_udp_payload(&mut packets, b"ping").await,
            (
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::new(10, 44, 0, 2),
                echo_address.port(),
                CLIENT_PORT,
            )
        );
        for fragment in fragment_ipv4_packet(
            &udp_datagram(CLIENT_PORT, echo_address, &large_payload),
            NETSTACK_MTU,
        ) {
            incoming
                .send(fragment)
                .await
                .expect("inject large fragmented UDP datagram into memory TUN");
        }
        timeout(Duration::from_secs(3), echo_task)
            .await
            .expect("large UDP datagram did not reach Freedom target")
            .expect("UDP echo task failed");

        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_ipv6_udp_local_ip_rule_uses_configured_tun_ipv6_address() {
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![
                OutboundSummary {
                    tag: "blocked".into(),
                    protocol: "blackhole".into(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                    sender_settings_type: None,
                    sender_settings_value: None,
                },
                OutboundSummary {
                    tag: "reverse-out".into(),
                    protocol: "vless-reverse".into(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                    sender_settings_type: None,
                    sender_settings_value: None,
                },
            ],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![
                    RuleConfig {
                        inbound_tag: vec!["office-tun".into()],
                        network: NetworkListConfig(vec!["udp".into()]),
                        local_ip: vec!["fd00:254::1/128".into()],
                        port: PortListConfig(vec![PortRangeConfig {
                            from: 5353,
                            to: 5353,
                        }]),
                        outbound_tag: Some("blocked".into()),
                        ..RuleConfig::default()
                    },
                    RuleConfig {
                        inbound_tag: vec!["office-tun".into()],
                        network: NetworkListConfig(vec!["udp".into()]),
                        outbound_tag: Some("reverse-out".into()),
                        ..RuleConfig::default()
                    },
                ],
                ..RoutingConfig::default()
            }))
            .expect("compile IPv6 local-address UDP route"),
        );
        let runtime = runtime_state.data_plane();
        let (portal_stream, mut bridge_peer) = tokio::io::duplex(16 * 1024);
        let _portal_lease = runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(portal_stream)),
            )
            .await
            .expect("attach Reverse Portal worker");
        let control = read_frame_with_source_and_local(&mut bridge_peer, true)
            .await
            .expect("read Reverse worker control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);

        let mut gateway_config = config();
        gateway_config.ipv6_address = Some("fd00:254::1/64".into());
        let plan = TunGatewayPlan::try_from(gateway_config)
            .expect("valid IPv6 gateway plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, _packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let cancellation = CancellationToken::new();
        let service =
            tokio::spawn(run_server(device, plan, runtime, cancellation.clone()));

        let control_target = SocketAddr::new(
            "2001:db8:44::50"
                .parse::<Ipv6Addr>()
                .expect("parse IPv6 target")
                .into(),
            5354,
        );
        incoming
            .send(udp_datagram_ipv6(
                45_557,
                control_target,
                b"nonmatching-route-control",
            ))
            .await
            .expect("inject IPv6 UDP control datagram into memory TUN");
        let control_packet = timeout(
            Duration::from_secs(1),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("nonmatching localIP route should reach Reverse")
        .expect("read Reverse control datagram");
        assert_eq!(
            control_packet.payload.as_ref(),
            b"nonmatching-route-control"
        );

        let target = SocketAddr::new(
            "2001:db8:44::50"
                .parse::<Ipv6Addr>()
                .expect("parse IPv6 target")
                .into(),
            5353,
        );
        incoming
            .send(udp_datagram_ipv6(45_558, target, b"must-hit-ipv6-localIP"))
            .await
            .expect("inject IPv6 UDP datagram into memory TUN");
        assert!(
            timeout(
                Duration::from_secs(1),
                read_frame_with_source_and_local(&mut bridge_peer, true),
            )
            .await
            .is_err(),
            "IPv6 localIP rule must select blackhole instead of Reverse"
        );
        assert!(
            !service.is_finished(),
            "a blackholed IPv6 UDP datagram must not stop the TUN service"
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after cancellation")
            .expect("TUN service task panicked")
            .expect("cooperative TUN shutdown should complete cleanly");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_udp_session_limit_drops_new_flow_before_target_send() {
        let first_target = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind first UDP target");
        let first_target_address =
            first_target.local_addr().expect("first target address");
        let (first_reply_tx, first_reply_rx) = oneshot::channel();
        let (release_target_tx, release_target_rx) = oneshot::channel();
        let first_target_task = tokio::spawn(async move {
            let mut payload = [0; 8];
            let (length, peer) = first_target
                .recv_from(&mut payload)
                .await
                .expect("receive first TUN UDP flow");
            first_target
                .send_to(&payload[..length], peer)
                .await
                .expect("reply to first TUN UDP flow");
            first_reply_tx
                .send(())
                .expect("report first UDP target reply");
            let _ = release_target_rx.await;
        });
        let excess_target = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind excess UDP target");
        let excess_target_address =
            excess_target.local_addr().expect("excess target address");

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "direct".into(),
                protocol: "freedom".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let mut gateway_config = config();
        gateway_config.max_udp_sessions = 1;
        let plan = TunGatewayPlan::try_from(gateway_config)
            .expect("valid single-session TUN plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let cancellation = CancellationToken::new();
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime_state.data_plane(),
            cancellation.clone(),
        ));

        const FIRST_CLIENT_PORT: u16 = 45_557;
        incoming
            .send(udp_datagram(
                FIRST_CLIENT_PORT,
                first_target_address,
                b"first",
            ))
            .await
            .expect("inject first UDP datagram into memory TUN");
        assert_eq!(
            next_udp_payload(&mut packets, b"first").await,
            (
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::new(10, 44, 0, 2),
                first_target_address.port(),
                FIRST_CLIENT_PORT,
            )
        );
        timeout(Duration::from_secs(1), first_reply_rx)
            .await
            .expect("first UDP target did not reply")
            .expect("first target reply notification was lost");

        const EXCESS_CLIENT_PORT: u16 = 45_558;
        incoming
            .send(udp_datagram(
                EXCESS_CLIENT_PORT,
                excess_target_address,
                b"excess",
            ))
            .await
            .expect("inject excess UDP datagram into memory TUN");
        let mut excess_payload = [0; 8];
        assert!(
            timeout(
                Duration::from_millis(250),
                excess_target.recv_from(&mut excess_payload),
            )
            .await
            .is_err(),
            "a new UDP flow must not reach its target after the session cap is full"
        );
        assert!(
            !service.is_finished(),
            "TUN service should remain alive after dropping an over-limit UDP flow"
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after cancellation")
            .expect("TUN service task panicked")
            .expect("cooperative TUN shutdown should complete cleanly");
        runtime_state.close_inbound_connection_tasks();
        let shutdown = runtime_state
            .drain_inbound_connection_tasks(Duration::ZERO)
            .await;
        assert!(
            shutdown.cancelled_tasks >= 1,
            "the active UDP relay should be cancelled after the drain deadline"
        );
        assert_eq!(
            runtime_state.tracked_inbound_connection_count(),
            0,
            "active UDP tasks must be removed from the connection owner"
        );
        release_target_tx
            .send(())
            .expect("release retained UDP target socket");
        first_target_task
            .await
            .expect("first UDP target task failed");
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test]
    async fn tun_reverse_udp_idle_expiry_reuses_single_session_slot_repeatedly() {
        const SESSION_CYCLES: usize = 32;
        const CLIENT_PORT: u16 = 45_561;

        let target = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Reverse UDP churn target");
        let target_addr = target.local_addr().expect("read churn target address");
        let target_task = tokio::spawn(async move {
            for _ in 0..SESSION_CYCLES {
                let mut payload = [0; 32];
                let (length, peer) = target
                    .recv_from(&mut payload)
                    .await
                    .expect("receive Reverse UDP churn datagram");
                target
                    .send_to(&payload[..length], peer)
                    .await
                    .expect("echo Reverse UDP churn datagram");
            }
        });

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN UDP route to Reverse"),
        );
        let hub_runtime = runtime_state.data_plane();
        let (portal_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
        let portal_lease = hub_runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(portal_stream)),
            )
            .await
            .expect("attach Hub Reverse Portal worker");
        let edge_runtime = RuntimeState::new(
            Vec::new(),
            vec![crate::outbound::freedom_outbound_allow_loopback("direct")],
        )
        .data_plane();
        let edge_worker = MuxServerWorker::new_with_context(
            Box::new(ReverseSessionStream::new(bridge_stream)),
            "bridge-in".into(),
            Arc::new(edge_runtime),
            BridgeDispatchContext {
                site_to_site: Some(loopback_site_policy(target_addr.port())),
                ..BridgeDispatchContext::default()
            },
        );

        let (response_sender, mut responses) = mpsc::channel(SESSION_CYCLES);
        let forwarder = TunUdpForwarder::new_with_idle_timeout(
            "office-tun".into(),
            2,
            hub_runtime,
            Arc::new(ChannelUdpReplySink {
                local_addr: SocketAddr::new(Ipv4Addr::new(10, 254, 0, 1).into(), 0),
                responses: response_sender,
            }),
            1,
            Duration::from_millis(250),
        );
        let client_addr = SocketAddr::from(([10, 44, 0, 2], CLIENT_PORT));
        let overlay_target =
            SocketAddr::from(([10, 200, 1, 20], target_addr.port()));

        for cycle in 0..SESSION_CYCLES {
            let payload = format!("reverse-session-churn-{cycle}").into_bytes();
            forwarder
                .forward(watfaq_netstack::UdpPacket::from((
                    watfaq_netstack::Packet::new(payload.clone()),
                    client_addr,
                    overlay_target,
                )))
                .await
                .expect("admit UDP datagram after previous session expiry");
            assert_eq!(
                runtime_state.tracked_inbound_connection_count(),
                1,
                "each churn cycle must own one active Reverse UDP relay before expiry"
            );

            let (reply, reply_client, reply_source) =
                timeout(Duration::from_secs(2), responses.recv())
                    .await
                    .expect("Reverse UDP churn response timed out")
                    .expect("Reverse UDP reply sink closed");
            assert_eq!(reply, payload);
            assert_eq!(reply_client, client_addr);
            assert_eq!(reply_source, overlay_target);
            assert_eq!(
                runtime_state.tracked_inbound_connection_count(),
                1,
                "the Reverse UDP relay must stay alive through its echo response"
            );

            timeout(Duration::from_secs(1), async {
                while runtime_state.tracked_inbound_connection_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("expired Reverse UDP worker did not release its tracked task");
        }

        target_task.await.expect("UDP churn target task failed");
        drop(edge_worker);
        drop(portal_lease);
        runtime_state.close_inbound_connection_tasks();
        let shutdown = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
        assert!(shutdown.drained);
        assert_eq!(runtime_state.tracked_inbound_connection_count(), 0);
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_reverse_udp_without_worker_drops_packet_and_recovers_on_same_tuple()
    {
        const CLIENT_PORT: u16 = 45_562;
        const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 44, 0, 2);

        let target = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind Reverse UDP fail-closed target");
        let target_addr = target.local_addr().expect("read Reverse UDP target");
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![
                OutboundSummary {
                    tag: "reverse-out".into(),
                    protocol: "vless-reverse".into(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                    sender_settings_type: None,
                    sender_settings_value: None,
                },
                OutboundSummary {
                    tag: "direct".into(),
                    protocol: "freedom".into(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                    sender_settings_type: None,
                    sender_settings_value: None,
                },
            ],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN UDP route to Reverse"),
        );
        let hub_runtime = runtime_state.data_plane();
        let plan = TunGatewayPlan::try_from(config()).expect("valid gateway plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            hub_runtime.clone(),
            CancellationToken::new(),
        ));

        incoming
            .send(udp_datagram(CLIENT_PORT, target_addr, b"without-bridge"))
            .await
            .expect("inject UDP datagram while Reverse has no workers");
        let mut payload = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(300), target.recv_from(&mut payload))
                .await
                .is_err(),
            "an offline Reverse route must not fall back to the configured Freedom outbound"
        );
        timeout(Duration::from_secs(1), async {
            while runtime_state.tracked_inbound_connection_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed offline UDP relay must release its task ownership");

        let (portal_stream, mut bridge_stream) = tokio::io::duplex(64 * 1024);
        let portal_lease = hub_runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(portal_stream)),
            )
            .await
            .expect("attach recovered Hub Reverse worker");
        let control = read_frame_with_source_and_local(&mut bridge_stream, true)
            .await
            .expect("read recovered Reverse control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);
        let edge_runtime = RuntimeState::new(
            Vec::new(),
            vec![crate::outbound::freedom_outbound_allow_loopback("direct")],
        )
        .data_plane();
        let edge_worker = MuxServerWorker::new_with_context(
            Box::new(ReverseSessionStream::new(bridge_stream)),
            "bridge-in".into(),
            Arc::new(edge_runtime),
            BridgeDispatchContext::default(),
        );

        let echo_task = tokio::spawn(async move {
            let (length, peer) = target
                .recv_from(&mut payload)
                .await
                .expect("receive recovered Reverse UDP packet");
            assert_eq!(&payload[..length], b"after-bridge-recovery");
            target
                .send_to(&payload[..length], peer)
                .await
                .expect("reply to recovered Reverse UDP packet");
        });
        incoming
            .send(udp_datagram(
                CLIENT_PORT,
                target_addr,
                b"after-bridge-recovery",
            ))
            .await
            .expect("inject UDP datagram again on the original tuple");
        assert_eq!(
            next_udp_payload(&mut packets, b"after-bridge-recovery").await,
            (
                Ipv4Addr::LOCALHOST,
                CLIENT_IP,
                target_addr.port(),
                CLIENT_PORT,
            ),
            "recovered UDP must retain the original target/source tuple"
        );
        echo_task.await.expect("recovered UDP echo task failed");
        assert_eq!(runtime_state.tracked_inbound_connection_count(), 1);

        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        edge_worker.close();
        edge_worker.wait_closed().await;
        drop(edge_worker);
        drop(portal_lease);
        runtime_state.close_inbound_connection_tasks();
        let shutdown = runtime_state
            .drain_inbound_connection_tasks(Duration::ZERO)
            .await;
        assert!(!shutdown.drained);
        assert_eq!(shutdown.cancelled_tasks, 1);
        assert_eq!(runtime_state.tracked_inbound_connection_count(), 0);
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_tcp_packet_routes_through_reverse_portal_and_returns_to_stack() {
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["tcp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN TCP to Reverse route"),
        );
        let runtime = runtime_state.data_plane();
        let (physical, mut bridge_peer) = tokio::io::duplex(16 * 1024);
        let _lease = runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(physical)),
            )
            .await
            .expect("attach Reverse Portal worker");
        let control = read_frame_with_source_and_local(&mut bridge_peer, true)
            .await
            .expect("read Reverse worker control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);

        let target = "192.0.2.50:443".parse().expect("Overlay target");
        let plan = TunGatewayPlan::try_from(config()).expect("valid gateway plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime.clone(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_556;
        incoming
            .send(tcp_syn(CLIENT_PORT, target))
            .await
            .expect("inject TCP SYN into memory TUN");
        let (_, server_sequence) = next_tcp_syn_ack(&mut packets).await;
        incoming
            .send(tcp_ack(
                CLIENT_PORT,
                target,
                101,
                server_sequence.wrapping_add(1),
                b"ping",
            ))
            .await
            .expect("inject TCP payload into memory TUN");

        let request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("Reverse TUN flow did not reach Portal")
        .expect("read Reverse TUN TCP frame");
        assert_eq!(request.metadata.status, SessionStatus::New);
        assert_eq!(
            request
                .metadata
                .target
                .as_ref()
                .expect("Reverse target")
                .location,
            NetLocation::from_ip_addr(target.ip(), target.port())
        );
        assert_eq!(request.payload.as_ref(), b"ping");
        let session_id = request.metadata.session_id;

        let response = encode_frame(&MuxFrame {
            metadata: FrameMetadata {
                session_id,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"pong"),
        })
        .expect("encode Reverse Bridge response");
        bridge_peer
            .write_all(&response)
            .await
            .expect("write Reverse Bridge response");

        let reply = timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if contains_tcp_payload(&packet, b"pong") {
                    return packet;
                }
            }
        })
        .await
        .expect("Reverse response did not return through the TUN stack");
        let reply =
            SlicedPacket::from_ip(&reply).expect("parse returned TCP packet");
        let Some(TransportSlice::Tcp(reply_tcp)) = reply.transport else {
            panic!("expected returned TCP packet");
        };
        assert_eq!(reply_tcp.source_port(), target.port());
        assert_eq!(reply_tcp.destination_port(), CLIENT_PORT);

        let server_next_sequence = reply_tcp
            .sequence_number()
            .wrapping_add(reply_tcp.payload().len() as u32);
        incoming
            .send(tcp_ack(CLIENT_PORT, target, 105, server_next_sequence, b""))
            .await
            .expect("acknowledge Reverse response");

        drop(bridge_peer);
        timeout(Duration::from_secs(2), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if contains_tcp_close(&packet) {
                    return;
                }
            }
        })
        .await
        .expect("Reverse physical close did not reach the TUN TCP client");

        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_udp_ipv4_fragments_reassemble_before_reverse_forwarding() {
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN UDP to Reverse route"),
        );
        let runtime = runtime_state.data_plane();
        let (physical, mut bridge_peer) = tokio::io::duplex(16 * 1024);
        let _lease = runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(physical)),
            )
            .await
            .expect("attach Reverse Portal worker");
        let control = read_frame_with_source_and_local(&mut bridge_peer, true)
            .await
            .expect("read Reverse worker control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);

        let target: SocketAddr = "192.0.2.50:5353".parse().expect("Overlay target");
        let mut gateway_config = config();
        gateway_config.max_udp_sessions = 1;
        gateway_config.mtu = MIN_TUN_GATEWAY_MTU;
        let plan = TunGatewayPlan::try_from(gateway_config)
            .expect("valid one-session gateway plan");
        let mtu = plan.mtu;
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime.clone(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_558;
        let payload = vec![0x5a; 4096];
        for fragment in
            fragment_ipv4_packet(&udp_datagram(CLIENT_PORT, target, &payload), mtu)
                .into_iter()
                .rev()
        {
            assert!(fragment.len() <= mtu);
            incoming
                .send(fragment)
                .await
                .expect("inject IPv4 UDP fragment into memory TUN");
        }

        let request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("Reverse TUN UDP flow did not reach Portal")
        .expect("read Reverse TUN UDP frame");
        assert_eq!(request.metadata.status, SessionStatus::New);
        assert_eq!(
            request
                .metadata
                .target
                .as_ref()
                .expect("Reverse target")
                .location,
            NetLocation::from_ip_addr(target.ip(), target.port())
        );
        assert_eq!(request.payload.as_ref(), payload.as_slice());
        let session_id = request.metadata.session_id;

        let response = encode_frame(&MuxFrame {
            metadata: FrameMetadata {
                session_id,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"pong"),
        })
        .expect("encode Reverse Bridge UDP response");
        bridge_peer
            .write_all(&response)
            .await
            .expect("write Reverse Bridge UDP response");
        assert_eq!(
            next_udp_payload(&mut packets, b"pong").await,
            (
                Ipv4Addr::new(192, 0, 2, 50),
                Ipv4Addr::new(10, 44, 0, 2),
                target.port(),
                CLIENT_PORT,
            )
        );

        let max_payload = vec![0x7a; XRAY_MUX_UDP_PACKET_SIZE];
        for fragment in fragment_ipv4_packet(
            &udp_datagram(CLIENT_PORT, target, &max_payload),
            mtu,
        ) {
            incoming
                .send(fragment)
                .await
                .expect("inject maximum-size UDP packet into memory TUN");
        }
        let max_request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("maximum-size UDP packet did not reach Reverse")
        .expect("read maximum-size Reverse UDP frame");
        assert_eq!(max_request.metadata.status, SessionStatus::Keep);
        assert_eq!(max_request.payload.as_ref(), max_payload.as_slice());

        let oversized_payload = vec![0x7b; XRAY_MUX_UDP_PACKET_SIZE + 1];
        for fragment in fragment_ipv4_packet(
            &udp_datagram(CLIENT_PORT, target, &oversized_payload),
            mtu,
        ) {
            incoming
                .send(fragment)
                .await
                .expect("inject oversized UDP packet into memory TUN");
        }
        let ended = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("oversized UDP packet did not close its Reverse session")
        .expect("read Reverse UDP session end");
        assert_eq!(ended.metadata.status, SessionStatus::End);
        assert!(ended.payload.is_empty());

        incoming
            .send(udp_datagram(CLIENT_PORT, target, b"after-size-limit"))
            .await
            .expect("inject valid UDP packet after oversized datagram");
        let recovered = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("new valid UDP flow did not reach Reverse")
        .expect("read recovered Reverse UDP frame");
        assert_eq!(recovered.metadata.status, SessionStatus::New);
        assert_eq!(recovered.payload.as_ref(), b"after-size-limit");
        assert_eq!(
            recovered
                .metadata
                .source
                .as_ref()
                .expect("recovered Reverse flow source")
                .location
                .port(),
            CLIENT_PORT,
            "the same UDP tuple must recover with a fresh packet session"
        );

        drop(bridge_peer);
        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_udp_conflicting_ipv4_overlap_is_dropped_and_service_continues() {
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN UDP to Reverse route"),
        );
        let runtime = runtime_state.data_plane();
        let (physical, mut bridge_peer) = tokio::io::duplex(16 * 1024);
        let _lease = runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(physical)),
            )
            .await
            .expect("attach Reverse Portal worker");
        let control = read_frame_with_source_and_local(&mut bridge_peer, true)
            .await
            .expect("read Reverse worker control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);

        let target: SocketAddr = "192.0.2.50:5353".parse().expect("Overlay target");
        let mut gateway_config = config();
        gateway_config.mtu = MIN_TUN_GATEWAY_MTU;
        let plan =
            TunGatewayPlan::try_from(gateway_config).expect("valid gateway plan");
        let mtu = plan.mtu;
        let (incoming, input) = mpsc::channel(8);
        let (output, _packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime.clone(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_558;
        let payload = (0..4096).map(|byte| (byte % 251) as u8).collect::<Vec<_>>();
        let mut truncated = fragment_ipv4_packet(
            &udp_datagram(CLIENT_PORT + 2, target, &payload),
            mtu,
        )
        .remove(0);
        truncated.pop();
        incoming
            .send(truncated)
            .await
            .expect("inject truncated IPv4 fragment into memory TUN");

        let mut fragments =
            fragment_ipv4_packet(&udp_datagram(CLIENT_PORT, target, &payload), mtu);
        assert!(fragments.len() >= 2, "test datagram must be fragmented");
        set_ipv4_fragment_offset(&mut fragments[1], 8);
        for fragment in fragments {
            incoming
                .send(fragment)
                .await
                .expect("inject overlapping IPv4 fragment into memory TUN");
        }

        assert!(
            timeout(
                Duration::from_millis(200),
                read_frame_with_source_and_local(&mut bridge_peer, true),
            )
            .await
            .is_err(),
            "truncated fragments and conflicting IPv4 overlaps must not reach Reverse"
        );

        incoming
            .send(udp_datagram(
                CLIENT_PORT + 1,
                target,
                b"valid-after-overlap",
            ))
            .await
            .expect("inject valid UDP after rejected fragment sequence");
        let request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("valid UDP after overlap did not reach Reverse")
        .expect("read valid Reverse UDP frame");
        assert_eq!(request.metadata.status, SessionStatus::New);
        assert_eq!(request.payload.as_ref(), b"valid-after-overlap");

        drop(bridge_peer);
        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_udp_conflicting_fragment_end_lengths_are_dropped_and_recover_for_both_families()
     {
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN UDP to Reverse route"),
        );
        let runtime = runtime_state.data_plane();
        let (physical, mut bridge_peer) = tokio::io::duplex(16 * 1024);
        let _lease = runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(physical)),
            )
            .await
            .expect("attach Reverse Portal worker");
        let control = read_frame_with_source_and_local(&mut bridge_peer, true)
            .await
            .expect("read Reverse worker control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);

        let (incoming, input) = mpsc::channel(8);
        let (output, _packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            TunGatewayPlan::try_from(config()).expect("valid gateway plan"),
            runtime.clone(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_570;
        let ipv4_target: SocketAddr =
            "192.0.2.60:5353".parse().expect("IPv4 Overlay target");
        let ipv4_payload = [0x41; 16];
        let ipv4_packet = udp_datagram(CLIENT_PORT, ipv4_target, &ipv4_payload);
        for fragment in [
            ipv4_fragment_piece(&ipv4_packet, 0x7171, 0, 8, true),
            ipv4_fragment_piece(&ipv4_packet, 0x7171, 16, 8, false),
            ipv4_fragment_piece(&ipv4_packet, 0x7171, 8, 8, false),
        ] {
            incoming
                .send(fragment)
                .await
                .expect("inject conflicting IPv4 final fragments");
        }
        assert!(
            timeout(
                Duration::from_millis(200),
                read_frame_with_source_and_local(&mut bridge_peer, true),
            )
            .await
            .is_err(),
            "conflicting IPv4 fragment end lengths must not reach Reverse"
        );

        for fragment in [
            ipv4_fragment_piece(&ipv4_packet, 0x7171, 0, 8, true),
            ipv4_fragment_piece(&ipv4_packet, 0x7171, 8, 8, true),
            ipv4_fragment_piece(&ipv4_packet, 0x7171, 16, 8, false),
        ] {
            incoming
                .send(fragment)
                .await
                .expect("inject valid IPv4 fragments after conflicting tails");
        }
        let ipv4_request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("valid IPv4 packet did not recover after conflicting tails")
        .expect("read recovered IPv4 Reverse frame");
        assert_eq!(ipv4_request.metadata.status, SessionStatus::New);
        assert_eq!(ipv4_request.payload.as_ref(), ipv4_payload.as_slice());
        assert_eq!(
            ipv4_request
                .metadata
                .target
                .as_ref()
                .expect("IPv4 Reverse target")
                .location,
            NetLocation::from_ip_addr(ipv4_target.ip(), ipv4_target.port())
        );

        let ipv6_target: SocketAddr = "[2001:db8:44::60]:5353"
            .parse()
            .expect("IPv6 Overlay target");
        let ipv6_payload = [0x42; 16];
        let ipv6_packet =
            udp_datagram_ipv6(CLIENT_PORT + 1, ipv6_target, &ipv6_payload);
        for fragment in [
            ipv6_fragment_piece(&ipv6_packet, 0x7171_7171, 0, 8, true),
            ipv6_fragment_piece(&ipv6_packet, 0x7171_7171, 16, 8, false),
            ipv6_fragment_piece(&ipv6_packet, 0x7171_7171, 8, 8, false),
        ] {
            incoming
                .send(fragment)
                .await
                .expect("inject conflicting IPv6 final fragments");
        }
        assert!(
            timeout(
                Duration::from_millis(200),
                read_frame_with_source_and_local(&mut bridge_peer, true),
            )
            .await
            .is_err(),
            "conflicting IPv6 fragment end lengths must not reach Reverse"
        );

        for fragment in [
            ipv6_fragment_piece(&ipv6_packet, 0x7171_7171, 0, 8, true),
            ipv6_fragment_piece(&ipv6_packet, 0x7171_7171, 8, 8, true),
            ipv6_fragment_piece(&ipv6_packet, 0x7171_7171, 16, 8, false),
        ] {
            incoming
                .send(fragment)
                .await
                .expect("inject valid IPv6 fragments after conflicting tails");
        }
        let ipv6_request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("valid IPv6 packet did not recover after conflicting tails")
        .expect("read recovered IPv6 Reverse frame");
        assert_eq!(ipv6_request.metadata.status, SessionStatus::New);
        assert_eq!(ipv6_request.payload.as_ref(), ipv6_payload.as_slice());
        assert_eq!(
            ipv6_request
                .metadata
                .target
                .as_ref()
                .expect("IPv6 Reverse target")
                .location,
            NetLocation::from_ip_addr(ipv6_target.ip(), ipv6_target.port())
        );

        drop(bridge_peer);
        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tun_udp_ipv6_fragments_reassemble_and_invalid_fragments_are_dropped() {
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN UDP to Reverse route"),
        );
        let runtime = runtime_state.data_plane();
        let (physical, mut bridge_peer) = tokio::io::duplex(16 * 1024);
        let _lease = runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(physical)),
            )
            .await
            .expect("attach Reverse Portal worker");
        let control = read_frame_with_source_and_local(&mut bridge_peer, true)
            .await
            .expect("read Reverse worker control frame");
        assert_eq!(control.metadata.status, SessionStatus::New);

        let target_ip = "2001:db8:44::50"
            .parse::<Ipv6Addr>()
            .expect("IPv6 Overlay target");
        let target = SocketAddr::new(target_ip.into(), 5353);
        let mut gateway_config = config();
        gateway_config.mtu = MIN_TUN_GATEWAY_MTU;
        let plan =
            TunGatewayPlan::try_from(gateway_config).expect("valid gateway plan");
        let mtu = plan.mtu;
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            runtime.clone(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_561;
        let payload = (0..4096).map(|byte| (byte % 241) as u8).collect::<Vec<_>>();
        for fragment in fragment_ipv6_packet(
            &udp_datagram_ipv6(CLIENT_PORT, target, &payload),
            0x1234_5678,
            mtu,
        )
        .into_iter()
        .rev()
        {
            assert!(fragment.len() <= mtu);
            incoming
                .send(fragment)
                .await
                .expect("inject out-of-order IPv6 UDP fragment into memory TUN");
        }

        let request = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("IPv6 TUN UDP flow did not reach Portal")
        .expect("read Reverse IPv6 UDP frame");
        assert_eq!(request.metadata.status, SessionStatus::New);
        assert_eq!(
            request
                .metadata
                .target
                .as_ref()
                .expect("Reverse target")
                .location,
            NetLocation::from_ip_addr(target.ip(), target.port())
        );
        assert_eq!(request.payload.as_ref(), payload.as_slice());

        let response = encode_frame(&MuxFrame {
            metadata: FrameMetadata {
                session_id: request.metadata.session_id,
                status: SessionStatus::Keep,
                option: FrameOption::default().with_data(),
                target: None,
                source: None,
                local: None,
                global_id: None,
            },
            payload: Bytes::from_static(b"pong-v6"),
        })
        .expect("encode Reverse Bridge IPv6 UDP response");
        bridge_peer
            .write_all(&response)
            .await
            .expect("write Reverse Bridge IPv6 UDP response");
        let source_ip = "fd00:254::2".parse::<Ipv6Addr>().expect("IPv6 source");
        assert_eq!(
            next_ipv6_udp_payload(&mut packets, b"pong-v6").await,
            (target_ip, source_ip, target.port(), CLIENT_PORT,)
        );

        let mut truncated = fragment_ipv6_packet(
            &udp_datagram_ipv6(CLIENT_PORT + 1, target, &payload),
            0x1234_5679,
            mtu,
        )
        .remove(0);
        truncated.pop();
        incoming
            .send(truncated)
            .await
            .expect("inject truncated IPv6 fragment into memory TUN");

        let mut overlapping = fragment_ipv6_packet(
            &udp_datagram_ipv6(CLIENT_PORT + 2, target, &payload),
            0x1234_567a,
            mtu,
        );
        assert!(overlapping.len() >= 2, "test datagram must be fragmented");
        set_ipv6_fragment_offset(&mut overlapping[1], 8);
        for fragment in overlapping {
            incoming
                .send(fragment)
                .await
                .expect("inject overlapping IPv6 fragment into memory TUN");
        }

        assert!(
            timeout(
                Duration::from_millis(200),
                read_frame_with_source_and_local(&mut bridge_peer, true),
            )
            .await
            .is_err(),
            "truncated and overlapping IPv6 fragments must not reach Reverse"
        );

        incoming
            .send(udp_datagram_ipv6(
                CLIENT_PORT + 2,
                target,
                b"valid-after-v6-overlap",
            ))
            .await
            .expect("inject valid IPv6 UDP after rejected fragments");
        let recovered = timeout(
            Duration::from_secs(3),
            read_frame_with_source_and_local(&mut bridge_peer, true),
        )
        .await
        .expect("valid IPv6 UDP after overlap did not reach Reverse")
        .expect("read recovered Reverse IPv6 UDP frame");
        assert_eq!(recovered.metadata.status, SessionStatus::New);
        assert_eq!(recovered.payload.as_ref(), b"valid-after-v6-overlap");
        assert_eq!(
            recovered
                .metadata
                .source
                .as_ref()
                .expect("recovered Reverse flow source")
                .location
                .port(),
            CLIENT_PORT + 2
        );

        drop(bridge_peer);
        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn global_xudp_reattach_reuses_reverse_site_session_and_edge_socket() {
        let echo_socket = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind site-to-site UDP echo target");
        let target_port = echo_socket
            .local_addr()
            .expect("site-to-site UDP echo address")
            .port();
        let (peer_sender, mut peer_receiver) = mpsc::channel(2);
        let echo_task = tokio::spawn(async move {
            for expected in [&b"before-detach"[..], &b"after-reattach"[..]] {
                let mut buffer = [0u8; 64];
                let (length, peer) = echo_socket
                    .recv_from(&mut buffer)
                    .await
                    .expect("receive site-to-site XUDP datagram");
                assert_eq!(&buffer[..length], expected);
                echo_socket
                    .send_to(&buffer[..length], peer)
                    .await
                    .expect("reply to site-to-site XUDP datagram");
                peer_sender
                    .send(peer)
                    .await
                    .expect("record Edge UDP socket address");
            }
        });

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        let hub_runtime = runtime_state.data_plane();
        let (portal_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
        let portal_lease = hub_runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(portal_stream)),
            )
            .await
            .expect("attach Hub Reverse Portal worker");
        let edge_runtime = RuntimeState::new(
            Vec::new(),
            vec![crate::outbound::freedom_outbound_allow_loopback("direct")],
        )
        .data_plane();
        let edge_worker = MuxServerWorker::new_with_context(
            Box::new(ReverseSessionStream::new(bridge_stream)),
            "bridge-in".into(),
            Arc::new(edge_runtime),
            BridgeDispatchContext {
                site_to_site: Some(loopback_site_policy(target_port)),
                ..BridgeDispatchContext::default()
            },
        );

        let overlay_target =
            SocketAddr::from((Ipv4Addr::new(10, 200, 1, 20), target_port));
        let target = crate::address::NetLocation::from_ip_addr(
            overlay_target.ip(),
            overlay_target.port(),
        );
        let source = SocketAddr::from((Ipv4Addr::new(10, 44, 0, 2), 34567));
        let global_id = [0x52, 0x53, 0x49, 0x54, 0x45, 0x31, 0x31, 0x01];
        let key = TargetedUdpSessionKey {
            target_addr: overlay_target,
            outbound_tag: Some("reverse-out".into()),
        };
        let mut sessions = std::collections::HashMap::new();
        let mut next_generation = 1;
        let (response_sender_a, mut response_receiver_a) = mpsc::channel(4);
        let sender_a = replace_reverse_session_udp_worker(
            &mut sessions,
            501,
            &mut next_generation,
            ReverseSessionUdpWorkerStart {
                key: key.clone(),
                response_sender: response_sender_a,
                traffic_context: None,
                resolver: Arc::new(NativeResolver::new()),
                runtime: hub_runtime.clone(),
                tag: "reverse-out".into(),
                target: target.clone(),
                source,
                local: None,
                global_id: Some(global_id),
                idle_timeout: Duration::from_secs(10),
            },
        )
        .await
        .expect("attach first XUDP GlobalID to Reverse site worker");
        sender_a
            .send_to(b"before-detach".to_vec(), overlay_target)
            .await
            .expect("send first XUDP datagram through Reverse site");
        let first_response =
            timeout(Duration::from_secs(3), response_receiver_a.recv())
                .await
                .expect("first Reverse site XUDP response timed out")
                .expect("first Reverse site response channel closed");
        let SessionUdpEvent::Data(first_response) = first_response else {
            panic!("first Reverse site XUDP response ended unexpectedly");
        };
        assert_eq!(first_response.session_id, 501);
        assert_eq!(first_response.generation, 1);
        assert_eq!(first_response.source, overlay_target);
        assert_eq!(first_response.payload, b"before-detach");

        expire_session_udp_worker(&mut sessions, 501).await;

        let (response_sender_b, mut response_receiver_b) = mpsc::channel(4);
        let sender_b = replace_reverse_session_udp_worker(
            &mut sessions,
            502,
            &mut next_generation,
            ReverseSessionUdpWorkerStart {
                key,
                response_sender: response_sender_b,
                traffic_context: None,
                resolver: Arc::new(NativeResolver::new()),
                runtime: hub_runtime.clone(),
                tag: "reverse-out".into(),
                target,
                source,
                local: None,
                global_id: Some(global_id),
                idle_timeout: Duration::from_secs(10),
            },
        )
        .await
        .expect("reattach XUDP GlobalID to existing Reverse site worker");
        sender_b
            .send_to(b"after-reattach".to_vec(), overlay_target)
            .await
            .expect("send reattached XUDP datagram through Reverse site");
        let second_response =
            timeout(Duration::from_secs(3), response_receiver_b.recv())
                .await
                .expect("reattached Reverse site XUDP response timed out")
                .expect("reattached Reverse site response channel closed");
        let SessionUdpEvent::Data(second_response) = second_response else {
            panic!("reattached Reverse site XUDP response ended unexpectedly");
        };
        assert_eq!(second_response.session_id, 502);
        assert_eq!(second_response.generation, 2);
        assert_eq!(second_response.source, overlay_target);
        assert_eq!(second_response.payload, b"after-reattach");

        let first_peer = timeout(Duration::from_secs(1), peer_receiver.recv())
            .await
            .expect("first Edge UDP peer timeout")
            .expect("first Edge UDP peer missing");
        let second_peer = timeout(Duration::from_secs(1), peer_receiver.recv())
            .await
            .expect("reattached Edge UDP peer timeout")
            .expect("reattached Edge UDP peer missing");
        assert_eq!(
            first_peer, second_peer,
            "GlobalID reattachment must keep the same Edge UDP socket"
        );
        echo_task.await.expect("site-to-site UDP echo task failed");

        terminate_session_udp_worker(&mut sessions, 502).await;
        edge_worker.close();
        edge_worker.wait_closed().await;
        drop(edge_worker);
        drop(portal_lease);
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tun_tcp_and_udp_cross_hub_reverse_edge_mapping_to_loopback_lan() {
        let first_mapped_ip = Ipv4Addr::new(127, 0, 0, 20);
        let second_mapped_ip = Ipv4Addr::new(127, 0, 0, 21);
        let tcp_listener = HostTcpListener::bind((first_mapped_ip, 0))
            .await
            .expect("bind mapped TCP target");
        let target_port = tcp_listener.local_addr().expect("TCP target").port();
        let first_udp_socket = HostUdpSocket::bind((first_mapped_ip, target_port))
            .await
            .expect("bind first mapped UDP target on shared port");
        let second_udp_socket = HostUdpSocket::bind((second_mapped_ip, target_port))
            .await
            .expect("bind second mapped UDP target on shared port");
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener
                .accept()
                .await
                .expect("accept mapped TUN TCP flow");
            let mut payload = [0; 4];
            stream
                .read_exact(&mut payload)
                .await
                .expect("read TCP request");
            stream.write_all(b"pong").await.expect("write TCP response");
        });
        let first_udp_echo = tokio::spawn(async move {
            let mut payload = [0; 8];
            let (len, peer) = first_udp_socket
                .recv_from(&mut payload)
                .await
                .expect("receive first mapped TUN UDP datagram");
            first_udp_socket
                .send_to(&payload[..len], peer)
                .await
                .expect("send first mapped UDP response");
        });
        let second_udp_echo = tokio::spawn(async move {
            let mut payload = [0; 8];
            let (len, peer) = second_udp_socket
                .recv_from(&mut payload)
                .await
                .expect("receive second mapped TUN UDP datagram");
            second_udp_socket
                .send_to(&payload[..len], peer)
                .await
                .expect("send second mapped UDP response");
        });

        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![OutboundSummary {
                tag: "reverse-out".into(),
                protocol: "vless-reverse".into(),
                proxy_settings_type: None,
                proxy_settings_value: None,
                sender_settings_type: None,
                sender_settings_value: None,
            }],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![RuleConfig {
                    inbound_tag: vec!["office-tun".into()],
                    network: NetworkListConfig(vec!["tcp".into(), "udp".into()]),
                    outbound_tag: Some("reverse-out".into()),
                    ..RuleConfig::default()
                }],
                ..RoutingConfig::default()
            }))
            .expect("compile TUN TCP/UDP route to Reverse"),
        );
        let hub_runtime = runtime_state.data_plane();
        let (portal_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
        let portal_lease = hub_runtime
            .attach_reverse_portal(
                "reverse-out",
                Box::new(ReverseSessionStream::new(portal_stream)),
            )
            .await
            .expect("attach Hub Reverse Portal worker");
        let edge_runtime = RuntimeState::new(
            Vec::new(),
            vec![crate::outbound::freedom_outbound_allow_loopback("direct")],
        )
        .data_plane();
        let edge_worker = MuxServerWorker::new_with_context(
            Box::new(ReverseSessionStream::new(bridge_stream)),
            "bridge-in".into(),
            Arc::new(edge_runtime),
            BridgeDispatchContext {
                site_to_site: Some(
                    SiteToSitePolicy::compile(&SiteToSiteConfig {
                        prefix_maps: vec![SitePrefixMapConfig {
                            from: "10.200.1.0/24".into(),
                            to: "127.0.0.0/24".into(),
                        }],
                        allow: vec![SiteTargetAllowConfig {
                            network: vec!["tcp".into(), "udp".into()],
                            ip: vec!["127.0.0.0/24".into()],
                            ports: vec![target_port.to_string()],
                        }],
                    })
                    .expect("compile shared-port mapped LAN policy"),
                ),
                ..BridgeDispatchContext::default()
            },
        );

        let plan = TunGatewayPlan::try_from(config()).expect("valid gateway plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(64);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_server(
            device,
            plan,
            hub_runtime,
            CancellationToken::new(),
        ));
        let overlay_target: SocketAddr = format!("10.200.1.20:{target_port}")
            .parse()
            .expect("Overlay target");

        const TCP_CLIENT_PORT: u16 = 45_559;
        incoming
            .send(tcp_syn(TCP_CLIENT_PORT, overlay_target))
            .await
            .expect("inject TCP SYN into memory TUN");
        let (_, server_sequence) = next_tcp_syn_ack(&mut packets).await;
        incoming
            .send(tcp_ack(
                TCP_CLIENT_PORT,
                overlay_target,
                101,
                server_sequence.wrapping_add(1),
                b"ping",
            ))
            .await
            .expect("inject TCP payload into memory TUN");
        let tcp_reply = timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if contains_tcp_payload(&packet, b"pong") {
                    return packet;
                }
            }
        })
        .await
        .expect("mapped TCP echo did not return through TUN");
        let tcp_ip = etherparse::Ipv4HeaderSlice::from_slice(&tcp_reply)
            .expect("parse returned TCP IPv4 header");
        let tcp =
            SlicedPacket::from_ip(&tcp_reply).expect("parse returned TCP packet");
        let Some(TransportSlice::Tcp(tcp)) = tcp.transport else {
            panic!("expected returned TCP packet");
        };
        assert_eq!(tcp_ip.source_addr(), Ipv4Addr::new(10, 200, 1, 20));
        assert_eq!(tcp_ip.destination_addr(), Ipv4Addr::new(10, 44, 0, 2));
        assert_eq!(tcp.source_port(), target_port);
        assert_eq!(tcp.destination_port(), TCP_CLIENT_PORT);
        tcp_echo.await.expect("mapped TCP echo task failed");

        const UDP_CLIENT_PORT: u16 = 45_560;
        let first_overlay_target: SocketAddr = format!("10.200.1.20:{target_port}")
            .parse()
            .expect("first Overlay target");
        incoming
            .send(udp_datagram(
                UDP_CLIENT_PORT,
                first_overlay_target,
                b"udp-one",
            ))
            .await
            .expect("inject first UDP datagram into memory TUN");
        assert_eq!(
            next_udp_payload(&mut packets, b"udp-one").await,
            (
                Ipv4Addr::new(10, 200, 1, 20),
                Ipv4Addr::new(10, 44, 0, 2),
                target_port,
                UDP_CLIENT_PORT,
            )
        );
        first_udp_echo
            .await
            .expect("first mapped UDP echo task failed");

        let second_overlay_target: SocketAddr = format!("10.200.1.21:{target_port}")
            .parse()
            .expect("second Overlay target");
        incoming
            .send(udp_datagram(
                UDP_CLIENT_PORT,
                second_overlay_target,
                b"udp-two",
            ))
            .await
            .expect("inject second UDP target from the same client port");
        assert_eq!(
            next_udp_payload(&mut packets, b"udp-two").await,
            (
                Ipv4Addr::new(10, 200, 1, 21),
                Ipv4Addr::new(10, 44, 0, 2),
                target_port,
                UDP_CLIENT_PORT,
            )
        );
        timeout(Duration::from_secs(2), second_udp_echo)
            .await
            .expect("second mapped UDP echo timed out")
            .expect("second mapped UDP echo task failed");

        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after device closure")
            .expect("TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        drop(edge_worker);
        drop(portal_lease);
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "vless-reverse")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tun_routes_overlapping_lan_prefixes_to_distinct_reverse_sites() {
        let shared_lan_ip = Ipv4Addr::new(127, 0, 0, 20);
        let tcp_listener = HostTcpListener::bind((shared_lan_ip, 0))
            .await
            .expect("bind shared overlapping-LAN TCP target");
        let target_port = tcp_listener.local_addr().expect("TCP target").port();
        let udp_socket = HostUdpSocket::bind((shared_lan_ip, target_port))
            .await
            .expect("bind shared overlapping-LAN UDP target");

        let tcp_echo = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = tcp_listener
                    .accept()
                    .await
                    .expect("accept TCP flow from a site");
                let mut payload = [0; 4];
                stream
                    .read_exact(&mut payload)
                    .await
                    .expect("read TCP payload");
                stream.write_all(&payload).await.expect("write TCP echo");
            }
        });
        let udp_echo = tokio::spawn(async move {
            let mut payload = [0; 8];
            for _ in 0..2 {
                let (len, peer) = udp_socket
                    .recv_from(&mut payload)
                    .await
                    .expect("receive UDP datagram from a site");
                udp_socket
                    .send_to(&payload[..len], peer)
                    .await
                    .expect("send UDP echo");
            }
        });

        let reverse_outbound = |tag: &str| OutboundSummary {
            tag: tag.into(),
            protocol: "vless-reverse".into(),
            proxy_settings_type: None,
            proxy_settings_value: None,
            sender_settings_type: None,
            sender_settings_value: None,
        };
        let runtime_state = RuntimeState::new(
            Vec::new(),
            vec![reverse_outbound("site-a"), reverse_outbound("site-b")],
        );
        runtime_state.replace_routing(
            RoutingState::from_config(Some(&RoutingConfig {
                rules: vec![
                    RuleConfig {
                        inbound_tag: vec!["office-tun".into()],
                        network: NetworkListConfig(vec!["tcp".into(), "udp".into()]),
                        ip: vec!["10.200.1.0/24".into()],
                        outbound_tag: Some("site-a".into()),
                        ..RuleConfig::default()
                    },
                    RuleConfig {
                        inbound_tag: vec!["office-tun".into()],
                        network: NetworkListConfig(vec!["tcp".into(), "udp".into()]),
                        ip: vec!["10.200.2.0/24".into()],
                        outbound_tag: Some("site-b".into()),
                        ..RuleConfig::default()
                    },
                ],
                ..RoutingConfig::default()
            }))
            .expect("compile separate routes for the two Overlay prefixes"),
        );
        let hub_runtime = runtime_state.data_plane();

        let (portal_stream_a, bridge_stream_a) = tokio::io::duplex(64 * 1024);
        let portal_lease_a = hub_runtime
            .attach_reverse_portal(
                "site-a",
                Box::new(ReverseSessionStream::new(portal_stream_a)),
            )
            .await
            .expect("attach Site A Reverse Portal");
        let edge_runtime_a = RuntimeState::new(
            Vec::new(),
            vec![crate::outbound::freedom_outbound_allow_loopback("direct")],
        )
        .data_plane();
        let edge_worker_a = MuxServerWorker::new_with_context(
            Box::new(ReverseSessionStream::new(bridge_stream_a)),
            "site-a-edge".into(),
            Arc::new(edge_runtime_a),
            BridgeDispatchContext {
                site_to_site: Some(overlapping_lan_site_policy(
                    "10.200.1.0/24",
                    target_port,
                )),
                ..BridgeDispatchContext::default()
            },
        );

        let (portal_stream_b, bridge_stream_b) = tokio::io::duplex(64 * 1024);
        let portal_lease_b = hub_runtime
            .attach_reverse_portal(
                "site-b",
                Box::new(ReverseSessionStream::new(portal_stream_b)),
            )
            .await
            .expect("attach Site B Reverse Portal");
        let edge_runtime_b = RuntimeState::new(
            Vec::new(),
            vec![crate::outbound::freedom_outbound_allow_loopback("direct")],
        )
        .data_plane();
        let edge_worker_b = MuxServerWorker::new_with_context(
            Box::new(ReverseSessionStream::new(bridge_stream_b)),
            "site-b-edge".into(),
            Arc::new(edge_runtime_b),
            BridgeDispatchContext {
                site_to_site: Some(overlapping_lan_site_policy(
                    "10.200.2.0/24",
                    target_port,
                )),
                ..BridgeDispatchContext::default()
            },
        );

        let plan = TunGatewayPlan::try_from(config()).expect("valid gateway plan");
        let (incoming, input) = mpsc::channel(16);
        let (output, mut packets) = mpsc::channel(64);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let cancellation = CancellationToken::new();
        let service = tokio::spawn(run_server(
            device,
            plan,
            hub_runtime,
            cancellation.clone(),
        ));

        let site_a: SocketAddr = format!("10.200.1.20:{target_port}")
            .parse()
            .expect("Site A Overlay target");
        let site_b: SocketAddr = format!("10.200.2.20:{target_port}")
            .parse()
            .expect("Site B Overlay target");
        for (source_port, target, payload) in [
            (45_561, site_a, b"site".as_slice()),
            (45_562, site_b, b"site".as_slice()),
        ] {
            incoming
                .send(tcp_syn(source_port, target))
                .await
                .expect("inject site TCP SYN into memory TUN");
            let (_, server_sequence) = next_tcp_syn_ack(&mut packets).await;
            incoming
                .send(tcp_ack(
                    source_port,
                    target,
                    101,
                    server_sequence.wrapping_add(1),
                    payload,
                ))
                .await
                .expect("inject site TCP payload into memory TUN");

            let reply = timeout(Duration::from_secs(3), async {
                loop {
                    let packet =
                        packets.recv().await.expect("memory TUN output closed");
                    if contains_tcp_payload(&packet, payload) {
                        break packet;
                    }
                }
            })
            .await
            .expect("overlapping-LAN TCP response timed out");
            let ip = etherparse::Ipv4HeaderSlice::from_slice(&reply)
                .expect("parse returned TCP IPv4 header");
            let reply =
                SlicedPacket::from_ip(&reply).expect("parse returned TCP packet");
            let Some(TransportSlice::Tcp(tcp)) = reply.transport else {
                panic!("expected returned TCP packet");
            };
            assert_eq!(ip.source_addr(), target.ip());
            assert_eq!(ip.destination_addr(), Ipv4Addr::new(10, 44, 0, 2));
            assert_eq!(tcp.source_port(), target_port);
            assert_eq!(tcp.destination_port(), source_port);
        }

        for (source_port, target, payload) in [
            (45_563, site_a, b"site-a".as_slice()),
            (45_564, site_b, b"site-b".as_slice()),
        ] {
            incoming
                .send(udp_datagram(source_port, target, payload))
                .await
                .expect("inject site UDP datagram into memory TUN");
            assert_eq!(
                next_udp_payload(&mut packets, payload).await,
                (
                    match target.ip() {
                        std::net::IpAddr::V4(address) => address,
                        std::net::IpAddr::V6(_) => unreachable!(),
                    },
                    Ipv4Addr::new(10, 44, 0, 2),
                    target_port,
                    source_port,
                )
            );
        }

        tcp_echo.await.expect("shared TCP echo task failed");
        udp_echo.await.expect("shared UDP echo task failed");
        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("TUN service did not stop after cancellation")
            .expect("TUN service task panicked")
            .expect("cooperative TUN shutdown should complete cleanly");
        drop(edge_worker_a);
        drop(edge_worker_b);
        drop(portal_lease_a);
        drop(portal_lease_b);
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }
}
