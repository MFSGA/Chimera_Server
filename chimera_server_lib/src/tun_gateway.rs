//! Linux TUN ingress services.
//!
//! The device-owned `tunGateway` extension and Xray-compatible `protocol: "tun"`
//! inbound have separate configuration plans and route ownership. Both feed
//! packets through watfaq-netstack and Chimera's Dokodemo routing paths.

use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::Error;
#[cfg(any(feature = "tun-gateway", test))]
use crate::config::def::TunGatewayConfig;
use crate::{
    address::NetLocation,
    async_stream::{AsyncPing, AsyncStream},
    config::server_config::DokodemoDoorConfig,
    config::server_config::InboundSniffingConfig,
    handler::{
        dokodemo::DokodemoDoorTcpHandler,
        tcp::tcp_handler::{TcpServerConnectionContext, TcpServerHandler},
    },
    runtime::DataPlaneRuntime,
    session::dispatcher::process_stream_with_context,
};
#[cfg(feature = "xray-tun")]
use rand::RngExt as _;
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
use watfaq_netstack::{NetStack, Packet, TcpStream};

mod system;

use system::{ManagedTunAddresses, ManagedTunRouting, ManagedTunSystemRoutes};
#[cfg(any(feature = "tun-gateway", test))]
use system::{
    TunIpv6AddressConfigureError, configure_ipv6_tun_address, install_tun_routing,
};
#[cfg(feature = "xray-tun")]
use system::{install_xray_tun_addresses, install_xray_tun_system_routes};

#[cfg(test)]
const NETSTACK_MTU: usize = 1500;
#[cfg(any(feature = "tun-gateway", test))]
const MIN_TUN_GATEWAY_MTU: usize = 1280;
#[cfg(any(feature = "tun-gateway", test))]
const MAX_TUN_GATEWAY_MTU: usize = 9000;
#[cfg(any(feature = "tun-gateway", feature = "xray-tun", test))]
const NETSTACK_MAX_TCP_STREAMS: usize = 512;
#[cfg(feature = "xray-tun")]
const XRAY_TUN_MAX_UDP_SESSIONS: usize = 1024;
#[cfg(feature = "xray-tun")]
const XRAY_TUN_MIN_MTU: usize = 1280;
#[cfg(any(feature = "tun-gateway", test))]
const MAX_MANAGED_TUN_PREFIXES: usize = 128;
#[cfg(any(feature = "tun-gateway", test))]
const DEFAULT_TUN_ROUTE_TABLE: u32 = 10_001;
#[cfg(any(feature = "tun-gateway", test))]
const DEFAULT_TUN_ROUTE_RULE_PRIORITY: u32 = 10_001;

#[cfg(any(feature = "tun-gateway", feature = "xray-tun", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpPrefix {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
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
    device_kind: &'static str,
    device_name: String,
    source: std::io::Error,
}

impl std::fmt::Display for TunDeviceCreateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "failed to create {} device {}: {}",
            self.device_kind, self.device_name, self.source
        )
    }
}

impl std::error::Error for TunDeviceCreateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(feature = "xray-tun")]
use crate::{
    config::def::{InboudItem, XrayTunConfig},
    config::server_config::collect_sniffing_config,
};

#[derive(Debug, Clone, Copy)]
struct TunInterfaceAddress {
    address: IpAddr,
    prefix_len: u8,
}

#[cfg(feature = "xray-tun")]
#[derive(Debug, Clone)]
pub(crate) struct XrayTunPlan {
    name: String,
    mtu: usize,
    gateway: Vec<TunInterfaceAddress>,
    system_routes: Vec<IpPrefix>,
    inbound_tag: String,
    user_level: u32,
    sniffing: Option<InboundSniffingConfig>,
    quic_route_only: bool,
}

#[derive(Debug, Clone)]
struct TunForwardingPlan {
    mtu: usize,
    local_ipv4: Option<Ipv4Addr>,
    local_ipv6: Option<Ipv6Addr>,
    inbound_tag: String,
    user_level: u32,
    max_tcp_connections: usize,
    max_udp_sessions: usize,
    sniffing: Option<InboundSniffingConfig>,
    quic_route_only: bool,
    // The shared stack repairs invalid IPv4 Echo Request checksums only for
    // Xray TUN, after IP fragments have been reassembled.
    accept_invalid_ipv4_icmp_echo_checksum: bool,
}

#[cfg(any(feature = "tun-gateway", test))]
impl TunGatewayPlan {
    fn forwarding_plan(&self) -> TunForwardingPlan {
        TunForwardingPlan {
            mtu: self.mtu,
            local_ipv4: Some(self.address),
            local_ipv6: self.ipv6_address.map(|(address, _)| address),
            inbound_tag: self.inbound_tag.clone(),
            user_level: self.user_level,
            max_tcp_connections: self.max_tcp_connections,
            max_udp_sessions: self.max_udp_sessions,
            sniffing: None,
            quic_route_only: false,
            accept_invalid_ipv4_icmp_echo_checksum: false,
        }
    }
}

#[cfg(feature = "xray-tun")]
impl XrayTunPlan {
    pub(crate) fn tag(&self) -> &str {
        &self.inbound_tag
    }

    pub(crate) fn try_from(item: InboudItem) -> Result<Self, String> {
        if !matches!(item.protocol, crate::config::Protocol::Tun) {
            return Err("expected an Xray TUN inbound".into());
        }
        let config = item
            .settings
            .as_ref()
            .map(|settings| settings.deserialize::<XrayTunConfig>())
            .transpose()
            .map_err(|error| format!("invalid tun settings: {error}"))?
            .unwrap_or_default();
        let mtu = if config.mtu == 0 { 1500 } else { config.mtu };
        if !(XRAY_TUN_MIN_MTU as u32..=u16::MAX as u32).contains(&mtu) {
            return Err(format!(
                "inbound tun settings.mtu must be from {XRAY_TUN_MIN_MTU} to {} on Linux",
                u16::MAX
            ));
        }
        let name = if config.name.is_empty() {
            available_xray_tun_name()?
        } else {
            validate_xray_tun_name(&config.name)?
        };
        let gateway = config
            .gateway
            .iter()
            .map(|address| parse_tun_interface_address(address))
            .collect::<Result<Vec<_>, _>>()?;
        let system_routes =
            parse_xray_system_routes(&config.auto_system_routing_table)?;
        // Xray's Linux backend does not consume desc, dns, or
        // autoOutboundsInterface; retain its platform-specific no-op behavior.
        let _linux_unused_settings =
            (config.desc, config.dns, config.auto_outbounds_interface);
        let quic_override = item
            .sniffing
            .as_ref()
            .is_some_and(sniffing_requests_quic_override);
        let quic_sniffing_enabled = quic_override
            && item
                .sniffing
                .as_ref()
                .and_then(|sniffing| sniffing.get("enabled"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        let quic_route_only = quic_sniffing_enabled
            && item
                .sniffing
                .as_ref()
                .and_then(|sniffing| sniffing.get("routeOnly"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
        if quic_sniffing_enabled && !quic_route_only {
            return Err(
                "inbound tun sniffing.destOverride=quic currently requires routeOnly=true; UDP destination override is not implemented yet".into(),
            );
        }
        let sniffing = collect_sniffing_config(&item.tag, item.sniffing)
            .map_err(|error| error.to_string())?;

        Ok(Self {
            name,
            mtu: mtu as usize,
            gateway,
            system_routes,
            inbound_tag: item.tag,
            user_level: config.user_level,
            sniffing,
            quic_route_only,
        })
    }

    fn forwarding_plan(&self) -> TunForwardingPlan {
        TunForwardingPlan {
            mtu: self.mtu,
            local_ipv4: self.gateway.iter().find_map(|address| {
                match address.address {
                    IpAddr::V4(address) => Some(address),
                    IpAddr::V6(_) => None,
                }
            }),
            local_ipv6: self.gateway.iter().find_map(|address| {
                match address.address {
                    IpAddr::V6(address) => Some(address),
                    IpAddr::V4(_) => None,
                }
            }),
            inbound_tag: self.inbound_tag.clone(),
            user_level: self.user_level,
            max_tcp_connections: NETSTACK_MAX_TCP_STREAMS,
            max_udp_sessions: XRAY_TUN_MAX_UDP_SESSIONS,
            sniffing: self.sniffing.clone(),
            quic_route_only: self.quic_route_only,
            accept_invalid_ipv4_icmp_echo_checksum: true,
        }
    }
}

#[cfg(feature = "xray-tun")]
fn parse_xray_system_routes(values: &[String]) -> Result<Vec<IpPrefix>, String> {
    let mut parsed = Vec::with_capacity(values.len());
    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        let route = parse_xray_system_route(value)?;
        if !seen.insert(route) {
            return Err(format!(
                "inbound tun settings.autoSystemRoutingTable contains duplicate route {value}"
            ));
        }
        parsed.push(route);
    }
    Ok(parsed)
}

#[cfg(feature = "xray-tun")]
fn parse_xray_system_route(value: &str) -> Result<IpPrefix, String> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        "inbound tun settings.autoSystemRoutingTable entries must be IP CIDRs"
            .to_string()
    })?;
    let address = address.parse::<IpAddr>().map_err(|_| {
        "inbound tun settings.autoSystemRoutingTable entries must be IP CIDRs"
            .to_string()
    })?;
    let prefix = prefix.parse::<u8>().map_err(|_| {
        "inbound tun settings.autoSystemRoutingTable entries must use valid prefix lengths"
            .to_string()
    })?;
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Ok(IpPrefix::V4(
                Ipv4Addr::from(u32::from(address) & mask),
                prefix,
            ))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            Ok(IpPrefix::V6(
                Ipv6Addr::from(u128::from(address) & mask),
                prefix,
            ))
        }
        IpAddr::V4(_) => Err(
            "inbound tun settings.autoSystemRoutingTable IPv4 prefix must not exceed 32"
                .into(),
        ),
        IpAddr::V6(_) => Err(
            "inbound tun settings.autoSystemRoutingTable IPv6 prefix must not exceed 128"
                .into(),
        ),
    }
}

#[cfg(feature = "xray-tun")]
fn sniffing_requests_quic_override(sniffing: &serde_json::Value) -> bool {
    sniffing
        .get("destOverride")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|protocols| {
            protocols.iter().any(|protocol| {
                protocol
                    .as_str()
                    .is_some_and(|protocol| protocol.eq_ignore_ascii_case("quic"))
            })
        })
}

#[cfg(feature = "xray-tun")]
fn validate_xray_tun_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(
            "inbound tun settings.name must contain 1-15 ASCII letters, digits, '.', '_' or '-'"
                .into(),
        );
    }
    Ok(name.to_owned())
}

#[cfg(feature = "xray-tun")]
fn available_xray_tun_name() -> Result<String, String> {
    let interfaces = std::fs::read_dir("/sys/class/net").map_err(|error| {
        format!("failed to list Linux network interfaces: {error}")
    })?;
    let used = interfaces
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect::<HashSet<_>>();
    let start = rand::rng().random_range(10..=1024);
    for offset in 0..=1014 {
        let index = 10 + (start - 10 + offset) % 1015;
        let name = format!("utun{index}");
        if !used.contains(std::ffi::OsStr::new(&name)) {
            return Ok(name);
        }
    }
    Err("no available Linux TUN name in range utun10-utun1024".into())
}

#[cfg(feature = "xray-tun")]
fn parse_tun_interface_address(value: &str) -> Result<TunInterfaceAddress, String> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        "inbound tun settings.gateway entries must be IP CIDRs".to_string()
    })?;
    let address = address.parse::<IpAddr>().map_err(|_| {
        "inbound tun settings.gateway entries must be IP CIDRs".to_string()
    })?;
    let prefix_len = prefix.parse::<u8>().map_err(|_| {
        "inbound tun settings.gateway entries must use valid prefix lengths"
            .to_string()
    })?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_prefix {
        return Err(format!(
            "inbound tun settings.gateway prefix length must not exceed {max_prefix}"
        ));
    }
    Ok(TunInterfaceAddress {
        address,
        prefix_len,
    })
}

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
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
                device_kind: "tunGateway",
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
                Error::Io(std::io::Error::other(TunIpv6AddressConfigureError::new(
                    plan.name.clone(),
                    address,
                    prefix_len,
                    source,
                )))
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
        plan.forwarding_plan(),
        runtime,
        cancellation.clone(),
        managed_routing,
        None,
        None,
    ));
    Ok(TunGatewayTask { task, cancellation })
}

#[cfg(feature = "xray-tun")]
pub(crate) async fn start_xray_tun_server(
    plan: XrayTunPlan,
    runtime: DataPlaneRuntime,
) -> Result<TunGatewayTask, Error> {
    if plan
        .system_routes
        .iter()
        .any(|route| matches!(route, IpPrefix::V4(_, 0) | IpPrefix::V6(_, 0)))
    {
        tracing::warn!(
            inbound_tag = %plan.inbound_tag,
            "Xray TUN installs a default route that may capture this server's own outbound connections; configure an escape route when needed"
        );
    }

    let mut config = tun::Configuration::default();
    config
        .tun_name(&plan.name)
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
            "failed to create Xray TUN inbound device"
        );
        Error::Io(std::io::Error::new(
            error_kind,
            TunDeviceCreateError {
                device_kind: "Xray TUN",
                device_name: plan.name.clone(),
                source: error,
            },
        ))
    })?;
    let addresses = install_xray_tun_addresses(&plan).await?;
    let system_routes = match install_xray_tun_system_routes(&plan).await {
        Ok(routes) => routes,
        Err(error) => {
            if let Some(addresses) = addresses
                && let Err(cleanup_error) = addresses.remove().await
            {
                tracing::error!(%cleanup_error, "failed to roll back Xray TUN addresses after route setup error");
            }
            return Err(error);
        }
    };
    tracing::info!(
        tun_name = %plan.name,
        mtu = plan.mtu,
        gateway_addresses = plan.gateway.len(),
        system_routes = plan.system_routes.len(),
        inbound_tag = %plan.inbound_tag,
        "starting Linux Xray TUN inbound"
    );

    let cancellation = CancellationToken::new();
    let task = tokio::spawn(run_server_with_routing(
        device,
        plan.forwarding_plan(),
        runtime,
        cancellation.clone(),
        None,
        addresses,
        system_routes,
    ));
    Ok(TunGatewayTask { task, cancellation })
}

#[cfg(any(feature = "tun-gateway", test))]
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
    run_server_with_routing(
        device,
        plan.forwarding_plan(),
        runtime,
        cancellation,
        None,
        None,
        None,
    )
    .await
}

#[cfg(all(test, feature = "xray-tun"))]
async fn run_forwarding_server<D: PacketDevice + 'static>(
    device: D,
    plan: TunForwardingPlan,
    runtime: DataPlaneRuntime,
    cancellation: CancellationToken,
) -> Result<(), Error> {
    run_server_with_routing(device, plan, runtime, cancellation, None, None, None)
        .await
}

async fn run_server_with_routing<D: PacketDevice + 'static>(
    device: D,
    plan: TunForwardingPlan,
    runtime: DataPlaneRuntime,
    cancellation: CancellationToken,
    managed_routing: Option<ManagedTunRouting>,
    managed_addresses: Option<ManagedTunAddresses>,
    managed_system_routes: Option<ManagedTunSystemRoutes>,
) -> Result<(), Error> {
    use futures::{SinkExt, StreamExt};

    let (stack, mut tcp_listener, udp_socket) =
        if plan.accept_invalid_ipv4_icmp_echo_checksum {
            NetStack::new_with_mtu_xray_tun_compat(plan.mtu)
        } else {
            NetStack::new_with_mtu(plan.mtu)
        }
        .map_err(Error::Io)?;
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
            plan.local_ipv4
                .map(|address| SocketAddr::new(address.into(), 0)),
            plan.local_ipv6
                .map(|address| SocketAddr::new(address.into(), 0)),
        )),
        plan.max_udp_sessions,
    )
    .with_route_only_quic_sniffing(
        plan.quic_route_only
            .then(|| plan.sniffing.clone())
            .flatten(),
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
                let sniffing = plan.sniffing.clone();
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
                        sniffing,
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

    // Stop the QUIC SNI timeout workers before draining forwarding state.
    udp_forwarder.shutdown().await;

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

    if let Some(managed_system_routes) = managed_system_routes
        && let Err(error) = managed_system_routes.remove().await
    {
        tracing::error!(
            inbound_tag = %plan.inbound_tag,
            %error,
            "failed to remove Xray TUN system routes during shutdown"
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

    if let Some(managed_addresses) = managed_addresses
        && let Err(error) = managed_addresses.remove().await
    {
        tracing::error!(
            inbound_tag = %plan.inbound_tag,
            %error,
            "failed to remove Xray TUN gateway addresses during shutdown"
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
        time::{sleep, timeout},
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
    #[cfg(all(feature = "xray-tun", not(feature = "vless-reverse")))]
    use crate::{
        config::rule::{NetworkListConfig, RoutingConfig, RuleConfig},
        routing_state::RoutingState,
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

    #[cfg(feature = "xray-tun")]
    fn xray_tun_inbound(settings: serde_json::Value) -> InboudItem {
        serde_json::from_value(serde_json::json!({
            "protocol": "tun",
            "tag": "xray-tun",
            "settings": settings
        }))
        .expect("valid Xray TUN inbound shape")
    }

    #[cfg(feature = "xray-tun")]
    fn xray_tun_inbound_with_sniffing(
        settings: serde_json::Value,
        sniffing: serde_json::Value,
    ) -> InboudItem {
        serde_json::from_value(serde_json::json!({
            "protocol": "tun",
            "tag": "xray-tun",
            "settings": settings,
            "sniffing": sniffing
        }))
        .expect("valid Xray TUN inbound with top-level sniffing")
    }

    #[cfg(feature = "xray-tun")]
    #[test]
    fn xray_tun_config_uses_xray_defaults_and_compiles_gateway_addresses() {
        let plan = XrayTunPlan::try_from(xray_tun_inbound(serde_json::json!({
            "name": "chimera-tun",
            "mtu": 1280,
            "gateway": ["10.10.0.1/24", "fd10::1/64"],
            "userLevel": 3,
            "autoSystemRoutingTable": [
                "192.0.2.99/24",
                "0.0.0.0/0",
                "2001:db8::9/64"
            ],
            "autoOutboundsInterface": "eth0"
        })))
        .expect("valid Xray TUN config");

        assert_eq!(plan.name, "chimera-tun");
        assert_eq!(plan.mtu, 1280);
        assert_eq!(plan.user_level, 3);
        assert_eq!(plan.tag(), "xray-tun");
        assert_eq!(
            plan.system_routes,
            vec![
                IpPrefix::V4("192.0.2.0".parse().unwrap(), 24),
                IpPrefix::V4(Ipv4Addr::UNSPECIFIED, 0),
                IpPrefix::V6("2001:db8::".parse().unwrap(), 64),
            ]
        );
        let forwarding = plan.forwarding_plan();
        assert_eq!(forwarding.local_ipv4, Some("10.10.0.1".parse().unwrap()));
        assert_eq!(forwarding.local_ipv6, Some("fd10::1".parse().unwrap()));
        assert_eq!(forwarding.max_tcp_connections, NETSTACK_MAX_TCP_STREAMS);
        assert_eq!(forwarding.max_udp_sessions, XRAY_TUN_MAX_UDP_SESSIONS);
        assert_eq!(forwarding.inbound_tag, "xray-tun");
    }

    #[cfg(feature = "xray-tun")]
    #[test]
    fn xray_tun_config_defaults_name_and_mtu_like_xray() {
        let plan = XrayTunPlan::try_from(xray_tun_inbound(serde_json::json!({})))
            .expect("default Xray TUN config");

        let index = plan
            .name
            .strip_prefix("utun")
            .expect("default Xray TUN name uses utun prefix")
            .parse::<u16>()
            .expect("default Xray TUN name has numeric suffix");
        assert!((10..=1024).contains(&index));
        assert_eq!(plan.mtu, 1500);
        assert!(plan.gateway.is_empty());
        assert_eq!(plan.user_level, 0);
    }

    #[cfg(feature = "xray-tun")]
    #[test]
    fn xray_tun_auto_routes_use_main_table_and_xray_metric() {
        use rtnetlink::packet_route::{AddressFamily, route::RouteAttribute};

        let route = system::build_xray_system_route(
            IpPrefix::V4("192.0.2.0".parse().unwrap(), 24),
            42,
        );
        assert_eq!(route.header.address_family, AddressFamily::Inet);
        assert_eq!(route.header.table, 254);
        assert_eq!(route.header.destination_prefix_length, 24);
        assert!(route.attributes.contains(&RouteAttribute::Destination(
            rtnetlink::packet_route::route::RouteAddress::Inet(
                "192.0.2.0".parse().unwrap()
            )
        )));
        assert!(route.attributes.contains(&RouteAttribute::Oif(42)));
        assert!(route.attributes.contains(&RouteAttribute::Priority(1)));

        let default_route = system::build_xray_system_route(
            IpPrefix::V6(Ipv6Addr::UNSPECIFIED, 0),
            43,
        );
        assert_eq!(default_route.header.address_family, AddressFamily::Inet6);
        assert_eq!(default_route.header.destination_prefix_length, 0);
        assert!(default_route.attributes.contains(&RouteAttribute::Oif(43)));
        assert!(
            default_route
                .attributes
                .contains(&RouteAttribute::Priority(1))
        );
    }

    #[cfg(feature = "xray-tun")]
    #[test]
    fn xray_tun_config_rejects_invalid_device_routes_and_udp_quic_override() {
        for (settings, expected_error) in [
            (
                serde_json::json!({"name": "interface-name-too-long"}),
                "settings.name",
            ),
            (serde_json::json!({"mtu": 1279}), "settings.mtu"),
            (serde_json::json!({"mtu": 65536}), "settings.mtu"),
            (
                serde_json::json!({"gateway": ["10.0.0.1/33"]}),
                "prefix length",
            ),
            (
                serde_json::json!({"gateway": ["not-an-address"]}),
                "IP CIDRs",
            ),
            (
                serde_json::json!({"autoSystemRoutingTable": ["not-a-route"]}),
                "autoSystemRoutingTable entries must be IP CIDRs",
            ),
            (
                serde_json::json!({"autoSystemRoutingTable": ["2001:db8::1/129"]}),
                "prefix must not exceed 128",
            ),
            (
                serde_json::json!({
                    "autoSystemRoutingTable": ["192.0.2.1/24", "192.0.2.0/24"]
                }),
                "contains duplicate route",
            ),
        ] {
            let error = XrayTunPlan::try_from(xray_tun_inbound(settings))
                .expect_err("invalid Xray TUN device value must be rejected");
            assert!(error.contains(expected_error), "{error}");
        }

        let inbound: InboudItem = serde_json::from_value(serde_json::json!({
            "protocol": "tun",
            "tag": "xray-tun",
            "sniffing": {
                "enabled": true,
                "destOverride": ["quic"]
            }
        }))
        .expect("valid Xray TUN sniffing shape");
        let error = XrayTunPlan::try_from(inbound)
            .expect_err("UDP QUIC destination rewrite must fail explicitly");
        assert!(error.contains("routeOnly=true"), "{error}");

        let route_only = XrayTunPlan::try_from(xray_tun_inbound_with_sniffing(
            serde_json::json!({}),
            serde_json::json!({
                "enabled": true,
                "destOverride": ["quic"],
                "routeOnly": true
            }),
        ))
        .expect("route-only QUIC SNI sniffing is supported for TUN UDP");
        assert!(route_only.quic_route_only);
        assert!(route_only.forwarding_plan().quic_route_only);

        let disabled = XrayTunPlan::try_from(xray_tun_inbound_with_sniffing(
            serde_json::json!({}),
            serde_json::json!({"destOverride": ["quic"]}),
        ))
        .expect("disabled Xray sniffing remains a no-op");
        assert!(!disabled.quic_route_only);
    }

    #[cfg(feature = "xray-tun")]
    #[test]
    fn xray_tun_config_compiles_sniffing_for_the_shared_dispatcher() {
        let plan = XrayTunPlan::try_from(
            serde_json::from_value(serde_json::json!({
                "protocol": "tun",
                "tag": "sniffing-tun",
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                }
            }))
            .expect("valid Xray TUN inbound shape"),
        )
        .expect("valid TUN sniffing settings");

        assert!(plan.sniffing.is_some());
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

    #[cfg(feature = "xray-tun")]
    async fn next_icmp_echo_reply(
        packets: &mut mpsc::Receiver<Vec<u8>>,
        ipv6: bool,
        expected_payload: &[u8],
    ) {
        timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                let Ok(packet) = SlicedPacket::from_ip(&packet) else {
                    continue;
                };
                let echo_reply = match packet.transport {
                    Some(TransportSlice::Icmpv4(icmp)) if !ipv6 => {
                        matches!(
                            icmp.icmp_type(),
                            etherparse::Icmpv4Type::EchoReply(_)
                        ) && icmp.payload() == expected_payload
                    }
                    Some(TransportSlice::Icmpv6(icmp)) if ipv6 => {
                        matches!(
                            icmp.icmp_type(),
                            etherparse::Icmpv6Type::EchoReply(_)
                        ) && icmp.payload() == expected_payload
                    }
                    _ => false,
                };
                if echo_reply {
                    break;
                }
            }
        })
        .await
        .expect("TUN ICMP echo reply timed out");
    }

    #[cfg(feature = "xray-tun")]
    async fn assert_xray_tun_drops_without_response(
        incoming: &mpsc::Sender<Vec<u8>>,
        packets: &mut mpsc::Receiver<Vec<u8>>,
        packet: Vec<u8>,
        label: &str,
    ) {
        incoming
            .send(packet)
            .await
            .unwrap_or_else(|_| panic!("could not inject {label} into Xray TUN"));
        assert!(
            timeout(Duration::from_millis(100), packets.recv())
                .await
                .is_err(),
            "{label} should be consumed without a TUN response"
        );
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

    #[cfg(feature = "xray-tun")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xray_tun_packet_enters_existing_dokodemo_dispatcher() {
        let echo_listener = HostTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local TCP echo listener");
        let echo_address = echo_listener.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener
                .accept()
                .await
                .expect("accept proxied Xray TUN flow");
            let mut payload = [0; 4];
            stream
                .read_exact(&mut payload)
                .await
                .expect("read Xray TUN payload");
            stream
                .write_all(&payload)
                .await
                .expect("write Xray TUN echo");
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
        let plan = XrayTunPlan::try_from(xray_tun_inbound(serde_json::json!({
            "name": "test-xray-tun",
            "gateway": ["10.254.0.1/24"]
        })))
        .expect("valid Xray TUN plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let service = tokio::spawn(run_forwarding_server(
            device,
            plan.forwarding_plan(),
            runtime_state.data_plane(),
            CancellationToken::new(),
        ));

        const CLIENT_PORT: u16 = 45_556;
        incoming
            .send(tcp_syn(CLIENT_PORT, echo_address))
            .await
            .expect("inject TCP SYN into Xray TUN packet path");
        let (_, server_sequence) = next_tcp_syn_ack(&mut packets).await;
        incoming
            .send(tcp_ack(
                CLIENT_PORT,
                echo_address,
                101,
                server_sequence.wrapping_add(1),
                b"xray",
            ))
            .await
            .expect("inject TCP payload into Xray TUN packet path");

        timeout(Duration::from_secs(3), async {
            loop {
                let packet = packets.recv().await.expect("memory TUN output closed");
                if contains_tcp_payload(&packet, b"xray") {
                    break;
                }
            }
        })
        .await
        .expect("Xray TUN TCP echo did not return through the packet path");
        echo_task.await.expect("echo task failed");

        drop(incoming);
        timeout(Duration::from_secs(2), service)
            .await
            .expect("Xray TUN service did not stop after device closure")
            .expect("Xray TUN service task panicked")
            .expect_err("device closure must be reported as a service failure");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "xray-tun")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xray_tun_udp_packet_uses_existing_dokodemo_session() {
        let echo_socket = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local UDP echo socket");
        let echo_address = echo_socket.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let mut payload = [0; 4];
            let (len, peer) = echo_socket
                .recv_from(&mut payload)
                .await
                .expect("receive Xray TUN datagram");
            assert_eq!(&payload[..len], b"ping");
            echo_socket
                .send_to(&payload[..len], peer)
                .await
                .expect("send Xray TUN UDP echo");
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
        let plan = XrayTunPlan::try_from(xray_tun_inbound(serde_json::json!({
            "name": "test-xray-udp",
            "gateway": ["10.254.0.1/24"]
        })))
        .expect("valid Xray TUN plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let cancellation = CancellationToken::new();
        let service = tokio::spawn(run_forwarding_server(
            device,
            plan.forwarding_plan(),
            runtime_state.data_plane(),
            cancellation.clone(),
        ));

        const CLIENT_PORT: u16 = 45_558;
        incoming
            .send(udp_datagram(CLIENT_PORT, echo_address, b"ping"))
            .await
            .expect("inject UDP datagram into Xray TUN");
        assert_eq!(
            next_udp_payload(&mut packets, b"ping").await,
            (
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::new(10, 44, 0, 2),
                echo_address.port(),
                CLIENT_PORT,
            )
        );
        echo_task.await.expect("UDP echo task failed");

        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("Xray TUN service did not stop after cancellation")
            .expect("Xray TUN service task panicked")
            .expect("cooperative Xray TUN shutdown should complete cleanly");
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "xray-tun")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xray_tun_quic_route_only_uses_sni_rule_and_pins_udp_flow() {
        let echo_socket = HostUdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind local UDP echo socket");
        let echo_address = echo_socket.local_addr().expect("echo address");
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
                rules: vec![
                    RuleConfig {
                        domain: vec!["full:www.google.com".into()],
                        network: NetworkListConfig(vec!["udp".into()]),
                        outbound_tag: Some("blocked".into()),
                        ..RuleConfig::default()
                    },
                    RuleConfig {
                        network: NetworkListConfig(vec!["udp".into()]),
                        outbound_tag: Some("direct".into()),
                        ..RuleConfig::default()
                    },
                ],
                ..RoutingConfig::default()
            }))
            .expect("compile QUIC SNI and UDP fallback routes"),
        );

        let plan = XrayTunPlan::try_from(
            serde_json::from_value(serde_json::json!({
                "protocol": "tun",
                "tag": "xray-tun",
                "settings": {
                    "name": "xray-quic-test",
                    "gateway": ["10.254.0.1/24"]
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["quic"],
                    "routeOnly": true
                }
            }))
            .expect("valid Xray TUN inbound with top-level sniffing"),
        )
        .expect("valid route-only QUIC sniffing plan");
        assert!(plan.quic_route_only);
        assert!(
            plan.sniffing
                .as_ref()
                .is_some_and(|sniffing| sniffing.enabled && sniffing.route_only)
        );
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let runtime = runtime_state.data_plane();
        let mut routing_events = runtime_state.subscribe_routing_events();
        let cancellation = CancellationToken::new();
        let service = tokio::spawn(run_forwarding_server(
            device,
            plan.forwarding_plan(),
            runtime,
            cancellation.clone(),
        ));

        const CLIENT_PORT: u16 = 45_560;
        let mut captured_initials =
            include_str!("session/testdata/quic_v1_xray_26_9_9_initials.hex")
                .lines();
        let first_initial = decode_hex_fixture(
            captured_initials.next().expect("first Xray Initial"),
        );
        let second_initial = decode_hex_fixture(
            captured_initials.next().expect("second Xray Initial"),
        );
        assert!(captured_initials.next().is_none());
        assert_eq!(
            crate::session::quic_sniff::inspect_quic_initial_server_name(
                &first_initial
            )
            .as_deref(),
            None,
            "the first Xray Initial has an incomplete ClientHello"
        );
        incoming
            .send(udp_datagram(CLIENT_PORT, echo_address, &first_initial))
            .await
            .expect("inject first fragmented Xray QUIC Initial into Xray TUN");
        let premature_echo = timeout(Duration::from_millis(75), async {
            let mut buffer = [0; 2048];
            echo_socket.recv_from(&mut buffer).await
        })
        .await;
        assert!(
            premature_echo.is_err(),
            "an incomplete QUIC SNI probe must hold its first datagram"
        );
        incoming
            .send(udp_datagram(CLIENT_PORT, echo_address, &second_initial))
            .await
            .expect("inject second fragmented Xray QUIC Initial into Xray TUN");
        // A later datagram on the same flow is not independently sniffable.
        // It must retain the route selected from the first Initial's SNI.
        incoming
            .send(udp_datagram(CLIENT_PORT, echo_address, b"subsequent-quic"))
            .await
            .expect("inject subsequent datagram into the same QUIC flow");

        let first_route = timeout(Duration::from_secs(1), routing_events.recv())
            .await
            .expect("QUIC route selection did not publish a routing event")
            .expect("routing event channel closed");
        assert_eq!(first_route.input.target_domain, "www.google.com");
        assert_eq!(first_route.route.outbound_tag, "blocked");

        let direct_probe = timeout(Duration::from_millis(300), async {
            let mut buffer = [0; 2048];
            echo_socket.recv_from(&mut buffer).await
        })
        .await;
        assert!(
            direct_probe.is_err(),
            "QUIC SNI route should select blackhole instead of the direct UDP fallback"
        );
        assert!(
            timeout(Duration::from_millis(100), packets.recv())
                .await
                .is_err(),
            "blackholed QUIC datagrams must not produce a TUN response"
        );
        while routing_events.try_recv().is_ok() {}

        const FALLBACK_CLIENT_PORT: u16 = 45_561;
        incoming
            .send(udp_datagram(
                FALLBACK_CLIENT_PORT,
                echo_address,
                &first_initial,
            ))
            .await
            .expect("inject an incomplete QUIC probe that will time out");
        let fallback_route = timeout(Duration::from_secs(2), routing_events.recv())
            .await
            .expect("timed-out QUIC probe did not resume original-IP routing")
            .expect("routing event channel closed");
        assert!(
            fallback_route.input.target_domain.is_empty(),
            "timed-out QUIC route unexpectedly retained domain metadata: {:?}",
            fallback_route.input
        );
        assert_eq!(
            fallback_route.input.source_port,
            u32::from(FALLBACK_CLIENT_PORT)
        );
        assert_eq!(fallback_route.route.outbound_tag, "direct");
        let (fallback_length, _) = timeout(Duration::from_secs(1), async {
            let mut buffer = [0; 2048];
            echo_socket.recv_from(&mut buffer).await
        })
        .await
        .expect("timed-out QUIC probe was not forwarded to its original IP")
        .expect("UDP echo target closed");
        assert_eq!(fallback_length, first_initial.len());

        const CANCELLED_CLIENT_PORT: u16 = 45_562;
        incoming
            .send(udp_datagram(
                CANCELLED_CLIENT_PORT,
                echo_address,
                &first_initial,
            ))
            .await
            .expect("inject a pending QUIC probe before service shutdown");
        sleep(Duration::from_millis(50)).await;

        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("Xray TUN QUIC service did not stop after cancellation")
            .expect("Xray TUN service task panicked")
            .expect("cooperative Xray TUN shutdown should complete cleanly");
        assert!(
            timeout(Duration::from_millis(600), async {
                let mut buffer = [0; 2048];
                echo_socket.recv_from(&mut buffer).await
            })
            .await
            .is_err(),
            "service shutdown must cancel pending QUIC fallback workers"
        );
        runtime_state.close_inbound_connection_tasks();
        let _ = runtime_state
            .drain_inbound_connection_tasks(Duration::from_secs(1))
            .await;
    }

    #[cfg(feature = "xray-tun")]
    fn decode_hex_fixture(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.trim().as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "hex fixture has an incomplete byte");
        pairs
            .iter()
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("invalid hexadecimal fixture"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[cfg(feature = "xray-tun")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn xray_tun_stack_matches_echo_and_unknown_protocol_icmp_behavior() {
        let runtime_state = RuntimeState::new(Vec::new(), Vec::new());
        let plan = XrayTunPlan::try_from(xray_tun_inbound(serde_json::json!({
            "name": "test-xray-icmp",
            "gateway": ["10.254.0.1/24", "fd10::1/64"]
        })))
        .expect("valid Xray TUN plan");
        let (incoming, input) = mpsc::channel(8);
        let (output, mut packets) = mpsc::channel(32);
        let device = MemoryTun {
            inbound: Mutex::new(input),
            outbound: output,
        };
        let cancellation = CancellationToken::new();
        let service = tokio::spawn(run_forwarding_server(
            device,
            plan.forwarding_plan(),
            runtime_state.data_plane(),
            cancellation.clone(),
        ));

        let mut ipv4_request = Vec::new();
        PacketBuilder::ipv4([10, 44, 0, 2], [203, 0, 113, 9], 64)
            .icmpv4_echo_request(7, 9)
            .write(&mut ipv4_request, b"chimera-v4-ping")
            .expect("build IPv4 echo request");
        incoming
            .send(ipv4_request)
            .await
            .expect("inject IPv4 ICMP echo into Xray TUN");
        next_icmp_echo_reply(&mut packets, false, b"chimera-v4-ping").await;

        let source: Ipv6Addr = "fd10:44::2".parse().expect("valid IPv6 source");
        let target: Ipv6Addr = "2001:db8::9".parse().expect("valid IPv6 target");
        let mut ipv6_request = Vec::new();
        PacketBuilder::ipv6(source.octets(), target.octets(), 64)
            .icmpv6_echo_request(7, 9)
            .write(&mut ipv6_request, b"chimera-v6-ping")
            .expect("build IPv6 echo request");
        incoming
            .send(ipv6_request)
            .await
            .expect("inject IPv6 ICMP echo into Xray TUN");
        next_icmp_echo_reply(&mut packets, true, b"chimera-v6-ping").await;

        let source_v4 = [10, 254, 0, 2];
        let target_v4 = [203, 0, 113, 9];
        let mut quoted_ipv4_udp = Vec::new();
        PacketBuilder::ipv4(source_v4, target_v4, 64)
            .udp(45_200, 443)
            .write(&mut quoted_ipv4_udp, b"quoted UDP packet")
            .expect("build quoted IPv4 UDP packet");
        let build_ipv4_error = |icmp_type, code, details| {
            let mut packet = Vec::new();
            PacketBuilder::ipv4(target_v4, source_v4, 64)
                .icmpv4_raw(icmp_type, code, details)
                .write(&mut packet, &quoted_ipv4_udp)
                .expect("build IPv4 ICMP error packet");
            packet
        };
        for (icmp_type, code, details, label) in [
            (3, 3, [0; 4], "IPv4 Destination Unreachable"),
            (11, 0, [0; 4], "IPv4 Time Exceeded"),
            (12, 0, [20, 0, 0, 0], "IPv4 Parameter Problem"),
        ] {
            assert_xray_tun_drops_without_response(
                &incoming,
                &mut packets,
                build_ipv4_error(icmp_type, code, details),
                label,
            )
            .await;
        }

        let source_v6: Ipv6Addr = "fd10::2".parse().expect("valid IPv6 source");
        let target_v6: Ipv6Addr = "2001:db8::9".parse().expect("valid IPv6 target");
        let mut quoted_ipv6_udp = Vec::new();
        PacketBuilder::ipv6(source_v6.octets(), target_v6.octets(), 64)
            .udp(45_201, 443)
            .write(&mut quoted_ipv6_udp, b"quoted UDP packet")
            .expect("build quoted IPv6 UDP packet");
        let build_ipv6_error = |icmp_type, code, details| {
            let mut packet = Vec::new();
            PacketBuilder::ipv6(target_v6.octets(), source_v6.octets(), 64)
                .icmpv6_raw(icmp_type, code, details)
                .write(&mut packet, &quoted_ipv6_udp)
                .expect("build IPv6 ICMP error packet");
            packet
        };
        for (icmp_type, code, details, label) in [
            (1, 4, [0; 4], "IPv6 Destination Unreachable"),
            (3, 0, [0; 4], "IPv6 Time Exceeded"),
            (4, 0, [0, 0, 0, 40], "IPv6 Parameter Problem"),
        ] {
            assert_xray_tun_drops_without_response(
                &incoming,
                &mut packets,
                build_ipv6_error(icmp_type, code, details),
                label,
            )
            .await;
        }

        let mut truncated_ipv4_header = etherparse::Ipv4Header::new(
            4,
            64,
            etherparse::ip_number::ICMP,
            [10, 44, 0, 2],
            [203, 0, 113, 9],
        )
        .expect("valid IPv4 header for truncated ICMP");
        truncated_ipv4_header.header_checksum =
            truncated_ipv4_header.calc_header_checksum();
        let mut truncated_ipv4_icmp = truncated_ipv4_header.to_bytes().to_vec();
        truncated_ipv4_icmp.extend_from_slice(&[8, 0, 0, 0]);
        assert_xray_tun_drops_without_response(
            &incoming,
            &mut packets,
            truncated_ipv4_icmp,
            "truncated IPv4 Echo Request",
        )
        .await;

        let truncated_ipv6_header = etherparse::Ipv6Header {
            payload_length: 4,
            next_header: etherparse::ip_number::IPV6_ICMP,
            hop_limit: 64,
            source: "fd10:44::2"
                .parse::<Ipv6Addr>()
                .expect("valid IPv6 source")
                .octets(),
            destination: "2001:db8::9"
                .parse::<Ipv6Addr>()
                .expect("valid IPv6 destination")
                .octets(),
            ..Default::default()
        };
        let mut truncated_ipv6_icmp = truncated_ipv6_header.to_bytes().to_vec();
        truncated_ipv6_icmp.extend_from_slice(&[128, 0, 0, 0]);
        assert_xray_tun_drops_without_response(
            &incoming,
            &mut packets,
            truncated_ipv6_icmp,
            "truncated IPv6 Echo Request",
        )
        .await;

        let mut bad_checksum_ipv4 = Vec::new();
        PacketBuilder::ipv4([10, 44, 0, 2], [203, 0, 113, 9], 64)
            .icmpv4_echo_request(7, 10)
            .write(&mut bad_checksum_ipv4, b"bad-v4-checksum!")
            .expect("build IPv4 Echo Request for checksum test");
        bad_checksum_ipv4[22] ^= 0x01;
        incoming
            .send(bad_checksum_ipv4)
            .await
            .expect("inject IPv4 Echo Request with invalid ICMP checksum");
        next_icmp_echo_reply(&mut packets, false, b"bad-v4-checksum!").await;

        let mut bad_checksum_ipv6 = Vec::new();
        PacketBuilder::ipv6(source.octets(), target.octets(), 64)
            .icmpv6_echo_request(7, 10)
            .write(&mut bad_checksum_ipv6, b"bad-v6-checksum")
            .expect("build IPv6 Echo Request for checksum test");
        bad_checksum_ipv6[42] ^= 0x01;
        assert_xray_tun_drops_without_response(
            &incoming,
            &mut packets,
            bad_checksum_ipv6,
            "IPv6 Echo Request with invalid ICMP checksum",
        )
        .await;

        let source_v4 = [10, 44, 0, 2];
        let destination_v4 = [203, 0, 113, 9];
        let mut ipv4_header = etherparse::Ipv4Header::new(
            8,
            64,
            etherparse::IpNumber(252),
            source_v4,
            destination_v4,
        )
        .expect("valid IPv4 header");
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();
        let mut unknown_ipv4 = ipv4_header.to_bytes().to_vec();
        unknown_ipv4.extend_from_slice(&[0; 8]);
        incoming
            .send(unknown_ipv4)
            .await
            .expect("inject unknown IPv4 protocol into Xray TUN");
        let ipv4_error = timeout(Duration::from_secs(3), packets.recv())
            .await
            .expect("IPv4 protocol-unreachable response timed out")
            .expect("memory TUN output closed");
        let ipv4_header_len = ((ipv4_error[0] & 0x0f) as usize) * 4;
        assert_eq!(ipv4_error[9], etherparse::ip_number::ICMP.0);
        assert_eq!(ipv4_error[ipv4_header_len], 3);
        assert_eq!(ipv4_error[ipv4_header_len + 1], 2);
        assert_eq!(&ipv4_error[12..16], &destination_v4);
        assert_eq!(&ipv4_error[16..20], &source_v4);

        let source_v6 = [0x20; 16];
        let destination_v6 = [0x21; 16];
        let ipv6_header = etherparse::Ipv6Header {
            payload_length: 8,
            next_header: etherparse::IpNumber(252),
            hop_limit: 64,
            source: source_v6,
            destination: destination_v6,
            ..Default::default()
        };
        let mut unknown_ipv6 = ipv6_header.to_bytes().to_vec();
        unknown_ipv6.extend_from_slice(&[0; 8]);
        incoming
            .send(unknown_ipv6)
            .await
            .expect("inject unknown IPv6 next header into Xray TUN");
        let ipv6_error = timeout(Duration::from_secs(3), packets.recv())
            .await
            .expect("IPv6 unrecognized-next-header response timed out")
            .expect("memory TUN output closed");
        assert_eq!(ipv6_error[6], etherparse::ip_number::IPV6_ICMP.0);
        assert_eq!(ipv6_error[40], 4);
        assert_eq!(ipv6_error[41], 1);
        assert_eq!(&ipv6_error[8..24], &destination_v6);
        assert_eq!(&ipv6_error[24..40], &source_v6);

        cancellation.cancel();
        timeout(Duration::from_secs(2), service)
            .await
            .expect("Xray TUN service did not stop after cancellation")
            .expect("Xray TUN service task panicked")
            .expect("cooperative Xray TUN shutdown should complete cleanly");
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
