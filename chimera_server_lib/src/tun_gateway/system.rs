//! Linux address and route transactions used by the TUN ingress owners.
//!
//! This module owns only netlink setup and rollback; packet processing and
//! device/task lifetime remain in the parent TUN service.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Error;
use futures::TryStreamExt;
use rtnetlink::{Handle as NetlinkHandle, RouteMessageBuilder};
use tokio::task::JoinHandle;

#[cfg(any(feature = "tun-gateway", test))]
use super::TunGatewayPlan;
#[cfg(feature = "xray-tun")]
use super::XrayTunPlan;
use super::{IpPrefix, TunInterfaceAddress};

#[derive(Debug)]
#[cfg(any(feature = "tun-gateway", test))]
pub(super) struct TunIpv6AddressConfigureError {
    device_name: String,
    address: Ipv6Addr,
    prefix_len: u8,
    source: std::io::Error,
}

#[cfg(any(feature = "tun-gateway", test))]
impl TunIpv6AddressConfigureError {
    pub(super) fn new(
        device_name: String,
        address: Ipv6Addr,
        prefix_len: u8,
        source: std::io::Error,
    ) -> Self {
        Self {
            device_name,
            address,
            prefix_len,
            source,
        }
    }
}

#[cfg(any(feature = "tun-gateway", test))]
impl std::fmt::Display for TunIpv6AddressConfigureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "failed to configure tunGateway IPv6 address {}/{} on {}: {}",
            self.address, self.prefix_len, self.device_name, self.source
        )
    }
}

#[cfg(any(feature = "tun-gateway", test))]
impl std::error::Error for TunIpv6AddressConfigureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(any(feature = "tun-gateway", test))]
pub(super) async fn configure_ipv6_tun_address(
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

pub(super) struct ManagedTunRouting {
    handle: NetlinkHandle,
    _connection: AbortOnDropNetlinkTask,
    routes: Vec<rtnetlink::packet_route::route::RouteMessage>,
    rules: Vec<rtnetlink::packet_route::rule::RuleMessage>,
}

pub(super) struct ManagedTunAddresses {
    handle: NetlinkHandle,
    _connection: AbortOnDropNetlinkTask,
    interface_index: u32,
    addresses: Vec<TunInterfaceAddress>,
}

pub(super) struct ManagedTunSystemRoutes {
    handle: NetlinkHandle,
    _connection: AbortOnDropNetlinkTask,
    routes: Vec<rtnetlink::packet_route::route::RouteMessage>,
}

impl ManagedTunSystemRoutes {
    pub(super) async fn remove(mut self) -> std::io::Result<()> {
        let mut first_error = None;
        for route in self.routes.drain(..).rev() {
            if let Err(error) = self.handle.route().del(route).execute().await {
                tracing::warn!(%error, "failed to remove an Xray TUN system route");
                first_error.get_or_insert_with(|| std::io::Error::other(error));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl ManagedTunAddresses {
    pub(super) async fn remove(mut self) -> std::io::Result<()> {
        let mut first_error = None;
        for address in self.addresses.drain(..).rev() {
            let message = tun_address_message(self.interface_index, address);
            if let Err(error) = self.handle.address().del(message).execute().await {
                tracing::warn!(
                    tun_address = %format_args!("{}/{}", address.address, address.prefix_len),
                    %error,
                    "failed to remove an Xray TUN inbound interface address"
                );
                first_error.get_or_insert_with(|| std::io::Error::other(error));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(feature = "xray-tun")]
pub(super) async fn install_xray_tun_addresses(
    plan: &XrayTunPlan,
) -> Result<Option<ManagedTunAddresses>, Error> {
    if plan.gateway.is_empty() {
        return Ok(None);
    }
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|source| {
        Error::Io(std::io::Error::other(format!(
            "failed to open route-netlink for Xray TUN inbound: {source}"
        )))
    })?;
    let connection = AbortOnDropNetlinkTask(tokio::spawn(connection));
    let mut links = handle.link().get().match_name(plan.name.clone()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|source| {
            Error::Io(std::io::Error::other(format!(
                "failed to find Xray TUN interface {}: {source}",
                plan.name
            )))
        })?
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Xray TUN interface {} was not found", plan.name),
            ))
        })?;
    let mut managed = ManagedTunAddresses {
        handle,
        _connection: connection,
        interface_index: link.header.index,
        addresses: Vec::with_capacity(plan.gateway.len()),
    };
    for address in &plan.gateway {
        if let Err(source) = managed
            .handle
            .address()
            .add(managed.interface_index, address.address, address.prefix_len)
            .execute()
            .await
        {
            let error = Error::Io(std::io::Error::other(format!(
                "failed to add Xray TUN gateway address {}/{}: {source}",
                address.address, address.prefix_len
            )));
            if let Err(cleanup_error) = managed.remove().await {
                tracing::error!(%cleanup_error, "failed to roll back partial Xray TUN address setup");
            }
            return Err(error);
        }
        managed.addresses.push(*address);
    }
    Ok(Some(managed))
}

fn tun_address_message(
    interface_index: u32,
    address: TunInterfaceAddress,
) -> rtnetlink::packet_route::address::AddressMessage {
    let prefix_len = address.prefix_len;
    match address.address {
        IpAddr::V4(ip) => rtnetlink::AddressMessageBuilder::<Ipv4Addr>::new()
            .index(interface_index)
            .address(ip, prefix_len)
            .build(),
        IpAddr::V6(ip) => rtnetlink::AddressMessageBuilder::<Ipv6Addr>::new()
            .index(interface_index)
            .address(ip, prefix_len)
            .build(),
    }
}

#[cfg(feature = "xray-tun")]
pub(super) fn build_xray_system_route(
    prefix: IpPrefix,
    interface_index: u32,
) -> rtnetlink::packet_route::route::RouteMessage {
    match prefix {
        IpPrefix::V4(network, length) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(network, length)
            .output_interface(interface_index)
            .priority(1)
            .build(),
        IpPrefix::V6(network, length) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(network, length)
            .output_interface(interface_index)
            .priority(1)
            .build(),
    }
}

#[cfg(feature = "xray-tun")]
pub(super) async fn install_xray_tun_system_routes(
    plan: &XrayTunPlan,
) -> Result<Option<ManagedTunSystemRoutes>, Error> {
    if plan.system_routes.is_empty() {
        return Ok(None);
    }

    let (connection, handle, _) = rtnetlink::new_connection().map_err(|source| {
        Error::Io(std::io::Error::other(format!(
            "failed to open route-netlink for Xray TUN system routes: {source}"
        )))
    })?;
    let connection = AbortOnDropNetlinkTask(tokio::spawn(connection));
    let mut links = handle.link().get().match_name(plan.name.clone()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|source| {
            Error::Io(std::io::Error::other(format!(
                "failed to find Xray TUN interface {} for system routes: {source}",
                plan.name
            )))
        })?
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Xray TUN interface {} was not found for system routes",
                    plan.name
                ),
            ))
        })?;
    let mut managed = ManagedTunSystemRoutes {
        handle,
        _connection: connection,
        routes: Vec::with_capacity(plan.system_routes.len()),
    };

    for prefix in &plan.system_routes {
        let route = build_xray_system_route(*prefix, link.header.index);
        if let Err(source) =
            managed.handle.route().add(route.clone()).execute().await
        {
            let error = Error::Io(std::io::Error::other(format!(
                "failed to install Xray TUN system route {prefix:?}: {source}"
            )));
            if let Err(cleanup_error) = managed.remove().await {
                tracing::error!(%cleanup_error, "failed to roll back partial Xray TUN system routes");
            }
            return Err(error);
        }
        managed.routes.push(route);
    }
    Ok(Some(managed))
}

impl ManagedTunRouting {
    pub(super) async fn remove(mut self) -> std::io::Result<()> {
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

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
pub(super) async fn install_tun_routing(
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

#[cfg(any(feature = "tun-gateway", test))]
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

#[cfg(any(feature = "tun-gateway", test))]
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
