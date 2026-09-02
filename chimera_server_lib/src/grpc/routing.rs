use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use prost::Message;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{
    config::rule::{
        BalancerConfig, NetworkListConfig, PortListConfig, PortRangeConfig,
        RuleConfig,
    },
    routing_state::{DomainStrategy, RoutingInput},
    runtime::RuntimeState,
};

use super::proto;

const ERR_NOT_ENOUGH_INFO: &str =
    "common: not enough information for making a decision";
const TYPE_ROUTER_CONFIG: &str = "xray.app.router.Config";
const TYPE_ROUTER_CONFIG_V2RAY: &str = "v2ray.core.app.router.Config";

#[derive(Clone)]
pub(super) struct RoutingServiceImpl {
    runtime: RuntimeState,
    balancer_overrides: Arc<RwLock<HashMap<String, String>>>,
    routing_stats_tx:
        broadcast::Sender<proto::xray::app::router::command::RoutingContext>,
}

#[derive(Clone, PartialEq, Message)]
struct RouterConfigPayload {
    #[prost(enumeration = "RouterDomainStrategyPayload", tag = "1")]
    domain_strategy: i32,
    #[prost(message, repeated, tag = "2")]
    rule: Vec<RoutingRulePayload>,
    #[prost(message, repeated, tag = "3")]
    balancing_rule: Vec<BalancingRulePayload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ::prost::Enumeration)]
#[repr(i32)]
enum RouterDomainStrategyPayload {
    AsIs = 0,
    IpIfNonMatch = 2,
    IpOnDemand = 3,
}

#[derive(Clone, PartialEq, Message)]
struct RoutingRulePayload {
    #[prost(oneof = "routing_rule_payload::TargetTag", tags = "1, 12")]
    target_tag: Option<routing_rule_payload::TargetTag>,
    #[prost(string, tag = "19")]
    rule_tag: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<DomainPayload>,
    #[prost(message, repeated, tag = "10")]
    geoip: Vec<GeoIpPayload>,
    #[prost(message, optional, tag = "14")]
    port_list: Option<PortListPayload>,
    #[prost(
        enumeration = "proto::xray::common::net::Network",
        repeated,
        tag = "13"
    )]
    networks: Vec<i32>,
    #[prost(message, repeated, tag = "11")]
    source_geoip: Vec<GeoIpPayload>,
    #[prost(message, optional, tag = "16")]
    source_port_list: Option<PortListPayload>,
    #[prost(string, repeated, tag = "7")]
    user_email: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    inbound_tag: Vec<String>,
    #[prost(string, repeated, tag = "9")]
    protocol: Vec<String>,
    #[prost(map = "string, string", tag = "15")]
    attributes: HashMap<String, String>,
    #[prost(message, repeated, tag = "17")]
    local_geoip: Vec<GeoIpPayload>,
    #[prost(message, optional, tag = "18")]
    local_port_list: Option<PortListPayload>,
    #[prost(message, optional, tag = "20")]
    vless_route_list: Option<PortListPayload>,
}

mod routing_rule_payload {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TargetTag {
        #[prost(string, tag = "1")]
        Tag(String),
        #[prost(string, tag = "12")]
        BalancingTag(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct DomainPayload {
    #[prost(enumeration = "DomainTypePayload", tag = "1")]
    r#type: i32,
    #[prost(string, tag = "2")]
    value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ::prost::Enumeration)]
#[repr(i32)]
enum DomainTypePayload {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpPayload {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<CidrPayload>,
    #[prost(bool, tag = "3")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct CidrPayload {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
struct PortListPayload {
    #[prost(message, repeated, tag = "1")]
    range: Vec<PortRangePayload>,
}

#[derive(Clone, PartialEq, Message)]
struct PortRangePayload {
    #[prost(uint32, tag = "1")]
    from: u32,
    #[prost(uint32, tag = "2")]
    to: u32,
}

#[derive(Clone, PartialEq, Message)]
struct BalancingRulePayload {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(string, repeated, tag = "2")]
    outbound_selector: Vec<String>,
    #[prost(string, tag = "5")]
    fallback_tag: String,
}

impl RoutingServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        let (routing_stats_tx, _) = broadcast::channel(128);
        Self {
            runtime,
            balancer_overrides: Arc::new(RwLock::new(HashMap::new())),
            routing_stats_tx,
        }
    }

    fn has_outbound_tag(&self, tag: &str) -> bool {
        self.runtime
            .outbounds()
            .iter()
            .any(|outbound| outbound.tag == tag)
    }

    fn parse_typed_message_type(
        typed_message: &proto::xray::common::serial::TypedMessage,
    ) -> &str {
        typed_message.r#type.trim_start_matches('.')
    }

    fn decode_router_config(
        &self,
        typed_message: &proto::xray::common::serial::TypedMessage,
    ) -> Result<RouterConfigPayload, Status> {
        let message_type = Self::parse_typed_message_type(typed_message);
        if ![TYPE_ROUTER_CONFIG, TYPE_ROUTER_CONFIG_V2RAY].contains(&message_type) {
            return Err(Status::invalid_argument(format!(
                "unsupported routing rule config type: {message_type}"
            )));
        }
        RouterConfigPayload::decode(typed_message.value.as_slice()).map_err(|err| {
            Status::invalid_argument(format!(
                "invalid routing rule config payload: {err}"
            ))
        })
    }

    fn resolve_outbound_group_tags(
        &self,
        group_tags: &[String],
    ) -> Result<(String, Vec<String>), Status> {
        if group_tags.is_empty() {
            return Err(Status::unknown(ERR_NOT_ENOUGH_INFO));
        }

        let overrides = self
            .balancer_overrides
            .read()
            .expect("routing balancer overrides lock poisoned");
        for group_tag in group_tags {
            if let Some(target) = overrides.get(group_tag)
                && self.has_outbound_tag(target)
            {
                return Ok((target.clone(), vec![group_tag.clone()]));
            }
        }
        drop(overrides);

        let routing = self.runtime.routing();
        let outbounds = self.runtime.outbounds();
        for group_tag in group_tags {
            if let Some(target) = routing
                .balancer_targets(group_tag, &outbounds)
                .into_iter()
                .next()
            {
                return Ok((target, vec![group_tag.clone()]));
            }
            if self.has_outbound_tag(group_tag) {
                return Ok((group_tag.clone(), vec![group_tag.clone()]));
            }
        }

        Err(Status::unknown(ERR_NOT_ENOUGH_INFO))
    }

    fn resolve_outbound_tag(
        &self,
        context: &proto::xray::app::router::command::RoutingContext,
    ) -> Result<(String, Vec<String>), Status> {
        if !context.outbound_tag.is_empty() {
            return if self.has_outbound_tag(&context.outbound_tag) {
                Ok((
                    context.outbound_tag.clone(),
                    context.outbound_group_tags.clone(),
                ))
            } else {
                Err(Status::not_found(format!(
                    "outbound {} not found",
                    context.outbound_tag
                )))
            };
        }

        let route = self.runtime.routing().route(
            &RoutingInput {
                inbound_tag: context.inbound_tag.clone(),
                network: context.network,
                source_ips: context.source_i_ps.clone(),
                target_ips: context.target_i_ps.clone(),
                source_port: context.source_port,
                target_port: context.target_port,
                target_domain: context.target_domain.clone(),
                protocol: context.protocol.clone(),
                user: context.user.clone(),
                process_id: 0,
                process_name: String::new(),
                process_path: String::new(),
                attributes: context.attributes.clone(),
                local_ips: context.local_i_ps.clone(),
                local_port: context.local_port,
                vless_route: context.vless_route,
            },
            &self.runtime.outbounds(),
            &self
                .balancer_overrides
                .read()
                .expect("routing balancer overrides lock poisoned"),
        );
        if let Some(route) = route {
            if let Some(error) = route.resolution_error {
                return Err(Status::unknown(error));
            }
            return Ok((route.outbound_tag, route.outbound_group_tags));
        }

        self.resolve_outbound_group_tags(&context.outbound_group_tags)
    }

    fn principle_targets(&self, balancer_tag: &str) -> Vec<String> {
        let outbounds = self.runtime.outbounds();
        let targets = self
            .runtime
            .routing()
            .balancer_targets(balancer_tag, &outbounds);
        if targets.is_empty() {
            outbounds.into_iter().map(|outbound| outbound.tag).collect()
        } else {
            targets
        }
    }
}

fn selector_enabled(selectors: &[String], target: &str) -> bool {
    selectors
        .iter()
        .any(|selector| selector.eq_ignore_ascii_case(target))
}

fn filter_routing_context(
    context: proto::xray::app::router::command::RoutingContext,
    selectors: &[String],
) -> proto::xray::app::router::command::RoutingContext {
    if selectors.is_empty() {
        return context;
    }

    let include_ip = selector_enabled(selectors, "ip");
    let include_port = selector_enabled(selectors, "port");
    let include_outbound = selector_enabled(selectors, "outbound");
    let mut filtered = proto::xray::app::router::command::RoutingContext::default();

    if selector_enabled(selectors, "inbound") {
        filtered.inbound_tag = context.inbound_tag;
    }
    if selector_enabled(selectors, "network") {
        filtered.network = context.network;
    }
    if include_ip || selector_enabled(selectors, "ip_source") {
        filtered.source_i_ps = context.source_i_ps;
    }
    if include_ip || selector_enabled(selectors, "ip_target") {
        filtered.target_i_ps = context.target_i_ps;
    }
    if include_port || selector_enabled(selectors, "port_source") {
        filtered.source_port = context.source_port;
    }
    if include_port || selector_enabled(selectors, "port_target") {
        filtered.target_port = context.target_port;
    }
    if selector_enabled(selectors, "domain") {
        filtered.target_domain = context.target_domain;
    }
    if selector_enabled(selectors, "protocol") {
        filtered.protocol = context.protocol;
    }
    if selector_enabled(selectors, "user") {
        filtered.user = context.user;
    }
    if selector_enabled(selectors, "attributes") {
        filtered.attributes = context.attributes;
    }
    if include_outbound || selector_enabled(selectors, "outbound_group") {
        filtered.outbound_group_tags = context.outbound_group_tags;
    }
    if include_outbound {
        filtered.outbound_tag = context.outbound_tag;
    }

    filtered
}

fn convert_router_config(
    config: RouterConfigPayload,
) -> Result<(DomainStrategy, Vec<RuleConfig>, Vec<BalancerConfig>), Status> {
    let domain_strategy =
        match RouterDomainStrategyPayload::try_from(config.domain_strategy) {
            Ok(RouterDomainStrategyPayload::AsIs) => DomainStrategy::AsIs,
            Ok(RouterDomainStrategyPayload::IpIfNonMatch) => {
                DomainStrategy::IpIfNonMatch
            }
            Ok(RouterDomainStrategyPayload::IpOnDemand) => {
                DomainStrategy::IpOnDemand
            }
            Err(_) => {
                return Err(Status::invalid_argument(
                    "unsupported routing domain strategy",
                ));
            }
        };
    let rules = config
        .rule
        .into_iter()
        .map(convert_rule_payload)
        .collect::<Result<Vec<_>, _>>()?;
    let balancers = config
        .balancing_rule
        .into_iter()
        .map(|balancer| BalancerConfig {
            tag: balancer.tag,
            outbound_selector: balancer.outbound_selector,
            strategy: Default::default(),
            fallback_tag: (!balancer.fallback_tag.is_empty())
                .then_some(balancer.fallback_tag),
        })
        .collect::<Vec<_>>();
    Ok((domain_strategy, rules, balancers))
}

fn convert_rule_payload(rule: RoutingRulePayload) -> Result<RuleConfig, Status> {
    let (outbound_tag, balancer_tag) = match rule.target_tag {
        Some(routing_rule_payload::TargetTag::Tag(tag)) => (Some(tag), None),
        Some(routing_rule_payload::TargetTag::BalancingTag(tag)) => {
            (None, Some(tag))
        }
        None => {
            return Err(Status::invalid_argument(
                "routing rule target tag is required",
            ));
        }
    };

    Ok(RuleConfig {
        rule_tag: (!rule.rule_tag.is_empty()).then_some(rule.rule_tag),
        inbound_tag: rule.inbound_tag,
        outbound_tag,
        balancer_tag,
        domain: rule
            .domain
            .into_iter()
            .map(convert_domain_payload)
            .collect::<Result<Vec<_>, _>>()?,
        domains: Vec::new(),
        ip: convert_geo_ip_payloads(rule.geoip)?,
        source_ip: convert_geo_ip_payloads(rule.source_geoip)?,
        source: Vec::new(),
        port: convert_port_list(rule.port_list),
        network: NetworkListConfig(
            rule.networks
                .into_iter()
                .filter_map(|network| {
                    proto::xray::common::net::Network::try_from(network).ok()
                })
                .map(|network| network.as_str_name().to_ascii_lowercase())
                .collect(),
        ),
        source_port: convert_port_list(rule.source_port_list),
        user: rule.user_email,
        vless_route: convert_port_list(rule.vless_route_list),
        protocol: rule.protocol,
        attrs: rule.attributes,
        local_ip: convert_geo_ip_payloads(rule.local_geoip)?,
        local_port: convert_port_list(rule.local_port_list),
        process: Vec::new(),
        webhook: None,
    })
}

fn convert_domain_payload(domain: DomainPayload) -> Result<String, Status> {
    let value = domain.value;
    let Ok(domain_type) = DomainTypePayload::try_from(domain.r#type) else {
        return Err(Status::invalid_argument("unsupported routing domain type"));
    };
    Ok(match domain_type {
        DomainTypePayload::Plain => value,
        DomainTypePayload::Regex => format!("regexp:{value}"),
        DomainTypePayload::Domain => format!("domain:{value}"),
        DomainTypePayload::Full => format!("full:{value}"),
    })
}

fn convert_geo_ip_payloads(
    entries: Vec<GeoIpPayload>,
) -> Result<Vec<String>, Status> {
    let mut values = Vec::new();
    for entry in entries {
        if !entry.country_code.is_empty() && entry.cidr.is_empty() {
            values.push(format!(
                "geoip:{}{}",
                if entry.reverse_match { "!" } else { "" },
                entry.country_code
            ));
            continue;
        }
        for cidr in entry.cidr {
            let ip = match cidr.ip.as_slice() {
                [a, b, c, d] => format!("{a}.{b}.{c}.{d}"),
                bytes if bytes.len() == 16 => std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).expect("valid ipv6 bytes"),
                )
                .to_string(),
                _ => {
                    return Err(Status::invalid_argument(
                        "routing cidr ip must be 4 or 16 bytes",
                    ));
                }
            };
            values.push(format!(
                "{}{ip}/{}",
                if entry.reverse_match { "!" } else { "" },
                cidr.prefix
            ));
        }
    }
    Ok(values)
}

fn convert_port_list(port_list: Option<PortListPayload>) -> PortListConfig {
    PortListConfig(
        port_list
            .map(|port_list| {
                port_list
                    .range
                    .into_iter()
                    .map(|range| PortRangeConfig {
                        from: range.from.min(u16::MAX as u32) as u16,
                        to: range.to.min(u16::MAX as u32) as u16,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

#[tonic::async_trait]
impl proto::xray::app::router::command::routing_service_server::RoutingService
    for RoutingServiceImpl
{
    type SubscribeRoutingStatsStream = ReceiverStream<
        Result<proto::xray::app::router::command::RoutingContext, Status>,
    >;

    async fn subscribe_routing_stats(
        &self,
        request: Request<
            proto::xray::app::router::command::SubscribeRoutingStatsRequest,
        >,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        let selectors = request.into_inner().field_selectors;
        let mut routing_updates = self.routing_stats_tx.subscribe();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            loop {
                match routing_updates.recv().await {
                    Ok(context) => {
                        let filtered = filter_routing_context(context, &selectors);
                        if tx.send(Ok(filtered)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn test_route(
        &self,
        request: Request<proto::xray::app::router::command::TestRouteRequest>,
    ) -> Result<Response<proto::xray::app::router::command::RoutingContext>, Status>
    {
        let request = request.into_inner();
        let mut context = request.routing_context.ok_or_else(|| {
            Status::invalid_argument("routing_context is required")
        })?;
        let (outbound_tag, outbound_group_tags) =
            self.resolve_outbound_tag(&context)?;
        context.outbound_tag = outbound_tag;
        context.outbound_group_tags = outbound_group_tags;

        if request.publish_result {
            let _ = self.routing_stats_tx.send(context.clone());
        }

        Ok(Response::new(filter_routing_context(
            context,
            &request.field_selectors,
        )))
    }

    async fn get_balancer_info(
        &self,
        request: Request<proto::xray::app::router::command::GetBalancerInfoRequest>,
    ) -> Result<
        Response<proto::xray::app::router::command::GetBalancerInfoResponse>,
        Status,
    > {
        let request = request.into_inner();
        let balancer_tag = request.tag.trim();
        if balancer_tag.is_empty() {
            return Err(Status::invalid_argument("balancer tag is required"));
        }

        let principle_targets = self.principle_targets(balancer_tag);
        if principle_targets.is_empty() {
            return Err(Status::failed_precondition("no outbounds configured"));
        }

        let override_target = self
            .balancer_overrides
            .read()
            .expect("routing balancer overrides lock poisoned")
            .get(balancer_tag)
            .cloned();

        Ok(Response::new(
            proto::xray::app::router::command::GetBalancerInfoResponse {
                balancer: Some(proto::xray::app::router::command::BalancerMsg {
                    r#override: override_target.map(|target| {
                        proto::xray::app::router::command::OverrideInfo { target }
                    }),
                    principle_target: Some(
                        proto::xray::app::router::command::PrincipleTargetInfo {
                            tag: principle_targets,
                        },
                    ),
                }),
            },
        ))
    }

    async fn override_balancer_target(
        &self,
        request: Request<
            proto::xray::app::router::command::OverrideBalancerTargetRequest,
        >,
    ) -> Result<
        Response<proto::xray::app::router::command::OverrideBalancerTargetResponse>,
        Status,
    > {
        let request = request.into_inner();
        let balancer_tag = request.balancer_tag.trim();
        if balancer_tag.is_empty() {
            return Err(Status::invalid_argument("balancer_tag is required"));
        }

        let target = request.target.trim();
        let mut overrides = self
            .balancer_overrides
            .write()
            .expect("routing balancer overrides lock poisoned");
        if target.is_empty() {
            overrides.remove(balancer_tag);
            return Ok(Response::new(
                proto::xray::app::router::command::OverrideBalancerTargetResponse {},
            ));
        }

        if !self.has_outbound_tag(target) {
            return Err(Status::not_found(format!("outbound {} not found", target)));
        }

        overrides.insert(balancer_tag.to_string(), target.to_string());
        Ok(Response::new(
            proto::xray::app::router::command::OverrideBalancerTargetResponse {},
        ))
    }

    async fn add_rule(
        &self,
        request: Request<proto::xray::app::router::command::AddRuleRequest>,
    ) -> Result<Response<proto::xray::app::router::command::AddRuleResponse>, Status>
    {
        let request = request.into_inner();
        let config = request
            .config
            .ok_or_else(|| Status::invalid_argument("routing config is required"))?;
        let (domain_strategy, rules, balancers) =
            convert_router_config(self.decode_router_config(&config)?)?;
        self.runtime
            .with_routing_mut(|routing| {
                routing.merge_with_domain_strategy(
                    rules,
                    balancers,
                    request.should_append,
                    Some(domain_strategy),
                )
            })
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(
            proto::xray::app::router::command::AddRuleResponse {},
        ))
    }

    async fn remove_rule(
        &self,
        request: Request<proto::xray::app::router::command::RemoveRuleRequest>,
    ) -> Result<
        Response<proto::xray::app::router::command::RemoveRuleResponse>,
        Status,
    > {
        let request = request.into_inner();
        if request.rule_tag.trim().is_empty() {
            return Err(Status::invalid_argument("rule_tag is required"));
        }
        let removed = self
            .runtime
            .with_routing_mut(|routing| routing.remove_rule(&request.rule_tag));
        if !removed {
            return Err(Status::not_found("routing rule not found"));
        }
        Ok(Response::new(
            proto::xray::app::router::command::RemoveRuleResponse {},
        ))
    }
}

pub(super) fn build_service(
    runtime: RuntimeState,
) -> proto::xray::app::router::command::routing_service_server::RoutingServiceServer<
    RoutingServiceImpl,
> {
    proto::xray::app::router::command::routing_service_server::RoutingServiceServer::new(
        RoutingServiceImpl::new(runtime),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prost::Message;
    use tokio_stream::StreamExt;
    use tonic::{Code, Request};

    use crate::{
        config::rule::{BalancerConfig, RuleConfig},
        geodata::{GeodataStore, proto as geodata_proto},
        routing_state::RoutingState,
        runtime::OutboundSummary,
    };

    use super::proto::xray::app::router::command::routing_service_server::RoutingService;
    use super::*;

    fn build_runtime(outbounds: &[&str]) -> RuntimeState {
        RuntimeState::new(
            vec![],
            outbounds
                .iter()
                .map(|tag| OutboundSummary {
                    tag: (*tag).to_string(),
                    protocol: "freedom".to_string(),
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                })
                .collect(),
        )
    }

    fn install_rules(
        runtime: &RuntimeState,
        rules: Vec<RuleConfig>,
        balancers: Vec<BalancerConfig>,
    ) {
        runtime.replace_routing(
            RoutingState::from_parts(rules, balancers)
                .expect("routing state should build"),
        );
    }

    fn install_geoip_fixture(runtime: &RuntimeState) {
        let mut geodata = GeodataStore::default();
        geodata
            .load_geoip_bytes(
                &geodata_proto::GeoIpList {
                    entry: vec![geodata_proto::GeoIp {
                        code: "TEST".into(),
                        cidr: vec![geodata_proto::Cidr {
                            ip: vec![203, 0, 113, 0],
                            prefix: 24,
                        }],
                        reverse_match: false,
                    }],
                }
                .encode_to_vec(),
            )
            .expect("load gRPC geoip fixture");
        runtime.replace_routing(
            RoutingState::from_parts_with_geodata(vec![], vec![], geodata)
                .expect("install gRPC geodata routing state"),
        );
    }

    fn encode_router_config(
        config: RouterConfigPayload,
    ) -> proto::xray::common::serial::TypedMessage {
        proto::xray::common::serial::TypedMessage {
            r#type: TYPE_ROUTER_CONFIG.to_string(),
            value: config.encode_to_vec(),
        }
    }

    #[tokio::test]
    async fn routing_test_route_uses_runtime_rules() {
        let runtime = build_runtime(&["direct", "backup"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["inbound-a".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        );
        let service = RoutingServiceImpl::new(runtime);

        let response = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "inbound-a".to_string(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect("test_route failed")
            .into_inner();
        assert_eq!(response.outbound_tag, "direct");
    }

    #[tokio::test]
    async fn routing_test_route_requires_route_clues() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct", "backup"]));
        let err = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "inbound-a".to_string(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect_err("expected missing routing clues error");
        assert_eq!(err.code(), Code::Unknown);
        assert_eq!(err.message(), ERR_NOT_ENOUGH_INFO);
    }

    #[tokio::test]
    async fn routing_add_rule_and_remove_rule_work() {
        let runtime = build_runtime(&["direct"]);
        let service = RoutingServiceImpl::new(runtime.clone());
        let router_config = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::AsIs as i32,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::Tag(
                    "direct".into(),
                )),
                rule_tag: "rule-a".into(),
                inbound_tag: vec!["api-in".into()],
                ..RoutingRulePayload::default()
            }],
            balancing_rule: vec![],
        };

        service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: true,
                },
            ))
            .await
            .expect("add_rule should succeed");

        let matched = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "api-in".into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect("test_route should use added rule")
            .into_inner();
        assert_eq!(matched.outbound_tag, "direct");

        service
            .remove_rule(Request::new(
                proto::xray::app::router::command::RemoveRuleRequest {
                    rule_tag: "rule-a".into(),
                },
            ))
            .await
            .expect("remove_rule should succeed");

        let err = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "api-in".into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect_err("expected route to disappear after remove_rule");
        assert_eq!(err.code(), Code::Unknown);

        let err = service
            .remove_rule(Request::new(
                proto::xray::app::router::command::RemoveRuleRequest {
                    rule_tag: "missing".into(),
                },
            ))
            .await
            .expect_err("expected missing routing rule");
        assert_eq!(err.code(), Code::NotFound);
        assert!(
            runtime
                .routing()
                .route(
                    &RoutingInput {
                        inbound_tag: "api-in".into(),
                        ..RoutingInput::default()
                    },
                    &runtime.outbounds(),
                    &HashMap::new()
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn routing_add_rule_applies_ip_on_demand_strategy() {
        let runtime = build_runtime(&["ip", "domain"]);
        let service = RoutingServiceImpl::new(runtime);
        let router_config = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::IpOnDemand as i32,
            rule: vec![
                RoutingRulePayload {
                    target_tag: Some(routing_rule_payload::TargetTag::Tag(
                        "ip".into(),
                    )),
                    rule_tag: "ip-rule".into(),
                    geoip: vec![GeoIpPayload {
                        country_code: String::new(),
                        cidr: vec![CidrPayload {
                            ip: vec![203, 0, 113, 7],
                            prefix: 32,
                        }],
                        reverse_match: false,
                    }],
                    ..RoutingRulePayload::default()
                },
                RoutingRulePayload {
                    target_tag: Some(routing_rule_payload::TargetTag::Tag(
                        "domain".into(),
                    )),
                    rule_tag: "domain-rule".into(),
                    domain: vec![DomainPayload {
                        r#type: DomainTypePayload::Full as i32,
                        value: "example.com".into(),
                    }],
                    ..RoutingRulePayload::default()
                },
            ],
            balancing_rule: vec![],
        };

        service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: false,
                },
            ))
            .await
            .expect("IPOnDemand add_rule should succeed");

        let matched = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            target_domain: "example.com".into(),
                            target_i_ps: vec![vec![203, 0, 113, 7]],
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect("IPOnDemand test_route should match")
            .into_inner();
        assert_eq!(matched.outbound_tag, "ip");
    }

    #[tokio::test]
    async fn routing_add_rule_rejects_unknown_strategy_without_mutation() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        );
        let service = RoutingServiceImpl::new(runtime.clone());
        let router_config = RouterConfigPayload {
            domain_strategy: 99,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::Tag(
                    "direct".into(),
                )),
                rule_tag: "replacement".into(),
                inbound_tag: vec!["replacement".into()],
                ..RoutingRulePayload::default()
            }],
            balancing_rule: vec![],
        };

        let error = service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: false,
                },
            ))
            .await
            .expect_err("unknown routing strategy must be rejected");
        assert_eq!(error.code(), Code::InvalidArgument);
        assert!(
            error
                .message()
                .contains("unsupported routing domain strategy")
        );

        assert!(
            runtime
                .routing()
                .route(
                    &RoutingInput {
                        inbound_tag: "existing".into(),
                        ..RoutingInput::default()
                    },
                    &runtime.outbounds(),
                    &HashMap::new(),
                )
                .is_some(),
            "existing routing state must survive rejected strategy"
        );
        assert!(
            runtime
                .routing()
                .route(
                    &RoutingInput {
                        inbound_tag: "replacement".into(),
                        ..RoutingInput::default()
                    },
                    &runtime.outbounds(),
                    &HashMap::new(),
                )
                .is_none(),
            "rejected replacement rule must not be installed"
        );
    }

    #[tokio::test]
    async fn routing_add_rule_resolves_geoip_country_code_from_loaded_data() {
        let runtime = build_runtime(&["direct"]);
        install_geoip_fixture(&runtime);
        let service = RoutingServiceImpl::new(runtime);
        let router_config = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::IpOnDemand as i32,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::Tag(
                    "direct".into(),
                )),
                rule_tag: "geoip-country".into(),
                geoip: vec![GeoIpPayload {
                    country_code: "test".into(),
                    cidr: vec![],
                    reverse_match: false,
                }],
                ..RoutingRulePayload::default()
            }],
            balancing_rule: vec![],
        };

        service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: false,
                },
            ))
            .await
            .expect("GeoIP country add_rule should succeed");

        for (ip, expected_match) in
            [(vec![203, 0, 113, 42], true), (vec![192, 0, 2, 42], false)]
        {
            let result = service
                .test_route(Request::new(
                    proto::xray::app::router::command::TestRouteRequest {
                        routing_context: Some(
                            proto::xray::app::router::command::RoutingContext {
                                target_i_ps: vec![ip],
                                ..Default::default()
                            },
                        ),
                        field_selectors: vec![],
                        publish_result: false,
                    },
                ))
                .await;
            assert_eq!(result.is_ok(), expected_match);
        }
    }

    #[tokio::test]
    async fn routing_add_rule_supports_reverse_geoip_cidrs() {
        let runtime = build_runtime(&["direct"]);
        let service = RoutingServiceImpl::new(runtime);
        let router_config = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::IpOnDemand as i32,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::Tag(
                    "direct".into(),
                )),
                rule_tag: "reverse-geoip".into(),
                geoip: vec![GeoIpPayload {
                    country_code: String::new(),
                    cidr: vec![CidrPayload {
                        ip: vec![10, 0, 0, 0],
                        prefix: 8,
                    }],
                    reverse_match: true,
                }],
                ..RoutingRulePayload::default()
            }],
            balancing_rule: vec![],
        };

        service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: false,
                },
            ))
            .await
            .expect("reverse GeoIP add_rule should succeed");

        for (ip, expected_match) in
            [(vec![10, 1, 2, 3], false), (vec![192, 0, 2, 9], true)]
        {
            let result = service
                .test_route(Request::new(
                    proto::xray::app::router::command::TestRouteRequest {
                        routing_context: Some(
                            proto::xray::app::router::command::RoutingContext {
                                target_i_ps: vec![ip],
                                ..Default::default()
                            },
                        ),
                        field_selectors: vec![],
                        publish_result: false,
                    },
                ))
                .await;
            assert_eq!(result.is_ok(), expected_match);
        }
    }

    #[tokio::test]
    async fn routing_test_route_reports_empty_balancer_error() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("empty".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "empty".into(),
                outbound_selector: vec!["missing-prefix".into()],
                fallback_tag: None,
                strategy: Default::default(),
            }],
        );
        let service = RoutingServiceImpl::new(runtime);

        let error = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "test".into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect_err("empty balancer must fail test_route");

        assert_eq!(error.code(), Code::Unknown);
        assert!(
            error
                .message()
                .contains("balancer empty has no available outbound")
        );
    }

    #[tokio::test]
    async fn routing_test_route_uses_balancer_fallback_and_group_tag() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("auto".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "auto".into(),
                outbound_selector: vec!["missing-prefix".into()],
                fallback_tag: Some("direct".into()),
                strategy: Default::default(),
            }],
        );
        let service = RoutingServiceImpl::new(runtime);

        let matched = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "test".into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect("balancer fallback should route")
            .into_inner();

        assert_eq!(matched.outbound_tag, "direct");
        assert_eq!(matched.outbound_group_tags, vec!["auto"]);
    }

    #[tokio::test]
    async fn routing_balancer_info_uses_configured_targets() {
        let runtime = build_runtime(&["direct", "backup", "blocked"]);
        install_rules(
            &runtime,
            vec![],
            vec![BalancerConfig {
                tag: "balancer-a".into(),
                outbound_selector: vec!["back".into(), "direct".into()],
                fallback_tag: None,
                strategy: Default::default(),
            }],
        );
        let service = RoutingServiceImpl::new(runtime);

        let response = service
            .get_balancer_info(Request::new(
                proto::xray::app::router::command::GetBalancerInfoRequest {
                    tag: "balancer-a".to_string(),
                },
            ))
            .await
            .expect("get_balancer_info failed")
            .into_inner();
        let balancer = response.balancer.expect("balancer info missing");
        assert_eq!(
            balancer
                .principle_target
                .expect("principle targets missing")
                .tag,
            vec!["backup".to_string(), "direct".to_string()]
        );
    }

    #[tokio::test]
    async fn routing_subscribe_receives_published_result() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["inbound-a".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        );
        let service = RoutingServiceImpl::new(runtime);
        let mut stream = service
            .subscribe_routing_stats(Request::new(
                proto::xray::app::router::command::SubscribeRoutingStatsRequest {
                    field_selectors: vec![
                        "inbound".to_string(),
                        "outbound".to_string(),
                    ],
                },
            ))
            .await
            .expect("subscribe_routing_stats failed")
            .into_inner();

        service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "inbound-a".to_string(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: true,
                },
            ))
            .await
            .expect("test_route publish failed");

        let next = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("timed out waiting for routing stream item")
            .expect("routing stream closed")
            .expect("routing stream returned error");
        assert_eq!(next.inbound_tag, "inbound-a");
        assert_eq!(next.outbound_tag, "direct");
    }
}
