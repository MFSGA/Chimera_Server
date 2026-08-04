use std::collections::HashMap;

use prost::Message;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{
    config::rule::{
        BalancerConfig, BalancerStrategyConfig, NetworkListConfig, PortListConfig,
        PortRangeConfig, RuleConfig, WebhookRuleConfig,
    },
    routing_process::enrich_routing_input,
    routing_state::{DomainStrategy, RouteMatch, RoutingEvent, RoutingInput},
    runtime::RuntimeState,
};

use super::proto;

const ERR_NOT_ENOUGH_INFO: &str =
    "common: not enough information for making a decision";
const TYPE_ROUTER_CONFIG: &str = "xray.app.router.Config";
const TYPE_LEAST_LOAD_CONFIG: &str = "xray.app.router.StrategyLeastLoadConfig";
const TYPE_ROUTER_CONFIG_V2RAY: &str = "v2ray.core.app.router.Config";

#[derive(Clone)]
pub(super) struct RoutingServiceImpl {
    runtime: RuntimeState,
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
    #[prost(string, repeated, tag = "21")]
    process: Vec<String>,
    #[prost(message, optional, tag = "22")]
    webhook: Option<WebhookConfigPayload>,
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
struct WebhookConfigPayload {
    #[prost(string, tag = "1")]
    url: String,
    #[prost(uint32, tag = "2")]
    deduplication: u32,
    #[prost(map = "string, string", tag = "3")]
    headers: HashMap<String, String>,
}

#[derive(Clone, PartialEq, Message)]
struct BalancingRulePayload {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(string, repeated, tag = "2")]
    outbound_selector: Vec<String>,
    #[prost(string, tag = "3")]
    strategy: String,
    #[prost(message, optional, tag = "4")]
    strategy_settings: Option<proto::xray::common::serial::TypedMessage>,
    #[prost(string, tag = "5")]
    fallback_tag: String,
}

#[derive(Clone, PartialEq, Message)]
struct StrategyWeightPayload {
    #[prost(bool, tag = "1")]
    regexp: bool,
    #[prost(string, tag = "2")]
    r#match: String,
    #[prost(float, tag = "3")]
    value: f32,
}

#[derive(Clone, PartialEq, Message)]
struct StrategyLeastLoadConfigPayload {
    #[prost(message, repeated, tag = "2")]
    costs: Vec<StrategyWeightPayload>,
    #[prost(int64, repeated, tag = "3")]
    baselines: Vec<i64>,
    #[prost(int32, tag = "4")]
    expected: i32,
    #[prost(int64, tag = "5")]
    max_rtt: i64,
    #[prost(float, tag = "6")]
    tolerance: f32,
}

impl RoutingServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
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

    async fn resolve_outbound_tag(
        &self,
        context: &proto::xray::app::router::command::RoutingContext,
    ) -> Result<(String, Vec<String>), Status> {
        let mut input = routing_input_from_context(context);
        let routing = self.runtime.routing();
        if routing.requires_process_lookup() {
            enrich_routing_input(&mut input).await;
        }
        let route = routing.route(
            &input,
            &self.runtime.outbounds(),
            &self.runtime.balancer_overrides(),
        );
        if let Some(route) = route {
            if let Some(error) = route.resolution_error {
                return Err(Status::unknown(error));
            }
            return Ok((route.outbound_tag, route.outbound_group_tags));
        }

        Err(Status::unknown(ERR_NOT_ENOUGH_INFO))
    }

    fn principle_targets(&self, balancer_tag: &str) -> Vec<String> {
        let outbounds = self.runtime.outbounds();
        self.runtime
            .routing()
            .balancer_principle_targets(balancer_tag, &outbounds)
    }
}

fn routing_input_from_context(
    context: &proto::xray::app::router::command::RoutingContext,
) -> RoutingInput {
    RoutingInput {
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
    }
}

fn routing_context_from_event(
    event: RoutingEvent,
) -> proto::xray::app::router::command::RoutingContext {
    proto::xray::app::router::command::RoutingContext {
        inbound_tag: event.input.inbound_tag,
        network: event.input.network,
        source_i_ps: event.input.source_ips,
        target_i_ps: event.input.target_ips,
        source_port: event.input.source_port,
        target_port: event.input.target_port,
        target_domain: event.input.target_domain,
        protocol: event.input.protocol,
        user: event.input.user,
        attributes: event.input.attributes,
        outbound_group_tags: event.route.outbound_group_tags,
        outbound_tag: event.route.outbound_tag,
        local_i_ps: event.input.local_ips,
        local_port: event.input.local_port,
        vless_route: event.input.vless_route,
    }
}

fn selector_enabled(selectors: &[String], target: &str) -> bool {
    selectors.is_empty()
        || selectors
            .iter()
            .any(|selector| target.starts_with(selector))
}

fn filter_routing_context(
    context: proto::xray::app::router::command::RoutingContext,
    selectors: &[String],
) -> proto::xray::app::router::command::RoutingContext {
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
    if include_ip || selector_enabled(selectors, "ip_local") {
        filtered.local_i_ps = context.local_i_ps;
    }
    if include_port || selector_enabled(selectors, "port_source") {
        filtered.source_port = context.source_port;
    }
    if include_port || selector_enabled(selectors, "port_target") {
        filtered.target_port = context.target_port;
    }
    if include_port || selector_enabled(selectors, "port_local") {
        filtered.local_port = context.local_port;
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
            Err(_) => DomainStrategy::AsIs,
        };
    let rules = config
        .rule
        .into_iter()
        .map(convert_rule_payload)
        .collect::<Result<Vec<_>, _>>()?;
    let balancers = config
        .balancing_rule
        .into_iter()
        .map(convert_balancer_payload)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((domain_strategy, rules, balancers))
}

fn convert_balancer_payload(
    balancer: BalancingRulePayload,
) -> Result<BalancerConfig, Status> {
    let settings = convert_strategy_settings(
        &balancer.strategy,
        balancer.strategy_settings.as_ref(),
    )?;
    Ok(BalancerConfig {
        tag: balancer.tag,
        outbound_selector: balancer.outbound_selector,
        strategy: BalancerStrategyConfig {
            kind: balancer.strategy,
            settings,
        },
        fallback_tag: (!balancer.fallback_tag.is_empty())
            .then_some(balancer.fallback_tag),
    })
}

fn convert_strategy_settings(
    strategy: &str,
    settings: Option<&proto::xray::common::serial::TypedMessage>,
) -> Result<Option<serde_json::Value>, Status> {
    if !strategy.eq_ignore_ascii_case("leastLoad") {
        return Ok(None);
    }
    let Some(settings) = settings else {
        return Ok(None);
    };
    let message_type = settings.r#type.trim_start_matches('.');
    if message_type != TYPE_LEAST_LOAD_CONFIG {
        return Err(Status::invalid_argument(format!(
            "unsupported leastLoad strategy settings type {}",
            settings.r#type
        )));
    }
    let payload = StrategyLeastLoadConfigPayload::decode(settings.value.as_slice())
        .map_err(|error| {
            Status::invalid_argument(format!(
                "invalid leastLoad strategy settings: {error}"
            ))
        })?;
    let nanos_to_millis = |value: i64| value as f64 / 1_000_000.0;
    Ok(Some(serde_json::json!({
        "costs": payload.costs.into_iter().map(|cost| serde_json::json!({
            "regexp": cost.regexp,
            "match": cost.r#match,
            "value": cost.value,
        })).collect::<Vec<_>>(),
        "baselines": payload.baselines.into_iter().map(nanos_to_millis).collect::<Vec<_>>(),
        "expected": payload.expected,
        "maxRTT": nanos_to_millis(payload.max_rtt),
        "tolerance": payload.tolerance,
    })))
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
        process: rule.process,
        attrs: rule.attributes,
        local_ip: convert_geo_ip_payloads(rule.local_geoip)?,
        local_port: convert_port_list(rule.local_port_list),
        webhook: rule.webhook.map(|webhook| WebhookRuleConfig {
            url: webhook.url,
            deduplication: webhook.deduplication,
            headers: webhook.headers,
        }),
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
                bytes if bytes.len() == 16 => {
                    let octets = <[u8; 16]>::try_from(bytes).map_err(|_| {
                        Status::invalid_argument(
                            "routing IPv6 CIDR must contain exactly 16 bytes",
                        )
                    })?;
                    std::net::Ipv6Addr::from(octets).to_string()
                }
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
                        from: range.from as u16,
                        to: range.to as u16,
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
        let mut routing_updates = self.runtime.subscribe_routing_events();
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            loop {
                match routing_updates.recv().await {
                    Ok(event) => {
                        let context = routing_context_from_event(event);
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
            self.resolve_outbound_tag(&context).await?;
        context.outbound_tag = outbound_tag;
        context.outbound_group_tags = outbound_group_tags;

        if request.publish_result {
            self.runtime.publish_routing_event(RoutingEvent {
                input: routing_input_from_context(&context),
                route: RouteMatch {
                    outbound_tag: context.outbound_tag.clone(),
                    outbound_group_tags: context.outbound_group_tags.clone(),
                    rule_tag: String::new(),
                    resolution_error: None,
                },
            });
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

        if !self.runtime.routing().has_balancer(balancer_tag) {
            return Err(Status::not_found(format!(
                "balancer {} not found",
                balancer_tag
            )));
        }
        let principle_targets = self.principle_targets(balancer_tag);
        let override_target = self.runtime.balancer_override(balancer_tag);

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

        if !self.runtime.routing().has_balancer(balancer_tag) {
            return Err(Status::not_found(format!(
                "balancer {} not found",
                balancer_tag
            )));
        }

        let target = request.target.trim();
        if target.is_empty() {
            self.runtime.remove_balancer_override(balancer_tag);
            return Ok(Response::new(
                proto::xray::app::router::command::OverrideBalancerTargetResponse {},
            ));
        }

        self.runtime.set_balancer_override(balancer_tag, target);
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
            return Err(Status::not_found(format!(
                "routing rule {} not found",
                request.rule_tag
            )));
        }
        Ok(Response::new(
            proto::xray::app::router::command::RemoveRuleResponse {},
        ))
    }

    async fn list_rule(
        &self,
        _request: Request<proto::xray::app::router::command::ListRuleRequest>,
    ) -> Result<Response<proto::xray::app::router::command::ListRuleResponse>, Status>
    {
        let rules = self
            .runtime
            .routing()
            .list_rules()
            .into_iter()
            .map(|rule| proto::xray::app::router::command::ListRuleItem {
                tag: rule.outbound_tag,
                rule_tag: rule.rule_tag,
            })
            .collect();
        Ok(Response::new(
            proto::xray::app::router::command::ListRuleResponse { rules },
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

    #[test]
    fn routing_field_selectors_follow_xray_prefix_rules() {
        let context = proto::xray::app::router::command::RoutingContext {
            inbound_tag: "in".into(),
            network: 2,
            source_i_ps: vec![vec![1, 1, 1, 1]],
            target_i_ps: vec![vec![2, 2, 2, 2]],
            source_port: 1000,
            target_port: 2000,
            target_domain: "example.com".into(),
            protocol: "tls".into(),
            user: "alice".into(),
            attributes: HashMap::from([("key".into(), "value".into())]),
            outbound_group_tags: vec!["group".into()],
            outbound_tag: "direct".into(),
            local_i_ps: vec![vec![127, 0, 0, 1]],
            local_port: 3000,
            vless_route: 4000,
        };

        let ip = filter_routing_context(context.clone(), &["ip".into()]);
        assert_eq!(ip.source_i_ps, context.source_i_ps);
        assert_eq!(ip.target_i_ps, context.target_i_ps);
        assert_eq!(ip.local_i_ps, context.local_i_ps);
        assert_eq!(ip.source_port, 0);

        let port = filter_routing_context(context.clone(), &["port".into()]);
        assert_eq!(port.source_port, 1000);
        assert_eq!(port.target_port, 2000);
        assert_eq!(port.local_port, 3000);
        assert!(port.source_i_ps.is_empty());

        let outbound_group =
            filter_routing_context(context.clone(), &["outbound_group".into()]);
        assert_eq!(outbound_group.outbound_group_tags, vec!["group"]);
        assert_eq!(outbound_group.outbound_tag, "");

        let uppercase = filter_routing_context(context.clone(), &["IP".into()]);
        assert!(uppercase.source_i_ps.is_empty());
        assert!(uppercase.local_i_ps.is_empty());

        let empty_prefix = filter_routing_context(context.clone(), &[String::new()]);
        assert_eq!(empty_prefix.inbound_tag, context.inbound_tag);
        assert_eq!(empty_prefix.local_i_ps, context.local_i_ps);
        assert_eq!(empty_prefix.local_port, context.local_port);
        assert_eq!(empty_prefix.outbound_tag, context.outbound_tag);
        assert_eq!(empty_prefix.vless_route, 0);

        let all_fields = filter_routing_context(context, &[]);
        assert_eq!(all_fields.vless_route, 0);
        assert_eq!(all_fields.target_domain, "example.com");
    }

    #[test]
    fn routing_port_payload_uses_xray_uint16_wrapping() {
        let ports = convert_port_list(Some(PortListPayload {
            range: vec![PortRangePayload {
                from: 65_536,
                to: 65_537,
            }],
        }));

        assert_eq!(ports.0.len(), 1);
        assert_eq!(ports.0[0].from, 0);
        assert_eq!(ports.0[0].to, 1);
    }

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
    async fn routing_test_route_ignores_prefilled_outbound_fields() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct", "backup"]));
        let err = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "inbound-a".to_string(),
                            outbound_tag: "direct".into(),
                            outbound_group_tags: vec!["direct".into()],
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect_err("prefilled outbound fields must not bypass PickRoute");
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

        let listed = service
            .list_rule(Request::new(
                proto::xray::app::router::command::ListRuleRequest {},
            ))
            .await
            .expect("list_rule should include added rule")
            .into_inner();
        assert_eq!(listed.rules.len(), 1);
        assert_eq!(listed.rules[0].tag, "direct");
        assert_eq!(listed.rules[0].rule_tag, "rule-a");

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

        let listed = service
            .list_rule(Request::new(
                proto::xray::app::router::command::ListRuleRequest {},
            ))
            .await
            .expect("list_rule should reflect removed rule")
            .into_inner();
        assert!(listed.rules.is_empty());

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

        let missing = service
            .remove_rule(Request::new(
                proto::xray::app::router::command::RemoveRuleRequest {
                    rule_tag: "missing".into(),
                },
            ))
            .await
            .expect_err("missing routing rule must return NotFound");
        assert_eq!(missing.code(), Code::NotFound);
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
    async fn routing_add_rule_decodes_least_load_strategy_settings() {
        let runtime = build_runtime(&["direct", "backup", "fallback"]);
        runtime.record_outbound_observation(
            "direct",
            crate::routing_state::OutboundObservation {
                alive: true,
                delay_ms: 45,
                ..Default::default()
            },
        );
        runtime.record_outbound_observation(
            "backup",
            crate::routing_state::OutboundObservation {
                alive: true,
                delay_ms: 7,
                ..Default::default()
            },
        );
        let service = RoutingServiceImpl::new(runtime);
        let least_load = StrategyLeastLoadConfigPayload {
            costs: vec![],
            baselines: vec![],
            expected: 1,
            max_rtt: 100_000_000,
            tolerance: 0.0,
        };
        let router_config = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::AsIs as i32,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::BalancingTag(
                    "latency".into(),
                )),
                rule_tag: "least-load-rule".into(),
                inbound_tag: vec!["api-in".into()],
                ..RoutingRulePayload::default()
            }],
            balancing_rule: vec![BalancingRulePayload {
                tag: "latency".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: "leastLoad".into(),
                strategy_settings: Some(proto::xray::common::serial::TypedMessage {
                    r#type: TYPE_LEAST_LOAD_CONFIG.into(),
                    value: least_load.encode_to_vec(),
                }),
                fallback_tag: "fallback".into(),
            }],
        };

        service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: false,
                },
            ))
            .await
            .expect("leastLoad AddRule should succeed");

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
            .expect("leastLoad route should resolve")
            .into_inner();
        assert_eq!(matched.outbound_tag, "backup");
        assert_eq!(matched.outbound_group_tags, vec!["latency"]);

        let listed = service
            .list_rule(Request::new(
                proto::xray::app::router::command::ListRuleRequest {},
            ))
            .await
            .expect("list leastLoad rule")
            .into_inner();
        assert_eq!(listed.rules[0].tag, "");
        assert_eq!(listed.rules[0].rule_tag, "least-load-rule");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn routing_add_rule_matches_process_from_socket_tuple() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind process route listener");
        let client = tokio::net::TcpStream::connect(
            listener.local_addr().expect("process listener address"),
        );
        let (client, accepted) = tokio::join!(client, listener.accept());
        let client = client.expect("connect process route client");
        let (_accepted, _) = accepted.expect("accept process route client");
        let source = client.local_addr().expect("process source address");

        let runtime = build_runtime(&["direct", "blocked"]);
        let service = RoutingServiceImpl::new(runtime);
        let router_config = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::AsIs as i32,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::Tag(
                    "blocked".into(),
                )),
                rule_tag: "process-rule".into(),
                inbound_tag: vec!["process-in".into()],
                networks: vec![proto::xray::common::net::Network::Tcp as i32],
                process: vec!["self/".into()],
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
            .expect("add process rule");

        let source_ip = match source.ip() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let matched = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "process-in".into(),
                            network: proto::xray::common::net::Network::Tcp as i32,
                            source_i_ps: vec![source_ip],
                            source_port: source.port().into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect("process TestRoute should resolve")
            .into_inner();

        assert_eq!(matched.outbound_tag, "blocked");
    }

    #[test]
    fn routing_rule_payload_preserves_webhook_config() {
        let rule = convert_rule_payload(RoutingRulePayload {
            target_tag: Some(routing_rule_payload::TargetTag::Tag("direct".into())),
            inbound_tag: vec!["webhook-in".into()],
            webhook: Some(WebhookConfigPayload {
                url: "https://example.test/hook".into(),
                deduplication: 30,
                headers: HashMap::from([("X-Token".into(), "secret".into())]),
            }),
            ..RoutingRulePayload::default()
        })
        .expect("webhook routing payload should decode");

        let webhook = rule.webhook.expect("webhook config missing");
        assert_eq!(webhook.url, "https://example.test/hook");
        assert_eq!(webhook.deduplication, 30);
        assert_eq!(webhook.headers["X-Token"], "secret");
    }

    #[tokio::test]
    async fn routing_add_rule_rejects_invalid_webhook_transactionally() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                rule_tag: Some("existing-rule".into()),
                ..RuleConfig::default()
            }],
            vec![],
        );
        let service = RoutingServiceImpl::new(runtime);
        let invalid = RouterConfigPayload {
            domain_strategy: RouterDomainStrategyPayload::AsIs as i32,
            rule: vec![RoutingRulePayload {
                target_tag: Some(routing_rule_payload::TargetTag::Tag(
                    "direct".into(),
                )),
                inbound_tag: vec!["invalid".into()],
                webhook: Some(WebhookConfigPayload {
                    url: "ftp://example.test/hook".into(),
                    ..WebhookConfigPayload::default()
                }),
                ..RoutingRulePayload::default()
            }],
            balancing_rule: vec![],
        };

        let error = service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(invalid)),
                    should_append: false,
                },
            ))
            .await
            .expect_err("invalid webhook AddRule must fail");
        assert_eq!(error.code(), Code::InvalidArgument);

        let listed = service
            .list_rule(Request::new(
                proto::xray::app::router::command::ListRuleRequest {},
            ))
            .await
            .expect("list rules after rejected webhook update")
            .into_inner();
        assert_eq!(listed.rules.len(), 1);
        assert_eq!(listed.rules[0].rule_tag, "existing-rule");
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
    async fn routing_add_rule_treats_unknown_strategy_as_as_is() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["existing".into()],
                outbound_tag: Some("direct".into()),
                rule_tag: Some("existing-rule".into()),
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

        service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest {
                    config: Some(encode_router_config(router_config)),
                    should_append: false,
                },
            ))
            .await
            .expect("unknown Xray enum values should behave as AsIs");

        let replacement = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "replacement".into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect("replacement rule should be installed")
            .into_inner();
        assert_eq!(replacement.outbound_tag, "direct");

        let existing = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "existing".into(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: false,
                },
            ))
            .await
            .expect_err("replacement should remove previous rules");
        assert_eq!(existing.code(), Code::Unknown);
        assert_eq!(existing.message(), ERR_NOT_ENOUGH_INFO);

        let listed = service
            .list_rule(Request::new(
                proto::xray::app::router::command::ListRuleRequest {},
            ))
            .await
            .expect("list replacement rule")
            .into_inner();
        assert_eq!(listed.rules.len(), 1);
        assert_eq!(listed.rules[0].rule_tag, "replacement");
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
                strategy: Default::default(),
                fallback_tag: None,
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
                strategy: Default::default(),
                fallback_tag: Some("direct".into()),
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
                strategy: Default::default(),
                fallback_tag: None,
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
        assert!(balancer.r#override.is_none());
        assert_eq!(
            balancer
                .principle_target
                .expect("principle targets missing")
                .tag,
            vec!["backup".to_string(), "direct".to_string()]
        );
    }

    #[tokio::test]
    async fn routing_balancer_info_rejects_unknown_balancer() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct"]));

        let error = service
            .get_balancer_info(Request::new(
                proto::xray::app::router::command::GetBalancerInfoRequest {
                    tag: "missing".into(),
                },
            ))
            .await
            .expect_err("unknown balancer info must fail");

        assert_eq!(error.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn routing_balancer_info_uses_least_ping_principle_target() {
        let runtime = build_runtime(&["direct", "backup", "fallback"]);
        install_rules(
            &runtime,
            vec![],
            vec![BalancerConfig {
                tag: "latency".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: BalancerStrategyConfig {
                    kind: "leastPing".into(),
                    settings: None,
                },
                fallback_tag: Some("fallback".into()),
            }],
        );
        runtime.record_outbound_observation(
            "direct",
            crate::routing_state::OutboundObservation {
                alive: true,
                delay_ms: 40,
                ..Default::default()
            },
        );
        runtime.record_outbound_observation(
            "backup",
            crate::routing_state::OutboundObservation {
                alive: true,
                delay_ms: 8,
                ..Default::default()
            },
        );
        let service = RoutingServiceImpl::new(runtime);

        let response = service
            .get_balancer_info(Request::new(
                proto::xray::app::router::command::GetBalancerInfoRequest {
                    tag: "latency".into(),
                },
            ))
            .await
            .expect("leastPing balancer info should resolve")
            .into_inner();

        assert_eq!(
            response
                .balancer
                .expect("balancer info missing")
                .principle_target
                .expect("principle target missing")
                .tag,
            vec!["backup"]
        );
    }

    #[tokio::test]
    async fn routing_balancer_override_affects_runtime_data_path() {
        let runtime = build_runtime(&["direct", "backup"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["test".into()],
                balancer_tag: Some("latency".into()),
                ..RuleConfig::default()
            }],
            vec![BalancerConfig {
                tag: "latency".into(),
                outbound_selector: vec!["direct".into(), "backup".into()],
                strategy: BalancerStrategyConfig {
                    kind: "leastPing".into(),
                    settings: None,
                },
                fallback_tag: None,
            }],
        );
        runtime.record_outbound_observation(
            "direct",
            crate::routing_state::OutboundObservation {
                alive: true,
                delay_ms: 5,
                ..Default::default()
            },
        );
        runtime.record_outbound_observation(
            "backup",
            crate::routing_state::OutboundObservation {
                alive: true,
                delay_ms: 50,
                ..Default::default()
            },
        );
        let service = RoutingServiceImpl::new(runtime.clone());
        let input = RoutingInput {
            inbound_tag: "test".into(),
            ..RoutingInput::default()
        };

        service
            .override_balancer_target(Request::new(
                proto::xray::app::router::command::OverrideBalancerTargetRequest {
                    balancer_tag: "latency".into(),
                    target: "backup".into(),
                },
            ))
            .await
            .expect("set balancer override");
        assert_eq!(
            runtime
                .select_outbound_checked(&input)
                .expect("runtime route with override")
                .expect("runtime outbound missing")
                .tag,
            "backup"
        );

        let info = service
            .get_balancer_info(Request::new(
                proto::xray::app::router::command::GetBalancerInfoRequest {
                    tag: "latency".into(),
                },
            ))
            .await
            .expect("get overridden balancer info")
            .into_inner();
        assert_eq!(
            info.balancer
                .expect("balancer info missing")
                .r#override
                .expect("override missing")
                .target,
            "backup"
        );

        service
            .override_balancer_target(Request::new(
                proto::xray::app::router::command::OverrideBalancerTargetRequest {
                    balancer_tag: "latency".into(),
                    target: "missing-outbound".into(),
                },
            ))
            .await
            .expect("Xray accepts unresolved override targets");
        let error = runtime
            .select_outbound_checked(&input)
            .expect_err("unresolved override must fail at route resolution");
        assert!(error.contains("missing outbound missing-outbound"));

        service
            .override_balancer_target(Request::new(
                proto::xray::app::router::command::OverrideBalancerTargetRequest {
                    balancer_tag: "latency".into(),
                    target: String::new(),
                },
            ))
            .await
            .expect("clear balancer override");
        assert_eq!(
            runtime
                .select_outbound_checked(&input)
                .expect("runtime route after clearing override")
                .expect("runtime outbound missing")
                .tag,
            "direct"
        );

        let error = service
            .override_balancer_target(Request::new(
                proto::xray::app::router::command::OverrideBalancerTargetRequest {
                    balancer_tag: "missing".into(),
                    target: "backup".into(),
                },
            ))
            .await
            .expect_err("unknown balancer override must fail");
        assert_eq!(error.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn routing_subscribe_receives_runtime_data_path_decision() {
        let runtime = build_runtime(&["direct"]);
        install_rules(
            &runtime,
            vec![RuleConfig {
                inbound_tag: vec!["runtime-in".into()],
                outbound_tag: Some("direct".into()),
                ..RuleConfig::default()
            }],
            vec![],
        );
        let service = RoutingServiceImpl::new(runtime.clone());
        let mut stream = service
            .subscribe_routing_stats(Request::new(
                proto::xray::app::router::command::SubscribeRoutingStatsRequest {
                    field_selectors: vec![
                        "inbound".into(),
                        "domain".into(),
                        "outbound".into(),
                    ],
                },
            ))
            .await
            .expect("subscribe runtime routing stats")
            .into_inner();

        let selected = runtime
            .select_outbound_checked(&RoutingInput {
                inbound_tag: "runtime-in".into(),
                network: 2,
                target_domain: "example.com".into(),
                target_port: 443,
                ..RoutingInput::default()
            })
            .expect("runtime routing selection")
            .expect("runtime outbound missing");
        assert_eq!(selected.tag, "direct");

        let update = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("runtime routing update timeout")
            .expect("runtime routing stream closed")
            .expect("runtime routing update failed");
        assert_eq!(update.inbound_tag, "runtime-in");
        assert_eq!(update.target_domain, "example.com");
        assert_eq!(update.outbound_tag, "direct");
        assert_eq!(update.network, 0, "unselected network field must be empty");
        assert_eq!(update.target_port, 0, "unselected port field must be empty");
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
