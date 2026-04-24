use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::runtime::RuntimeState;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::proto;

const ERR_NOT_ENOUGH_INFO: &str =
    "common: not enough information for making a decision";

#[derive(Clone)]
pub(super) struct RoutingServiceImpl {
    runtime: RuntimeState,
    balancer_overrides: Arc<RwLock<HashMap<String, String>>>,
    routing_stats_tx:
        broadcast::Sender<proto::xray::app::router::command::RoutingContext>,
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

    fn resolve_outbound_tag(
        &self,
        context: &proto::xray::app::router::command::RoutingContext,
    ) -> Result<String, Status> {
        if !context.outbound_tag.is_empty() {
            return if self.has_outbound_tag(&context.outbound_tag) {
                Ok(context.outbound_tag.clone())
            } else {
                Err(Status::not_found(format!(
                    "outbound {} not found",
                    context.outbound_tag
                )))
            };
        }

        if context.outbound_group_tags.is_empty() {
            return Err(Status::unknown(ERR_NOT_ENOUGH_INFO));
        }

        let overrides = self
            .balancer_overrides
            .read()
            .expect("routing balancer overrides lock poisoned");
        for group_tag in &context.outbound_group_tags {
            if let Some(target) = overrides.get(group_tag) {
                if self.has_outbound_tag(target) {
                    return Ok(target.clone());
                }
            }
        }
        drop(overrides);

        for group_tag in &context.outbound_group_tags {
            if self.has_outbound_tag(group_tag) {
                return Ok(group_tag.clone());
            }
        }

        Err(Status::unknown(ERR_NOT_ENOUGH_INFO))
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

#[tonic::async_trait]
impl proto::xray::app::router::command::routing_service_server::RoutingService
    for RoutingServiceImpl
{
    type SubscribeRoutingStatsStream = tokio_stream::wrappers::ReceiverStream<
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
        context.outbound_tag = self.resolve_outbound_tag(&context)?;

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

        let principle_targets = self
            .runtime
            .outbounds()
            .iter()
            .map(|outbound| outbound.tag.clone())
            .collect::<Vec<_>>();
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
        _request: Request<proto::xray::app::router::command::AddRuleRequest>,
    ) -> Result<Response<proto::xray::app::router::command::AddRuleResponse>, Status>
    {
        Err(Status::unimplemented("AddRule is not supported"))
    }

    async fn remove_rule(
        &self,
        _request: Request<proto::xray::app::router::command::RemoveRuleRequest>,
    ) -> Result<
        Response<proto::xray::app::router::command::RemoveRuleResponse>,
        Status,
    > {
        Err(Status::unimplemented("RemoveRule is not supported"))
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

    use crate::runtime::OutboundSummary;
    use tokio_stream::StreamExt;

    use super::proto::xray::app::router::command::routing_service_server::RoutingService;
    use super::*;
    use tonic::{Code, Request};

    fn build_runtime(outbounds: &[&str]) -> RuntimeState {
        RuntimeState::new(
            vec![],
            outbounds
                .iter()
                .map(|tag| OutboundSummary {
                    tag: (*tag).to_string(),
                    protocol: "freedom".to_string(),
                })
                .collect(),
        )
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
    async fn routing_test_route_accepts_explicit_outbound() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct", "backup"]));
        let response = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
                            inbound_tag: "inbound-a".to_string(),
                            outbound_tag: "direct".to_string(),
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
        assert_eq!(response.inbound_tag, "inbound-a");
    }

    #[tokio::test]
    async fn routing_override_and_get_balancer_info() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct", "backup"]));
        service
            .override_balancer_target(Request::new(
                proto::xray::app::router::command::OverrideBalancerTargetRequest {
                    balancer_tag: "balancer-a".to_string(),
                    target: "backup".to_string(),
                },
            ))
            .await
            .expect("override_balancer_target failed");

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
            balancer.r#override.expect("override info missing").target,
            "backup"
        );
        assert_eq!(
            balancer
                .principle_target
                .expect("principle targets missing")
                .tag,
            vec!["direct".to_string(), "backup".to_string()]
        );
    }

    #[tokio::test]
    async fn routing_subscribe_receives_published_result() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct"]));
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
                            inbound_tag: "inbound-stream".to_string(),
                            outbound_tag: "direct".to_string(),
                            ..Default::default()
                        },
                    ),
                    field_selectors: vec![],
                    publish_result: true,
                },
            ))
            .await
            .expect("test_route publish failed");

        let next = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("timed out waiting for routing stream item")
            .expect("routing stream closed")
            .expect("routing stream returned error");

        assert_eq!(next.inbound_tag, "inbound-stream");
        assert_eq!(next.outbound_tag, "direct");
    }

    #[tokio::test]
    async fn routing_methods_validate_inputs_and_keep_unimplemented_rules() {
        let service = RoutingServiceImpl::new(build_runtime(&["direct"]));

        let err = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest::default(),
            ))
            .await
            .expect_err("expected invalid argument for missing context");
        assert_eq!(err.code(), Code::InvalidArgument);

        let err = service
            .override_balancer_target(Request::new(
                proto::xray::app::router::command::OverrideBalancerTargetRequest {
                    balancer_tag: "balancer-a".to_string(),
                    target: "missing-outbound".to_string(),
                },
            ))
            .await
            .expect_err("expected missing outbound target");
        assert_eq!(err.code(), Code::NotFound);

        let err = service
            .add_rule(Request::new(
                proto::xray::app::router::command::AddRuleRequest::default(),
            ))
            .await
            .expect_err("expected add_rule to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);

        let err = service
            .remove_rule(Request::new(
                proto::xray::app::router::command::RemoveRuleRequest::default(),
            ))
            .await
            .expect_err("expected remove_rule to be unimplemented");
        assert_eq!(err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn routing_without_outbounds_returns_unknown_without_route_clues() {
        let service = RoutingServiceImpl::new(build_runtime(&[]));
        let err = service
            .test_route(Request::new(
                proto::xray::app::router::command::TestRouteRequest {
                    routing_context: Some(
                        proto::xray::app::router::command::RoutingContext {
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

        let err = service
            .get_balancer_info(Request::new(
                proto::xray::app::router::command::GetBalancerInfoRequest {
                    tag: "balancer-a".to_string(),
                },
            ))
            .await
            .expect_err("expected no outbounds configured error");
        assert_eq!(err.code(), Code::FailedPrecondition);
    }
}
