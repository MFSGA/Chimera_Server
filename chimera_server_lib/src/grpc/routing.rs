use tonic::{Request, Response, Status};

use super::proto;

pub(super) struct RoutingServiceImpl;

#[tonic::async_trait]
impl proto::xray::app::router::command::routing_service_server::RoutingService
    for RoutingServiceImpl
{
    type SubscribeRoutingStatsStream =
        tokio_stream::wrappers::ReceiverStream<Result<proto::xray::app::router::command::RoutingContext, Status>>;

    async fn subscribe_routing_stats(
        &self,
        _request: Request<proto::xray::app::router::command::SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        Err(Status::unimplemented("SubscribeRoutingStats is not supported"))
    }

    async fn test_route(
        &self,
        _request: Request<proto::xray::app::router::command::TestRouteRequest>,
    ) -> Result<Response<proto::xray::app::router::command::RoutingContext>, Status> {
        Err(Status::unimplemented("TestRoute is not supported"))
    }

    async fn get_balancer_info(
        &self,
        _request: Request<proto::xray::app::router::command::GetBalancerInfoRequest>,
    ) -> Result<Response<proto::xray::app::router::command::GetBalancerInfoResponse>, Status> {
        Err(Status::unimplemented("GetBalancerInfo is not supported"))
    }

    async fn override_balancer_target(
        &self,
        _request: Request<proto::xray::app::router::command::OverrideBalancerTargetRequest>,
    ) -> Result<Response<proto::xray::app::router::command::OverrideBalancerTargetResponse>, Status> {
        Err(Status::unimplemented("OverrideBalancerTarget is not supported"))
    }

    async fn add_rule(
        &self,
        _request: Request<proto::xray::app::router::command::AddRuleRequest>,
    ) -> Result<Response<proto::xray::app::router::command::AddRuleResponse>, Status> {
        Err(Status::unimplemented("AddRule is not supported"))
    }

    async fn remove_rule(
        &self,
        _request: Request<proto::xray::app::router::command::RemoveRuleRequest>,
    ) -> Result<Response<proto::xray::app::router::command::RemoveRuleResponse>, Status> {
        Err(Status::unimplemented("RemoveRule is not supported"))
    }
}

pub(super) fn build_service(
) -> proto::xray::app::router::command::routing_service_server::RoutingServiceServer<
    RoutingServiceImpl,
> {
    proto::xray::app::router::command::routing_service_server::RoutingServiceServer::new(
        RoutingServiceImpl,
    )
}
