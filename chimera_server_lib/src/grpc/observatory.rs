use tonic::{Request, Response, Status};

use super::proto;

pub(super) struct ObservatoryServiceImpl;

#[tonic::async_trait]
impl proto::xray::core::app::observatory::command::observatory_service_server::ObservatoryService
    for ObservatoryServiceImpl
{
    async fn get_outbound_status(
        &self,
        _request: Request<proto::xray::core::app::observatory::command::GetOutboundStatusRequest>,
    ) -> Result<
        Response<proto::xray::core::app::observatory::command::GetOutboundStatusResponse>,
        Status,
    > {
        Err(Status::unimplemented("GetOutboundStatus is not supported"))
    }
}

pub(super) fn build_service(
) -> proto::xray::core::app::observatory::command::observatory_service_server::ObservatoryServiceServer<
    ObservatoryServiceImpl,
>{
    proto::xray::core::app::observatory::command::observatory_service_server::ObservatoryServiceServer::new(
        ObservatoryServiceImpl,
    )
}
