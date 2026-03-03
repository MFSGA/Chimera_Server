use std::time::{SystemTime, UNIX_EPOCH};

use crate::runtime::RuntimeState;
use tonic::{Request, Response, Status};

use super::proto;

#[derive(Clone)]
pub(super) struct ObservatoryServiceImpl {
    runtime: RuntimeState,
}

impl ObservatoryServiceImpl {
    fn new(runtime: RuntimeState) -> Self {
        Self { runtime }
    }
}

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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let status = self
            .runtime
            .outbounds()
            .iter()
            .map(
                |outbound| proto::xray::core::app::observatory::OutboundStatus {
                    alive: false,
                    delay: 0,
                    last_error_reason: format!(
                        "observatory probe for protocol {} is not implemented",
                        outbound.protocol
                    ),
                    outbound_tag: outbound.tag.clone(),
                    last_seen_time: 0,
                    last_try_time: now,
                    health_ping: None,
                },
            )
            .collect();

        Ok(Response::new(
            proto::xray::core::app::observatory::command::GetOutboundStatusResponse {
                status: Some(proto::xray::core::app::observatory::ObservationResult { status }),
            },
        ))
    }
}

pub(super) fn build_service(
    runtime: RuntimeState,
) -> proto::xray::core::app::observatory::command::observatory_service_server::ObservatoryServiceServer<
    ObservatoryServiceImpl,
>{
    proto::xray::core::app::observatory::command::observatory_service_server::ObservatoryServiceServer::new(
        ObservatoryServiceImpl::new(runtime),
    )
}

#[cfg(test)]
mod tests {
    use crate::runtime::OutboundSummary;

    use super::proto::xray::core::app::observatory::command::observatory_service_server::ObservatoryService;
    use super::*;

    fn build_runtime(outbounds: &[(&str, &str)]) -> RuntimeState {
        RuntimeState::new(
            vec![],
            outbounds
                .iter()
                .map(|(tag, protocol)| OutboundSummary {
                    tag: (*tag).to_string(),
                    protocol: (*protocol).to_string(),
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn observatory_returns_outbound_status() {
        let service = ObservatoryServiceImpl::new(build_runtime(&[
            ("direct", "freedom"),
            ("block", "blackhole"),
        ]));
        let response = service
            .get_outbound_status(Request::new(
                proto::xray::core::app::observatory::command::GetOutboundStatusRequest::default(),
            ))
            .await
            .expect("get_outbound_status failed")
            .into_inner();

        let status = response.status.expect("status missing").status;
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].outbound_tag, "direct");
        assert_eq!(status[1].outbound_tag, "block");
        assert!(!status[0].alive);
        assert!(
            status[0]
                .last_error_reason
                .contains("observatory probe for protocol freedom")
        );
    }

    #[tokio::test]
    async fn observatory_returns_empty_status_when_no_outbounds() {
        let service = ObservatoryServiceImpl::new(build_runtime(&[]));
        let response = service
            .get_outbound_status(Request::new(
                proto::xray::core::app::observatory::command::GetOutboundStatusRequest::default(),
            ))
            .await
            .expect("get_outbound_status failed")
            .into_inner();
        assert!(response.status.expect("status missing").status.is_empty());
    }
}
