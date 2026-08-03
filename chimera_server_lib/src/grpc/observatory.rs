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

        let observations = self.runtime.outbound_observations();
        let status = self
            .runtime
            .outbounds()
            .iter()
            .map(|outbound| {
                let observation = observations.get(&outbound.tag);
                proto::xray::core::app::observatory::OutboundStatus {
                    alive: observation.is_some_and(|status| status.alive),
                    delay: observation.map_or(0, |status| status.delay_ms),
                    last_error_reason: observation.map_or_else(
                        || format!(
                            "outbound {} has not been observed yet",
                            outbound.tag
                        ),
                        |status| status.last_error_reason.clone(),
                    ),
                    outbound_tag: outbound.tag.clone(),
                    last_seen_time: observation
                        .map_or(0, |status| status.last_seen_time),
                    last_try_time: observation.map_or(now, |status| status.last_try_time),
                    health_ping: observation.and_then(|status| {
                        (status.health_all > 0).then(|| {
                            let millis_to_nanos = |value: i64| {
                                value.saturating_mul(1_000_000)
                            };
                            proto::xray::core::app::observatory::HealthPingMeasurementResult {
                                all: status.health_all,
                                fail: status.health_fail,
                                deviation: millis_to_nanos(
                                    status.health_deviation_ms,
                                ),
                                average: millis_to_nanos(status.health_average_ms),
                                max: millis_to_nanos(status.health_max_ms),
                                min: millis_to_nanos(status.health_min_ms),
                            }
                        })
                    }),
                }
            })
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
    use crate::{routing_state::OutboundObservation, runtime::OutboundSummary};

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
                    proxy_settings_type: None,
                    proxy_settings_value: None,
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn observatory_returns_outbound_status() {
        let runtime =
            build_runtime(&[("direct", "freedom"), ("block", "blackhole")]);
        runtime.record_outbound_observation(
            "direct",
            OutboundObservation {
                alive: true,
                delay_ms: 27,
                last_seen_time: 123,
                last_try_time: 124,
                health_all: 10,
                health_fail: 2,
                health_deviation_ms: 3,
                health_average_ms: 7,
                health_max_ms: 11,
                health_min_ms: 4,
                ..OutboundObservation::default()
            },
        );
        let service = ObservatoryServiceImpl::new(runtime);
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
        assert!(status[0].alive);
        assert_eq!(status[0].delay, 27);
        assert_eq!(status[0].last_seen_time, 123);
        assert_eq!(status[0].last_try_time, 124);
        let health = status[0].health_ping.as_ref().expect("health ping missing");
        assert_eq!(health.all, 10);
        assert_eq!(health.fail, 2);
        assert_eq!(health.deviation, 3_000_000);
        assert_eq!(health.average, 7_000_000);
        assert_eq!(health.max, 11_000_000);
        assert_eq!(health.min, 4_000_000);
        assert!(!status[1].alive);
        assert!(
            status[1]
                .last_error_reason
                .contains("has not been observed yet")
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
