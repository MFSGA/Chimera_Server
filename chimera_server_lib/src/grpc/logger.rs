use tonic::{Request, Response, Status};

use crate::log;

use super::proto;

pub(super) struct LoggerServiceImpl;

#[tonic::async_trait]
impl proto::xray::app::log::command::logger_service_server::LoggerService for LoggerServiceImpl {
    async fn restart_logger(
        &self,
        _request: Request<proto::xray::app::log::command::RestartLoggerRequest>,
    ) -> Result<Response<proto::xray::app::log::command::RestartLoggerResponse>, Status> {
        log::restart()
            .map_err(|err| Status::failed_precondition(format!("restart failed: {err}")))?;
        Ok(Response::new(
            proto::xray::app::log::command::RestartLoggerResponse {},
        ))
    }
}

pub(super) fn build_service(
) -> proto::xray::app::log::command::logger_service_server::LoggerServiceServer<LoggerServiceImpl> {
    proto::xray::app::log::command::logger_service_server::LoggerServiceServer::new(
        LoggerServiceImpl,
    )
}
