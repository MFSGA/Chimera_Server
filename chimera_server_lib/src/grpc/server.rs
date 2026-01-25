use std::net::SocketAddr;

use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;

use crate::runtime::RuntimeState;

use super::{handler, logger, observatory, routing, stats};

#[derive(Debug, Clone)]
pub struct GrpcServerConfig {
    pub listen: SocketAddr,
    pub services: Vec<String>,
}

pub async fn start_grpc_server(
    config: GrpcServerConfig,
    runtime: RuntimeState,
) -> std::io::Result<JoinHandle<()>> {
    let listen = config.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;

    let mut builder = Some(tonic::transport::Server::builder());
    let mut router: Option<tonic::transport::server::Router> = None;
    let mut service_count = 0usize;

    if has_service(&config.services, "StatsService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            stats::build_service(),
        ));
        service_count += 1;
    }

    if has_service(&config.services, "LoggerService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            logger::build_service(),
        ));
        service_count += 1;
    }

    if has_service(&config.services, "HandlerService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            handler::build_service(runtime.clone()),
        ));
        service_count += 1;
    }

    if has_service(&config.services, "RoutingService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            routing::build_service(),
        ));
        service_count += 1;
    }

    if has_service(&config.services, "ObservatoryService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            observatory::build_service(),
        ));
        service_count += 1;
    }

    if service_count == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no supported grpc services configured",
        ));
    }

    let incoming = TcpListenerStream::new(listener);

    let router = router.expect("grpc router should exist when services are configured");
    Ok(tokio::spawn(async move {
        if let Err(err) = router.serve_with_incoming(incoming).await {
            tracing::error!("grpc server stopped with error: {}", err);
        }
    }))
}

fn add_service<S>(
    builder: Option<tonic::transport::Server>,
    router: Option<tonic::transport::server::Router>,
    service: S,
) -> tonic::transport::server::Router
where
    S: tonic::codegen::Service<
            http::Request<tonic::body::BoxBody>,
            Response = http::Response<tonic::body::BoxBody>,
            Error = std::convert::Infallible,
        > + tonic::server::NamedService
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    match (builder, router) {
        (Some(mut builder), None) => builder.add_service(service),
        (None, Some(router)) => router.add_service(service),
        (Some(_), Some(_)) => unreachable!("grpc builder/router should be mutually exclusive"),
        (None, None) => unreachable!("grpc builder or router must be available"),
    }
}

fn has_service(services: &[String], name: &str) -> bool {
    services
        .iter()
        .any(|service| service.eq_ignore_ascii_case(name))
}
