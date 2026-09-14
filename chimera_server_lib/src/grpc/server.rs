use std::io;

use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
#[cfg(target_os = "linux")]
use tokio_stream::wrappers::UnixListenerStream;

use crate::{ApiListen, runtime::RuntimeState};

use super::{handler, logger, observatory, routing, stats, user_domain};

#[derive(Debug, Clone)]
pub struct GrpcServerConfig {
    pub listen: ApiListen,
    pub services: Vec<String>,
}

pub async fn start_grpc_server(
    config: GrpcServerConfig,
    runtime: RuntimeState,
) -> io::Result<JoinHandle<()>> {
    let GrpcServerConfig { listen, services } = config;
    match listen {
        ApiListen::Tcp(listen) => {
            start_tcp_grpc_server(listen, services, runtime).await
        }
        ApiListen::AbstractUnix(name) => {
            start_abstract_unix_grpc_server(name, services, runtime).await
        }
    }
}

async fn start_tcp_grpc_server(
    listen: std::net::SocketAddr,
    services: Vec<String>,
    runtime: RuntimeState,
) -> io::Result<JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let router = build_router(&services, runtime)?;
    let incoming = TcpListenerStream::new(listener);

    Ok(tokio::spawn(async move {
        if let Err(err) = router.serve_with_incoming(incoming).await {
            tracing::error!("grpc server stopped with error: {}", err);
        }
    }))
}

#[cfg(target_os = "linux")]
async fn start_abstract_unix_grpc_server(
    name: String,
    services: Vec<String>,
    runtime: RuntimeState,
) -> io::Result<JoinHandle<()>> {
    let listener = bind_abstract_unix_listener(&name)?;
    let router = build_router(&services, runtime)?;
    let incoming = UnixListenerStream::new(listener);

    Ok(tokio::spawn(async move {
        if let Err(err) = router.serve_with_incoming(incoming).await {
            tracing::error!("grpc server stopped with error: {}", err);
        }
    }))
}

#[cfg(not(target_os = "linux"))]
async fn start_abstract_unix_grpc_server(
    name: String,
    services: Vec<String>,
    runtime: RuntimeState,
) -> io::Result<JoinHandle<()>> {
    let _ = (name, services, runtime);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "abstract Unix gRPC listeners are supported only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn bind_abstract_unix_listener(name: &str) -> io::Result<tokio::net::UnixListener> {
    use std::os::linux::net::SocketAddrExt as _;

    let address =
        std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
    listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(listener)
}

fn build_router(
    services: &[String],
    runtime: RuntimeState,
) -> io::Result<tonic::transport::server::Router> {
    let mut builder = Some(tonic::transport::Server::builder());
    let mut router: Option<tonic::transport::server::Router> = None;
    let mut service_count = 0usize;

    if has_service(services, "StatsService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            stats::build_service(runtime.clone()),
        ));
        service_count += 1;
    }

    if has_service(services, "LoggerService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            logger::build_service(),
        ));
        service_count += 1;
    }

    if has_service(services, "HandlerService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            handler::build_service(runtime.clone()),
        ));
        service_count += 1;
    }

    if has_service(services, "RoutingService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            routing::build_service(runtime.clone()),
        ));
        service_count += 1;
    }

    if has_service(services, "ObservatoryService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            observatory::build_service(runtime.clone()),
        ));
        service_count += 1;
    }

    if has_service(services, "UserDomainAccessService") {
        router = Some(add_service(
            builder.take(),
            router.take(),
            user_domain::build_service(runtime.clone()),
        ));
        service_count += 1;
    }

    if service_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no supported grpc services configured",
        ));
    }

    Ok(router.expect("grpc router should exist when services are configured"))
}

fn add_service<S>(
    builder: Option<tonic::transport::Server>,
    router: Option<tonic::transport::server::Router>,
    service: S,
) -> tonic::transport::server::Router
where
    S: tonic::codegen::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<tonic::body::Body>,
            Error = std::convert::Infallible,
        > + tonic::server::NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    match (builder, router) {
        (Some(mut builder), None) => builder.add_service(service),
        (None, Some(router)) => router.add_service(service),
        (Some(_), Some(_)) => {
            unreachable!("grpc builder/router should be mutually exclusive")
        }
        (None, None) => unreachable!("grpc builder or router must be available"),
    }
}

fn has_service(services: &[String], name: &str) -> bool {
    services
        .iter()
        .any(|service| service.eq_ignore_ascii_case(name))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        os::linux::net::SocketAddrExt as _,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(1);

    fn unique_abstract_name() -> String {
        format!(
            "chimera-grpc-test-{}-{}",
            std::process::id(),
            NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[tokio::test]
    async fn abstract_unix_listener_uses_linux_namespace() {
        let name = unique_abstract_name();
        let listener =
            bind_abstract_unix_listener(&name).expect("bind abstract Unix listener");
        let local = listener.local_addr().expect("read local Unix address");

        assert_eq!(local.as_abstract_name(), Some(name.as_bytes()));
        assert!(local.as_pathname().is_none());
    }

    #[tokio::test]
    async fn grpc_server_accepts_abstract_unix_connections() {
        let name = unique_abstract_name();
        let runtime = RuntimeState::new(Vec::new(), Vec::new());
        let handle = start_grpc_server(
            GrpcServerConfig {
                listen: ApiListen::AbstractUnix(name.clone()),
                services: vec!["StatsService".into()],
            },
            runtime,
        )
        .await
        .expect("start abstract Unix gRPC server");

        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
                .expect("build abstract Unix client address");
        let stream = std::os::unix::net::UnixStream::connect_addr(&address)
            .expect("connect to abstract Unix gRPC listener");
        drop(stream);

        handle.abort();
        let _ = handle.await;
        bind_abstract_unix_listener(&name)
            .expect("abstract namespace should be released after server abort");
    }
}
