use std::time::Duration;

use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "api")]
use crate::ApiListen;
#[cfg(feature = "vless-reverse")]
use crate::handler::vless_reverse::bridge_runtime::ReverseBridgePlan;
// Provisional Linux-only device backend; other targets need their own TUN
// implementation and packet/lifecycle validation before this gate is widened.
#[cfg(all(feature = "tun-gateway", target_os = "linux"))]
use crate::tun_gateway::TunGatewayPlan;
use crate::{
    Error,
    config::def::{ApiConfig, BurstObservatoryConfig, ObservatoryConfig},
    inbound::InboundFailure,
    mcp::{self, McpServerConfig},
    routing_observer,
    runtime::RuntimeState,
};

#[derive(Debug)]
struct ServerShutdownReport {
    stopped_inbounds: usize,
    drained_connections: bool,
    cancelled_connections: usize,
    stopped_global_xudp_workers: usize,
}

enum ServerExit {
    Signal(&'static str),
    SignalError(std::io::Error),
    ServiceTask(Result<(), Error>),
    InboundFailure(InboundFailure),
}

pub(crate) struct ServerServiceTask {
    task: JoinHandle<Result<(), Error>>,
    abort: AbortHandle,
    cancellation: Option<CancellationToken>,
    joined: bool,
}

impl ServerServiceTask {
    fn abort_on_shutdown(task: JoinHandle<()>) -> Self {
        let abort = task.abort_handle();
        let task = tokio::spawn(async move {
            task.await
                .map_err(|error| Error::Io(std::io::Error::other(error)))
        });
        Self {
            task,
            abort,
            cancellation: None,
            joined: false,
        }
    }

    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    fn cooperative(
        task: JoinHandle<Result<(), Error>>,
        cancellation: CancellationToken,
    ) -> Self {
        let abort = task.abort_handle();
        let task = tokio::spawn(async move {
            match task.await {
                Ok(result) => result,
                Err(error) => Err(Error::Io(std::io::Error::other(error))),
            }
        });
        Self {
            task,
            abort,
            cancellation: Some(cancellation),
            joined: false,
        }
    }

    fn request_shutdown(&self) {
        if let Some(cancellation) = &self.cancellation {
            cancellation.cancel();
        } else {
            self.abort.abort();
        }
    }
}

pub(crate) struct ServerStartupConfig {
    pub(crate) mcp: Option<McpServerConfig>,
    pub(crate) mcp_configured_without_listen: bool,
    pub(crate) skip_inbound_tag: Option<String>,
    pub(crate) observatory: Option<ObservatoryConfig>,
    pub(crate) burst_observatory: Option<BurstObservatoryConfig>,
    pub(crate) api: Option<ApiConfig>,
    #[cfg(feature = "api")]
    pub(crate) api_listen: Option<ApiListen>,
    #[cfg(feature = "vless-reverse")]
    pub(crate) reverse_bridge_plans: Vec<ReverseBridgePlan>,
    // Only the implemented Linux device owner can be passed to startup.
    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    pub(crate) tun_gateway: Option<TunGatewayPlan>,
}

pub(crate) async fn start_server_resources(
    runtime_state: &RuntimeState,
    config: ServerStartupConfig,
    connection_drain_timeout: Duration,
) -> Result<Vec<ServerServiceTask>, Error> {
    let mut join_handles = Vec::with_capacity(4);
    let startup_result: Result<(), Error> = async {
        let mut has_started_server = false;
        if let Some(mcp) = config.mcp {
            let mcp_handle = mcp::start_mcp_server(mcp).await?;
            join_handles.push(ServerServiceTask::abort_on_shutdown(mcp_handle));
            has_started_server = true;
        } else if config.mcp_configured_without_listen {
            tracing::warn!("mcp is configured but no listen address was resolved");
        }

        // Bind every configured data-plane listener before advertising the
        // control plane. rnode uses GetSysStats as its readiness probe, so
        // starting gRPC first would allow a process with a failed inbound
        // bind to look healthy.
        if let Some(tag) = config.skip_inbound_tag.as_deref() {
            tracing::info!("skip api inbound {} to avoid grpc port conflict", tag);
        }
        let started_inbounds = runtime_state
            .inbound_manager()
            .start_configured_inbounds(
                runtime_state.clone(),
                config.skip_inbound_tag.as_deref(),
            )
            .await?;
        has_started_server |= started_inbounds > 0;

        // Keep device creation behind the Linux resource owner. Other targets
        // reject this configuration in ValidatedServerPlan::compile.
        #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
        if let Some(tun_gateway) = config.tun_gateway {
            let task = crate::tun_gateway::start_server(
                tun_gateway,
                runtime_state.data_plane(),
            )
            .await?;
            join_handles.push(ServerServiceTask::cooperative(
                task.task,
                task.cancellation,
            ));
            has_started_server = true;
        }

        #[cfg(feature = "vless-reverse")]
        {
            let bridge_tasks = crate::handler::vless_reverse::bridge_runtime::start_reverse_bridge_monitors(
                runtime_state.data_plane(),
                config.reverse_bridge_plans,
            );
            has_started_server |= !bridge_tasks.is_empty();
            join_handles.extend(
                bridge_tasks
                    .into_iter()
                    .map(ServerServiceTask::abort_on_shutdown),
            );
        }

        if let Some(observer) = routing_observer::start_observer(
            runtime_state.data_plane(),
            config.observatory,
            config.burst_observatory,
        )
        .map_err(Error::InvalidConfig)?
        {
            join_handles.push(ServerServiceTask::abort_on_shutdown(observer));
            has_started_server = true;
        }

        #[cfg(feature = "api")]
        if let Some(api) = config.api.as_ref()
            && let Some(listen) = config.api_listen
        {
            if !api.services.is_empty() {
                let grpc_handle = crate::grpc::start_grpc_server(
                    crate::grpc::GrpcServerConfig {
                        listen,
                        services: api.services.clone(),
                    },
                    runtime_state.clone(),
                )
                .await?;
                join_handles
                    .push(ServerServiceTask::abort_on_shutdown(grpc_handle));
                has_started_server = true;
            } else {
                tracing::warn!("api is configured but no services are enabled");
            }
        }

        #[cfg(not(feature = "api"))]
        if let Some(api) = config.api.as_ref()
            && !api.services.is_empty()
        {
            tracing::warn!(
                "api services configured but the \"api\" feature is disabled; grpc support is unavailable"
            );
        }

        if !has_started_server {
            return Err(Error::InvalidConfig(
                "no servers started; check inbounds/api configuration".into(),
            ));
        }
        Ok(())
    }
    .await;

    if let Err(error) = startup_result {
        let shutdown = shutdown_server_runtime(
            runtime_state,
            join_handles,
            connection_drain_timeout,
            true,
        )
        .await;
        tracing::error!(
            stopped_inbounds = shutdown.stopped_inbounds,
            cancelled_connections = shutdown.cancelled_connections,
            "server startup failed; startup resources rolled back"
        );
        return Err(error);
    }

    if !runtime_state.mark_running() {
        let shutdown = shutdown_server_runtime(
            runtime_state,
            join_handles,
            connection_drain_timeout,
            true,
        )
        .await;
        tracing::error!(
            stopped_inbounds = shutdown.stopped_inbounds,
            cancelled_connections = shutdown.cancelled_connections,
            "server startup lifecycle transition failed; startup resources rolled back"
        );
        return Err(Error::Io(std::io::Error::other(
            "runtime lifecycle left starting state before startup completed",
        )));
    }

    Ok(join_handles)
}

pub(crate) async fn supervise_server(
    runtime_state: &RuntimeState,
    mut service_tasks: Vec<ServerServiceTask>,
    connection_drain_timeout: Duration,
) -> Result<(), Error> {
    let exit = {
        let shutdown_signal = wait_for_shutdown_signal();
        let service_task = wait_for_service_task(&mut service_tasks);
        let inbound_failure = runtime_state.wait_for_inbound_failure();
        tokio::pin!(shutdown_signal);
        tokio::pin!(service_task);
        tokio::pin!(inbound_failure);
        tokio::select! {
            result = &mut shutdown_signal => match result {
                Ok(signal) => ServerExit::Signal(signal),
                Err(error) => ServerExit::SignalError(error),
            },
            result = &mut service_task => ServerExit::ServiceTask(result),
            failure = &mut inbound_failure => ServerExit::InboundFailure(failure),
        }
    };

    match &exit {
        ServerExit::Signal(signal) => {
            tracing::info!(
                %signal,
                grace_period_seconds = connection_drain_timeout.as_secs(),
                "shutdown requested; stopping listeners"
            );
        }
        ServerExit::InboundFailure(failure) => {
            tracing::error!(
                inbound_tag = %failure.tag,
                generation = failure.generation,
                "inbound listener exited unexpectedly; shutting down server"
            );
        }
        ServerExit::SignalError(_) | ServerExit::ServiceTask(_) => {}
    }

    let failed = !matches!(&exit, ServerExit::Signal(_));
    let shutdown = shutdown_server_runtime(
        runtime_state,
        service_tasks,
        connection_drain_timeout,
        failed,
    )
    .await;
    tracing::info!(
        stopped_inbounds = shutdown.stopped_inbounds,
        drained_connections = shutdown.drained_connections,
        cancelled_connections = shutdown.cancelled_connections,
        stopped_global_xudp_workers = shutdown.stopped_global_xudp_workers,
        lifecycle = runtime_state.lifecycle_state().as_str(),
        "server shutdown complete"
    );

    match exit {
        ServerExit::Signal(_) => Ok(()),
        ServerExit::SignalError(error) => {
            tracing::error!(%error, "shutdown signal listener failed");
            Err(Error::Io(error))
        }
        ServerExit::ServiceTask(Ok(())) => Err(Error::Io(std::io::Error::other(
            "server task finished unexpectedly",
        ))),
        ServerExit::ServiceTask(Err(error)) => {
            tracing::error!(%error, "runtime task failed; server shut down");
            Err(error)
        }
        ServerExit::InboundFailure(failure) => {
            Err(Error::Io(std::io::Error::other(format!(
                "inbound {} generation {} listener exited unexpectedly",
                failure.tag, failure.generation
            ))))
        }
    }
}

async fn wait_for_shutdown_signal() -> std::io::Result<&'static str> {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                Ok("SIGINT")
            }
            signal = terminate.recv() => {
                signal.ok_or_else(|| std::io::Error::other("SIGTERM listener closed"))?;
                Ok("SIGTERM")
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("CTRL_C")
    }
}

async fn wait_for_service_task(
    handles: &mut [ServerServiceTask],
) -> Result<(), Error> {
    if handles.is_empty() {
        return std::future::pending().await;
    }
    use futures::FutureExt;
    let (result, index, _) =
        futures::future::select_all(handles.iter_mut().map(|service| {
            (&mut service.task).map(|result| {
                result.unwrap_or_else(|error| {
                    Err(Error::Io(std::io::Error::other(error)))
                })
            })
        }))
        .await;
    handles[index].joined = true;
    result
}

async fn shutdown_server_runtime(
    runtime_state: &RuntimeState,
    service_tasks: Vec<ServerServiceTask>,
    connection_grace_period: Duration,
    failed: bool,
) -> ServerShutdownReport {
    runtime_state.begin_draining();

    // Close connection registration first so an accept racing with listener
    // teardown cannot escape the server-level owner.
    runtime_state.close_inbound_connection_tasks();

    // Stop every non-inbound service promptly before waiting for data-plane
    // listener cleanup. InboundManager aborts all listeners before awaiting any
    // one handle, so the process stops accepting across the whole server first.
    for task in &service_tasks {
        task.request_shutdown();
    }
    let stopped_inbounds = runtime_state.inbound_manager().stop_all_tasks().await;
    for task in service_tasks {
        if !task.joined {
            let _ = task.task.await;
        }
    }

    let connection_shutdown = runtime_state
        .drain_inbound_connection_tasks(connection_grace_period)
        .await;
    let stopped_global_xudp_workers =
        crate::session::udp::shutdown_global_xudp_workers().await;
    runtime_state.finish_shutdown(failed);

    ServerShutdownReport {
        stopped_inbounds,
        drained_connections: connection_shutdown.drained,
        cancelled_connections: connection_shutdown.cancelled_tasks,
        stopped_global_xudp_workers,
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerServiceTask, wait_for_service_task};
    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    use super::{
        ServerStartupConfig, shutdown_server_runtime, start_server_resources,
    };
    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    use crate::tun_gateway::TunGatewayPlan;
    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    use crate::{
        address::{BindLocation, NetLocation},
        config::{
            Transport,
            def::TunGatewayConfig,
            server_config::{ServerConfig, ServerProxyConfig, SocksUserStore},
        },
        runtime::RuntimeState,
    };
    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    use std::{
        net::{IpAddr, Ipv4Addr, TcpListener},
        time::Duration,
    };

    #[tokio::test]
    async fn service_supervisor_records_the_joined_task() {
        let completed_task = tokio::spawn(async {});
        let mut services =
            vec![ServerServiceTask::abort_on_shutdown(completed_task)];

        assert!(wait_for_service_task(&mut services).await.is_ok());
        assert!(services[0].joined);
    }

    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    #[tokio::test]
    async fn service_supervisor_preserves_a_reported_task_failure() {
        let failed_task = tokio::spawn(async {
            Err(crate::Error::Io(std::io::Error::other(
                "injected TUN device read failure",
            )))
        });
        let cancellation = tokio_util::sync::CancellationToken::new();
        let mut services =
            vec![ServerServiceTask::cooperative(failed_task, cancellation)];

        let error = wait_for_service_task(&mut services)
            .await
            .expect_err("failed service task must report its cause");
        assert!(
            error
                .to_string()
                .contains("injected TUN device read failure")
        );
        assert!(services[0].joined);
    }

    #[cfg(all(feature = "tun-gateway", target_os = "linux"))]
    #[tokio::test]
    async fn tun_device_startup_failure_rolls_back_bound_inbound() {
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve an ephemeral inbound port");
        let listen_address = probe.local_addr().expect("read inbound address");
        drop(probe);

        let inbound = ServerConfig {
            tag: "rollback-probe".into(),
            bind_location: BindLocation::Address(NetLocation::from_ip_addr(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                listen_address.port(),
            )),
            protocol: ServerProxyConfig::Socks {
                accounts: SocksUserStore::new(Vec::new()),
                udp_enabled: false,
                udp_response_ip: None,
                user_level: 0,
            },
            transport: Transport::Tcp,
            quic_settings: None,
            sniffing: None,
            tcp_socket_policy: None,
        };
        let runtime_state = RuntimeState::new(vec![inbound], Vec::new());
        let tun_gateway = TunGatewayPlan::try_from(TunGatewayConfig {
            // `lo` already names Linux's loopback device. TUNSETIFF must reject
            // this incompatible existing device without changing host links.
            name: "lo".into(),
            address: "10.253.0.1/24".into(),
            ipv6_address: None,
            mtu: 1500,
            routes: Vec::new(),
            route_from: Vec::new(),
            route_input_interface: None,
            route_table: None,
            route_rule_priority: None,
            inbound_tag: "tun-gateway".into(),
            user_level: 0,
            max_tcp_connections: 1,
            max_udp_sessions: 1,
        })
        .expect("compile valid TUN gateway plan");

        let startup = start_server_resources(
            &runtime_state,
            ServerStartupConfig {
                mcp: None,
                mcp_configured_without_listen: false,
                skip_inbound_tag: None,
                observatory: None,
                burst_observatory: None,
                api: None,
                #[cfg(feature = "api")]
                api_listen: None,
                #[cfg(feature = "vless-reverse")]
                reverse_bridge_plans: Vec::new(),
                tun_gateway: Some(tun_gateway),
            },
            Duration::from_secs(1),
        )
        .await;

        let error = match startup {
            Err(error) => error,
            Ok(service_tasks) => {
                shutdown_server_runtime(
                    &runtime_state,
                    service_tasks,
                    Duration::from_secs(1),
                    true,
                )
                .await;
                panic!(
                    "TUN creation with the existing loopback interface name must fail"
                );
            }
        };
        assert!(
            error
                .to_string()
                .contains("failed to create tunGateway device lo"),
            "expected TUN creation failure, got: {error}"
        );
        let crate::Error::Io(io_error) = &error else {
            panic!("TUN creation failure must remain an I/O error: {error}");
        };
        let context = io_error.get_ref().expect(
            "the contextual I/O error should retain the TUN creation context",
        );
        let original_io_error = std::error::Error::source(context)
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .expect("the contextual error must retain the original operating-system error");
        assert_eq!(
            io_error.kind(),
            original_io_error.kind(),
            "TUN startup must preserve the operating-system error kind"
        );

        TcpListener::bind(listen_address)
            .expect("startup rollback must release the previously bound inbound");
    }
}
