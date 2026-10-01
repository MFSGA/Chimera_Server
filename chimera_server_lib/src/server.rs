use std::time::Duration;

use tokio::task::{JoinError, JoinHandle};

#[cfg(feature = "api")]
use crate::ApiListen;
#[cfg(feature = "vless-reverse")]
use crate::handler::vless_reverse::bridge_runtime::ReverseBridgePlan;
use crate::{
    Error, beginning,
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
    ServiceTask(Result<(), JoinError>),
    InboundFailure(InboundFailure),
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
}

pub(crate) async fn start_server_resources(
    runtime_state: &RuntimeState,
    config: ServerStartupConfig,
    connection_drain_timeout: Duration,
) -> Result<Vec<JoinHandle<()>>, Error> {
    let mut join_handles = Vec::with_capacity(4);
    let startup_result: Result<(), Error> = async {
        let mut has_started_server = false;
        if let Some(mcp) = config.mcp {
            let mcp_handle = mcp::start_mcp_server(mcp).await?;
            join_handles.push(mcp_handle);
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

        #[cfg(feature = "vless-reverse")]
        {
            let bridge_tasks = crate::handler::vless_reverse::bridge_runtime::start_reverse_bridge_monitors(
                runtime_state.data_plane(),
                config.reverse_bridge_plans,
            );
            has_started_server |= !bridge_tasks.is_empty();
            join_handles.extend(bridge_tasks);
        }

        if let Some(observer) = routing_observer::start_observer(
            runtime_state.data_plane(),
            config.observatory,
            config.burst_observatory,
        )
        .map_err(Error::InvalidConfig)?
        {
            join_handles.push(observer);
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
                join_handles.push(grpc_handle);
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
    mut service_tasks: Vec<JoinHandle<()>>,
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
            Err(Error::Io(std::io::Error::other(error)))
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
    handles: &mut [JoinHandle<()>],
) -> Result<(), JoinError> {
    if handles.is_empty() {
        return std::future::pending().await;
    }
    futures::future::select_all(handles.iter_mut()).await.0
}

async fn shutdown_server_runtime(
    runtime_state: &RuntimeState,
    service_tasks: Vec<JoinHandle<()>>,
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
        task.abort();
    }
    let stopped_inbounds = runtime_state.inbound_manager().stop_all_tasks().await;
    for task in service_tasks {
        let _ = task.await;
    }

    let connection_shutdown = runtime_state
        .drain_inbound_connection_tasks(connection_grace_period)
        .await;
    let stopped_global_xudp_workers =
        beginning::udp::shutdown_global_xudp_workers().await;
    runtime_state.finish_shutdown(failed);

    ServerShutdownReport {
        stopped_inbounds,
        drained_connections: connection_shutdown.drained,
        cancelled_connections: connection_shutdown.cancelled_tasks,
        stopped_global_xudp_workers,
    }
}
