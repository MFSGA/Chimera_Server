use std::{collections::HashMap, io, sync::Arc, time::Duration};

use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{Instant, sleep_until},
};

use crate::{
    config::{MkcpTransportConfig, server_config::ServerConfig},
    handler::tcp::{
        tcp_handler::TcpServerHandler, tcp_handler_util::create_tcp_server_handler,
    },
    resolver::{NativeResolver, Resolver},
    runtime::RuntimeState,
    session::dispatcher::{process_stream_with_context, stream_connection_context},
};

use super::{
    COMMAND_TERMINATE, MkcpSegment, MkcpSessionKey, PreparedMkcpListener,
    connection::MkcpConnectionPhase,
    runtime::{MkcpByteStream, MkcpConnectionRuntime},
};

const RECEIVE_BUFFER_SIZE: usize = 65_535;
const EMPTY_REGISTRY_SLEEP: Duration = Duration::from_secs(60 * 60);

struct ActiveSession {
    runtime: MkcpConnectionRuntime,
    started: Instant,
    next_update: Option<Instant>,
}

impl ActiveSession {
    fn new(runtime: MkcpConnectionRuntime, now: Instant) -> Self {
        let mut session = Self {
            runtime,
            started: now,
            next_update: None,
        };
        session.reschedule(now);
        session
    }

    fn elapsed_ms(&self, now: Instant) -> u32 {
        now.duration_since(self.started).as_millis() as u32
    }

    fn reschedule(&mut self, now: Instant) {
        self.next_update = self.runtime.next_update_delay().map(|delay| now + delay);
    }
}

pub(crate) async fn start_mkcp_server(
    config: ServerConfig,
    runtime: RuntimeState,
    mkcp: MkcpTransportConfig,
) -> io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        tag,
        bind_location,
        protocol,
        sniffing,
        tcp_socket_policy,
        ..
    } = config;

    let mut rules_stack = Vec::new();
    let server_handler: Arc<Box<dyn TcpServerHandler>> =
        Arc::new(create_tcp_server_handler(protocol, &tag, &mut rules_stack)?);
    if server_handler.requires_original_destination() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mKCP original-destination handling is not implemented",
        ));
    }

    let listener = PreparedMkcpListener::bind(
        &bind_location,
        tcp_socket_policy.as_ref(),
        mkcp,
    )?;
    let local_addr = listener.local_addr()?;

    Ok(Some(tokio::spawn(async move {
        if let Err(error) = run_mkcp_server(
            listener,
            local_addr,
            server_handler,
            runtime,
            sniffing,
            mkcp,
        )
        .await
        {
            tracing::error!(%error, "mKCP listener stopped with error");
        }
    })))
}

async fn run_mkcp_server(
    listener: PreparedMkcpListener,
    local_addr: std::net::SocketAddr,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    runtime: RuntimeState,
    sniffing: Option<crate::config::server_config::InboundSniffingConfig>,
    mkcp: MkcpTransportConfig,
) -> io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let shared_wake = Arc::new(Notify::new());
    let mut sessions = HashMap::<MkcpSessionKey, ActiveSession>::new();
    let mut receive_buffer = vec![0u8; RECEIVE_BUFFER_SIZE];

    loop {
        let deadline = sessions
            .values()
            .filter_map(|session| session.next_update)
            .min()
            .unwrap_or_else(|| Instant::now() + EMPTY_REGISTRY_SLEEP);

        tokio::select! {
            received = listener.recv_packet(&mut receive_buffer) => {
                let (remote, segments) = received?;
                handle_packet(
                    &listener,
                    &mut sessions,
                    Arc::clone(&shared_wake),
                    remote,
                    segments,
                    local_addr,
                    Arc::clone(&server_handler),
                    Arc::clone(&resolver),
                    &runtime,
                    sniffing.clone(),
                    mkcp,
                ).await?;
            }
            _ = shared_wake.notified() => {
                drive_sessions(&listener, &mut sessions, true).await?;
            }
            _ = sleep_until(deadline) => {
                drive_sessions(&listener, &mut sessions, false).await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_packet(
    listener: &PreparedMkcpListener,
    sessions: &mut HashMap<MkcpSessionKey, ActiveSession>,
    shared_wake: Arc<Notify>,
    remote: std::net::SocketAddr,
    segments: Vec<MkcpSegment>,
    local_addr: std::net::SocketAddr,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: &RuntimeState,
    sniffing: Option<crate::config::server_config::InboundSniffingConfig>,
    mkcp: MkcpTransportConfig,
) -> io::Result<()> {
    let Some(first) = segments.first() else {
        return Ok(());
    };
    let key = MkcpSessionKey {
        remote,
        conversation: first.conversation(),
    };

    if let std::collections::hash_map::Entry::Vacant(entry) = sessions.entry(key) {
        if first.command() == COMMAND_TERMINATE {
            return Ok(());
        }
        let (connection, stream) = MkcpConnectionRuntime::new_with_wake(
            key.conversation,
            mkcp,
            shared_wake,
        );
        if !spawn_protocol_session(
            stream,
            remote,
            local_addr,
            server_handler,
            resolver,
            runtime,
            sniffing,
        ) {
            return Ok(());
        }
        entry.insert(ActiveSession::new(connection, Instant::now()));
    }

    let now = Instant::now();
    let Some(session) = sessions.get_mut(&key) else {
        return Ok(());
    };
    let current = session.elapsed_ms(now);
    session.runtime.ingest(current, segments);
    let output = session.runtime.update(current);
    session.reschedule(now);
    send_segments(listener, remote, output).await;
    if session.runtime.phase() == MkcpConnectionPhase::Terminated {
        sessions.remove(&key);
    }
    Ok(())
}

fn spawn_protocol_session(
    stream: MkcpByteStream,
    remote: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    resolver: Arc<dyn Resolver>,
    runtime: &RuntimeState,
    sniffing: Option<crate::config::server_config::InboundSniffingConfig>,
) -> bool {
    let data_plane = runtime.data_plane();
    let mut connection_context =
        stream_connection_context(&data_plane, Some(local_addr));
    connection_context.peer_addr = Some(remote);
    connection_context.listener_addr = Some(local_addr);

    runtime.spawn_inbound_connection(async move {
        if let Err(error) = process_stream_with_context(
            stream,
            server_handler,
            resolver,
            remote,
            data_plane,
            connection_context,
            sniffing,
        )
        .await
        {
            tracing::debug!(peer = %remote, %error, "mKCP stream finished with error");
        }
    })
}

async fn drive_sessions(
    listener: &PreparedMkcpListener,
    sessions: &mut HashMap<MkcpSessionKey, ActiveSession>,
    drive_all: bool,
) -> io::Result<()> {
    let now = Instant::now();
    let mut outgoing = Vec::new();
    let mut terminated = Vec::new();

    for (key, session) in sessions.iter_mut() {
        if !drive_all && session.next_update.is_some_and(|deadline| deadline > now) {
            continue;
        }
        let current = session.elapsed_ms(now);
        let output = session.runtime.update(current);
        session.reschedule(now);
        if !output.is_empty() {
            outgoing.push((key.remote, output));
        }
        if session.runtime.phase() == MkcpConnectionPhase::Terminated {
            terminated.push(*key);
        }
    }

    for key in terminated {
        sessions.remove(&key);
    }
    for (remote, segments) in outgoing {
        send_segments(listener, remote, segments).await;
    }
    Ok(())
}

async fn send_segments(
    listener: &PreparedMkcpListener,
    remote: std::net::SocketAddr,
    segments: Vec<MkcpSegment>,
) {
    for segment in segments {
        if let Err(error) = listener.send_packet(remote, &[segment]).await {
            tracing::debug!(peer = %remote, %error, "failed to send mKCP segment");
        }
    }
}
