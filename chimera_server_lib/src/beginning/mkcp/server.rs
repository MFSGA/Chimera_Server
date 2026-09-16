use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::Arc,
    time::Duration,
};

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
    resolver::Resolver,
    runtime::DataPlaneRuntime,
    session::dispatcher::{process_stream_with_context, stream_connection_context},
};

use super::{
    COMMAND_TERMINATE, MkcpSegment, MkcpSessionKey, PreparedMkcpListener,
    connection::MkcpConnectionPhase,
    runtime::{MkcpByteStream, MkcpConnectionRuntime},
};

const RECEIVE_BUFFER_SIZE: usize = 65_535;
const EMPTY_REGISTRY_SLEEP: Duration = Duration::from_secs(60 * 60);
const SEND_RETRY_ATTEMPTS: u8 = 5;
const SEND_RETRY_DELAY: Duration = Duration::from_millis(100);

trait MkcpSegmentSender {
    async fn send_segment(
        &self,
        remote: std::net::SocketAddr,
        segment: &MkcpSegment,
    ) -> io::Result<usize>;
}

impl MkcpSegmentSender for PreparedMkcpListener {
    async fn send_segment(
        &self,
        remote: std::net::SocketAddr,
        segment: &MkcpSegment,
    ) -> io::Result<usize> {
        self.send_packet(remote, std::slice::from_ref(segment))
            .await
    }
}

#[derive(Debug)]
enum RetryableSendState {
    Ready,
    Retry { attempts_made: u8, at: Instant },
    Exhausted { at: Instant, error: io::Error },
}

#[derive(Debug)]
struct RetryableSegmentQueue {
    segments: VecDeque<MkcpSegment>,
    state: RetryableSendState,
}

impl Default for RetryableSegmentQueue {
    fn default() -> Self {
        Self {
            segments: VecDeque::new(),
            state: RetryableSendState::Ready,
        }
    }
}

impl RetryableSegmentQueue {
    fn extend(&mut self, segments: Vec<MkcpSegment>) {
        self.segments.extend(segments);
    }

    fn deadline(&self) -> Option<Instant> {
        match &self.state {
            RetryableSendState::Ready => None,
            RetryableSendState::Retry { at, .. }
            | RetryableSendState::Exhausted { at, .. } => Some(*at),
        }
    }

    fn is_blocking(&self) -> bool {
        !matches!(self.state, RetryableSendState::Ready)
    }

    fn is_idle(&self) -> bool {
        self.segments.is_empty() && !self.is_blocking()
    }

    #[cfg(test)]
    fn make_due(&mut self) {
        match &mut self.state {
            RetryableSendState::Ready => {}
            RetryableSendState::Retry { at, .. }
            | RetryableSendState::Exhausted { at, .. } => {
                *at = Instant::now();
            }
        }
    }
}

struct ActiveSession {
    runtime: MkcpConnectionRuntime,
    started: Instant,
    next_update: Option<Instant>,
    update_pending: bool,
    send_queue: RetryableSegmentQueue,
}

impl ActiveSession {
    fn new(runtime: MkcpConnectionRuntime, now: Instant) -> Self {
        let mut session = Self {
            runtime,
            started: now,
            next_update: None,
            update_pending: false,
            send_queue: RetryableSegmentQueue::default(),
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

    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if let Some(deadline) = self.send_queue.deadline() {
            return Some(deadline);
        }
        if self.update_pending {
            return Some(now);
        }
        self.next_update
    }

    fn can_remove(&self) -> bool {
        self.runtime.phase() == MkcpConnectionPhase::Terminated
            && self.send_queue.is_idle()
    }
}

pub(crate) async fn start_mkcp_server(
    config: ServerConfig,
    runtime: DataPlaneRuntime,
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
    runtime: DataPlaneRuntime,
    sniffing: Option<crate::config::server_config::InboundSniffingConfig>,
    mkcp: MkcpTransportConfig,
) -> io::Result<()> {
    let resolver = runtime.resolver();
    let shared_wake = Arc::new(Notify::new());
    let mut sessions = HashMap::<MkcpSessionKey, ActiveSession>::new();
    let mut receive_buffer = vec![0u8; RECEIVE_BUFFER_SIZE];

    loop {
        let now = Instant::now();
        let deadline = sessions
            .values()
            .filter_map(|session| session.next_deadline(now))
            .min()
            .unwrap_or(now + EMPTY_REGISTRY_SLEEP);

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
    runtime: &DataPlaneRuntime,
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
    session.update_pending = true;
    drive_active_session(listener, remote, session).await;
    if session.can_remove() {
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
    runtime: &DataPlaneRuntime,
    sniffing: Option<crate::config::server_config::InboundSniffingConfig>,
) -> bool {
    let data_plane = runtime.clone();
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
    let keys = sessions.keys().copied().collect::<Vec<_>>();
    let mut terminated = Vec::new();

    for key in keys {
        let Some(session) = sessions.get_mut(&key) else {
            continue;
        };
        if drive_all {
            session.update_pending = true;
        }
        if !drive_all
            && session
                .next_deadline(now)
                .is_some_and(|deadline| deadline > now)
        {
            continue;
        }
        drive_active_session(listener, key.remote, session).await;
        if session.can_remove() {
            terminated.push(key);
        }
    }

    for key in terminated {
        sessions.remove(&key);
    }
    Ok(())
}

async fn drive_active_session<S: MkcpSegmentSender>(
    sender: &S,
    remote: std::net::SocketAddr,
    session: &mut ActiveSession,
) {
    loop {
        pump_send_queue(sender, remote, &mut session.send_queue).await;
        if session.send_queue.is_blocking() {
            return;
        }

        let now = Instant::now();
        let timer_due = session.next_update.is_some_and(|deadline| deadline <= now);
        if !session.update_pending && !timer_due {
            return;
        }

        session.update_pending = false;
        let current = session.elapsed_ms(now);
        let output = session.runtime.update(current);
        session.reschedule(now);
        session.send_queue.extend(output);
    }
}

async fn pump_send_queue<S: MkcpSegmentSender>(
    sender: &S,
    remote: std::net::SocketAddr,
    queue: &mut RetryableSegmentQueue,
) {
    loop {
        let now = Instant::now();
        let attempts_made =
            match std::mem::replace(&mut queue.state, RetryableSendState::Ready) {
                RetryableSendState::Ready => 0,
                RetryableSendState::Retry { attempts_made, at } => {
                    if at > now {
                        queue.state =
                            RetryableSendState::Retry { attempts_made, at };
                        return;
                    }
                    attempts_made
                }
                RetryableSendState::Exhausted { at, error } => {
                    if at > now {
                        queue.state = RetryableSendState::Exhausted { at, error };
                        return;
                    }
                    queue.segments.pop_front();
                    tracing::debug!(
                        peer = %remote,
                        attempts = SEND_RETRY_ATTEMPTS,
                        %error,
                        "failed to send mKCP segment after retries"
                    );
                    continue;
                }
            };

        let Some(segment) = queue.segments.front() else {
            return;
        };
        let attempt = attempts_made.saturating_add(1);
        match sender.send_segment(remote, segment).await {
            Ok(_) => {
                queue.segments.pop_front();
            }
            Err(_error) if attempt < SEND_RETRY_ATTEMPTS => {
                queue.state = RetryableSendState::Retry {
                    attempts_made: attempt,
                    at: Instant::now() + SEND_RETRY_DELAY,
                };
                return;
            }
            Err(error) => {
                // Xray retry.Timed(5, 100) sleeps once more after the fifth
                // failed write before returning the final error to its caller.
                queue.state = RetryableSendState::Exhausted {
                    at: Instant::now() + SEND_RETRY_DELAY,
                    error,
                };
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    struct ScriptedSender {
        failures_before_success: usize,
        attempts: AtomicUsize,
        conversations: Mutex<Vec<u16>>,
    }

    impl ScriptedSender {
        fn new(failures_before_success: usize) -> Self {
            Self {
                failures_before_success,
                attempts: AtomicUsize::new(0),
                conversations: Mutex::new(Vec::new()),
            }
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }

        fn conversations(&self) -> Vec<u16> {
            self.conversations
                .lock()
                .expect("conversation log lock")
                .clone()
        }
    }

    impl MkcpSegmentSender for ScriptedSender {
        async fn send_segment(
            &self,
            _remote: std::net::SocketAddr,
            segment: &MkcpSegment,
        ) -> io::Result<usize> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            self.conversations
                .lock()
                .expect("conversation log lock")
                .push(segment.conversation());
            if attempt <= self.failures_before_success {
                Err(io::Error::other("injected mKCP UDP send failure"))
            } else {
                Ok(1)
            }
        }
    }

    fn command(conversation: u16) -> MkcpSegment {
        MkcpSegment::Command {
            conversation,
            command: 3,
            option: 0,
            sending_next: 0,
            receiving_next: 0,
            peer_rto: 100,
        }
    }

    #[tokio::test]
    async fn retryable_send_queue_stops_after_xray_five_attempts() {
        let sender = ScriptedSender::new(usize::MAX);
        let remote = std::net::SocketAddr::from(([127, 0, 0, 1], 10001));
        let mut queue = RetryableSegmentQueue::default();
        queue.extend(vec![command(7)]);

        pump_send_queue(&sender, remote, &mut queue).await;
        assert_eq!(sender.attempts(), 1);
        assert!(matches!(
            queue.state,
            RetryableSendState::Retry {
                attempts_made: 1,
                ..
            }
        ));

        for expected_attempts in 2..=SEND_RETRY_ATTEMPTS {
            queue.make_due();
            pump_send_queue(&sender, remote, &mut queue).await;
            assert_eq!(sender.attempts(), usize::from(expected_attempts));
        }
        assert!(matches!(queue.state, RetryableSendState::Exhausted { .. }));
        assert!(!queue.is_idle());

        queue.make_due();
        pump_send_queue(&sender, remote, &mut queue).await;
        assert_eq!(sender.attempts(), usize::from(SEND_RETRY_ATTEMPTS));
        assert!(queue.is_idle());
        assert_eq!(SEND_RETRY_DELAY, Duration::from_millis(100));
    }

    #[tokio::test]
    async fn retryable_send_queue_keeps_segment_order_after_recovery() {
        let sender = ScriptedSender::new(2);
        let remote = std::net::SocketAddr::from(([127, 0, 0, 1], 10002));
        let mut queue = RetryableSegmentQueue::default();
        queue.extend(vec![command(11), command(12)]);

        pump_send_queue(&sender, remote, &mut queue).await;
        queue.make_due();
        pump_send_queue(&sender, remote, &mut queue).await;
        queue.make_due();
        pump_send_queue(&sender, remote, &mut queue).await;

        assert!(queue.is_idle());
        assert_eq!(sender.attempts(), 4);
        assert_eq!(sender.conversations(), vec![11, 11, 11, 12]);
    }
}
