use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use prost::Message;
use tonic::{
    Code, Request, Status,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const SOCKS_TAG: &str = "socks-grpc-e2e";
const DIRECT_TAG: &str = "direct";
const BACKUP_TAG: &str = "backup";
const TEST_USERNAME: &str = "grpc-e2e-user";
const TEST_PASSWORD: &str = "grpc-e2e-pass";

const PATH_STATS_GET_STATS: &str = "/xray.app.stats.command.StatsService/GetStats";
const PATH_STATS_GET_STATS_ONLINE: &str =
    "/xray.app.stats.command.StatsService/GetStatsOnline";
const PATH_STATS_QUERY_STATS: &str =
    "/xray.app.stats.command.StatsService/QueryStats";
const PATH_STATS_GET_SYS_STATS: &str =
    "/xray.app.stats.command.StatsService/GetSysStats";
const PATH_STATS_GET_STATS_ONLINE_IP_LIST: &str =
    "/xray.app.stats.command.StatsService/GetStatsOnlineIpList";
const PATH_STATS_GET_ALL_ONLINE_USERS: &str =
    "/xray.app.stats.command.StatsService/GetAllOnlineUsers";

const PATH_LOGGER_RESTART: &str =
    "/xray.app.log.command.LoggerService/RestartLogger";

const PATH_HANDLER_ADD_INBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/AddInbound";
const PATH_HANDLER_REMOVE_INBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/RemoveInbound";
const PATH_HANDLER_ALTER_INBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/AlterInbound";
const PATH_HANDLER_LIST_INBOUNDS: &str =
    "/xray.app.proxyman.command.HandlerService/ListInbounds";
const PATH_HANDLER_GET_INBOUND_USERS: &str =
    "/xray.app.proxyman.command.HandlerService/GetInboundUsers";
const PATH_HANDLER_GET_INBOUND_USERS_COUNT: &str =
    "/xray.app.proxyman.command.HandlerService/GetInboundUsersCount";
const PATH_HANDLER_ADD_OUTBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/AddOutbound";
const PATH_HANDLER_REMOVE_OUTBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/RemoveOutbound";
const PATH_HANDLER_ALTER_OUTBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/AlterOutbound";
const PATH_HANDLER_LIST_OUTBOUNDS: &str =
    "/xray.app.proxyman.command.HandlerService/ListOutbounds";

const PATH_ROUTING_SUBSCRIBE_ROUTING_STATS: &str =
    "/xray.app.router.command.RoutingService/SubscribeRoutingStats";
const PATH_ROUTING_TEST_ROUTE: &str =
    "/xray.app.router.command.RoutingService/TestRoute";
const PATH_ROUTING_GET_BALANCER_INFO: &str =
    "/xray.app.router.command.RoutingService/GetBalancerInfo";
const PATH_ROUTING_OVERRIDE_BALANCER_TARGET: &str =
    "/xray.app.router.command.RoutingService/OverrideBalancerTarget";
const PATH_ROUTING_ADD_RULE: &str =
    "/xray.app.router.command.RoutingService/AddRule";
const PATH_ROUTING_REMOVE_RULE: &str =
    "/xray.app.router.command.RoutingService/RemoveRule";

const PATH_OBSERVATORY_GET_OUTBOUND_STATUS: &str =
    "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus";

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

fn trace_step(step: impl AsRef<str>) {
    eprintln!("[grpc-all-interfaces-e2e] {}", step.as_ref());
}

fn global_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct ServerProcess {
    child: Child,
    workdir: PathBuf,
    log_path: PathBuf,
}

impl ServerProcess {
    fn spawn(config_content: &str) -> io::Result<Self> {
        let workdir = unique_test_dir()?;
        trace_step(format!(
            "spawn server with temporary workspace {}",
            workdir.display()
        ));
        fs::write(workdir.join("config.json5"), config_content)?;

        let log_path = workdir.join("server.log");
        let stdout_file = File::create(&log_path)?;
        let stderr_file = stdout_file.try_clone()?;

        let child = Command::new(env!("CARGO_BIN_EXE_chimera_server_app"))
            .current_dir(&workdir)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()?;
        trace_step(format!(
            "server spawned pid={} log={}",
            child.id(),
            log_path.display()
        ));

        Ok(Self {
            child,
            workdir,
            log_path,
        })
    }

    fn wait_until_ready(&mut self, listen_addr: SocketAddr) -> io::Result<()> {
        trace_step(format!("waiting for listener {}", listen_addr));
        let deadline = Instant::now() + STARTUP_TIMEOUT;

        loop {
            if let Some(status) = self.child.try_wait()? {
                let logs = self.logs();
                return Err(io::Error::other(format!(
                    "chimera exited early with status {status}; logs:\n{logs}"
                )));
            }

            if let Ok(stream) = TcpStream::connect_timeout(&listen_addr, IO_TIMEOUT)
            {
                drop(stream);
                trace_step(format!("listener {} is ready", listen_addr));
                return Ok(());
            }

            if Instant::now() >= deadline {
                let logs = self.logs();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timeout waiting for listener {listen_addr}; logs:\n{logs}"
                    ),
                ));
            }

            thread::sleep(CONNECT_RETRY_INTERVAL);
        }
    }

    fn logs(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_else(|err| {
            format!(
                "(failed to read logs from {}: {err})",
                self.log_path.display()
            )
        })
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        trace_step(format!(
            "teardown server pid={} workspace={}",
            self.child.id(),
            self.workdir.display()
        ));
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

struct Harness {
    _guard: MutexGuard<'static, ()>,
    server: ServerProcess,
    runtime: tokio::runtime::Runtime,
    channel: Channel,
}

impl Harness {
    fn start() -> io::Result<Self> {
        trace_step("harness start");
        let guard = global_test_lock().lock().map_err(|err| {
            io::Error::other(format!("failed to acquire test lock: {err}"))
        })?;
        trace_step("global test lock acquired");

        let grpc_port = free_localhost_port()?;
        let socks_port = free_localhost_port()?;
        let grpc_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, grpc_port);
        trace_step(format!(
            "allocated grpc_port={} socks_port={}",
            grpc_port, socks_port
        ));

        let config = build_config(grpc_port, socks_port);
        let mut server = ServerProcess::spawn(&config)?;
        server.wait_until_ready(SocketAddr::V4(grpc_addr))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        trace_step("tokio runtime built");

        let channel =
            match runtime.block_on(connect_channel(SocketAddr::V4(grpc_addr))) {
                Ok(channel) => channel,
                Err(err) => {
                    return Err(io::Error::other(format!(
                        "failed to connect grpc channel: {err}; logs:\n{}",
                        server.logs()
                    )));
                }
            };
        trace_step("grpc channel connected");

        Ok(Self {
            _guard: guard,
            server,
            runtime,
            channel,
        })
    }

    fn logs(&self) -> String {
        self.server.logs()
    }

    fn unary<Req, Resp>(
        &self,
        path: &'static str,
        request: Req,
    ) -> Result<Resp, Status>
    where
        Req: prost::Message + Default + Send + Sync + 'static,
        Resp: prost::Message + Default + Send + Sync + 'static,
    {
        trace_step(format!(
            "harness unary path={} req_type={} resp_type={}",
            path,
            std::any::type_name::<Req>(),
            std::any::type_name::<Resp>()
        ));
        self.runtime
            .block_on(grpc_unary(self.channel.clone(), path, request))
    }

    fn expect_ok<T>(&self, result: Result<T, Status>, context: &str) -> T {
        trace_step(format!("expect_ok context={}", context));
        result.unwrap_or_else(|err| {
            panic!("{context} failed: {err}; logs:\n{}", self.logs())
        })
    }

    fn assert_status_code<T>(
        &self,
        result: Result<T, Status>,
        expected: Code,
        context: &str,
    ) {
        trace_step(format!(
            "assert_status_code context={} expected={:?}",
            context, expected
        ));
        match result {
            Ok(_) => panic!(
                "{context} unexpectedly succeeded; expected {expected:?}; logs:\n{}",
                self.logs()
            ),
            Err(status) => {
                assert_eq!(
                    status.code(),
                    expected,
                    "{context} returned unexpected status {}; logs:\n{}",
                    status,
                    self.logs()
                );
            }
        }
    }
}

fn unique_test_dir() -> io::Result<PathBuf> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let pid = std::process::id();
    let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("chimera-grpc-all-e2e-{pid}-{millis}-{test_id}"));
    fs::create_dir_all(&path)?;
    trace_step(format!("allocated temporary test dir {}", path.display()));
    Ok(path)
}

fn free_localhost_port() -> io::Result<u16> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    trace_step(format!("allocated localhost tcp port {}", port));
    Ok(port)
}

fn build_config(grpc_port: u16, socks_port: u16) -> String {
    trace_step(format!(
        "building integration config grpc_port={} socks_port={}",
        grpc_port, socks_port
    ));
    format!(
        r#"{{
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {socks_port},
      "protocol": "socks",
      "settings": {{
        "auth": "password",
        "accounts": [
          {{
            "user": "{TEST_USERNAME}",
            "pass": "{TEST_PASSWORD}"
          }}
        ]
      }},
      "tag": "{SOCKS_TAG}"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "freedom",
      "tag": "{DIRECT_TAG}"
    }},
    {{
      "protocol": "blackhole",
      "tag": "{BACKUP_TAG}"
    }}
  ],
  "api": {{
    "listen": "127.0.0.1:{grpc_port}",
    "services": [
      "StatsService",
      "LoggerService",
      "HandlerService",
      "RoutingService",
      "ObservatoryService"
    ]
  }}
}}"#
    )
}

async fn connect_channel(grpc_addr: SocketAddr) -> io::Result<Channel> {
    trace_step(format!("connecting grpc channel to {}", grpc_addr));
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let endpoint =
        Endpoint::from_shared(format!("http://{grpc_addr}")).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid grpc endpoint for {grpc_addr}: {err}"),
            )
        })?;
    let endpoint = endpoint.connect_timeout(IO_TIMEOUT).timeout(IO_TIMEOUT);

    loop {
        match endpoint.clone().connect().await {
            Ok(channel) => {
                trace_step(format!("grpc channel connected to {}", grpc_addr));
                return Ok(channel);
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "timeout connecting to grpc endpoint {grpc_addr}; last error: {err}"
                        ),
                    ));
                }
                tokio::time::sleep(CONNECT_RETRY_INTERVAL).await;
            }
        }
    }
}

async fn grpc_unary<Req, Resp>(
    channel: Channel,
    path: &'static str,
    request: Req,
) -> Result<Resp, Status>
where
    Req: prost::Message + Default + Send + Sync + 'static,
    Resp: prost::Message + Default + Send + Sync + 'static,
{
    trace_step(format!(
        "rpc unary path={} req_type={} resp_type={}",
        path,
        std::any::type_name::<Req>(),
        std::any::type_name::<Resp>()
    ));
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| Status::unknown(format!("grpc service not ready: {err}")))?;
    let codec = tonic_prost::ProstCodec::default();
    let path = PathAndQuery::from_static(path);
    let response = grpc.unary(Request::new(request), path, codec).await?;
    trace_step("rpc unary response received");
    Ok(response.into_inner())
}

async fn grpc_server_stream<Req, Resp>(
    channel: Channel,
    path: &'static str,
    request: Req,
) -> Result<tonic::Streaming<Resp>, Status>
where
    Req: prost::Message + Default + Send + Sync + 'static,
    Resp: prost::Message + Default + Send + Sync + 'static,
{
    trace_step(format!(
        "rpc server stream path={} req_type={} resp_type={}",
        path,
        std::any::type_name::<Req>(),
        std::any::type_name::<Resp>()
    ));
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| Status::unknown(format!("grpc service not ready: {err}")))?;
    let codec = tonic_prost::ProstCodec::default();
    let path = PathAndQuery::from_static(path);
    let response = grpc
        .server_streaming(Request::new(request), path, codec)
        .await?;
    trace_step("rpc server stream established");
    Ok(response.into_inner())
}

#[derive(Clone, PartialEq, prost::Message)]
struct TypedMessage {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Stat {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int64, tag = "2")]
    value: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetStatsRequest {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(bool, tag = "2")]
    reset: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetStatsResponse {
    #[prost(message, optional, tag = "1")]
    stat: Option<Stat>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct QueryStatsRequest {
    #[prost(string, tag = "1")]
    pattern: String,
    #[prost(bool, tag = "2")]
    reset: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct QueryStatsResponse {
    #[prost(message, repeated, tag = "1")]
    stat: Vec<Stat>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SysStatsRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct SysStatsResponse {
    #[prost(uint32, tag = "10")]
    uptime: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetStatsOnlineIpListResponse {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(map = "string, int64", tag = "2")]
    ips: HashMap<String, i64>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetAllOnlineUsersRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct GetAllOnlineUsersResponse {
    #[prost(string, repeated, tag = "1")]
    users: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RestartLoggerRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct RestartLoggerResponse {}
#[derive(Clone, PartialEq, prost::Message)]
struct InboundHandlerConfig {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    receiver_settings: Option<TypedMessage>,
    #[prost(message, optional, tag = "3")]
    proxy_settings: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct OutboundHandlerConfig {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    sender_settings: Option<TypedMessage>,
    #[prost(message, optional, tag = "3")]
    proxy_settings: Option<TypedMessage>,
    #[prost(int64, tag = "4")]
    expire: i64,
    #[prost(string, tag = "5")]
    comment: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddInboundRequest {
    #[prost(message, optional, tag = "1")]
    inbound: Option<InboundHandlerConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddInboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveInboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveInboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterInboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterInboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct AddUserOperation {
    #[prost(message, optional, tag = "1")]
    user: Option<User>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveUserOperation {
    #[prost(string, tag = "1")]
    email: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SocksAccount {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ListInboundsRequest {
    #[prost(bool, tag = "1")]
    is_only_tags: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ListInboundsResponse {
    #[prost(message, repeated, tag = "1")]
    inbounds: Vec<InboundHandlerConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetInboundUserRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(string, tag = "2")]
    email: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct User {
    #[prost(uint32, tag = "1")]
    level: u32,
    #[prost(string, tag = "2")]
    email: String,
    #[prost(message, optional, tag = "3")]
    account: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetInboundUserResponse {
    #[prost(message, repeated, tag = "1")]
    users: Vec<User>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetInboundUsersCountResponse {
    #[prost(int64, tag = "1")]
    count: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddOutboundRequest {
    #[prost(message, optional, tag = "1")]
    outbound: Option<OutboundHandlerConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddOutboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveOutboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveOutboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterOutboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterOutboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct ListOutboundsRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct ListOutboundsResponse {
    #[prost(message, repeated, tag = "1")]
    outbounds: Vec<OutboundHandlerConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RoutingContext {
    #[prost(string, tag = "1")]
    inbound_tag: String,
    #[prost(string, repeated, tag = "11")]
    outbound_group_tags: Vec<String>,
    #[prost(string, tag = "12")]
    outbound_tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SubscribeRoutingStatsRequest {
    #[prost(string, repeated, tag = "1")]
    field_selectors: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TestRouteRequest {
    #[prost(message, optional, tag = "1")]
    routing_context: Option<RoutingContext>,
    #[prost(string, repeated, tag = "2")]
    field_selectors: Vec<String>,
    #[prost(bool, tag = "3")]
    publish_result: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetBalancerInfoRequest {
    #[prost(string, tag = "1")]
    tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetBalancerInfoResponse {
    #[prost(message, optional, tag = "1")]
    balancer: Option<BalancerMsg>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PrincipleTargetInfo {
    #[prost(string, repeated, tag = "1")]
    tag: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct OverrideInfo {
    #[prost(string, tag = "2")]
    target: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct BalancerMsg {
    #[prost(message, optional, tag = "5")]
    r#override: Option<OverrideInfo>,
    #[prost(message, optional, tag = "6")]
    principle_target: Option<PrincipleTargetInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct OverrideBalancerTargetRequest {
    #[prost(string, tag = "1")]
    balancer_tag: String,
    #[prost(string, tag = "2")]
    target: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct OverrideBalancerTargetResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct AddRuleRequest {
    #[prost(message, optional, tag = "1")]
    config: Option<TypedMessage>,
    #[prost(bool, tag = "2")]
    should_append: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddRuleResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveRuleRequest {
    #[prost(string, tag = "1")]
    rule_tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveRuleResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct GetOutboundStatusRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct GetOutboundStatusResponse {
    #[prost(message, optional, tag = "1")]
    status: Option<ObservationResult>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ObservationResult {
    #[prost(message, repeated, tag = "1")]
    status: Vec<OutboundStatus>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct OutboundStatus {
    #[prost(bool, tag = "1")]
    alive: bool,
    #[prost(string, tag = "4")]
    outbound_tag: String,
}

#[test]
fn stats_get_stats_returns_not_found_for_unknown_name() {
    trace_step(
        "==== test stats_get_stats_returns_not_found_for_unknown_name start ====",
    );
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<GetStatsResponse, Status> = harness.unary(
        PATH_STATS_GET_STATS,
        GetStatsRequest {
            name: "inbound>>>non-existent>>>traffic>>>uplink".to_string(),
            reset: false,
        },
    );
    harness.assert_status_code(result, Code::NotFound, "StatsService/GetStats");
}

#[test]
fn stats_get_stats_online_executes() {
    trace_step("==== test stats_get_stats_online_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let name = format!("inbound>>>{SOCKS_TAG}>>>online");
    let response: GetStatsResponse = harness.expect_ok(
        harness.unary(
            PATH_STATS_GET_STATS_ONLINE,
            GetStatsRequest {
                name: name.clone(),
                reset: false,
            },
        ),
        "StatsService/GetStatsOnline",
    );
    let stat = response.stat.expect("GetStatsOnline should return stat");
    assert_eq!(stat.name, name);
}

#[test]
fn stats_query_stats_executes() {
    trace_step("==== test stats_query_stats_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: QueryStatsResponse = harness.expect_ok(
        harness.unary(
            PATH_STATS_QUERY_STATS,
            QueryStatsRequest {
                pattern: String::new(),
                reset: false,
            },
        ),
        "StatsService/QueryStats",
    );
    let _ = response.stat;
}

#[test]
fn stats_get_sys_stats_executes() {
    trace_step("==== test stats_get_sys_stats_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: SysStatsResponse = harness.expect_ok(
        harness.unary(PATH_STATS_GET_SYS_STATS, SysStatsRequest {}),
        "StatsService/GetSysStats",
    );
    let _ = response.uptime;
}

#[test]
fn stats_get_stats_online_ip_list_executes() {
    trace_step("==== test stats_get_stats_online_ip_list_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let name = format!("inbound>>>{SOCKS_TAG}>>>online");
    let response: GetStatsOnlineIpListResponse = harness.expect_ok(
        harness.unary(
            PATH_STATS_GET_STATS_ONLINE_IP_LIST,
            GetStatsRequest {
                name: name.clone(),
                reset: false,
            },
        ),
        "StatsService/GetStatsOnlineIpList",
    );
    assert_eq!(response.name, name);
}

#[test]
fn stats_get_all_online_users_executes() {
    trace_step("==== test stats_get_all_online_users_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: GetAllOnlineUsersResponse = harness.expect_ok(
        harness.unary(PATH_STATS_GET_ALL_ONLINE_USERS, GetAllOnlineUsersRequest {}),
        "StatsService/GetAllOnlineUsers",
    );
    println!("All online users: {}", response.users.len());
    println!("All online users: {:?}", response.users.len());
}

#[test]
fn logger_restart_logger_executes() {
    trace_step("==== test logger_restart_logger_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let _: RestartLoggerResponse = harness.expect_ok(
        harness.unary(PATH_LOGGER_RESTART, RestartLoggerRequest {}),
        "LoggerService/RestartLogger",
    );
}
#[test]
fn handler_add_inbound_is_unimplemented() {
    trace_step("==== test handler_add_inbound_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<AddInboundResponse, Status> = harness.unary(
        PATH_HANDLER_ADD_INBOUND,
        AddInboundRequest { inbound: None },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "HandlerService/AddInbound",
    );
}

#[test]
fn handler_remove_inbound_is_unimplemented() {
    trace_step("==== test handler_remove_inbound_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<RemoveInboundResponse, Status> = harness.unary(
        PATH_HANDLER_REMOVE_INBOUND,
        RemoveInboundRequest {
            tag: SOCKS_TAG.to_string(),
        },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "HandlerService/RemoveInbound",
    );
}

#[test]
fn handler_alter_inbound_without_operation_is_noop() {
    trace_step(
        "==== test handler_alter_inbound_without_operation_is_noop start ====",
    );
    let harness = Harness::start().expect("failed to start test harness");
    let _: AlterInboundResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_ALTER_INBOUND,
            AlterInboundRequest {
                tag: SOCKS_TAG.to_string(),
                operation: None,
            },
        ),
        "HandlerService/AlterInbound",
    );

    let users_count: GetInboundUsersCountResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_GET_INBOUND_USERS_COUNT,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ),
        "HandlerService/GetInboundUsersCount(after AlterInbound noop)",
    );
    assert_eq!(users_count.count, 1);
}

#[test]
fn handler_alter_inbound_add_and_remove_user_executes() {
    trace_step(
        "==== test handler_alter_inbound_add_and_remove_user_executes start ====",
    );
    let harness = Harness::start().expect("failed to start test harness");
    let added_user = "grpc-e2e-added-user";

    let add_operation = AddUserOperation {
        user: Some(User {
            level: 0,
            email: added_user.to_string(),
            account: Some(TypedMessage {
                r#type: "xray.proxy.socks.Account".to_string(),
                value: SocksAccount {
                    username: added_user.to_string(),
                    password: "grpc-e2e-added-pass".to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    let _: AlterInboundResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_ALTER_INBOUND,
            AlterInboundRequest {
                tag: SOCKS_TAG.to_string(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                    value: add_operation.encode_to_vec(),
                }),
            },
        ),
        "HandlerService/AlterInbound(add user)",
    );

    let users_count_after_add: GetInboundUsersCountResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_GET_INBOUND_USERS_COUNT,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ),
        "HandlerService/GetInboundUsersCount(after add)",
    );
    assert_eq!(users_count_after_add.count, 2);

    let remove_operation = RemoveUserOperation {
        email: added_user.to_string(),
    };
    let _: AlterInboundResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_ALTER_INBOUND,
            AlterInboundRequest {
                tag: SOCKS_TAG.to_string(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.RemoveUserOperation"
                        .to_string(),
                    value: remove_operation.encode_to_vec(),
                }),
            },
        ),
        "HandlerService/AlterInbound(remove user)",
    );

    let users_count_after_remove: GetInboundUsersCountResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_GET_INBOUND_USERS_COUNT,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ),
        "HandlerService/GetInboundUsersCount(after remove)",
    );
    assert_eq!(users_count_after_remove.count, 1);
}

#[test]
fn handler_list_inbounds_executes() {
    trace_step("==== test handler_list_inbounds_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: ListInboundsResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_LIST_INBOUNDS,
            ListInboundsRequest { is_only_tags: true },
        ),
        "HandlerService/ListInbounds",
    );
    assert!(
        response
            .inbounds
            .iter()
            .any(|inbound| inbound.tag == SOCKS_TAG),
        "expected inbound tag {SOCKS_TAG}, got {:?}",
        response
            .inbounds
            .iter()
            .map(|inbound| inbound.tag.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn handler_get_inbound_users_executes() {
    trace_step("==== test handler_get_inbound_users_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: GetInboundUserResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_GET_INBOUND_USERS,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ),
        "HandlerService/GetInboundUsers",
    );
    let emails = response
        .users
        .iter()
        .map(|user| user.email.as_str())
        .collect::<HashSet<_>>();
    assert!(emails.contains(TEST_USERNAME));
}

#[test]
fn handler_get_inbound_users_count_executes() {
    trace_step("==== test handler_get_inbound_users_count_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: GetInboundUsersCountResponse = harness.expect_ok(
        harness.unary(
            PATH_HANDLER_GET_INBOUND_USERS_COUNT,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ),
        "HandlerService/GetInboundUsersCount",
    );
    assert_eq!(response.count, 1);
}

#[test]
fn handler_add_outbound_is_unimplemented() {
    trace_step("==== test handler_add_outbound_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<AddOutboundResponse, Status> = harness.unary(
        PATH_HANDLER_ADD_OUTBOUND,
        AddOutboundRequest { outbound: None },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "HandlerService/AddOutbound",
    );
}

#[test]
fn handler_remove_outbound_is_unimplemented() {
    trace_step("==== test handler_remove_outbound_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<RemoveOutboundResponse, Status> = harness.unary(
        PATH_HANDLER_REMOVE_OUTBOUND,
        RemoveOutboundRequest {
            tag: DIRECT_TAG.to_string(),
        },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "HandlerService/RemoveOutbound",
    );
}

#[test]
fn handler_alter_outbound_is_unimplemented() {
    trace_step("==== test handler_alter_outbound_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<AlterOutboundResponse, Status> = harness.unary(
        PATH_HANDLER_ALTER_OUTBOUND,
        AlterOutboundRequest {
            tag: DIRECT_TAG.to_string(),
            operation: None,
        },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "HandlerService/AlterOutbound",
    );
}

#[test]
fn handler_list_outbounds_executes() {
    trace_step("==== test handler_list_outbounds_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: ListOutboundsResponse = harness.expect_ok(
        harness.unary(PATH_HANDLER_LIST_OUTBOUNDS, ListOutboundsRequest {}),
        "HandlerService/ListOutbounds",
    );
    let tags = response
        .outbounds
        .iter()
        .map(|outbound| outbound.tag.as_str())
        .collect::<HashSet<_>>();
    assert!(tags.contains(DIRECT_TAG));
    assert!(tags.contains(BACKUP_TAG));
}

#[test]
fn routing_subscribe_routing_stats_executes() {
    trace_step("==== test routing_subscribe_routing_stats_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result = harness.runtime.block_on(async {
        let mut stream = grpc_server_stream::<
            SubscribeRoutingStatsRequest,
            RoutingContext,
        >(
            harness.channel.clone(),
            PATH_ROUTING_SUBSCRIBE_ROUTING_STATS,
            SubscribeRoutingStatsRequest {
                field_selectors: vec!["inbound".to_string(), "outbound".to_string()],
            },
        )
        .await?;

        let _ = grpc_unary::<TestRouteRequest, RoutingContext>(
            harness.channel.clone(),
            PATH_ROUTING_TEST_ROUTE,
            TestRouteRequest {
                routing_context: Some(RoutingContext {
                    inbound_tag: SOCKS_TAG.to_string(),
                    outbound_group_tags: Vec::new(),
                    outbound_tag: String::new(),
                }),
                field_selectors: Vec::new(),
                publish_result: true,
            },
        )
        .await?;

        let next = tokio::time::timeout(IO_TIMEOUT, stream.message())
            .await
            .map_err(|_| Status::deadline_exceeded("timed out waiting for routing stream event"))?? // Result<Option<_>, Status>
            .ok_or_else(|| Status::unavailable("routing stream closed"))?;

        Ok::<RoutingContext, Status>(next)
    });
    let event = harness.expect_ok(result, "RoutingService/SubscribeRoutingStats");
    assert_eq!(event.inbound_tag, SOCKS_TAG);
    assert_eq!(event.outbound_tag, DIRECT_TAG);
}

#[test]
fn routing_test_route_executes() {
    trace_step("==== test routing_test_route_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: RoutingContext = harness.expect_ok(
        harness.unary(
            PATH_ROUTING_TEST_ROUTE,
            TestRouteRequest {
                routing_context: Some(RoutingContext {
                    inbound_tag: SOCKS_TAG.to_string(),
                    outbound_group_tags: Vec::new(),
                    outbound_tag: String::new(),
                }),
                field_selectors: Vec::new(),
                publish_result: false,
            },
        ),
        "RoutingService/TestRoute",
    );
    assert_eq!(response.outbound_tag, DIRECT_TAG);
}

#[test]
fn routing_get_balancer_info_executes() {
    trace_step("==== test routing_get_balancer_info_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: GetBalancerInfoResponse = harness.expect_ok(
        harness.unary(
            PATH_ROUTING_GET_BALANCER_INFO,
            GetBalancerInfoRequest {
                tag: "balancer-a".to_string(),
            },
        ),
        "RoutingService/GetBalancerInfo",
    );
    let balancer = response.balancer.expect("balancer info should be present");
    assert!(balancer.r#override.is_none());
    let principle = balancer
        .principle_target
        .expect("principle targets should be present")
        .tag
        .into_iter()
        .collect::<HashSet<_>>();
    assert!(principle.contains(DIRECT_TAG));
    assert!(principle.contains(BACKUP_TAG));
}

#[test]
fn routing_override_balancer_target_executes() {
    trace_step("==== test routing_override_balancer_target_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let _: OverrideBalancerTargetResponse = harness.expect_ok(
        harness.unary(
            PATH_ROUTING_OVERRIDE_BALANCER_TARGET,
            OverrideBalancerTargetRequest {
                balancer_tag: "balancer-a".to_string(),
                target: BACKUP_TAG.to_string(),
            },
        ),
        "RoutingService/OverrideBalancerTarget(set)",
    );

    let set_info: GetBalancerInfoResponse = harness.expect_ok(
        harness.unary(
            PATH_ROUTING_GET_BALANCER_INFO,
            GetBalancerInfoRequest {
                tag: "balancer-a".to_string(),
            },
        ),
        "RoutingService/GetBalancerInfo(after set)",
    );
    assert_eq!(
        set_info
            .balancer
            .and_then(|balancer| balancer.r#override)
            .map(|override_info| override_info.target),
        Some(BACKUP_TAG.to_string())
    );

    let _: OverrideBalancerTargetResponse = harness.expect_ok(
        harness.unary(
            PATH_ROUTING_OVERRIDE_BALANCER_TARGET,
            OverrideBalancerTargetRequest {
                balancer_tag: "balancer-a".to_string(),
                target: String::new(),
            },
        ),
        "RoutingService/OverrideBalancerTarget(clear)",
    );

    let cleared_info: GetBalancerInfoResponse = harness.expect_ok(
        harness.unary(
            PATH_ROUTING_GET_BALANCER_INFO,
            GetBalancerInfoRequest {
                tag: "balancer-a".to_string(),
            },
        ),
        "RoutingService/GetBalancerInfo(after clear)",
    );
    assert!(
        cleared_info
            .balancer
            .and_then(|balancer| balancer.r#override)
            .is_none()
    );
}

#[test]
fn routing_add_rule_is_unimplemented() {
    trace_step("==== test routing_add_rule_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<AddRuleResponse, Status> = harness.unary(
        PATH_ROUTING_ADD_RULE,
        AddRuleRequest {
            config: None,
            should_append: false,
        },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "RoutingService/AddRule",
    );
}

#[test]
fn routing_remove_rule_is_unimplemented() {
    trace_step("==== test routing_remove_rule_is_unimplemented start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let result: Result<RemoveRuleResponse, Status> = harness.unary(
        PATH_ROUTING_REMOVE_RULE,
        RemoveRuleRequest {
            rule_tag: "rule-a".to_string(),
        },
    );
    harness.assert_status_code(
        result,
        Code::Unimplemented,
        "RoutingService/RemoveRule",
    );
}

#[test]
fn observatory_get_outbound_status_executes() {
    trace_step("==== test observatory_get_outbound_status_executes start ====");
    let harness = Harness::start().expect("failed to start test harness");
    let response: GetOutboundStatusResponse = harness.expect_ok(
        harness.unary(
            PATH_OBSERVATORY_GET_OUTBOUND_STATUS,
            GetOutboundStatusRequest {},
        ),
        "ObservatoryService/GetOutboundStatus",
    );
    let status = response
        .status
        .expect("observatory response should include status")
        .status;
    let tags = status
        .iter()
        .map(|entry| entry.outbound_tag.as_str())
        .collect::<HashSet<_>>();
    assert!(tags.contains(DIRECT_TAG));
    assert!(tags.contains(BACKUP_TAG));
}
