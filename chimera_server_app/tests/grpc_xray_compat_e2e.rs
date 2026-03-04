use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tonic::{
    Code, Request, Status,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const XRAY_BIN_ENV: &str = "XRAY_BIN";
const XRAY_STRICT_ENV: &str = "XRAY_COMPAT_STRICT";

const SOCKS_TAG: &str = "socks-grpc-e2e";
const DIRECT_TAG: &str = "direct";
const BACKUP_TAG: &str = "backup";
const BALANCER_TAG: &str = "balancer-a";
const API_INBOUND_TAG: &str = "api-in";
const API_OUTBOUND_TAG: &str = "api";
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

const CODES_OK_ONLY: &[Code] = &[Code::Ok];
const CODES_OK_OR_UNKNOWN: &[Code] = &[Code::Ok, Code::Unknown];
const CODES_NOT_FOUND_ONLY: &[Code] = &[Code::NotFound];
const CODES_OK_OR_UNIMPLEMENTED: &[Code] = &[Code::Ok, Code::Unimplemented];
const CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN: &[Code] =
    &[Code::Ok, Code::Unimplemented, Code::Unknown];
const CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN_OR_UNAVAILABLE: &[Code] = &[
    Code::Ok,
    Code::Unimplemented,
    Code::Unknown,
    Code::Unavailable,
];
const CODES_OK_OR_NOT_FOUND: &[Code] = &[Code::Ok, Code::NotFound];
const CODES_OK_OR_NOT_FOUND_OR_UNIMPLEMENTED: &[Code] =
    &[Code::Ok, Code::NotFound, Code::Unimplemented];
const CODES_OK_OR_NOT_FOUND_OR_UNIMPLEMENTED_OR_UNKNOWN: &[Code] =
    &[Code::Ok, Code::NotFound, Code::Unimplemented, Code::Unknown];
const CODES_OK_OR_UNIMPLEMENTED_OR_FAILED_PRECONDITION: &[Code] =
    &[Code::Ok, Code::Unimplemented, Code::FailedPrecondition];

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

fn trace_step(step: impl AsRef<str>) {
    eprintln!("[grpc-xray-compat-e2e] {}", step.as_ref());
}

#[derive(Clone, Copy, Debug)]
enum TargetKind {
    Chimera,
    Xray,
}

impl TargetKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chimera => "chimera",
            Self::Xray => "xray",
        }
    }
}

fn global_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct ServerProcess {
    target: TargetKind,
    child: Child,
    workdir: PathBuf,
    log_path: PathBuf,
}

impl ServerProcess {
    fn spawn(target: TargetKind, config_content: &str) -> io::Result<Self> {
        let workdir = unique_test_dir(target.as_str())?;
        trace_step(format!(
            "spawn {} server with workspace {}",
            target.as_str(),
            workdir.display()
        ));
        let (config_name, mut command) = build_target_command(target, &workdir)?;
        fs::write(workdir.join(config_name), config_content)?;

        let log_path = workdir.join(format!("{}-server.log", target.as_str()));
        let stdout_file = File::create(&log_path)?;
        let stderr_file = stdout_file.try_clone()?;

        command
            .current_dir(&workdir)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        let child = command.spawn()?;
        trace_step(format!(
            "{} server spawned pid={} log={}",
            target.as_str(),
            child.id(),
            log_path.display()
        ));

        Ok(Self {
            target,
            child,
            workdir,
            log_path,
        })
    }

    fn wait_until_ready(&mut self, listen_addr: SocketAddr) -> io::Result<()> {
        trace_step(format!(
            "waiting for {} listener {}",
            self.target.as_str(),
            listen_addr
        ));
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "{} exited early with status {status}; logs:\n{}",
                    self.target.as_str(),
                    self.logs()
                )));
            }
            if let Ok(stream) = TcpStream::connect_timeout(&listen_addr, IO_TIMEOUT)
            {
                drop(stream);
                trace_step(format!(
                    "{} listener {} is ready",
                    self.target.as_str(),
                    listen_addr
                ));
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timeout waiting for {} listener {listen_addr}; logs:\n{}",
                        self.target.as_str(),
                        self.logs()
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
            "teardown {} server pid={} workspace={}",
            self.target.as_str(),
            self.child.id(),
            self.workdir.display()
        ));
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

struct Harness {
    server: ServerProcess,
    runtime: tokio::runtime::Runtime,
    channel: Channel,
}

impl Harness {
    fn start_unlocked(target: TargetKind) -> io::Result<Self> {
        trace_step(format!("harness start for {}", target.as_str()));
        let grpc_port = free_localhost_port()?;
        let mut socks_port = free_localhost_port()?;
        while socks_port == grpc_port {
            socks_port = free_localhost_port()?;
        }
        trace_step(format!(
            "{} allocated grpc_port={} socks_port={}",
            target.as_str(),
            grpc_port,
            socks_port
        ));
        let grpc_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, grpc_port);
        let config = match target {
            TargetKind::Chimera => build_chimera_config(grpc_port, socks_port),
            TargetKind::Xray => build_xray_config(grpc_port, socks_port),
        };
        let mut server = ServerProcess::spawn(target, &config)?;
        server.wait_until_ready(SocketAddr::V4(grpc_addr))?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        trace_step(format!("{} tokio runtime built", target.as_str()));
        let channel = runtime
            .block_on(connect_channel(SocketAddr::V4(grpc_addr)))
            .map_err(|err| {
                io::Error::other(format!(
                    "failed to connect grpc channel to {}: {err}; logs:\n{}",
                    target.as_str(),
                    server.logs()
                ))
            })?;
        trace_step(format!("{} grpc channel connected", target.as_str()));
        Ok(Self {
            server,
            runtime,
            channel,
        })
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
            "{} unary path={} req_type={} resp_type={}",
            self.server.target.as_str(),
            path,
            std::any::type_name::<Req>(),
            std::any::type_name::<Resp>()
        ));
        self.runtime
            .block_on(grpc_unary(self.channel.clone(), path, request))
    }

    fn logs(&self) -> String {
        self.server.logs()
    }
}

fn build_target_command(
    target: TargetKind,
    workdir: &Path,
) -> io::Result<(&'static str, Command)> {
    match target {
        TargetKind::Chimera => Ok((
            "config.json5",
            Command::new(env!("CARGO_BIN_EXE_chimera_server_app")),
        )),
        TargetKind::Xray => {
            let xray_bin = env::var_os(XRAY_BIN_ENV).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("missing {XRAY_BIN_ENV} environment variable"),
                )
            })?;
            let mut command = Command::new(PathBuf::from(xray_bin));
            command
                .arg("run")
                .arg("-c")
                .arg(workdir.join("config.json"));
            trace_step(format!(
                "xray command configured with config {}",
                workdir.join("config.json").display()
            ));
            Ok(("config.json", command))
        }
    }
}

fn unique_test_dir(prefix: &str) -> io::Result<PathBuf> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let pid = std::process::id();
    let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("{prefix}-grpc-compat-{pid}-{millis}-{test_id}"));
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

fn build_chimera_config(grpc_port: u16, socks_port: u16) -> String {
    trace_step(format!(
        "building chimera config grpc_port={} socks_port={}",
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

fn build_xray_config(grpc_port: u16, socks_port: u16) -> String {
    trace_step(format!(
        "building xray config grpc_port={} socks_port={}",
        grpc_port, socks_port
    ));
    format!(
        r#"{{
  "log": {{
    "loglevel": "warning"
  }},
  "api": {{
    "tag": "{API_OUTBOUND_TAG}",
    "services": [
      "StatsService",
      "LoggerService",
      "HandlerService",
      "RoutingService"
    ]
  }},
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
    }},
    {{
      "listen": "127.0.0.1",
      "port": {grpc_port},
      "protocol": "dokodemo-door",
      "settings": {{
        "address": "127.0.0.1"
      }},
      "tag": "{API_INBOUND_TAG}"
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
    }},
    {{
      "protocol": "freedom",
      "tag": "{API_OUTBOUND_TAG}"
    }}
  ],
  "routing": {{
    "domainStrategy": "AsIs",
    "balancers": [
      {{
        "tag": "{BALANCER_TAG}",
        "selector": ["{DIRECT_TAG}", "{BACKUP_TAG}"]
      }}
    ],
    "rules": [
      {{
        "type": "field",
        "inboundTag": ["{API_INBOUND_TAG}"],
        "outboundTag": "{API_OUTBOUND_TAG}"
      }}
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
    let codec = tonic::codec::ProstCodec::default();
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
    let codec = tonic::codec::ProstCodec::default();
    let path = PathAndQuery::from_static(path);
    let response = grpc
        .server_streaming(Request::new(request), path, codec)
        .await?;
    trace_step("rpc server stream established");
    Ok(response.into_inner())
}

#[derive(Debug)]
struct RpcOutcome {
    code: Code,
    detail: String,
}

fn outcome_from_result<T>(
    result: Result<T, Status>,
    on_ok: impl FnOnce(&T) -> String,
) -> RpcOutcome {
    match result {
        Ok(response) => RpcOutcome {
            code: Code::Ok,
            detail: on_ok(&response),
        },
        Err(status) => RpcOutcome {
            code: status.code(),
            detail: status.message().to_string(),
        },
    }
}

fn outcome_from_status(status: Status) -> RpcOutcome {
    RpcOutcome {
        code: status.code(),
        detail: status.message().to_string(),
    }
}

type RpcRunner = fn(&Harness) -> RpcOutcome;

struct RpcCase {
    name: &'static str,
    runner: RpcRunner,
    chimera_expected: Code,
    xray_allowed: &'static [Code],
}

fn strict_mode_enabled() -> bool {
    trace_step("evaluating strict mode from XRAY_COMPAT_STRICT");
    match env::var_os(XRAY_STRICT_ENV) {
        Some(value) => {
            let lowered = os_string_to_lower(value);
            matches!(lowered.as_str(), "1" | "true" | "yes" | "on")
        }
        None => false,
    }
}

fn os_string_to_lower(value: OsString) -> String {
    value.to_string_lossy().to_ascii_lowercase()
}

fn format_codes(codes: &[Code]) -> String {
    codes
        .iter()
        .map(|code| format!("{code:?}"))
        .collect::<Vec<_>>()
        .join("|")
}

fn rpc_cases() -> Vec<RpcCase> {
    trace_step("constructing rpc compatibility matrix");
    vec![
        RpcCase {
            name: "StatsService/GetStats",
            runner: run_stats_get_stats,
            chimera_expected: Code::NotFound,
            xray_allowed: CODES_NOT_FOUND_ONLY,
        },
        RpcCase {
            name: "StatsService/GetStatsOnline",
            runner: run_stats_get_stats_online,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_NOT_FOUND,
        },
        RpcCase {
            name: "StatsService/QueryStats",
            runner: run_stats_query_stats,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_UNKNOWN,
        },
        RpcCase {
            name: "StatsService/GetSysStats",
            runner: run_stats_get_sys_stats,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_ONLY,
        },
        RpcCase {
            name: "StatsService/GetStatsOnlineIpList",
            runner: run_stats_get_stats_online_ip_list,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_NOT_FOUND,
        },
        RpcCase {
            name: "StatsService/GetAllOnlineUsers",
            runner: run_stats_get_all_online_users,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_ONLY,
        },
        RpcCase {
            name: "LoggerService/RestartLogger",
            runner: run_logger_restart_logger,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_FAILED_PRECONDITION,
        },
        RpcCase {
            name: "HandlerService/AddInbound",
            runner: run_handler_add_inbound,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN_OR_UNAVAILABLE,
        },
        RpcCase {
            name: "HandlerService/RemoveInbound",
            runner: run_handler_remove_inbound,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED,
        },
        RpcCase {
            name: "HandlerService/AlterInbound",
            runner: run_handler_alter_inbound,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "HandlerService/ListInbounds",
            runner: run_handler_list_inbounds,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_ONLY,
        },
        RpcCase {
            name: "HandlerService/GetInboundUsers",
            runner: run_handler_get_inbound_users,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_NOT_FOUND_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "HandlerService/GetInboundUsersCount",
            runner: run_handler_get_inbound_users_count,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_NOT_FOUND_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "HandlerService/AddOutbound",
            runner: run_handler_add_outbound,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "HandlerService/RemoveOutbound",
            runner: run_handler_remove_outbound,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED,
        },
        RpcCase {
            name: "HandlerService/AlterOutbound",
            runner: run_handler_alter_outbound,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "HandlerService/ListOutbounds",
            runner: run_handler_list_outbounds,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_ONLY,
        },
        RpcCase {
            name: "RoutingService/SubscribeRoutingStats",
            runner: run_routing_subscribe_routing_stats,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "RoutingService/TestRoute",
            runner: run_routing_test_route,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "RoutingService/GetBalancerInfo",
            runner: run_routing_get_balancer_info,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_NOT_FOUND_OR_UNIMPLEMENTED,
        },
        RpcCase {
            name: "RoutingService/OverrideBalancerTarget",
            runner: run_routing_override_balancer_target,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_NOT_FOUND_OR_UNIMPLEMENTED,
        },
        RpcCase {
            name: "RoutingService/AddRule",
            runner: run_routing_add_rule,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED_OR_UNKNOWN,
        },
        RpcCase {
            name: "RoutingService/RemoveRule",
            runner: run_routing_remove_rule,
            chimera_expected: Code::Unimplemented,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED,
        },
        RpcCase {
            name: "ObservatoryService/GetOutboundStatus",
            runner: run_observatory_get_outbound_status,
            chimera_expected: Code::Ok,
            xray_allowed: CODES_OK_OR_UNIMPLEMENTED,
        },
    ]
}

#[test]
#[ignore = "requires XRAY_BIN=<path-to-xray>; optional XRAY_COMPAT_STRICT=1"]
fn grpc_all_interfaces_compat_with_xray_core() {
    trace_step("==== test grpc_all_interfaces_compat_with_xray_core start ====");
    if env::var_os(XRAY_BIN_ENV).is_none() {
        panic!("missing required env var {XRAY_BIN_ENV}");
    }

    let _guard = global_test_lock()
        .lock()
        .expect("failed to acquire global test lock");
    trace_step("global test lock acquired");
    let strict_mode = strict_mode_enabled();
    trace_step(format!("strict_mode={}", strict_mode));

    let mut failures = Vec::new();
    for case in rpc_cases() {
        trace_step(format!("running compatibility case {}", case.name));
        let chimera = match Harness::start_unlocked(TargetKind::Chimera) {
            Ok(harness) => harness,
            Err(err) => {
                failures.push(format!(
                    "[{}] failed to start chimera harness: {err}",
                    case.name
                ));
                continue;
            }
        };

        let xray = match Harness::start_unlocked(TargetKind::Xray) {
            Ok(harness) => harness,
            Err(err) => {
                failures.push(format!(
                    "[{}] failed to start xray harness: {err}",
                    case.name
                ));
                continue;
            }
        };

        let chimera_outcome = (case.runner)(&chimera);
        let xray_outcome = (case.runner)(&xray);
        trace_step(format!(
            "case={} chimera={:?} xray={:?} chimera_detail={} xray_detail={}",
            case.name,
            chimera_outcome.code,
            xray_outcome.code,
            chimera_outcome.detail,
            xray_outcome.detail
        ));

        if chimera_outcome.code != case.chimera_expected {
            failures.push(format!(
                "[{}] chimera expected {:?}, got {:?} (detail: {})",
                case.name,
                case.chimera_expected,
                chimera_outcome.code,
                chimera_outcome.detail
            ));
        }
        if !case.xray_allowed.contains(&xray_outcome.code) {
            failures.push(format!(
                "[{}] xray expected one of [{}], got {:?} (detail: {})",
                case.name,
                format_codes(case.xray_allowed),
                xray_outcome.code,
                xray_outcome.detail
            ));
        }
        if strict_mode && chimera_outcome.code != xray_outcome.code {
            failures.push(format!(
                "[{}] strict mode mismatch: chimera={:?}, xray={:?}",
                case.name, chimera_outcome.code, xray_outcome.code
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "grpc compatibility matrix failed (strict_mode={strict_mode})\n{}",
            failures.join("\n")
        );
    }
    trace_step("==== test grpc_all_interfaces_compat_with_xray_core done ====");
}

fn run_stats_get_stats(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_STATS_GET_STATS,
        GetStatsRequest {
            name: "inbound>>>non-existent>>>traffic>>>uplink".to_string(),
            reset: false,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_stats_get_stats_online(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_STATS_GET_STATS_ONLINE,
        GetStatsRequest {
            name: format!("inbound>>>{SOCKS_TAG}>>>online"),
            reset: false,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_stats_query_stats(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_STATS_QUERY_STATS,
        QueryStatsRequest {
            pattern: String::new(),
            reset: false,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_stats_get_sys_stats(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> =
        harness.unary(PATH_STATS_GET_SYS_STATS, Empty {});
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_stats_get_stats_online_ip_list(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_STATS_GET_STATS_ONLINE_IP_LIST,
        GetStatsRequest {
            name: format!("inbound>>>{SOCKS_TAG}>>>online"),
            reset: false,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_stats_get_all_online_users(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> =
        harness.unary(PATH_STATS_GET_ALL_ONLINE_USERS, Empty {});
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_logger_restart_logger(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(PATH_LOGGER_RESTART, Empty {});
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_add_inbound(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_ADD_INBOUND,
        AddInboundRequest { inbound: None },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_remove_inbound(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_REMOVE_INBOUND,
        RemoveInboundRequest {
            tag: SOCKS_TAG.to_string(),
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_alter_inbound(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_ALTER_INBOUND,
        AlterInboundRequest {
            tag: SOCKS_TAG.to_string(),
            operation: None,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_list_inbounds(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_LIST_INBOUNDS,
        ListInboundsRequest { is_only_tags: true },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_get_inbound_users(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_GET_INBOUND_USERS,
        GetInboundUserRequest {
            tag: SOCKS_TAG.to_string(),
            email: String::new(),
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_get_inbound_users_count(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_GET_INBOUND_USERS_COUNT,
        GetInboundUserRequest {
            tag: SOCKS_TAG.to_string(),
            email: String::new(),
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_add_outbound(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_ADD_OUTBOUND,
        AddOutboundRequest { outbound: None },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_remove_outbound(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_REMOVE_OUTBOUND,
        RemoveOutboundRequest {
            tag: DIRECT_TAG.to_string(),
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_alter_outbound(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_HANDLER_ALTER_OUTBOUND,
        AlterOutboundRequest {
            tag: DIRECT_TAG.to_string(),
            operation: None,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_handler_list_outbounds(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> =
        harness.unary(PATH_HANDLER_LIST_OUTBOUNDS, Empty {});
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_routing_subscribe_routing_stats(harness: &Harness) -> RpcOutcome {
    let result = harness.runtime.block_on(async {
        let mut stream = grpc_server_stream::<SubscribeRoutingStatsRequest, Empty>(
            harness.channel.clone(),
            PATH_ROUTING_SUBSCRIBE_ROUTING_STATS,
            SubscribeRoutingStatsRequest {
                field_selectors: vec!["inbound".to_string(), "outbound".to_string()],
            },
        )
        .await?;

        let _: Empty = grpc_unary(
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

        let _event = tokio::time::timeout(IO_TIMEOUT, stream.message())
            .await
            .map_err(|_| {
                Status::deadline_exceeded(
                    "timed out waiting for routing stream event",
                )
            })??
            .ok_or_else(|| Status::unavailable("routing stream closed"))?;

        Ok::<(), Status>(())
    });

    outcome_from_result(result, |_| "stream-event".to_string())
}

fn run_routing_test_route(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
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
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_routing_get_balancer_info(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_ROUTING_GET_BALANCER_INFO,
        GetBalancerInfoRequest {
            tag: BALANCER_TAG.to_string(),
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_routing_override_balancer_target(harness: &Harness) -> RpcOutcome {
    let set_result: Result<Empty, Status> = harness.unary(
        PATH_ROUTING_OVERRIDE_BALANCER_TARGET,
        OverrideBalancerTargetRequest {
            balancer_tag: BALANCER_TAG.to_string(),
            target: BACKUP_TAG.to_string(),
        },
    );
    if let Err(status) = set_result {
        return outcome_from_status(status);
    }
    let clear_result: Result<Empty, Status> = harness.unary(
        PATH_ROUTING_OVERRIDE_BALANCER_TARGET,
        OverrideBalancerTargetRequest {
            balancer_tag: BALANCER_TAG.to_string(),
            target: String::new(),
        },
    );
    if let Err(status) = clear_result {
        return outcome_from_status(status);
    }
    RpcOutcome {
        code: Code::Ok,
        detail: "set-and-clear".to_string(),
    }
}

fn run_routing_add_rule(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_ROUTING_ADD_RULE,
        AddRuleRequest {
            config: None,
            should_append: false,
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_routing_remove_rule(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> = harness.unary(
        PATH_ROUTING_REMOVE_RULE,
        RemoveRuleRequest {
            rule_tag: "rule-a".to_string(),
        },
    );
    outcome_from_result(result, |_| "ok".to_string())
}

fn run_observatory_get_outbound_status(harness: &Harness) -> RpcOutcome {
    let result: Result<Empty, Status> =
        harness.unary(PATH_OBSERVATORY_GET_OUTBOUND_STATUS, Empty {});
    outcome_from_result(result, |_| "ok".to_string())
}

#[derive(Clone, PartialEq, prost::Message)]
struct Empty {}

#[derive(Clone, PartialEq, prost::Message)]
struct TypedMessage {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetStatsRequest {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(bool, tag = "2")]
    reset: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct QueryStatsRequest {
    #[prost(string, tag = "1")]
    pattern: String,
    #[prost(bool, tag = "2")]
    reset: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddInboundRequest {
    #[prost(message, optional, tag = "1")]
    inbound: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveInboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterInboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ListInboundsRequest {
    #[prost(bool, tag = "1")]
    is_only_tags: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetInboundUserRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(string, tag = "2")]
    email: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddOutboundRequest {
    #[prost(message, optional, tag = "1")]
    outbound: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveOutboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterOutboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    operation: Option<TypedMessage>,
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
struct OverrideBalancerTargetRequest {
    #[prost(string, tag = "1")]
    balancer_tag: String,
    #[prost(string, tag = "2")]
    target: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AddRuleRequest {
    #[prost(message, optional, tag = "1")]
    config: Option<TypedMessage>,
    #[prost(bool, tag = "2")]
    should_append: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RemoveRuleRequest {
    #[prost(string, tag = "1")]
    rule_tag: String,
}
