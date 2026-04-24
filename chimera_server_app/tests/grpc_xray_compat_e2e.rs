use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
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

use prost::Message;
use serde::Serialize;
use tonic::{
    Code, Request, Status,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const XRAY_BIN_ENV: &str = "XRAY_BIN";
const DEFAULT_XRAY_BIN: &str = "xray";

const SOCKS_TAG: &str = "socks-grpc-e2e";
const DIRECT_TAG: &str = "direct";
const BACKUP_TAG: &str = "backup";
const BALANCER_TAG: &str = "balancer-a";
const API_INBOUND_TAG: &str = "api-in";
const API_OUTBOUND_TAG: &str = "api";
const TEST_USERNAME: &str = "grpc-e2e-user";
const TEST_PASSWORD: &str = "grpc-e2e-pass";
const ADDED_USER: &str = "grpc-e2e-added-user";
const ADDED_PASSWORD: &str = "grpc-e2e-added-pass";
const ADDED_INBOUND_TAG: &str = "grpc-e2e-added-inbound";
const ADDED_OUTBOUND_TAG: &str = "grpc-e2e-added-outbound";

const PATH_STATS_GET_STATS: &str = "/xray.app.stats.command.StatsService/GetStats";
const PATH_STATS_GET_STATS_ONLINE: &str =
    "/xray.app.stats.command.StatsService/GetStatsOnline";
const PATH_STATS_GET_STATS_ONLINE_IP_LIST: &str =
    "/xray.app.stats.command.StatsService/GetStatsOnlineIpList";
const PATH_STATS_GET_ALL_ONLINE_USERS: &str =
    "/xray.app.stats.command.StatsService/GetAllOnlineUsers";
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
    eprintln!("[grpc-xray-compat-e2e] {}", step.as_ref());
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseStatus {
    Passed,
    Failed,
    Skipped,
    Informational,
}

#[derive(Clone, Copy, Debug)]
enum CaseMode {
    Strict,
    Informational,
    BaselineProbe,
}

#[derive(Clone, Debug, Serialize)]
struct CompatSnapshot {
    outcome: String,
    grpc_code: String,
    raw: String,
    normalized: String,
}

#[derive(Debug, Serialize)]
struct CompatStepResult {
    phase: String,
    request: String,
    snapshot: CompatSnapshot,
}

#[derive(Debug, Serialize)]
struct CompatTargetResult {
    target: TargetKind,
    log_path: String,
    workdir: String,
    steps: Vec<CompatStepResult>,
}

#[derive(Debug, Serialize)]
struct CompatCase {
    name: String,
    category: String,
    mode: String,
}

#[derive(Debug, Serialize)]
struct CompatCaseResult {
    case: CompatCase,
    status: CaseStatus,
    summary: String,
    xray: CompatTargetResult,
    chimera: CompatTargetResult,
}

#[derive(Debug, Serialize)]
struct CompatReport {
    generated_at_unix_ms: u128,
    xray_version: String,
    xray_bin: String,
    config_summary: Vec<String>,
    passed: usize,
    failed: usize,
    skipped: usize,
    informational: usize,
    cases: Vec<CompatCaseResult>,
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

        Ok(Self {
            target,
            child,
            workdir,
            log_path,
        })
    }

    fn wait_until_ready(&mut self, listen_addr: SocketAddr) -> io::Result<()> {
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
        let grpc_port = free_localhost_port()?;
        let mut socks_port = free_localhost_port()?;
        while socks_port == grpc_port {
            socks_port = free_localhost_port()?;
        }

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
        let channel = runtime
            .block_on(connect_channel(SocketAddr::V4(grpc_addr)))
            .map_err(|err| {
                io::Error::other(format!(
                    "failed to connect grpc channel to {}: {err}; logs:\n{}",
                    target.as_str(),
                    server.logs()
                ))
            })?;

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
        self.runtime
            .block_on(grpc_unary(self.channel.clone(), path, request))
    }

    fn target_result(&self, steps: Vec<CompatStepResult>) -> CompatTargetResult {
        CompatTargetResult {
            target: self.server.target,
            log_path: self.server.log_path.display().to_string(),
            workdir: self.server.workdir.display().to_string(),
            steps,
        }
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
            let xray_bin = resolve_xray_bin();
            let mut command = Command::new(&xray_bin);
            command
                .arg("run")
                .arg("-c")
                .arg(workdir.join("config.json"));
            Ok(("config.json", command))
        }
    }
}

fn resolve_xray_bin() -> PathBuf {
    let candidate = env::var_os(XRAY_BIN_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join(DEFAULT_XRAY_BIN));
    if candidate.is_absolute() {
        candidate
    } else {
        workspace_root().join(candidate)
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
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
    Ok(path)
}

fn free_localhost_port() -> io::Result<u16> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn build_chimera_config(grpc_port: u16, socks_port: u16) -> String {
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
            Ok(channel) => return Ok(channel),
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
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| Status::unknown(format!("grpc service not ready: {err}")))?;
    let codec = tonic_prost::ProstCodec::default();
    let path = PathAndQuery::from_static(path);
    let response = grpc.unary(Request::new(request), path, codec).await?;
    Ok(response.into_inner())
}

type CaseRunner = fn(&Harness, &Harness) -> CompatCaseResult;

struct CaseDef {
    name: &'static str,
    category: &'static str,
    mode: CaseMode,
    runner: CaseRunner,
}

fn case_def(
    name: &'static str,
    category: &'static str,
    mode: CaseMode,
    runner: CaseRunner,
) -> CaseDef {
    CaseDef {
        name,
        category,
        mode,
        runner,
    }
}

fn compat_cases() -> Vec<CaseDef> {
    vec![
        case_def(
            "HandlerService/ListInbounds",
            "query",
            CaseMode::Strict,
            case_list_inbounds,
        ),
        case_def(
            "HandlerService/GetInboundUsers",
            "query",
            CaseMode::Strict,
            case_get_inbound_users,
        ),
        case_def(
            "HandlerService/GetInboundUsersCount",
            "query",
            CaseMode::Strict,
            case_get_inbound_users_count,
        ),
        case_def(
            "HandlerService/ListOutbounds",
            "query",
            CaseMode::Strict,
            case_list_outbounds,
        ),
        case_def(
            "RoutingService/TestRoute",
            "query",
            CaseMode::Strict,
            case_test_route,
        ),
        case_def(
            "RoutingService/GetBalancerInfo",
            "query",
            CaseMode::Strict,
            case_get_balancer_info,
        ),
        case_def(
            "StatsService/GetStats",
            "query",
            CaseMode::Strict,
            case_get_stats,
        ),
        case_def(
            "StatsService/GetStatsOnline",
            "query",
            CaseMode::Strict,
            case_get_stats_online,
        ),
        case_def(
            "StatsService/GetStatsOnlineIpList",
            "query",
            CaseMode::Strict,
            case_get_stats_online_ip_list,
        ),
        case_def(
            "StatsService/GetAllOnlineUsers",
            "query",
            CaseMode::Strict,
            case_get_all_online_users,
        ),
        case_def(
            "HandlerService/AlterInbound AddUser",
            "mutation",
            CaseMode::Strict,
            case_alter_inbound_add_user,
        ),
        case_def(
            "HandlerService/AlterInbound RemoveUser",
            "mutation",
            CaseMode::Strict,
            case_alter_inbound_remove_user,
        ),
        case_def(
            "RoutingService/OverrideBalancerTarget set backup",
            "mutation",
            CaseMode::Strict,
            case_override_balancer_set,
        ),
        case_def(
            "RoutingService/OverrideBalancerTarget clear",
            "mutation",
            CaseMode::Strict,
            case_override_balancer_clear,
        ),
        case_def(
            "HandlerService/AddInbound",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_add_inbound_probe,
        ),
        case_def(
            "HandlerService/RemoveInbound",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_remove_inbound_probe,
        ),
        case_def(
            "HandlerService/AddOutbound",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_add_outbound_probe,
        ),
        case_def(
            "HandlerService/RemoveOutbound",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_remove_outbound_probe,
        ),
        case_def(
            "HandlerService/AlterOutbound",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_alter_outbound_probe,
        ),
        case_def(
            "RoutingService/AddRule",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_add_rule_probe,
        ),
        case_def(
            "RoutingService/RemoveRule",
            "mutation_probe",
            CaseMode::BaselineProbe,
            case_remove_rule_probe,
        ),
        case_def(
            "ObservatoryService/GetOutboundStatus",
            "informational",
            CaseMode::Informational,
            case_observatory_status,
        ),
    ]
}

#[test]
#[ignore = "runs xray baseline gRPC compatibility matrix and writes target/grpc-xray-compat/report.{json,md}"]
fn grpc_all_interfaces_compat_with_xray_core() {
    trace_step("==== test grpc_all_interfaces_compat_with_xray_core start ====");
    let _guard = global_test_lock()
        .lock()
        .expect("failed to acquire global test lock");

    let mut results = Vec::new();
    for case in compat_cases() {
        trace_step(format!("running case {}", case.name));
        match run_case(&case) {
            Ok(result) => results.push(result),
            Err(err) => results.push(infra_failure_result(&case, err)),
        }
    }

    let xray_bin = resolve_xray_bin();
    let xray_version = xray_version(&xray_bin);
    let report = build_report(results, xray_bin.display().to_string(), xray_version);
    write_report_artifacts(&report).expect("failed to write compatibility report");

    let failures = report
        .cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Failed))
        .map(|case| format!("[{}] {}", case.case.name, case.summary))
        .collect::<Vec<_>>();

    if !failures.is_empty() {
        panic!(
            "grpc compatibility report contains failures\n{}",
            failures.join("\n")
        );
    }
}

fn run_case(case: &CaseDef) -> io::Result<CompatCaseResult> {
    let chimera = Harness::start_unlocked(TargetKind::Chimera)?;
    let xray = Harness::start_unlocked(TargetKind::Xray)?;
    Ok((case.runner)(&chimera, &xray))
}

fn infra_failure_result(case: &CaseDef, err: io::Error) -> CompatCaseResult {
    let snapshot = CompatSnapshot {
        outcome: "infra_error".to_string(),
        grpc_code: "n/a".to_string(),
        raw: err.to_string(),
        normalized: err.to_string(),
    };
    CompatCaseResult {
        case: describe_case(case),
        status: CaseStatus::Failed,
        summary: format!("failed to start harnesses: {err}"),
        xray: CompatTargetResult {
            target: TargetKind::Xray,
            log_path: String::new(),
            workdir: String::new(),
            steps: vec![CompatStepResult {
                phase: "infra".to_string(),
                request: "start harness".to_string(),
                snapshot: snapshot.clone(),
            }],
        },
        chimera: CompatTargetResult {
            target: TargetKind::Chimera,
            log_path: String::new(),
            workdir: String::new(),
            steps: vec![CompatStepResult {
                phase: "infra".to_string(),
                request: "start harness".to_string(),
                snapshot,
            }],
        },
    }
}

fn describe_case(case: &CaseDef) -> CompatCase {
    CompatCase {
        name: case.name.to_string(),
        category: case.category.to_string(),
        mode: match case.mode {
            CaseMode::Strict => "strict",
            CaseMode::Informational => "informational",
            CaseMode::BaselineProbe => "baseline_probe",
        }
        .to_string(),
    }
}

fn run_strict_query_case(
    case: &CaseDef,
    chimera: &Harness,
    xray: &Harness,
    request: &str,
    query: fn(&Harness) -> CompatSnapshot,
) -> CompatCaseResult {
    let chimera_step = CompatStepResult {
        phase: "query".to_string(),
        request: request.to_string(),
        snapshot: query(chimera),
    };
    let xray_step = CompatStepResult {
        phase: "query".to_string(),
        request: request.to_string(),
        snapshot: query(xray),
    };
    let matched = chimera_step.snapshot.normalized == xray_step.snapshot.normalized;

    CompatCaseResult {
        case: describe_case(case),
        status: if matched {
            CaseStatus::Passed
        } else {
            CaseStatus::Failed
        },
        summary: if matched {
            "query snapshot matches xray baseline".to_string()
        } else {
            format!(
                "query snapshot mismatch: chimera={} xray={}",
                chimera_step.snapshot.normalized, xray_step.snapshot.normalized
            )
        },
        xray: xray.target_result(vec![xray_step]),
        chimera: chimera.target_result(vec![chimera_step]),
    }
}

fn run_informational_case(
    case: &CaseDef,
    chimera: &Harness,
    xray: &Harness,
    request: &str,
    query: fn(&Harness) -> CompatSnapshot,
) -> CompatCaseResult {
    let chimera_step = CompatStepResult {
        phase: "query".to_string(),
        request: request.to_string(),
        snapshot: query(chimera),
    };
    let xray_step = CompatStepResult {
        phase: "query".to_string(),
        request: request.to_string(),
        snapshot: query(xray),
    };
    let matched = chimera_step.snapshot.normalized == xray_step.snapshot.normalized;

    CompatCaseResult {
        case: describe_case(case),
        status: CaseStatus::Informational,
        summary: if matched {
            "informational snapshot matches xray baseline".to_string()
        } else {
            format!(
                "informational difference: chimera={} xray={}",
                chimera_step.snapshot.normalized, xray_step.snapshot.normalized
            )
        },
        xray: xray.target_result(vec![xray_step]),
        chimera: chimera.target_result(vec![chimera_step]),
    }
}

fn run_mutation_case(
    case: &CaseDef,
    chimera: &Harness,
    xray: &Harness,
    xray_steps: Vec<CompatStepResult>,
    chimera_steps: Vec<CompatStepResult>,
) -> CompatCaseResult {
    let status = if steps_match(&chimera_steps, &xray_steps) {
        CaseStatus::Passed
    } else {
        CaseStatus::Failed
    };
    let summary = if matches!(status, CaseStatus::Passed) {
        "mutation side effects match xray baseline".to_string()
    } else {
        format!(
            "mutation side effects diverged: chimera={} xray={}",
            steps_normalized_summary(&chimera_steps),
            steps_normalized_summary(&xray_steps),
        )
    };

    CompatCaseResult {
        case: describe_case(case),
        status,
        summary,
        xray: xray.target_result(xray_steps),
        chimera: chimera.target_result(chimera_steps),
    }
}

fn run_probe_case(
    case: &CaseDef,
    chimera: &Harness,
    xray: &Harness,
    xray_steps: Vec<CompatStepResult>,
    chimera_steps: Vec<CompatStepResult>,
) -> CompatCaseResult {
    let xray_mutation = xray_steps
        .iter()
        .find(|step| step.phase == "mutate")
        .expect("probe case requires xray mutate step");

    let (status, summary) = if xray_mutation.snapshot.outcome != "ok" {
        (
            CaseStatus::Skipped,
            format!(
                "xray baseline does not support this request in current config: {}",
                xray_mutation.snapshot.normalized
            ),
        )
    } else if steps_match(&chimera_steps, &xray_steps) {
        (
            CaseStatus::Passed,
            "baseline-supported mutation matches xray baseline".to_string(),
        )
    } else {
        (
            CaseStatus::Failed,
            format!(
                "baseline-supported mutation diverged: chimera={} xray={}",
                steps_normalized_summary(&chimera_steps),
                steps_normalized_summary(&xray_steps),
            ),
        )
    };

    CompatCaseResult {
        case: describe_case(case),
        status,
        summary,
        xray: xray.target_result(xray_steps),
        chimera: chimera.target_result(chimera_steps),
    }
}

fn steps_match(
    chimera_steps: &[CompatStepResult],
    xray_steps: &[CompatStepResult],
) -> bool {
    chimera_steps.len() == xray_steps.len()
        && chimera_steps.iter().zip(xray_steps).all(|(chimera, xray)| {
            chimera.snapshot.normalized == xray.snapshot.normalized
        })
}

fn steps_normalized_summary(steps: &[CompatStepResult]) -> String {
    steps
        .iter()
        .map(|step| format!("{}={}", step.phase, step.snapshot.normalized))
        .collect::<Vec<_>>()
        .join("; ")
}

fn case_list_inbounds(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/ListInbounds",
        "query",
        CaseMode::Strict,
        case_list_inbounds,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "ListInbounds(is_only_tags=true)",
        query_list_inbounds,
    )
}

fn case_get_inbound_users(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/GetInboundUsers",
        "query",
        CaseMode::Strict,
        case_get_inbound_users,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetInboundUsers(tag=socks-grpc-e2e, email=\"\")",
        query_get_inbound_users,
    )
}

fn case_get_inbound_users_count(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/GetInboundUsersCount",
        "query",
        CaseMode::Strict,
        case_get_inbound_users_count,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetInboundUsersCount(tag=socks-grpc-e2e, email=\"\")",
        query_get_inbound_users_count,
    )
}

fn case_list_outbounds(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/ListOutbounds",
        "query",
        CaseMode::Strict,
        case_list_outbounds,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "ListOutbounds()",
        query_list_outbounds,
    )
}

fn case_test_route(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "RoutingService/TestRoute",
        "query",
        CaseMode::Strict,
        case_test_route,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "TestRoute(inbound=socks-grpc-e2e, publish=false)",
        query_test_route,
    )
}

fn case_get_balancer_info(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "RoutingService/GetBalancerInfo",
        "query",
        CaseMode::Strict,
        case_get_balancer_info,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetBalancerInfo(tag=balancer-a)",
        query_get_balancer_info,
    )
}

fn case_get_stats(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "StatsService/GetStats",
        "query",
        CaseMode::Strict,
        case_get_stats,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetStats(name=inbound>>>non-existent>>>traffic>>>uplink, reset=false)",
        query_get_stats,
    )
}

fn case_get_stats_online(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "StatsService/GetStatsOnline",
        "query",
        CaseMode::Strict,
        case_get_stats_online,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetStatsOnline(name=inbound>>>socks-grpc-e2e>>>online, reset=false)",
        query_get_stats_online,
    )
}

fn case_get_stats_online_ip_list(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "StatsService/GetStatsOnlineIpList",
        "query",
        CaseMode::Strict,
        case_get_stats_online_ip_list,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetStatsOnlineIpList(name=inbound>>>socks-grpc-e2e>>>online, reset=false)",
        query_get_stats_online_ip_list,
    )
}

fn case_get_all_online_users(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "StatsService/GetAllOnlineUsers",
        "query",
        CaseMode::Strict,
        case_get_all_online_users,
    );
    run_strict_query_case(
        &case,
        chimera,
        xray,
        "GetAllOnlineUsers()",
        query_get_all_online_users,
    )
}

fn case_alter_inbound_add_user(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/AlterInbound AddUser",
        "mutation",
        CaseMode::Strict,
        case_alter_inbound_add_user,
    );

    let xray_steps = vec![
        mutate_add_user_step(xray),
        verify_get_inbound_users_step(xray, "verify-users"),
        verify_get_inbound_users_count_step(xray, "verify-count"),
    ];
    let chimera_steps = vec![
        mutate_add_user_step(chimera),
        verify_get_inbound_users_step(chimera, "verify-users"),
        verify_get_inbound_users_count_step(chimera, "verify-count"),
    ];

    run_mutation_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_alter_inbound_remove_user(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/AlterInbound RemoveUser",
        "mutation",
        CaseMode::Strict,
        case_alter_inbound_remove_user,
    );

    let xray_steps = vec![
        setup_add_user_step(xray),
        mutate_remove_user_step(xray),
        verify_get_inbound_users_step(xray, "verify-users"),
        verify_get_inbound_users_count_step(xray, "verify-count"),
    ];
    let chimera_steps = vec![
        setup_add_user_step(chimera),
        mutate_remove_user_step(chimera),
        verify_get_inbound_users_step(chimera, "verify-users"),
        verify_get_inbound_users_count_step(chimera, "verify-count"),
    ];

    run_mutation_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_override_balancer_set(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "RoutingService/OverrideBalancerTarget set backup",
        "mutation",
        CaseMode::Strict,
        case_override_balancer_set,
    );

    let xray_steps = vec![
        mutate_override_balancer_step(xray, "mutate", BACKUP_TAG),
        verify_get_balancer_info_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_override_balancer_step(chimera, "mutate", BACKUP_TAG),
        verify_get_balancer_info_step(chimera, "verify"),
    ];

    run_mutation_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_override_balancer_clear(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "RoutingService/OverrideBalancerTarget clear",
        "mutation",
        CaseMode::Strict,
        case_override_balancer_clear,
    );

    let xray_steps = vec![
        setup_override_balancer_step(xray),
        mutate_override_balancer_step(xray, "mutate", ""),
        verify_get_balancer_info_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        setup_override_balancer_step(chimera),
        mutate_override_balancer_step(chimera, "mutate", ""),
        verify_get_balancer_info_step(chimera, "verify"),
    ];

    run_mutation_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_add_inbound_probe(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/AddInbound",
        "mutation_probe",
        CaseMode::BaselineProbe,
        case_add_inbound_probe,
    );
    let xray_steps = vec![
        mutate_add_inbound_probe_step(xray),
        verify_list_inbounds_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_add_inbound_probe_step(chimera),
        verify_list_inbounds_step(chimera, "verify"),
    ];
    run_probe_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_remove_inbound_probe(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/RemoveInbound",
        "mutation_probe",
        CaseMode::BaselineProbe,
        case_remove_inbound_probe,
    );
    let xray_steps = vec![
        mutate_remove_inbound_probe_step(xray),
        verify_list_inbounds_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_remove_inbound_probe_step(chimera),
        verify_list_inbounds_step(chimera, "verify"),
    ];
    run_probe_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_add_outbound_probe(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/AddOutbound",
        "mutation_probe",
        CaseMode::BaselineProbe,
        case_add_outbound_probe,
    );
    let xray_steps = vec![
        mutate_add_outbound_probe_step(xray),
        verify_list_outbounds_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_add_outbound_probe_step(chimera),
        verify_list_outbounds_step(chimera, "verify"),
    ];
    run_probe_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_remove_outbound_probe(
    chimera: &Harness,
    xray: &Harness,
) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/RemoveOutbound",
        "mutation_probe",
        CaseMode::BaselineProbe,
        case_remove_outbound_probe,
    );
    let xray_steps = vec![
        mutate_remove_outbound_probe_step(xray),
        verify_list_outbounds_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_remove_outbound_probe_step(chimera),
        verify_list_outbounds_step(chimera, "verify"),
    ];
    run_probe_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_alter_outbound_probe(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "HandlerService/AlterOutbound",
        "mutation_probe",
        CaseMode::BaselineProbe,
        case_alter_outbound_probe,
    );
    let xray_steps = vec![
        mutate_alter_outbound_probe_step(xray),
        verify_list_outbounds_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_alter_outbound_probe_step(chimera),
        verify_list_outbounds_step(chimera, "verify"),
    ];
    run_probe_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_add_rule_probe(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "RoutingService/AddRule",
        "mutation_probe",
        CaseMode::BaselineProbe,
        case_add_rule_probe,
    );
    let xray_steps = vec![
        mutate_add_rule_probe_step(xray),
        verify_test_route_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_add_rule_probe_step(chimera),
        verify_test_route_step(chimera, "verify"),
    ];
    run_probe_case(&case, chimera, xray, xray_steps, chimera_steps)
}

fn case_remove_rule_probe(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "RoutingService/RemoveRule",
        "informational",
        CaseMode::Informational,
        case_remove_rule_probe,
    );
    let xray_steps = vec![
        mutate_remove_rule_probe_step(xray),
        verify_test_route_step(xray, "verify"),
    ];
    let chimera_steps = vec![
        mutate_remove_rule_probe_step(chimera),
        verify_test_route_step(chimera, "verify"),
    ];
    let mut result = run_probe_case(&case, chimera, xray, xray_steps, chimera_steps);
    result.status = CaseStatus::Informational;
    if result
        .summary
        .starts_with("baseline-supported mutation diverged")
    {
        result.summary = format!("informational difference: {}", result.summary);
    }
    result
}

fn case_observatory_status(chimera: &Harness, xray: &Harness) -> CompatCaseResult {
    let case = case_def(
        "ObservatoryService/GetOutboundStatus",
        "informational",
        CaseMode::Informational,
        case_observatory_status,
    );
    run_informational_case(
        &case,
        chimera,
        xray,
        "GetOutboundStatus()",
        query_observatory_status,
    )
}

fn query_list_inbounds(harness: &Harness) -> CompatSnapshot {
    let result: Result<ListInboundsResponse, Status> = harness.unary(
        PATH_HANDLER_LIST_INBOUNDS,
        ListInboundsRequest { is_only_tags: true },
    );
    snapshot_from_result(result, |response| {
        let tags = response
            .inbounds
            .iter()
            .map(|inbound| inbound.tag.as_str())
            .filter(|tag| *tag != API_INBOUND_TAG)
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        format!("tags={}", join_strings(tags))
    })
}

fn query_get_inbound_users(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetInboundUserResponse, Status> = harness.unary(
        PATH_HANDLER_GET_INBOUND_USERS,
        GetInboundUserRequest {
            tag: SOCKS_TAG.to_string(),
            email: String::new(),
        },
    );
    snapshot_from_result(result, |response| {
        let users = response
            .users
            .iter()
            .map(|user| user.email.clone())
            .collect::<BTreeSet<_>>();
        format!("users={}", join_strings(users))
    })
}

fn query_get_inbound_users_count(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetInboundUsersCountResponse, Status> = harness.unary(
        PATH_HANDLER_GET_INBOUND_USERS_COUNT,
        GetInboundUserRequest {
            tag: SOCKS_TAG.to_string(),
            email: String::new(),
        },
    );
    snapshot_from_result(result, |response| format!("count={}", response.count))
}

fn query_list_outbounds(harness: &Harness) -> CompatSnapshot {
    let result: Result<ListOutboundsResponse, Status> =
        harness.unary(PATH_HANDLER_LIST_OUTBOUNDS, ListOutboundsRequest {});
    snapshot_from_result(result, |response| {
        let tags = response
            .outbounds
            .iter()
            .map(|outbound| outbound.tag.as_str())
            .filter(|tag| *tag != API_OUTBOUND_TAG)
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        format!("tags={}", join_strings(tags))
    })
}

fn query_test_route(harness: &Harness) -> CompatSnapshot {
    let result: Result<RoutingContext, Status> = harness.unary(
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
    snapshot_from_result(result, |response| {
        let groups = response
            .outbound_group_tags
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        format!(
            "inbound={} outbound={} groups={}",
            response.inbound_tag,
            response.outbound_tag,
            join_strings(groups),
        )
    })
}

fn query_get_balancer_info(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetBalancerInfoResponse, Status> = harness.unary(
        PATH_ROUTING_GET_BALANCER_INFO,
        GetBalancerInfoRequest {
            tag: BALANCER_TAG.to_string(),
        },
    );
    snapshot_from_result(result, |response| {
        let override_target = response
            .balancer
            .as_ref()
            .and_then(|balancer| balancer.r#override.as_ref())
            .map(|item| item.target.as_str())
            .unwrap_or("");
        let targets = response
            .balancer
            .as_ref()
            .and_then(|balancer| balancer.principle_target.as_ref())
            .map(|info| info.tag.iter().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        format!(
            "override={} targets={}",
            override_target,
            join_strings(targets),
        )
    })
}

fn query_get_stats(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetStatsResponse, Status> = harness.unary(
        PATH_STATS_GET_STATS,
        GetStatsRequest {
            name: "inbound>>>non-existent>>>traffic>>>uplink".to_string(),
            reset: false,
        },
    );
    snapshot_from_result(result, |response| match &response.stat {
        Some(stat) => format!("stat:{}={}", stat.name, stat.value),
        None => "stat:none".to_string(),
    })
}

fn query_get_stats_online(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetStatsResponse, Status> = harness.unary(
        PATH_STATS_GET_STATS_ONLINE,
        GetStatsRequest {
            name: format!("inbound>>>{SOCKS_TAG}>>>online"),
            reset: false,
        },
    );
    snapshot_from_result(result, |response| match &response.stat {
        Some(stat) => format!("stat:{}={}", stat.name, stat.value),
        None => "stat:none".to_string(),
    })
}

fn query_get_stats_online_ip_list(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetStatsOnlineIpListResponse, Status> = harness.unary(
        PATH_STATS_GET_STATS_ONLINE_IP_LIST,
        GetStatsRequest {
            name: format!("inbound>>>{SOCKS_TAG}>>>online"),
            reset: false,
        },
    );
    snapshot_from_result(result, |response| {
        let mut ips = BTreeMap::new();
        for (key, value) in &response.ips {
            ips.insert(key.clone(), *value);
        }
        format!("name={} ips={}", response.name, format_map(ips))
    })
}

fn query_get_all_online_users(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetAllOnlineUsersResponse, Status> =
        harness.unary(PATH_STATS_GET_ALL_ONLINE_USERS, GetAllOnlineUsersRequest {});
    snapshot_from_result(result, |response| {
        let users = response.users.iter().cloned().collect::<BTreeSet<_>>();
        format!("users={}", join_strings(users))
    })
}

fn query_observatory_status(harness: &Harness) -> CompatSnapshot {
    let result: Result<GetOutboundStatusResponse, Status> = harness.unary(
        PATH_OBSERVATORY_GET_OUTBOUND_STATUS,
        GetOutboundStatusRequest {},
    );
    snapshot_from_result(result, |response| {
        let statuses = response
            .status
            .as_ref()
            .map(|item| {
                item.status
                    .iter()
                    .map(|status| {
                        format!("{}:{}", status.outbound_tag, status.alive)
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        format!("statuses={}", join_strings(statuses))
    })
}

fn localhost_ip_or_domain() -> IpOrDomain {
    IpOrDomain {
        address: Some(ip_or_domain::Address::Ip(
            Ipv4Addr::LOCALHOST.octets().to_vec(),
        )),
    }
}

fn build_added_inbound_config(port: u16) -> InboundHandlerConfig {
    let mut accounts = HashMap::new();
    accounts.insert(TEST_USERNAME.to_string(), TEST_PASSWORD.to_string());

    InboundHandlerConfig {
        tag: ADDED_INBOUND_TAG.to_string(),
        receiver_settings: Some(TypedMessage {
            r#type: "xray.app.proxyman.ReceiverConfig".to_string(),
            value: ReceiverConfig {
                port_list: Some(PortList {
                    range: vec![PortRange {
                        from: port as u32,
                        to: port as u32,
                    }],
                }),
                listen: Some(localhost_ip_or_domain()),
            }
            .encode_to_vec(),
        }),
        proxy_settings: Some(TypedMessage {
            r#type: "xray.proxy.socks.ServerConfig".to_string(),
            value: SocksServerConfig {
                auth_type: SocksAuthType::Password as i32,
                accounts,
                address: Some(localhost_ip_or_domain()),
                udp_enabled: false,
                user_level: 0,
            }
            .encode_to_vec(),
        }),
    }
}

fn build_added_outbound_config() -> OutboundHandlerConfig {
    OutboundHandlerConfig {
        tag: ADDED_OUTBOUND_TAG.to_string(),
        sender_settings: None,
        proxy_settings: Some(TypedMessage {
            r#type: "xray.proxy.freedom.Config".to_string(),
            value: FreedomConfig::default().encode_to_vec(),
        }),
        expire: 0,
        comment: String::new(),
    }
}

fn mutate_add_user_step(harness: &Harness) -> CompatStepResult {
    grpc_step(
        "mutate",
        "AlterInbound(AddUserOperation)",
        mutate_add_user(harness),
    )
}

fn setup_add_user_step(harness: &Harness) -> CompatStepResult {
    grpc_step(
        "setup",
        "AlterInbound(AddUserOperation)",
        mutate_add_user(harness),
    )
}

fn mutate_add_user(harness: &Harness) -> CompatSnapshot {
    let add_operation = AddUserOperation {
        user: Some(User {
            level: 0,
            email: ADDED_USER.to_string(),
            account: Some(TypedMessage {
                r#type: "xray.proxy.socks.Account".to_string(),
                value: SocksAccount {
                    username: ADDED_USER.to_string(),
                    password: ADDED_PASSWORD.to_string(),
                }
                .encode_to_vec(),
            }),
        }),
    };
    let result: Result<AlterInboundResponse, Status> = harness.unary(
        PATH_HANDLER_ALTER_INBOUND,
        AlterInboundRequest {
            tag: SOCKS_TAG.to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                value: add_operation.encode_to_vec(),
            }),
        },
    );
    snapshot_from_result(result, |_| "ok".to_string())
}

fn mutate_remove_user_step(harness: &Harness) -> CompatStepResult {
    let remove_operation = RemoveUserOperation {
        email: ADDED_USER.to_string(),
    };
    let result: Result<AlterInboundResponse, Status> = harness.unary(
        PATH_HANDLER_ALTER_INBOUND,
        AlterInboundRequest {
            tag: SOCKS_TAG.to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.app.proxyman.command.RemoveUserOperation".to_string(),
                value: remove_operation.encode_to_vec(),
            }),
        },
    );
    grpc_step(
        "mutate",
        "AlterInbound(RemoveUserOperation)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_override_balancer_step(
    harness: &Harness,
    phase: &str,
    target: &str,
) -> CompatStepResult {
    let result: Result<OverrideBalancerTargetResponse, Status> = harness.unary(
        PATH_ROUTING_OVERRIDE_BALANCER_TARGET,
        OverrideBalancerTargetRequest {
            balancer_tag: BALANCER_TAG.to_string(),
            target: target.to_string(),
        },
    );
    grpc_step(
        phase,
        &format!("OverrideBalancerTarget(target={target})"),
        snapshot_from_result(result, |_| {
            if target.is_empty() {
                "ok:cleared".to_string()
            } else {
                format!("ok:{target}")
            }
        }),
    )
}

fn setup_override_balancer_step(harness: &Harness) -> CompatStepResult {
    mutate_override_balancer_step(harness, "setup", BACKUP_TAG)
}

fn mutate_add_inbound_probe_step(harness: &Harness) -> CompatStepResult {
    let inbound_port = free_localhost_port()
        .expect("failed to allocate localhost port for added inbound");
    let result: Result<AddInboundResponse, Status> = harness.unary(
        PATH_HANDLER_ADD_INBOUND,
        AddInboundRequest {
            inbound: Some(build_added_inbound_config(inbound_port)),
        },
    );
    grpc_step(
        "mutate",
        "AddInbound(tag=grpc-e2e-added-inbound, protocol=socks)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_remove_inbound_probe_step(harness: &Harness) -> CompatStepResult {
    let result: Result<RemoveInboundResponse, Status> = harness.unary(
        PATH_HANDLER_REMOVE_INBOUND,
        RemoveInboundRequest {
            tag: SOCKS_TAG.to_string(),
        },
    );
    grpc_step(
        "mutate",
        "RemoveInbound(tag=socks-grpc-e2e)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_add_outbound_probe_step(harness: &Harness) -> CompatStepResult {
    let result: Result<AddOutboundResponse, Status> = harness.unary(
        PATH_HANDLER_ADD_OUTBOUND,
        AddOutboundRequest {
            outbound: Some(build_added_outbound_config()),
        },
    );
    grpc_step(
        "mutate",
        "AddOutbound(tag=grpc-e2e-added-outbound, protocol=freedom)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_remove_outbound_probe_step(harness: &Harness) -> CompatStepResult {
    let result: Result<RemoveOutboundResponse, Status> = harness.unary(
        PATH_HANDLER_REMOVE_OUTBOUND,
        RemoveOutboundRequest {
            tag: DIRECT_TAG.to_string(),
        },
    );
    grpc_step(
        "mutate",
        "RemoveOutbound(tag=direct)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_alter_outbound_probe_step(harness: &Harness) -> CompatStepResult {
    let result: Result<AlterOutboundResponse, Status> = harness.unary(
        PATH_HANDLER_ALTER_OUTBOUND,
        AlterOutboundRequest {
            tag: DIRECT_TAG.to_string(),
            operation: Some(TypedMessage {
                r#type: "xray.proxy.freedom.Config".to_string(),
                value: FreedomConfig::default().encode_to_vec(),
            }),
        },
    );
    grpc_step(
        "mutate",
        "AlterOutbound(tag=direct, operation=FreedomConfig())",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_add_rule_probe_step(harness: &Harness) -> CompatStepResult {
    let result: Result<AddRuleResponse, Status> = harness.unary(
        PATH_ROUTING_ADD_RULE,
        AddRuleRequest {
            config: None,
            should_append: false,
        },
    );
    grpc_step(
        "mutate",
        "AddRule(config=None, should_append=false)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn mutate_remove_rule_probe_step(harness: &Harness) -> CompatStepResult {
    let result: Result<RemoveRuleResponse, Status> = harness.unary(
        PATH_ROUTING_REMOVE_RULE,
        RemoveRuleRequest {
            rule_tag: "rule-a".to_string(),
        },
    );
    grpc_step(
        "mutate",
        "RemoveRule(rule_tag=rule-a)",
        snapshot_from_result(result, |_| "ok".to_string()),
    )
}

fn verify_get_inbound_users_step(
    harness: &Harness,
    phase: &str,
) -> CompatStepResult {
    grpc_step(
        phase,
        "GetInboundUsers(tag=socks-grpc-e2e, email=\"\")",
        query_get_inbound_users(harness),
    )
}

fn verify_get_inbound_users_count_step(
    harness: &Harness,
    phase: &str,
) -> CompatStepResult {
    grpc_step(
        phase,
        "GetInboundUsersCount(tag=socks-grpc-e2e, email=\"\")",
        query_get_inbound_users_count(harness),
    )
}

fn verify_get_balancer_info_step(
    harness: &Harness,
    phase: &str,
) -> CompatStepResult {
    grpc_step(
        phase,
        "GetBalancerInfo(tag=balancer-a)",
        query_get_balancer_info(harness),
    )
}

fn verify_list_inbounds_step(harness: &Harness, phase: &str) -> CompatStepResult {
    grpc_step(
        phase,
        "ListInbounds(is_only_tags=true)",
        query_list_inbounds(harness),
    )
}

fn verify_list_outbounds_step(harness: &Harness, phase: &str) -> CompatStepResult {
    grpc_step(phase, "ListOutbounds()", query_list_outbounds(harness))
}

fn verify_test_route_step(harness: &Harness, phase: &str) -> CompatStepResult {
    grpc_step(
        phase,
        "TestRoute(inbound=socks-grpc-e2e, publish=false)",
        query_test_route(harness),
    )
}

fn grpc_step(
    phase: &str,
    request: &str,
    snapshot: CompatSnapshot,
) -> CompatStepResult {
    CompatStepResult {
        phase: phase.to_string(),
        request: request.to_string(),
        snapshot,
    }
}

fn snapshot_from_result<T>(
    result: Result<T, Status>,
    on_ok: impl FnOnce(&T) -> String,
) -> CompatSnapshot {
    match result {
        Ok(response) => {
            let raw = on_ok(&response);
            CompatSnapshot {
                outcome: "ok".to_string(),
                grpc_code: Code::Ok.to_string(),
                normalized: raw.clone(),
                raw,
            }
        }
        Err(status) => {
            let raw = format!("status:{:?}:{}", status.code(), status.message());
            CompatSnapshot {
                outcome: "status".to_string(),
                grpc_code: format!("{:?}", status.code()),
                normalized: normalize_status_message(
                    status.code(),
                    status.message(),
                ),
                raw,
            }
        }
    }
}

fn normalize_status_message(code: Code, message: &str) -> String {
    let trimmed = message.trim().trim_end_matches('.');
    let squashed = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("status:{code:?}:{squashed}")
}

fn join_strings(values: impl IntoIterator<Item = String>) -> String {
    let collected = values.into_iter().collect::<Vec<_>>();
    if collected.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", collected.join(","))
    }
}

fn format_map(values: BTreeMap<String, i64>) -> String {
    let parts = values
        .into_iter()
        .map(|(key, value)| format!("{key}:{value}"))
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "{}".to_string()
    } else {
        format!("{{{}}}", parts.join(","))
    }
}

fn build_report(
    cases: Vec<CompatCaseResult>,
    xray_bin: String,
    xray_version: String,
) -> CompatReport {
    let passed = cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Passed))
        .count();
    let failed = cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Failed))
        .count();
    let skipped = cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Skipped))
        .count();
    let informational = cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Informational))
        .count();

    CompatReport {
        generated_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        xray_version,
        xray_bin,
        config_summary: vec![
            "shared logical config: socks inbound, direct/backup outbounds, api listener, routing balancer".to_string(),
            "query comparisons normalize away xray api plumbing tags api-in/api".to_string(),
            "baseline probe cases are skipped when xray does not support the request in the current config".to_string(),
        ],
        passed,
        failed,
        skipped,
        informational,
        cases,
    }
}

fn report_output_dir() -> PathBuf {
    workspace_root().join("target/grpc-xray-compat")
}

fn write_report_artifacts(report: &CompatReport) -> io::Result<()> {
    let output_dir = report_output_dir();
    fs::create_dir_all(&output_dir)?;

    let report_json = serde_json::to_string_pretty(report)
        .map_err(|err| io::Error::other(err.to_string()))?;
    fs::write(output_dir.join("report.json"), report_json)?;
    fs::write(output_dir.join("report.md"), render_markdown_report(report))?;
    Ok(())
}

fn render_markdown_report(report: &CompatReport) -> String {
    let mut out = String::new();
    out.push_str("# gRPC Compatibility Report\n\n");
    out.push_str(&format!("- Xray binary: `{}`\n", report.xray_bin));
    out.push_str(&format!(
        "- Xray version: `{}`\n",
        report.xray_version.trim()
    ));
    out.push_str(&format!(
        "- Totals: passed={} failed={} skipped={} informational={}\n\n",
        report.passed, report.failed, report.skipped, report.informational
    ));
    out.push_str("## Config Summary\n\n");
    for item in &report.config_summary {
        out.push_str(&format!("- {}\n", item));
    }
    out.push_str("\n## Case Matrix\n\n");
    out.push_str("| Case | Category | Status | Summary |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for case in &report.cases {
        out.push_str(&format!(
            "| {} | {} | {:?} | {} |\n",
            case.case.name,
            case.case.category,
            case.status,
            escape_table_cell(&case.summary),
        ));
    }
    out.push_str("\n## Details\n\n");
    for case in &report.cases {
        out.push_str(&format!("### {}\n\n", case.case.name));
        out.push_str(&format!(
            "- Status: `{:?}`\n- Category: `{}`\n- Summary: {}\n",
            case.status, case.case.category, case.summary
        ));
        out.push_str(&format!(
            "- Xray log: `{}`\n- Chimera log: `{}`\n\n",
            case.xray.log_path, case.chimera.log_path
        ));
        out.push_str("| Target | Phase | Request | Snapshot |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for target in [&case.xray, &case.chimera] {
            for step in &target.steps {
                out.push_str(&format!(
                    "| {} | {} | {} | `{}` |\n",
                    target.target.as_str(),
                    step.phase,
                    escape_table_cell(&step.request),
                    escape_table_cell(&step.snapshot.normalized),
                ));
            }
        }
        out.push('\n');
    }
    out
}

fn escape_table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn xray_version(xray_bin: &Path) -> String {
    let output = Command::new(xray_bin).arg("version").output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Ok(output) => format!(
            "failed to get version: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(err) => format!("failed to get version: {err}"),
    }
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
struct PortRange {
    #[prost(uint32, tag = "1")]
    from: u32,
    #[prost(uint32, tag = "2")]
    to: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PortList {
    #[prost(message, repeated, tag = "1")]
    range: Vec<PortRange>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct IpOrDomain {
    #[prost(oneof = "ip_or_domain::Address", tags = "1, 2")]
    address: Option<ip_or_domain::Address>,
}

mod ip_or_domain {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Address {
        #[prost(bytes, tag = "1")]
        Ip(Vec<u8>),
        #[prost(string, tag = "2")]
        Domain(String),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct ReceiverConfig {
    #[prost(message, optional, tag = "1")]
    port_list: Option<PortList>,
    #[prost(message, optional, tag = "2")]
    listen: Option<IpOrDomain>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SocksServerConfig {
    #[prost(enumeration = "SocksAuthType", tag = "1")]
    auth_type: i32,
    #[prost(map = "string, string", tag = "2")]
    accounts: HashMap<String, String>,
    #[prost(message, optional, tag = "3")]
    address: Option<IpOrDomain>,
    #[prost(bool, tag = "4")]
    udp_enabled: bool,
    #[prost(uint32, tag = "6")]
    user_level: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum SocksAuthType {
    NoAuth = 0,
    Password = 1,
}

#[derive(Clone, PartialEq, prost::Message)]
struct FreedomConfig {}

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
