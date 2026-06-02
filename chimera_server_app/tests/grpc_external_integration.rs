use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use prost::Message;
use tonic::{
    Request, Status,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKS_TAG: &str = "socks-grpc-e2e";
const SOCKS_ADDED_USER: &str = "grpc-e2e-added-user";
const SOCKS_ADDED_PASS: &str = "grpc-e2e-added-pass";
const DIRECT_TAG: &str = "direct";
const BACKUP_TAG: &str = "backup";
static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

fn trace_step(step: impl AsRef<str>) {
    eprintln!("[grpc-external-e2e] {}", step.as_ref());
}

const PATH_STATS_GET_SYS_STATS: &str =
    "/xray.app.stats.command.StatsService/GetSysStats";
const PATH_LOGGER_RESTART: &str =
    "/xray.app.log.command.LoggerService/RestartLogger";
const PATH_HANDLER_LIST_INBOUNDS: &str =
    "/xray.app.proxyman.command.HandlerService/ListInbounds";
const PATH_HANDLER_GET_INBOUND_USERS_COUNT: &str =
    "/xray.app.proxyman.command.HandlerService/GetInboundUsersCount";
const PATH_HANDLER_ALTER_INBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/AlterInbound";
const PATH_HANDLER_LIST_OUTBOUNDS: &str =
    "/xray.app.proxyman.command.HandlerService/ListOutbounds";
const PATH_ROUTING_TEST_ROUTE: &str =
    "/xray.app.router.command.RoutingService/TestRoute";
const PATH_OBSERVATORY_GET_OUTBOUND_STATUS: &str =
    "/xray.core.app.observatory.command.ObservatoryService/GetOutboundStatus";

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
        trace_step(format!("waiting for grpc listener {}", listen_addr));
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

fn unique_test_dir() -> io::Result<PathBuf> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let pid = std::process::id();
    let test_id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("chimera-grpc-e2e-{pid}-{millis}-{test_id}"));
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
            "user": "grpc-e2e-user",
            "pass": "grpc-e2e-pass"
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
  }},
  "routing": {{
    "domainStrategy": "AsIs",
    "rules": [
      {{
        "inboundTag": ["{SOCKS_TAG}"],
        "outboundTag": "{DIRECT_TAG}"
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
                            "timeout connecting to grpc endpoint {grpc_addr}; last error: {}",
                            err
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
        "rpc request path={} req_type={} resp_type={}",
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
    trace_step("rpc response received");
    Ok(response.into_inner())
}

fn socks_connect_with_password(
    socks_port: u16,
    target_port: u16,
    username: &str,
    password: &str,
) -> io::Result<()> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, socks_port)),
        IO_TIMEOUT,
    )?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    stream.write_all(&[0x05, 0x01, 0x02])?;
    let mut method_response = [0u8; 2];
    stream.read_exact(&mut method_response)?;
    if method_response != [0x05, 0x02] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected socks method response: {method_response:?}"),
        ));
    }

    let username = username.as_bytes();
    let password = password.as_bytes();
    stream.write_all(&[0x01, username.len() as u8])?;
    stream.write_all(username)?;
    stream.write_all(&[password.len() as u8])?;
    stream.write_all(password)?;
    let mut auth_response = [0u8; 2];
    stream.read_exact(&mut auth_response)?;
    if auth_response != [0x01, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unexpected socks auth response: {auth_response:?}"),
        ));
    }

    let port_bytes = target_port.to_be_bytes();
    stream.write_all(&[
        0x05,
        0x01,
        0x00,
        0x01,
        127,
        0,
        0,
        1,
        port_bytes[0],
        port_bytes[1],
    ])?;
    let mut connect_response = [0u8; 10];
    stream.read_exact(&mut connect_response)?;
    if connect_response[0] != 0x05 || connect_response[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("unexpected socks connect response: {connect_response:?}"),
        ));
    }

    Ok(())
}

#[derive(Clone, PartialEq, prost::Message)]
struct RestartLoggerRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct RestartLoggerResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct SysStatsRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct SysStatsResponse {
    #[prost(uint32, tag = "10")]
    uptime: u32,
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
struct InboundHandlerConfig {
    #[prost(string, tag = "1")]
    tag: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetInboundUserRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(string, tag = "2")]
    email: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetInboundUsersCountResponse {
    #[prost(int64, tag = "1")]
    count: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TypedMessage {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes, tag = "2")]
    value: Vec<u8>,
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
struct SocksAccount {
    #[prost(string, tag = "1")]
    username: String,
    #[prost(string, tag = "2")]
    password: String,
}

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
struct AlterInboundRequest {
    #[prost(string, tag = "1")]
    tag: String,
    #[prost(message, optional, tag = "2")]
    operation: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct AlterInboundResponse {}

#[derive(Clone, PartialEq, prost::Message)]
struct ListOutboundsRequest {}

#[derive(Clone, PartialEq, prost::Message)]
struct ListOutboundsResponse {
    #[prost(message, repeated, tag = "1")]
    outbounds: Vec<OutboundHandlerConfig>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct OutboundHandlerConfig {
    #[prost(string, tag = "1")]
    tag: String,
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
struct RoutingContext {
    #[prost(string, tag = "1")]
    inbound_tag: String,
    #[prost(string, repeated, tag = "11")]
    outbound_group_tags: Vec<String>,
    #[prost(string, tag = "12")]
    outbound_tag: String,
}

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
fn grpc_services_external_end_to_end() {
    trace_step("==== test grpc_services_external_end_to_end start ====");
    let _guard = global_test_lock()
        .lock()
        .expect("failed to acquire test lock");
    let grpc_port = free_localhost_port().expect("failed to allocate grpc port");
    let socks_port = free_localhost_port().expect("failed to allocate socks port");
    let grpc_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, grpc_port);

    let config = build_config(grpc_port, socks_port);
    println!("test config:\n{}", config);
    trace_step(format!(
        "using grpc_addr={} socks_port={}",
        grpc_addr, socks_port
    ));
    let mut server =
        ServerProcess::spawn(&config).expect("failed to spawn chimera process");
    server
        .wait_until_ready(SocketAddr::V4(grpc_addr))
        .unwrap_or_else(|err| panic!("chimera grpc listener not ready: {err}"));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    trace_step("tokio runtime built");
    let channel = runtime
        .block_on(connect_channel(SocketAddr::V4(grpc_addr)))
        .unwrap_or_else(|err| {
            panic!(
                "failed to connect grpc channel: {err}; logs:\n{}",
                server.logs()
            )
        });

    let sys_stats: SysStatsResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_STATS_GET_SYS_STATS,
            SysStatsRequest {},
        ))
        .unwrap_or_else(|err| {
            panic!("stats service call failed: {err}; logs:\n{}", server.logs())
        });
    let _ = sys_stats.uptime;
    trace_step(format!("stats uptime={}", sys_stats.uptime));

    let _: RestartLoggerResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_LOGGER_RESTART,
            RestartLoggerRequest {},
        ))
        .unwrap_or_else(|err| {
            panic!(
                "logger service call failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    trace_step("logger restart rpc passed");

    let inbounds: ListInboundsResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_LIST_INBOUNDS,
            ListInboundsRequest { is_only_tags: true },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "handler ListInbounds failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    assert!(
        inbounds
            .inbounds
            .iter()
            .any(|inbound| inbound.tag == SOCKS_TAG),
        "expected inbound tag {SOCKS_TAG}, got {:?}",
        inbounds
            .inbounds
            .iter()
            .map(|inbound| inbound.tag.clone())
            .collect::<Vec<_>>()
    );
    trace_step("handler list inbounds rpc passed");

    let users_count: GetInboundUsersCountResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_GET_INBOUND_USERS_COUNT,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "handler GetInboundUsersCount failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    assert_eq!(users_count.count, 1);
    trace_step(format!("handler inbound users count={}", users_count.count));

    let _: AlterInboundResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_ALTER_INBOUND,
            AlterInboundRequest {
                tag: SOCKS_TAG.to_string(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.AddUserOperation".to_string(),
                    value: AddUserOperation {
                        user: Some(User {
                            level: 0,
                            email: SOCKS_ADDED_USER.to_string(),
                            account: Some(TypedMessage {
                                r#type: "xray.proxy.socks.Account".to_string(),
                                value: SocksAccount {
                                    username: SOCKS_ADDED_USER.to_string(),
                                    password: SOCKS_ADDED_PASS.to_string(),
                                }
                                .encode_to_vec(),
                            }),
                        }),
                    }
                    .encode_to_vec(),
                }),
            },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "handler AlterInbound AddUser failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    socks_connect_with_password(
        socks_port,
        grpc_port,
        SOCKS_ADDED_USER,
        SOCKS_ADDED_PASS,
    )
    .unwrap_or_else(|err| {
        panic!(
            "added socks user could not authenticate: {err}; logs:\n{}",
            server.logs()
        )
    });
    trace_step("added socks user authenticated through running handler");

    let _: AlterInboundResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_ALTER_INBOUND,
            AlterInboundRequest {
                tag: SOCKS_TAG.to_string(),
                operation: Some(TypedMessage {
                    r#type: "xray.app.proxyman.command.RemoveUserOperation"
                        .to_string(),
                    value: RemoveUserOperation {
                        email: SOCKS_ADDED_USER.to_string(),
                    }
                    .encode_to_vec(),
                }),
            },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "handler AlterInbound RemoveUser failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    let removed_auth = socks_connect_with_password(
        socks_port,
        grpc_port,
        SOCKS_ADDED_USER,
        SOCKS_ADDED_PASS,
    );
    assert!(
        removed_auth.is_err(),
        "removed socks user should not authenticate"
    );
    trace_step("removed socks user was rejected by running handler");

    let outbounds: ListOutboundsResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_LIST_OUTBOUNDS,
            ListOutboundsRequest {},
        ))
        .unwrap_or_else(|err| {
            panic!(
                "handler ListOutbounds failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    let outbound_tags = outbounds
        .outbounds
        .iter()
        .map(|outbound| outbound.tag.as_str())
        .collect::<HashSet<_>>();
    assert!(outbound_tags.contains(DIRECT_TAG));
    assert!(outbound_tags.contains(BACKUP_TAG));
    trace_step("handler list outbounds rpc passed");

    let route: RoutingContext = runtime
        .block_on(grpc_unary(
            channel.clone(),
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
        ))
        .unwrap_or_else(|err| {
            panic!("routing TestRoute failed: {err}; logs:\n{}", server.logs())
        });
    assert_eq!(route.outbound_tag, DIRECT_TAG);
    trace_step(format!(
        "routing test route returned outbound_tag={}",
        route.outbound_tag
    ));

    let observatory: GetOutboundStatusResponse = runtime
        .block_on(grpc_unary(
            channel,
            PATH_OBSERVATORY_GET_OUTBOUND_STATUS,
            GetOutboundStatusRequest {},
        ))
        .unwrap_or_else(|err| {
            panic!(
                "observatory GetOutboundStatus failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    let status = observatory
        .status
        .expect("observatory response should include status")
        .status;
    let observed_tags = status
        .iter()
        .map(|entry| entry.outbound_tag.as_str())
        .collect::<HashSet<_>>();
    assert!(observed_tags.contains(DIRECT_TAG));
    assert!(observed_tags.contains(BACKUP_TAG));
    trace_step("observatory rpc returned expected outbound tags");
    trace_step("==== test grpc_services_external_end_to_end done ====");
}
