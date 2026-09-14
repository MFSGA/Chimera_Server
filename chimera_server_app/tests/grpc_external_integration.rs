use std::{
    collections::HashSet,
    fs::{self, File},
    io,
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

#[cfg(target_os = "linux")]
use hyper_util::rt::TokioIo;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt as _;
#[cfg(target_os = "linux")]
use tonic::codegen::{Service, http::Uri};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKS_TAG: &str = "socks-grpc-e2e";
const DIRECT_TAG: &str = "direct";
const BACKUP_TAG: &str = "backup";
const ABSTRACT_API_TAG: &str = "chimera-api";
const ABSTRACT_API_INBOUND_TAG: &str = "chimera-api-in";
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
const PATH_HANDLER_ADD_INBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/AddInbound";
const PATH_HANDLER_REMOVE_INBOUND: &str =
    "/xray.app.proxyman.command.HandlerService/RemoveInbound";
const PATH_HANDLER_GET_INBOUND_USERS_COUNT: &str =
    "/xray.app.proxyman.command.HandlerService/GetInboundUsersCount";
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

#[cfg(target_os = "linux")]
fn build_abstract_tunnel_config(socket_name: &str, socks_port: u16) -> String {
    format!(
        r#"{{
  "inbounds": [
    {{
      "listen": "127.0.0.1",
      "port": {socks_port},
      "protocol": "socks",
      "settings": {{
        "auth": "password",
        "accounts": [{{"user": "grpc-e2e-user", "pass": "grpc-e2e-pass"}}]
      }},
      "tag": "{SOCKS_TAG}"
    }},
    {{
      "listen": "@{socket_name}",
      "protocol": "tunnel",
      "tag": "{ABSTRACT_API_INBOUND_TAG}"
    }}
  ],
  "outbounds": [
    {{"protocol": "freedom", "tag": "{DIRECT_TAG}"}},
    {{"protocol": "blackhole", "tag": "{BACKUP_TAG}"}}
  ],
  "api": {{
    "tag": "{ABSTRACT_API_TAG}",
    "services": ["StatsService", "HandlerService"]
  }},
  "routing": {{
    "domainStrategy": "AsIs",
    "rules": [
      {{
        "inboundTag": ["{ABSTRACT_API_INBOUND_TAG}"],
        "outboundTag": "{ABSTRACT_API_TAG}"
      }},
      {{
        "inboundTag": ["{SOCKS_TAG}"],
        "outboundTag": "{DIRECT_TAG}"
      }}
    ]
  }}
}}"#
    )
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

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct AbstractUnixConnector {
    name: String,
}

#[cfg(target_os = "linux")]
impl Service<Uri> for AbstractUnixConnector {
    type Response = TokioIo<tokio::net::UnixStream>;
    type Error = io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<Self::Response>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let name = self.name.clone();
        Box::pin(async move {
            let stream = tokio::task::spawn_blocking(move || {
                let address = std::os::unix::net::SocketAddr::from_abstract_name(
                    name.as_bytes(),
                )?;
                std::os::unix::net::UnixStream::connect_addr(&address)
            })
            .await
            .map_err(io::Error::other)??;
            stream.set_nonblocking(true)?;
            let stream = tokio::net::UnixStream::from_std(stream)?;
            Ok(TokioIo::new(stream))
        })
    }
}

#[cfg(target_os = "linux")]
async fn connect_abstract_channel(name: &str) -> io::Result<Channel> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let endpoint = Endpoint::from_static("http://chimera.abstract")
        .connect_timeout(IO_TIMEOUT)
        .timeout(IO_TIMEOUT);

    loop {
        let connector = AbstractUnixConnector {
            name: name.to_string(),
        };
        match endpoint.clone().connect_with_connector(connector).await {
            Ok(channel) => return Ok(channel),
            Err(_err) if Instant::now() < deadline => {
                tokio::time::sleep(CONNECT_RETRY_INTERVAL).await;
            }
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timeout connecting to abstract grpc socket @{name}; last error: {err}"
                    ),
                ));
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
    #[prost(message, optional, tag = "2")]
    receiver_settings: Option<TypedMessage>,
    #[prost(message, optional, tag = "3")]
    proxy_settings: Option<TypedMessage>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TypedMessage {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes, tag = "2")]
    value: Vec<u8>,
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
struct PortRangePayload {
    #[prost(uint32, tag = "1")]
    from: u32,
    #[prost(uint32, tag = "2")]
    to: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct PortListPayload {
    #[prost(message, repeated, tag = "1")]
    range: Vec<PortRangePayload>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct IpOrDomainPayload {
    #[prost(oneof = "ip_or_domain_payload::Address", tags = "1, 2")]
    address: Option<ip_or_domain_payload::Address>,
}

mod ip_or_domain_payload {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Address {
        #[prost(bytes, tag = "1")]
        Ip(Vec<u8>),
        #[prost(string, tag = "2")]
        Domain(String),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct ReceiverConfigPayload {
    #[prost(message, optional, tag = "1")]
    port_list: Option<PortListPayload>,
    #[prost(message, optional, tag = "2")]
    listen: Option<IpOrDomainPayload>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct SocksServerConfigPayload {
    #[prost(int32, tag = "1")]
    auth_type: i32,
    #[prost(map = "string, string", tag = "2")]
    accounts: std::collections::HashMap<String, String>,
    #[prost(bool, tag = "4")]
    udp_enabled: bool,
    #[prost(uint32, tag = "6")]
    user_level: u32,
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

fn build_dynamic_add_inbound_request(tag: &str, port: u16) -> AddInboundRequest {
    let mut accounts = std::collections::HashMap::new();
    accounts.insert(
        "grpc-dynamic-user".to_string(),
        "grpc-dynamic-pass".to_string(),
    );
    AddInboundRequest {
        inbound: Some(InboundHandlerConfig {
            tag: tag.to_string(),
            receiver_settings: Some(TypedMessage {
                r#type: "xray.app.proxyman.ReceiverConfig".to_string(),
                value: ReceiverConfigPayload {
                    port_list: Some(PortListPayload {
                        range: vec![PortRangePayload {
                            from: port as u32,
                            to: port as u32,
                        }],
                    }),
                    listen: Some(IpOrDomainPayload {
                        address: Some(ip_or_domain_payload::Address::Ip(
                            Ipv4Addr::LOCALHOST.octets().to_vec(),
                        )),
                    }),
                }
                .encode_to_vec(),
            }),
            proxy_settings: Some(TypedMessage {
                r#type: "xray.proxy.socks.ServerConfig".to_string(),
                value: SocksServerConfigPayload {
                    auth_type: 1,
                    accounts,
                    udp_enabled: false,
                    user_level: 0,
                }
                .encode_to_vec(),
            }),
        }),
    }
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

    let users_count: Result<GetInboundUsersCountResponse, Status> = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_GET_INBOUND_USERS_COUNT,
            GetInboundUserRequest {
                tag: SOCKS_TAG.to_string(),
                email: String::new(),
            },
        ));
    let err = users_count.expect_err("SOCKS should not expose Xray UserManager");
    assert_eq!(err.code(), tonic::Code::Unknown);
    trace_step("handler SOCKS user manager rejection matched Xray");

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

#[cfg(target_os = "linux")]
#[test]
fn grpc_services_over_abstract_unix_tunnel_end_to_end() {
    trace_step("==== test abstract Unix grpc tunnel start ====");
    let _guard = global_test_lock()
        .lock()
        .expect("failed to acquire test lock");
    let socks_port = free_localhost_port().expect("failed to allocate socks port");
    let socket_name = format!(
        "chimera-grpc-e2e-{}-{}",
        std::process::id(),
        NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
    );
    let config = build_abstract_tunnel_config(&socket_name, socks_port);
    let mut server =
        ServerProcess::spawn(&config).expect("failed to spawn chimera process");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let channel = runtime
        .block_on(connect_abstract_channel(&socket_name))
        .unwrap_or_else(|err| {
            panic!(
                "failed to connect abstract grpc channel @{socket_name}: {err}; logs:\n{}",
                server.logs()
            )
        });

    let dynamic_tag = format!(
        "grpc-dynamic-in-{}",
        NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
    );
    let dynamic_port =
        free_localhost_port().expect("failed to allocate dynamic inbound port");
    let _: AddInboundResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_ADD_INBOUND,
            build_dynamic_add_inbound_request(&dynamic_tag, dynamic_port),
        ))
        .unwrap_or_else(|err| {
            panic!(
                "abstract HandlerService/AddInbound failed: {err}; logs:\n{}",
                server.logs()
            )
        });

    let inbounds_after_add: ListInboundsResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_LIST_INBOUNDS,
            ListInboundsRequest { is_only_tags: true },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "abstract HandlerService/ListInbounds after AddInbound failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    assert!(
        inbounds_after_add
            .inbounds
            .iter()
            .any(|inbound| inbound.tag == dynamic_tag)
    );
    TcpStream::connect_timeout(
        &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, dynamic_port)),
        IO_TIMEOUT,
    )
    .expect("dynamically added inbound listener should accept connections");

    let _: RemoveInboundResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_HANDLER_REMOVE_INBOUND,
            RemoveInboundRequest {
                tag: dynamic_tag.clone(),
            },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "abstract HandlerService/RemoveInbound failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, dynamic_port))
        .expect("removed inbound listener should release its port");

    let sys_stats: SysStatsResponse = runtime
        .block_on(grpc_unary(
            channel.clone(),
            PATH_STATS_GET_SYS_STATS,
            SysStatsRequest {},
        ))
        .unwrap_or_else(|err| {
            panic!(
                "abstract StatsService/GetSysStats failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    let _ = sys_stats.uptime;

    let inbounds: ListInboundsResponse = runtime
        .block_on(grpc_unary(
            channel,
            PATH_HANDLER_LIST_INBOUNDS,
            ListInboundsRequest { is_only_tags: true },
        ))
        .unwrap_or_else(|err| {
            panic!(
                "abstract HandlerService/ListInbounds failed: {err}; logs:\n{}",
                server.logs()
            )
        });
    assert!(
        inbounds
            .inbounds
            .iter()
            .any(|inbound| inbound.tag == SOCKS_TAG),
        "expected data-plane inbound tag {SOCKS_TAG}, got {:?}",
        inbounds
            .inbounds
            .iter()
            .map(|inbound| inbound.tag.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        server
            .child
            .try_wait()
            .expect("query chimera status")
            .is_none(),
        "chimera exited after abstract Unix gRPC calls; logs:\n{}",
        server.logs()
    );
    trace_step("==== test abstract Unix grpc tunnel done ====");
}
