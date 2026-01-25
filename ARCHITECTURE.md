# Chimera Server 架构（按代码执行时序）

本文档按“代码真实执行顺序”梳理 Chimera_Server 的架构与运行流程，覆盖构建期、启动期、控制面与数据面、连接生命周期及观测链路。

## 0. 项目组成

- Workspace：`chimera_server_app`（入口应用） + `chimera_server_lib`（核心库）。
- `chimera_server_app` 只负责 CLI、配置文件定位与启动库。
- `chimera_server_lib` 负责配置解析、协议处理、控制面服务与数据面代理。

## 1. 构建期（Build-Time）

1. `chimera_server_lib/build.rs` 在构建阶段执行：
   - 设置 `PROTOC` 为 vendored protoc。
   - 使用 `tonic_build` 编译 `proto/` 下的 xray 相关 proto。
2. 生成的 gRPC 代码通过 `chimera_server_lib/src/grpc/proto.rs` 的
   `tonic::include_proto!` 被引入到运行时模块。

## 2. 进程启动（App Entry）

1. `chimera_server_app/src/main.rs` 解析 CLI：
   - 组装配置文件路径（目录 + 文件名）。
   - 校验配置文件存在性。
2. 调用 `chimera::start`（`chimera_server_lib/src/lib.rs`）：
   - 安装 rustls crypto provider。
   - 创建 Tokio runtime（多线程或单线程）。
   - 进入 `start_async` 异步初始化流程。

## 3. 配置解析与运行态准备（start_async）

1. 配置解析：
   - `Config::try_parse` -> `LiteralConfig`（支持 JSON/JSON5）。
2. Inbound 转换：
   - `ServerConfig::try_from(InboudItem)` 把 Inbound 转为运行态配置。
   - 应用协议层（VLESS/Trojan/Socks/Hysteria2/XHTTP）。
   - 应用安全层（TLS/REALITY）、WS 包装。
3. RuntimeState 组装：
   - `RuntimeState::new` 保存入站与出站摘要。
4. API 监听地址解析：
   - 优先使用 `api.listen`，否则尝试用 `api.tag` 对应 inbound 的地址。
   - 若 api 使用了 inbound 的端口，会记录 `skip_inbound_tag` 以避免冲突。
5. 日志初始化：
   - `log::init` 目前在 `start_async` 中被注释掉（实际不执行）。

## 4. 控制面服务启动（Control Plane）

1. gRPC 服务（`grpc::start_grpc_server`）：
   - 监听 `api.listen` 地址。
   - 依据配置注册服务：Stats / Logger / Handler / Routing / Observatory。
   - 服务内部读取 `RuntimeState` 与 `traffic` 统计。
2. MCP 服务（`mcp::start_mcp_server`）：
   - Axum WebSocket 服务，默认路径 `/mcp`。
   - 周期推送 `chimera://status/connection_count` 的更新通知。

## 5. 数据面服务启动（Inbound Servers）

1. 逐个 inbound 启动（跳过 `skip_inbound_tag`）：
   - `beginning::start_servers` 选择传输层：
     - TCP：`start_tcp_server`
     - QUIC：`start_quic_server`（当前仅 Hysteria2）
     - XHTTP：`start_xhttp_server`
     - UDP：未支持（panic）
2. 所有服务任务进入 `join_handles`：
   - `select_all` 等待任意任务退出。
   - 任意服务退出即视为错误并触发退出。

## 6. TCP 入站连接生命周期（核心数据面）

1. Listener 接受连接，设置 `TCP_NODELAY`。
2. `process_stream`：
   - 在 60s 超时内调用 `setup_server_stream` 完成协议握手。
   - 解析目标 `NetLocation`，生成 `TrafficContext`。
   - 在 60s 超时内解析 DNS 并连接目标地址。
   - 必要时回写“连接成功响应”（如 VLESS/Socks）。
   - `copy_bidirectional` 双向转发数据。
   - 记录流量统计与活动连接。
3. Handler 链路构建：
   - `create_tcp_server_handler` 构建协议处理器。
   - 可能叠加 WebSocket / TLS / REALITY 的包装层。

## 7. TCP 协议处理顺序（握手阶段）

- VLESS：读取版本与用户 ID -> 解析目标地址 -> 返回响应头。
- Trojan：校验密码哈希 -> 解析目标地址 -> 校验 CRLF。
- SOCKS5：协商鉴权 -> 可选用户名密码 -> CONNECT 解析 -> 返回成功响应。
- TLS：先完成 TLS 握手，再交给内层 handler。
- REALITY：解析 ClientHello -> SNI 校验 -> 自定义握手 -> 交给内层 handler。
- WebSocket：解析 HTTP Upgrade -> 路由匹配 -> 回写 101 -> 使用 WebsocketStream。

## 8. QUIC / Hysteria2 生命周期

1. `start_quic_server`：
   - 读取证书与私钥，构建 rustls QUIC 配置。
   - 启动 quinn Endpoint 并等待连接。
2. 每条 QUIC 连接：
   - 先进行 HTTP/3 `/auth` 认证（`Hysteria-Auth`）。
   - 成功后并行处理：
     - TCP 流：读取目标地址 -> 连接目标 -> QUIC <-> TCP 转发。
     - UDP 数据报：维护会话、分片与转发。
3. 连接层记录流量与在线统计。

## 9. XHTTP 生命周期

1. Axum HTTP 服务提供 `GET`/`POST`：
   - `up_handler`：按 seq 排序写入上游 TCP。
   - `down_handler`：将上游读取流回传给客户端（event-stream）。
2. SessionStore 维护会话与上游连接，支持 padding 与 host/path 校验。

## 10. 观测与统计链路

- `traffic` 记录总量、按协议/入站/用户聚合的流量。
- 活动连接通过 `register_connection` 维护，供 Stats/MCP 读取。
- gRPC StatsService 映射为 xray 风格命名键值。
- MCP 提供实时连接数订阅。

## 11. 当前限制与代码现状（便于理解执行分支）

- UDP 传输层未支持（`beginning` 中直接 panic）。
- VMess inbound 尚未实现。
- WebSocket 流、YAML/TOML 配置解析等存在 `todo!()`。
- 日志初始化在启动流程中被注释，需显式开启才能生效。
