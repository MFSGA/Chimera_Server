# AGENTS

本文件面向自动化代理与贡献者，说明项目目标、架构参考与实现参考，帮助在修改代码时保持一致性。

## 项目目标
- Chimera_Server 是 Rust 网络服务核心，目标是与 xray-core 在协议行为与配置语义上保持兼容。
- 当前重点在 inbound 解析与协议处理，outbound/routing/policy 仍在扩展中。

## 架构参考：clash-rs
- 架构层次参考 clash-rs：配置解析 -> 运行态状态 -> 控制面/数据面分离 -> 异步任务调度。
- 数据面以 “inbound listener -> handler 链 -> outbound 连接” 的流水线思路组织，协议/传输包装按层叠加。
- 控制面服务（gRPC/MCP/统计）与数据面解耦，避免阻塞核心转发路径。

## 实现参考：shoes
- 具体协议实现与配置映射参考 https://github.com/cfal/shoes 。
- 新增/调整协议行为时，优先对照 shoes 的握手流程、字段默认值与异常处理路径。

## 代码地图
- 入口应用：`chimera_server_app/src/main.rs`
- 核心库启动流程：`chimera_server_lib/src/lib.rs`
- 配置解析与结构：`chimera_server_lib/src/config`
- 入站服务与传输层：`chimera_server_lib/src/beginning`
- 协议处理链与包装：`chimera_server_lib/src/handler`
- 控制面 gRPC：`chimera_server_lib/src/grpc`
- MCP WebSocket 推送：`chimera_server_lib/src/mcp`
- 运行态与统计：`chimera_server_lib/src/runtime`、`chimera_server_lib/src/traffic`
- TLS/REALITY 相关：`chimera_server_lib/src/reality`
- 构建期 proto 生成：`chimera_server_lib/build.rs`

## 开发约定
- 保持 xray-core 配置字段、默认值与行为一致，尤其是 inbound 相关结构。
- 任何协议新增或变更，需同步更新 config -> ServerConfig -> handler 链路。
- 控制面与数据面分层清晰，避免在数据面引入阻塞或重 IO 操作。
- 对外可观测性优先复用现有统计通道（traffic/gRPC/MCP）。

## 常用命令
- 启动：`cargo run --package chimera_server_app -- --config config.json5`
- 热更新：`./start.sh` 或 `start_server.ps1`
- 测试：`cargo test`
