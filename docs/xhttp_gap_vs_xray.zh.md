# XHTTP 与 Xray-core 差距清单（历史工作文档）

> 本文基线为 2026-02-10，正文保留用于追踪历史演进，未勾选项不再代表当前实现状态。2026-08-06 的实现已覆盖 VLESS XHTTP inbound/outbound、H2/H3、`stream-one`/`stream-up`/`packet-up`/`auto`、metadata/data placement、流控与 TTL、TLS/REALITY、`xPaddingObfs*`、独立 `downloadSettings`、H2/H3 `xmux` 连接复用，以及 native VLESS UDP 与 `packetEncoding: "xudp"`；上述能力均有 Chimera↔Xray 真实进程互通测试。剩余明确边界是 Unix-domain XHTTP listener 尚未实现；HTTP/1.1 仅开放可靠的 `packet-up`/`auto`，`stream-one`/`stream-up` 因 Go HTTP/1.x request-body 半双工限制保持 fail-closed。

## 文档目的
用于记录 Chimera_Server 当前 `xhttp` 与 `xray-core` 的差距，并作为后续逐步完善的执行清单。

## 基线信息
- 更新日期：2026-02-10
- Xray-core 基线：`main` @ `12ee51e4bb1d02ece4ef4b7114efa2bcdc130995`（提交时间：2026-02-06 09:42:41 +0000）
- Chimera 基线：本仓库当前工作区（`chimera_server_lib`）

## 当前实现概况（基于最新本地代码）
- `xhttp` 目前是顶层 inbound 协议：`protocol: "xhttp"`，通过 `settings.upstream` 转发到上游 TCP。
  - 证据：`chimera_server_lib/src/config/server_config/builder/mod.rs:241`
- `streamSettings.network = xhttp/splithttp` 这条 transport 路径当前不存在。
  - 证据：`chimera_server_lib/src/config/mod.rs:49`
- 当前解析字段为 `upstream/host/path/headers/xPaddingBytes`，无 `mode` 字段。
  - 证据：`chimera_server_lib/src/config/server_config/builder/collectors.rs:273`
  - 证据：`chimera_server_lib/src/config/server_config/types.rs:111`
- 服务端实现是 Axum 的 `GET + POST` 路由，固定“下行 GET + 上行 POST(带 seq)”模型。
  - 证据：`chimera_server_lib/src/beginning/xhttp.rs:51`
  - 证据：`chimera_server_lib/src/beginning/xhttp.rs:262`

## 主要差距（按优先级）

### P0（直接影响互通/可用性）

- [ ] G1: 入口语义与 xray 不一致（transport vs 独立 inbound）
  - 当前 Chimera：`xhttp` 只能作为 `protocol` 使用。
  - xray 语义：`xhttp/splithttp` 主要是 transport（挂在 `streamSettings`）。
  - Chimera 证据：
    - `chimera_server_lib/src/config/server_config/builder/mod.rs:241`
    - `chimera_server_lib/src/config/mod.rs:49`
  - Xray 证据：
    - `transport/internet/splithttp/config.proto:25`

- [ ] G2: 无 inner protocol handler 链（仅 raw upstream 转发）
  - 当前 Chimera 的 `Xhttp` 不携带 `inner`，由 `session -> TcpStream(upstream)` 直接转发。
  - 这和 xray 的“transport 层承载上层协议”模型不一致。
  - Chimera 证据：
    - `chimera_server_lib/src/config/server_config/types.rs:191`
    - `chimera_server_lib/src/beginning/xhttp.rs:350`

- [ ] G3: `mode` 能力缺失（stream-one/stream-up/packet-up/auto 语义未显式实现）
  - 当前配置里没有 `mode`；上行路径强制 `/{session}/{seq}`，本质只覆盖固定 packet 化上传。
  - Chimera 证据：
    - `chimera_server_lib/src/config/server_config/builder/collectors.rs:273`
    - `chimera_server_lib/src/beginning/xhttp.rs:270`
  - Xray 证据：
    - `transport/internet/splithttp/config.proto:28`
    - `transport/internet/splithttp/hub.go:207`
    - `transport/internet/splithttp/hub.go:345`

- [ ] G4: 安全层与传输矩阵缺失（TLS/REALITY/h3/UNIX）
  - 当前 `xhttp` 监听仅 TCP，未见 TLS/REALITY 包装与 HTTP/3 监听分支。
  - Chimera 证据：
    - `chimera_server_lib/src/beginning/xhttp.rs:55`
  - Xray 证据：
    - `transport/internet/splithttp/hub.go:458`
    - `transport/internet/splithttp/hub.go:467`
    - `transport/internet/splithttp/hub.go:504`
    - `transport/internet/splithttp/hub.go:509`

### P1（兼容语义与可配置能力）

- [ ] G5: 配置面过窄（大量 xray 字段未接入）
  - 当前仅解析：`upstream/host/path/headers/xPaddingBytes`。
  - xray 还包括：`mode`、`noGRPCHeader`、`noSSEHeader`、`sc*`、`xmux`、`downloadSettings`、`xPaddingObfs*`、`uplinkHTTPMethod`、`sessionPlacement/seqPlacement`、`uplinkDataPlacement` 等。
  - Chimera 证据：
    - `chimera_server_lib/src/config/server_config/builder/collectors.rs:273`
  - Xray 证据：
    - `transport/internet/splithttp/config.proto:25`

- [ ] G6: 元信息与数据放置策略缺失（当前固定 path + body）
  - 当前 `session/seq` 仅从 path 读取，上传数据仅请求体。
  - 不支持 query/header/cookie 放置策略。
  - Chimera 证据：
    - `chimera_server_lib/src/beginning/xhttp.rs:262`
    - `chimera_server_lib/src/beginning/xhttp.rs:291`
  - Xray 证据：
    - `transport/internet/splithttp/config.go:113`
    - `transport/internet/splithttp/config.go:199`
    - `transport/internet/splithttp/hub.go:193`

- [ ] G7: 流控与保护不足（大小限制、缓冲上限、会话回收）
  - 当前代码未体现 `scMaxEachPostBytes`、`scMaxBufferedPosts`、`scMinPostsIntervalMs` 等防护。
  - `packet_queue` 无上限；会话 map 也无 TTL 回收路径（仅依赖 GET 生命周期触发删除）。
  - Chimera 证据：
    - `chimera_server_lib/src/beginning/xhttp.rs:292`
    - `chimera_server_lib/src/beginning/xhttp.rs:335`
    - `chimera_server_lib/src/beginning/xhttp.rs:369`
  - Xray 证据：
    - `transport/internet/splithttp/config.go:94`
    - `transport/internet/splithttp/hub.go:73`
    - `transport/internet/splithttp/hub.go:185`

- [ ] G8: xPadding 高级语义缺失（obfs/placement/method）
  - 当前仅校验 `x_padding` 长度（query 或 Referer.query）。
  - 未接入 `xPaddingObfsMode`、`xPaddingPlacement`、`xPaddingMethod`、`xPaddingKey/Header`。
  - Chimera 证据：
    - `chimera_server_lib/src/beginning/xhttp.rs:171`
    - `chimera_server_lib/src/beginning/xhttp.rs:420`
  - Xray 证据：
    - `transport/internet/splithttp/xpadding.go:224`
    - `transport/internet/splithttp/xpadding.go:280`

- [ ] G9: 路径规范化语义与 xray 存在偏差
  - 当前 `normalize_path` 不处理 query 拆分（xray 会先 split `?` 再规范化 path）。
  - Chimera 证据：
    - `chimera_server_lib/src/config/server_config/builder/collectors.rs:346`
  - Xray 证据：
    - `transport/internet/splithttp/config.go:14`

### P2（工程化与观测）

- [ ] G10: grpc handler 对 Xhttp 身份收集为空
  - 影响：控制面用户身份可观测性不足。
  - Chimera 证据：
    - `chimera_server_lib/src/grpc/handler.rs:56`

- [ ] G11: feature gate 与文档/测试覆盖不足
  - 当前 `Cargo.toml` features 未见 `xhttp` 独立开关；`config` README 中也无 xhttp 章节；仓库内未见 xhttp 专项单测。
  - Chimera 证据：
    - `chimera_server_lib/Cargo.toml:58`
    - `chimera_server_lib/src/config/README.md:1`

## 分阶段完善建议（可逐步打勾）

### 阶段 1：恢复与 xray 语义接近的入口模型
- [ ] 增加 `streamSettings.network = xhttp/splithttp` 的 transport 入口。
- [ ] 为 `vless/trojan/socks` 等协议接入 xhttp 包裹链路（inner protocol）。
- [ ] 明确 `protocol: xhttp` 的定位（保留为兼容模式或改为内部实现细节）。

### 阶段 2：先补齐互通关键能力
- [ ] 接入 `mode` 并实现 `stream-one/stream-up/packet-up/auto` 行为。
- [ ] 接入 `sessionPlacement/seqPlacement/uplinkDataPlacement` 及 key 配置。
- [ ] 接入 `uplinkHTTPMethod`、`noSSEHeader`、`noGRPCHeader`。

### 阶段 3：补齐稳定性与传输能力
- [ ] 接入 `scMaxEachPostBytes/scMaxBufferedPosts/scMinPostsIntervalMs/scStreamUpServerSecs`。
- [ ] 会话 TTL 清理、队列上限、上传限流与异常回收。
- [ ] 接入 TLS/REALITY/h3/UNIX（至少先补 TLS + h3 路径）。

### 阶段 4：高级能力与收口
- [ ] 接入 `downloadSettings` 与 `xmux`。
- [ ] 接入 `xPaddingObfs*`。
- [ ] 完成 grpc/mcp/traffic 身份和指标口径对齐。
- [ ] 增加 xhttp 解析与互通测试矩阵（最小样例 + 典型样例）。

## 验证建议
- 配置检查：`cargo run --package chimera_server_app -- --check`
- 全量 lint：`cargo clippy --all-targets --all-features -- -D warnings`
- 重点测试：`cargo test -p chimera_server_lib --lib`

## 外部参考（固定基线）
- Xray `config.proto`:
  - `https://github.com/XTLS/Xray-core/blob/12ee51e4bb1d02ece4ef4b7114efa2bcdc130995/transport/internet/splithttp/config.proto`
- Xray `hub.go`:
  - `https://github.com/XTLS/Xray-core/blob/12ee51e4bb1d02ece4ef4b7114efa2bcdc130995/transport/internet/splithttp/hub.go`
- Xray `config.go`:
  - `https://github.com/XTLS/Xray-core/blob/12ee51e4bb1d02ece4ef4b7114efa2bcdc130995/transport/internet/splithttp/config.go`
- Xray `xpadding.go`:
  - `https://github.com/XTLS/Xray-core/blob/12ee51e4bb1d02ece4ef4b7114efa2bcdc130995/transport/internet/splithttp/xpadding.go`
- Xray `dialer.go`:
  - `https://github.com/XTLS/Xray-core/blob/12ee51e4bb1d02ece4ef4b7114efa2bcdc130995/transport/internet/splithttp/dialer.go`
