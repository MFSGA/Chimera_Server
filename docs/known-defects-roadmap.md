# Chimera_Server 已知缺陷与渐进式实现路线

> 本文记录当前代码检查发现、但尚未完成修复的问题，供后续 AI 或开发者逐项实现。
>
> 明确排除：本文不记录此前列出的第 1 条“gRPC 控制面缺少 TLS/认证”问题。该问题需要单独制定安全方案，不纳入本路线图。

## 当前基线

- 检查分支：`master`
- 检查时间：2026-09-03
- `cargo test --all-features`：已通过当前启用的测试
- `cargo clippy --all-targets --all-features -- -D warnings`：已通过
- 被忽略的测试：99 个，包含 Xray、REALITY、XHTTP、gRPC 等互操作场景

“启用测试通过”只说明现有测试覆盖范围内没有失败，不代表下面的运行时、策略一致性和互操作问题已经解决。

## 优先级定义

- **P1**：可能造成访问控制绕过、旧配置继续提供服务，或影响运行时安全边界。
- **P2**：会造成策略不一致、资源增长、性能退化或公共 API 行为错误。
- **P3**：能力缺失、验证不足或主要影响可维护性和使用体验。

---

## P1：UDP 路径绕过用户域名策略

### 现状

TCP 或部分协议路径会调用用户域名访问检查：

```rust
runtime.allows_user_domain_access(&input.user, &input.target_domain)
```

位置：`chimera_server_lib/src/outbound.rs:150-180`。

但是 Shadowsocks UDP 和 Dokodemo UDP 使用 `select_udp_outbound`：

```rust
let outbound = select_udp_outbound(
    &runtime,
    &route_input,
    ...
)?;
```

位置：

- `chimera_server_lib/src/beginning/udp.rs:1671-1691`
- `chimera_server_lib/src/beginning/udp.rs:1813-1829`
- `chimera_server_lib/src/beginning/udp.rs:2013-2057`

该选择函数没有调用 `allows_user_domain_access`，构造的 `RoutingInput` 也没有携带用户身份，通常会使用空用户：

```rust
let route_input = RoutingInput {
    user: String::new(),
    ...
};
```

### 影响

用户级 `reject` 或域名白名单规则在这些 UDP 路径上可能不生效。尤其是 Shadowsocks UDP 请求已经具备 `request.identity`，但身份没有传到路由和策略检查阶段。

### 实现要求

1. 统一 TCP 和 UDP 的路由前置流程：身份解析、域名策略检查、路由选择、outbound 创建。
2. `select_udp_outbound` 必须接收完整的用户身份和目标域名。
3. 不允许通过把用户设置为空字符串来跳过用户策略。
4. 为 Shadowsocks UDP、Dokodemo UDP 增加用户拒绝和允许场景测试。

### 验收标准

- 同一用户对同一域名的 TCP 和 UDP 请求得到一致的允许/拒绝结果。
- 用户级 `reject` 规则能够阻止 Shadowsocks UDP 和 Dokodemo UDP。
- 无身份请求仍按明确的匿名用户策略处理，而不是隐式绕过检查。

---

## P1：共享 SOCKS UDP 模式丢失用户身份

### 现状

共享 UDP listener 中，路由输入的用户被硬编码为空字符串：

```rust
let route_input = connection_routing_input(
    inbound_tag,
    "",
    3,
    ...
);
```

位置：`chimera_server_lib/src/handler/socks.rs:851-866`。

另一个连接级 UDP 路径会提取并传递身份，位置为 `chimera_server_lib/src/handler/socks.rs:1013-1029`，两条路径行为不一致。

### 影响

如果 SOCKS 使用用户名密码区分用户，共享 UDP 模式会以匿名用户参与路由和域名策略判断，导致用户级规则无法生效。

### 实现要求

1. 在共享 UDP 模式中解析 SOCKS 认证身份，并将其写入 `TrafficContext` 或等价的请求上下文。
2. `connection_routing_input` 不再接受隐式空用户作为正常路径参数。
3. 明确无认证 SOCKS 请求的匿名身份语义。
4. 添加多用户共享 UDP 的隔离测试。

### 验收标准

- 用户 A 和用户 B 使用同一 SOCKS UDP listener 时，能够命中各自的规则。
- 用户 A 被拒绝的域名不能通过用户 B 或匿名身份绕过。
- 无认证请求的行为由测试固定下来。

---

## P1/P2：删除或修改入站后，子任务不会立即停止

### 现状

运行时停止入站时只管理顶层 listener task：

```rust
pub async fn stop_inbound_tasks(&self, tag: &str) -> Result<()> {
    ...
    handle.abort();
    handle.await?;
}
```

位置：`chimera_server_lib/src/runtime.rs:135-153`。

但是 TCP accept 后会创建未登记的任务：

```rust
tokio::spawn(async move {
    process_stream_with_context(...).await
});
```

位置：`chimera_server_lib/src/beginning/mod.rs:290-305`。

UDP 也会按数据包创建 detached task：

- `chimera_server_lib/src/beginning/udp.rs:1632-1668`
- `chimera_server_lib/src/beginning/udp.rs:1787-1809`

控制面删除和修改入站时会调用停止逻辑：

- `chimera_server_lib/src/grpc/handler.rs:2238-2251`
- `chimera_server_lib/src/grpc/handler.rs:2272-2307`

### 影响

停止 listener 不等于停止已有连接和数据包任务。旧连接可能继续使用旧配置转发，策略更新也不能立即覆盖已经建立的流量，同时可能造成任务和资源延迟回收。

### 实现要求

1. 每个 inbound 创建独立的 `CancellationToken`。
2. TCP 子连接、UDP 数据包任务和相关 handler 都监听该 token。
3. 使用 `JoinSet` 或任务注册表统一追踪和回收子任务。
4. 删除、修改、重启 inbound 时，先取消旧任务，再等待其退出，最后启动新任务。
5. 为长连接和正在转发的 UDP 请求增加生命周期测试。

### 验收标准

- inbound 删除后，已有连接不能继续产生新的转发流量。
- inbound 修改后，不会再出现旧配置和新配置同时处理同一入站的情况。
- 所有子任务在停止流程结束后都已退出或进入明确的超时处理。

---

## P2：用户域名策略 revision 历史无限增长

### 现状

策略状态保存所有发布版本：

```rust
revisions: BTreeMap<u64, UserDomainAccessPublication>
```

位置：`chimera_server_lib/src/user_domain.rs:163-168`。

每次 apply 都保存完整 publication，但没有淘汰旧版本：

```rust
self.revisions.insert(version, publication);
```

位置：`chimera_server_lib/src/user_domain.rs:177-204`。

### 影响

持续提交合法策略会让进程内存持续增长。虽然单个策略有用户数、规则数和字节数限制，但 revision 总数量没有限制。

### 实现要求

1. 明确 rollback 的保留范围。
2. 默认只保留最近 N 个 revision，N 应可配置或有明确常量。
3. 淘汰旧版本时保留当前版本和必要的回滚版本。
4. 为 revision 数量和内存上限增加测试。

### 验收标准

- 连续发布大量策略后，revision 数量有确定上限。
- 回滚到保留范围内的版本仍然有效。
- 回滚到已淘汰版本返回明确错误，而不是静默失败。

---

## P2：策略检查使用阻塞锁和线性搜索

### 现状

每次策略检查都获取 `std::sync::RwLock` 的写锁：

```rust
let mut state = self.state.write()?;
```

位置：`chimera_server_lib/src/user_domain.rs:239-253`。

用户和规则匹配均采用线性遍历：

```rust
users.iter().find(...)
```

位置：

- `chimera_server_lib/src/user_domain.rs:311-314`
- `chimera_server_lib/src/user_domain.rs:329-333`

### 影响

并发数据面请求会争抢阻塞锁，用户数和规则数增加后，连接建立或首包处理成本会线性增长。这不符合项目要求的数据面非阻塞原则。

### 实现要求

1. 将策略编译为不可变的 `Arc` 快照。
2. 使用身份到用户的索引，避免每次扫描全部用户。
3. 预编译域名规则或建立更高效的匹配结构。
4. 将统计更新与策略快照读取分离，避免每次判断获取写锁。
5. 用基准测试验证大规模用户和规则下的延迟。

### 验收标准

- 普通策略读取不再依赖数据面上的阻塞写锁。
- 用户身份查找不再是 O(用户数) 的全量扫描。
- 统计功能不会显著延长策略判断临界区。

---

## P2：不同用户之间允许重复协议身份

### 现状

当前校验主要检查 `user_uuid` 是否重复：

```rust
let mut user_ids = HashSet::new();
```

位置：`chimera_server_lib/src/user_domain.rs:425-434`。

但身份匹配支持多个协议字段：

```rust
vless_uuid
vmess_uuid
tuic_uuid
username
password
```

位置：`chimera_server_lib/src/user_domain.rs:275-290`。

最终使用第一个匹配用户：

```rust
users.iter().find(...)
```

### 影响

两个用户使用相同 VLESS UUID、VMess UUID 或用户名密码时，实际权限取决于配置顺序，可能造成错误授权或错误拒绝。

### 实现要求

1. 将每一种协议身份规范化为统一的身份键。
2. 在策略发布前检查跨用户重复身份。
3. 对大小写、空白、空值和协议字段差异定义统一规则。
4. 错误信息应指出冲突身份类型和相关用户。

### 验收标准

- 重复协议身份无法发布。
- 不同协议之间不会错误地互相冲突。
- 身份冲突错误可被 API 调用方理解和处理。

---

## P2：`ConfigType::Str` 会触发 `todo!()` panic

### 现状

公共配置类型暴露了字符串来源：

```rust
pub enum ConfigType {
    File(String),
    Str(String),
}
```

但解析时只实现了文件分支：

```rust
match self {
    ConfigType::File(file) => ...,
    _ => todo!(),
}
```

位置：`chimera_server_lib/src/lib.rs:62-80`。

### 影响

库调用方传入 `ConfigType::Str` 会 panic，而不是得到可处理的 `Result` 错误。该行为不符合公共 API 的错误处理约定。

### 实现要求

1. 实现字符串配置的解析。
2. 明确字符串默认采用 JSON、JSON5 还是 YAML。
3. 对格式错误返回 `InvalidConfig` 或等价的显式错误。
4. 为 JSON5/YAML 与文件配置路径分别增加测试。

### 验收标准

- `ConfigType::Str` 不再触发 panic。
- 合法字符串配置和文件配置得到一致的 `LiteralConfig`。
- 非法内容返回结构化错误。

---

## P2：外部配置加载缺少超时和响应大小限制

### 现状

HTTP 配置使用 blocking client，但没有设置超时或响应大小上限：

```rust
let client = reqwest::blocking::Client::new();
let response = client.get(url).send()?;
let content = response.text()?;
```

位置：`chimera_server_lib/src/config_loader.rs:76-100`。

Unix socket 配置使用无上限的 `read_to_end`：

位置：`chimera_server_lib/src/config_loader.rs:128-161`。

### 影响

- 远程配置服务不响应时，启动或校验可能长时间阻塞。
- 异常响应可能导致不必要的内存消耗。
- 外部配置源的资源边界不明确。

### 实现要求

1. 配置连接超时、请求超时和整体读取超时。
2. 对 HTTP 响应检查 `Content-Length`，并限制实际读取字节数。
3. 对 Unix socket 使用有上限的读取逻辑。
4. 超时和超限错误需要带有配置源信息。
5. 添加超时、超限和截断响应测试。

### 验收标准

- 配置源异常时能在确定时间内失败返回。
- 响应体超过上限时不会继续读取。
- 错误信息能定位到具体 URL 或 socket。

---

## P3：未实现的 outbound 可能通过配置校验后才在请求时失败

### 现状

Outbound 配置目前主要只有协议名和 tag：

```rust
pub struct OutboundItem {
    pub protocol: String,
    pub tag: String,
}
```

位置：`chimera_server_lib/src/config/def.rs:117-121`。

实际运行时只处理 `freedom` 和 `blackhole`：

```rust
"freedom" => ...,
"blackhole" => ...,
_ => Err(...),
```

位置：

- `chimera_server_lib/src/outbound.rs:150-180`
- `chimera_server_lib/src/beginning/udp.rs:2034-2057`

### 影响

配置中的 `vless`、`vmess`、`socks`、`hysteria` 等 outbound 可能通过解析和启动，但第一个请求到来时才报“不支持协议”。这会让服务处于“看似启动成功、实际无法转发”的状态。

### 实现要求

1. 明确当前版本支持的 outbound 协议集合。
2. 尚未实现的协议在启动阶段拒绝，而不是请求阶段才失败。
3. 每个已支持协议补齐配置结构、`ServerConfig` 转换、handler/runtime 行为和测试。
4. TCP 与 UDP 对 outbound 能力的判断保持一致。

### 验收标准

- 未实现 outbound 在配置校验阶段明确报错。
- 已实现 outbound 启动后可以完成最小 TCP/UDP 转发。
- 配置文档与运行时实际能力一致。

---

## P3：关键互操作测试仍被忽略

### 现状

当前共有 99 个 ignored tests，包含以下关键场景：

- Xray Shadowsocks 2022
- Xray Hysteria2
- Xray gRPC
- REALITY Vision
- TLS Vision
- XHTTP 多种组合
- fallback 和负向校验

### 影响

当前测试只能证明已启用测试通过，无法充分证明与 Xray 的握手、默认值、错误处理和长连接行为兼容。

### 实现要求

1. 标记每个 ignored test 的环境依赖和忽略原因。
2. 先恢复与当前主协议目标相关的测试。
3. 将需要外部 Xray 进程的测试改为可重复启动的 fixture 或容器测试。
4. 将协议互操作测试纳入发布前检查。

### 验收标准

- 关键协议测试不再无原因地 ignored。
- 忽略测试都有明确的环境前置条件。
- 发布目标对应的 Xray 互操作测试在 CI 中执行。

---

## 建议的 AI 实施顺序

后续每次只实现一个垂直小切片，并在进入下一项前完成格式化、编译和针对性测试：

1. 统一 UDP 用户身份和域名策略检查。
2. 修复共享 SOCKS UDP 身份传递。
3. 为 inbound 增加取消和子任务回收。
4. 将用户策略改为不可变快照和索引查找。
5. 限制 revision 历史并补充回滚边界。
6. 禁止跨用户重复协议身份。
7. 实现 `ConfigType::Str` 并补齐错误处理。
8. 为外部配置加载增加超时和响应大小限制。
9. 在启动阶段拒绝未实现的 outbound。
10. 分批恢复 Xray/REALITY/XHTTP 互操作测试。

每个实现切片都应至少包含：代码变更、对应单元或集成测试、`cargo fmt --all -- --check`、相关 `cargo test`，以及必要的变更说明。
