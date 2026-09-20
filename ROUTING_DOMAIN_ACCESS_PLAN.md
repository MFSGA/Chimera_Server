# Linux 用户域名访问控制与 Xray Routing 兼容计划

## 1. 文档目的

本文定义 Chimera Server routing 模块下一阶段的实现范围、行为契约、迁移顺序和验收标准。

本计划的核心目标是：

> 在 Linux 服务端实现按用户限制可访问域名的能力，同时保持 Xray-compatible 配置和可观察语义。内部 Rust 模块、数据结构和任务组织可以与 xray-core 不同。

本文不是 Xray 全部 routing 功能的实现承诺，也不是要求复制 xray-core 的 Go 代码结构。

## 当前实施进度（2026-09-16）

本轮已补齐 Xray DNS `clientIp`：顶层值作用于 plain UDP nameserver，nameserver 对象的 `clientIp` 可覆盖顶层值；查询按 Xray 生成 IPv4 `/24` 或 IPv6 `/96` 的 EDNS Client Subnet。配置和 resolver wire/override 回归测试已通过，DoH/DoT 等其他 nameserver 传输仍未纳入本切片。

随后完成了 Xray DNS 顶层 `disableCache`：`true` 时共享 resolver 绕过 DNS 结果缓存，`false`/省略保持既有缓存行为；nameserver 对象级 `disableCache` 尚未实现并继续显式拒绝。

本轮随后增加了字符串形式 `tcp://IP[:port]` 的 DNS nameserver：使用 Xray/RFC 7766 的两字节长度前缀收发 DNS 报文，复用现有 queryStrategy、ECS、超时、IP 筛选和 fallback；nameserver 高级对象仍为 UDP-only，DoH/DoT 和经 dispatcher 的远程 DNS 仍未实现。

随后接入了顶层 `dns.enableParallelQuery`：默认关闭时保持顺序查询；启用时按相邻且策略等价的 nameserver 分组并发查询，只有高优先级分组全部失败后才接受低优先级分组结果。

随后补齐了 Shadowsocks 用户身份映射：`userDomainAccess.protocolIdentity.shadowsocksEmail` 对应 Xray Shadowsocks 入站认证后 `MemoryUser.Email` 的 routing user；旧策略省略该字段时仍按默认空值处理。

按当前迭代指令，本轮协议范围收敛为 VLESS、XHTTP（VLESS 的 XHTTP 传输）、Hysteria2、Socks5 和 Trojan；Shadowsocks 的后续身份/传输扩展暂缓，已完成的 Shadowsocks 证据保留但不继续扩大范围。其他协议暂不作为本轮域名访问控制目标，若配置命中未实现的协议身份或组合，应返回明确的“不支持”诊断。

本轮新增的诊断切片已完成：routing metadata 现在同时保留实际入站协议和
sniffing 得到的 payload 协议，避免把 `http1`/`tls` 误当成入站协议。用户域名策略在
检测到非本轮目标协议时，按 `inbound_tag + protocol` 有界去重并输出
`user_domain_access_unsupported_protocol` warning；该 warning 不改变既有 allow/reject
决策，也不保存认证凭据。VLESS、XHTTP、Hysteria2、Socks5 和 Trojan 不触发该诊断；
VMess、TUIC、HTTP、Shadowsocks 等协议仍不纳入本轮新的兼容性声明。

Hysteria2 UDP 的目标解析顺序也已收紧：新 session 的首次目标以及完整分片后发生变化的
目标，都会先执行用户域名策略，再调用 resolver；拒绝路径不会为该目标创建 UDP session
或发起 DNS 查询。转发前仍保留一次统一 outbound routing 检查，以覆盖策略动态更新和
session 内目标变化。该切片已有本地策略回归，真实 Xray Hysteria2 UDP allow/reject 互操作
已通过；测试同时覆盖 Hysteria2 TCP 和 UDP 的用户域名 allow/reject。

Socks5 UDP 用户域名策略的真实覆盖也已补齐：服务端 `settings.udp` 开启后，UDP
ASSOCIATE 与 TCP CONNECT 都复用统一的 `select_direct_outbound_for_location`，认证后的
用户名继续作为 Xray routing user。Xray 26.2.6/Linux 的允许/拒绝域名 TCP/UDP
allow/reject 互操作均已通过。

Trojan UDP 用户域名策略的真实覆盖也已补齐：Trojan 的 `CMD_UDP_ASSOCIATE` 进入
targeted UDP relay，在创建 UDP session 前复用统一域名策略检查，认证 password identity
保持可用于用户匹配。Xray 26.2.6/Linux 的 Trojan TCP/UDP allow/reject 互操作均已通过。

说明：阶段 4 原记录中的 1464 个测试是本轮新增 resolver 能力之前的基线；加入 `clientIp`、`disableCache`、DNS-over-TCP 和 `enableParallelQuery` 回归后为 1474 个通过；加入 Shadowsocks email 身份策略回归、协议诊断和 Hysteria2 UDP 顺序回归后，当前完整库测试为 1477 个通过。

阶段 2 的一个身份映射切片已完成：`protocolIdentity.shadowsocksEmail` 对应 Xray Shadowsocks 入站认证产生的 `MemoryUser.Email`，并在用户域名策略匹配中生效；省略该可选字段的旧策略保持兼容。已通过 `user_domain::tests::policy_matches_shadowsocks_email_identity` 和 Linux 上 Xray 26.2.6 的 Shadowsocks TCP/legacy UDP/2022 EIH UDP allow/reject 互操作测试。

已完成第一步“阶段 3：未知目标放行并审计”：[user_domain.rs](chimera_server_lib/src/user_domain.rs) 现在会在用户策略查找前识别空域名、直接 IP 或无法规范化的目标，并固定返回 allow；启用策略时记录 `user_domain_access_unknown_target` 结构化事件，策略统计记录 `UnknownTarget`。数据面和 `TestRoute` 已传入 inbound、协议、网络、目标和 routing user 摘要，routing user 只记录 SHA-256 摘要；同一审计维度在 1 秒窗口内去重，内存键上限为 4096，统计不去重。旧 `unknownTargetAction: reject` 仍可被已有 Chimera 发布物携带，但加载时会明确告警且不再改变放行语义。

阶段 4 已完成 resolver 实现切片：新增 Xray `dns.hosts` 的静态 IP 映射，支持单 IP、多 IP、大小写、末尾点、IDN 规范化以及 `full:`、`domain:`、`keyword:`、`regexp:`、`dotless:` 规则；多个命中规则的 IP 会合并，`proxiedDomain` 会按 Xray 语义递归替换域名并限制最大深度，替换后的别名未命中静态 hosts 时继续使用最终别名进行 DNS 查询；响应码 host 值（如 `#3`，`#0` 表示空响应）命中后直接返回 DNS 错误，不回落到上游 nameserver。随后增加了 plain UDP `dns.servers` 的单字符串/字符串数组配置、默认 53 端口、A/AAAA 查询、多个服务器顺序尝试和共享 resolver 接入，并支持全局 `queryStrategy` 的地址族选择以及 `disableFallback`/`disableFallbackIfMatch`；现在还支持 nameserver 基础对象的 `address`、`port`、`domains`、单服务器 `queryStrategy`、`skipFallback`、`finalQuery`、`timeoutMs`、`expectedIPs`/`expectIPs` 和 `unexpectedIPs`，以及字符串形式的 `tcp://IP[:port]` nameserver；全局策略会作为未覆盖服务器的默认值，匹配的 nameserver 会按 Xray 规则优先尝试，响应地址会按 Xray IP 规则筛选，筛选后为空会继续尝试下一个 nameserver。`RuntimeState` 持有共享 resolver，启动配置、`TestRoute` 和主要 TCP/UDP 数据面使用同一实例。其他 fallback 字段、URL、DoH/DoT 等字段目前会显式报“不支持”，不会被静默忽略。随后补齐了 route-only sniffed domain 与原始目标 IP 的边界：数据面区分原始 IP 和 resolver 输出，使 `AsIs`、`IpIfNonMatch`、`IpOnDemand` 的 DNS 时机与 Xray 路由上下文一致；`TestRoute` 的调用方提供 IP 仍按既有“已解析候选”语义处理。阶段 4 早期的定向验证为 `cargo test -p chimera_server_lib --lib`（1464 passed）；加入 `clientIp`、`disableCache`、DNS-over-TCP 后、但尚未加入 `enableParallelQuery` 时为 1471 passed；当前完整库测试为 1474 passed，all-features 工作区编译和 no-default-features 库编译也已通过。

阶段 3 的实现切片及真实 Xray 客户端验证均已完成：VLESS TCP 通过直接 IP 目标成功回显，并在 Chimera stderr 中捕获 `user_domain_access_unknown_target` 审计事件。

阶段 5 已完成第一个实现切片：VLESS/VMess XUDP 的 `SessionMessage` 现在保留原始 `NetLocation`，不再在 XUDP 消息流内部提前解析域名；`run_session_based_udp` 先通过共享 resolver 执行用户域名策略和 Xray routing，再仅在选定 outbound 确实需要目标地址时解析。已增加“拒绝域名在 DNS 之前被策略拦截”的回归测试。已用 Xray 26.2.6 真实客户端验证 VLESS TCP/XUDP、Trojan TCP/UDP、Hysteria2 TCP/UDP、Socks5 TCP/UDP、VLESS XHTTP over TCP 的允许/拒绝域名场景，以及 VLESS TCP 直接 IP 的放行和审计；更多目标组合仍待执行，VMess/HTTP/其他协议本轮不再扩展。

阶段 6 已完成第一个控制面切片：`RoutingService.AddRule` 的 Xray typed-message 路径已用 `user_email + full:domain` 规则测试，并由 `TestRoute` 验证用户与域名条件同时生效；`UserDomainAccessService` 的 `ApplyPolicy`、`GetPolicyStatus` 和 `RollbackPolicy` 也已完成服务层回归测试。该结果证明控制面入口和运行时状态连接正确，但尚不等于所有真实远程调用、跨节点更新或所有协议组合都已完成互操作验证。

阶段 6 的第二个切片也已完成：Linux 实际 SOCKS TCP 数据面在动态策略更新前允许 `allowed.example` 回显；通过 gRPC 应用 `defaultAction=reject` 后，新建 `blocked.example` 请求被拒绝。该结果证明新建 TCP 会话会消费更新后的策略；真实 Xray 远程控制面更新、既有连接边界、统计运维查询和其他协议/传输组合仍待验证。

阶段 6 的第三个切片已完成运行时 XUDP 验证：在同一个 session-based XUDP relay 已经处理完第一条域名会话后，运行时发布 `defaultAction=reject`，随后创建的第二条域名会话被 `userDomainAccess` 拒绝，且不会触达 UDP echo socket。该测试证明 XUDP 数据面读取的是共享的最新策略，而不是连接建立时复制的旧快照；它尚不等于真实 Xray 客户端通过远程 gRPC 更新后发起 XUDP 的完整互操作验证。

阶段 6 的第四个切片已完成并发版本发布回归：两个任务同时提交同一版本时只有一个能成为 active publication，另一个得到 `FailedPrecondition`；active 版本保持完整且唯一。该测试覆盖策略存储的版本闸门和原子替换，不等于高并发真实 gRPC 压测或跨节点一致性验证。

阶段 6 的第五个切片已完成真实远程 XUDP 控制面验证：Xray 26.2.6 客户端先通过 XUDP 成功访问 `allowed.example`，再通过 TCP gRPC 调用 Chimera 的 `UserDomainAccessService/ApplyPolicy`，随后新建的 `blocked.example` XUDP 请求未成功回显。该结果证明远程策略发布能够到达正在运行的 XUDP 数据面；不覆盖既有 session 的策略生命周期、GlobalID 跨连接重附着或其他传输组合。

阶段 6 的第六个切片已完成 DNS 失败统计：`TestRoute` 和 TCP/UDP 共享 outbound 解析路径在 resolver 返回错误或空地址时，返回明确的 DNS 错误并增加 `GetPolicyStatus.stats.dnsFailures`，不会增加域名策略的 `rejected` 计数。该字段是 Chimera protobuf 的向后兼容扩展；真实高并发统计查询仍待实现。

阶段 6 的第七个切片已完成审计运维查询：新增 Chimera `UserDomainAccessService/GetAuditEvents`，返回最近的 unknown-target allow 事件，按最新优先排列；查询默认 100 条、上限 1000 条，运行时仅保留最多 1024 条且限制字段长度。事件中的 routing user 继续使用 SHA-256 摘要，不保存认证凭据；策略重新激活或回滚时清空旧版本事件。已通过服务层测试和 Linux 实际 TCP gRPC 进程测试。

当前工作树的 Clippy 全量检查仍未通过，命中的是已有的 `outbound.rs` 未使用导入、`beginning/udp.rs` 的大枚举以及 `outbound/routing.rs` 的 `manual_inspect` 建议；本次 `dns.hosts`/plain UDP-TCP resolver/`queryStrategy`/`enableParallelQuery` 切片未新增 Clippy 错误。该问题应作为后续独立清理切片处理，不能用放宽 lint 的方式掩盖。

## 2. 外部兼容基线

- Xray 源码基线：`ref/xray-core/` 的 Xray-core `v26.9.9`，提交为 `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`（pre-release）。
- 当前兼容性复核使用的 Xray 客户端：`Xray 26.2.6`。
- 平台重点：Linux。
- 兼容目标：Xray 客户端不修改配置即可连接 Chimera；Xray routing 配置在支持范围内产生等价的路由、DNS 时机和失败结果。

Xray 原生规则已经同时包含用户和域名条件：

- [ref/xray-core/app/router/config.proto](ref/xray-core/app/router/config.proto) 的 `user_email` 与 `domain`。
- [ref/xray-core/app/router/config.go](ref/xray-core/app/router/config.go) 将多个条件组合为同一条规则。
- [ref/xray-core/app/router/router.go](ref/xray-core/app/router/router.go) 实现有序规则匹配和 `domainStrategy`。

因此，“按用户限制域名”不是 Xray 不具备的能力。Chimera 的工作重点是把这个能力接入 Linux 数据面，并对当前项目需要的策略管理做兼容扩展。

## 3. 用户需求解释

### 3.1 必须实现的行为

对于已经识别出的目标域名：

```text
认证用户 + 目标域名
        ↓
Xray routing 规则 / 等价的用户域名策略
        ↓
允许：继续选择 outbound
拒绝：进入 blackhole，不建立目标连接
```

例如：

```text
alice@example.com → example.com       允许
alice@example.com → blocked.example   拒绝
bob@example.com   → example.com       按 bob 的规则处理
```

对于没有可确认域名的目标，必须采用以下语义：

```text
只有 IP、没有 SNI/Host、sniffing 未识别出域名
        ↓
域名访问策略不阻断
        ↓
允许继续处理
        ↓
记录 unknown-target 审计日志
```

“未知目标放行”只表示域名访问控制不拒绝该请求。之后仍然可以继续执行普通 Xray routing 的 IP、端口、用户或 outbound 规则；如果用户显式配置了 IP 黑洞规则，那是另一项 routing 决策，不能归因于域名策略。

### 3.2 不改变的行为

- Xray `routing.rules` 仍然是外部兼容的主要规则来源。
- `routing.user` 继续表示 Xray 的用户字段，通常是 email。
- 协议 UUID、密码、SOCKS 用户名等认证凭据不能直接替换 Xray `routing.user` 的语义。
- 规则内部条件按 AND 组合，规则之间按配置顺序执行，第一条匹配规则生效。
- 用户域名策略拒绝必须发生在目标 outbound 建立之前。
- 未识别域名不能触发策略拒绝，也不能因为“无法判断”而静默丢弃。

## 4. 当前实现基础与缺口

当前项目已经具备 routing 基础：

1. `RuleConfig` 已包含 `domain`、`user`、`ip`、端口、网络、协议、属性、进程和 outbound 等字段，见 [chimera_server_lib/src/config/rule/mod.rs](chimera_server_lib/src/config/rule/mod.rs)。
2. `CompiledRule` 已有域名、IP、用户、端口、网络、协议和属性 matcher，见 [chimera_server_lib/src/routing_state/rule.rs](chimera_server_lib/src/routing_state/rule.rs)。
3. `RoutingState` 已实现有序规则匹配及 `AsIs`、`IpIfNonMatch`、`IpOnDemand` 三种域名策略，见 [chimera_server_lib/src/routing_state.rs](chimera_server_lib/src/routing_state.rs)。
4. `select_direct_outbound_for_location` 已在 outbound 选择前执行用户域名策略，见 [chimera_server_lib/src/outbound/routing.rs](chimera_server_lib/src/outbound/routing.rs)。
5. `TestRoute` 已能执行 routing 决策，并在需要时使用 resolver，见 [chimera_server_lib/src/grpc/routing.rs](chimera_server_lib/src/grpc/routing.rs)。
6. `userDomainAccess` 已支持用户映射、allowlist/denylist、exact/suffix、优先级、版本和校验和；协议身份覆盖 VLESS/VMess/TUIC/Hysteria2/Trojan/HTTP/SOCKS，以及 Shadowsocks email。

当前主要缺口不是“有没有 matcher”，而是以下行为是否在所有目标路径中形成一致契约：

- 已识别域名和未知目标的单元/主路径决策边界已固定为本文语义；真实 Xray 客户端的 VLESS TCP/XUDP、Trojan TCP/UDP、Hysteria2 TCP/UDP、Socks5 TCP/UDP、VLESS XHTTP over TCP、Shadowsocks TCP/legacy UDP/2022 EIH UDP 允许/拒绝，以及 VLESS TCP unknown-target 放行和审计已通过，更多目标组合仍待验证。
- Xray 自定义 DNS 目前完成 `dns.hosts` 静态 IP 映射、自定义域名规则匹配、有界 `proxiedDomain` 链、响应码 host 值、基础 plain UDP `dns.servers`、字符串 `tcp://IP[:port]` nameserver、全局 `queryStrategy`、`enableParallelQuery`、全局 `disableFallback`/`disableFallbackIfMatch`、nameserver 基础对象的 `address`、`port`、单服务器 `queryStrategy`、`domains` 优先选择、`timeoutMs`、`expectedIPs`/`expectIPs`/`unexpectedIPs` 响应地址筛选、`skipFallback` 和 `finalQuery`；URL、其他 fallback、DoH/DoT 仍未实现，但会显式拒绝或报错。
- 目标协议的主要认证身份映射已有 TCP/UDP 真实证据；XHTTP 的 TLS/HTTP/3/REALITY 组合、既有连接生命周期和其他未验证传输仍需要逐组合核验。
- Shadowsocks 的 `email` 已映射为 `protocolIdentity.shadowsocksEmail` 并加入策略匹配；Linux 上 Xray 26.2.6 的 Shadowsocks TCP/legacy UDP/2022 EIH UDP 域名策略 allow/reject 互操作已通过，后续 Shadowsocks 扩展按当前任务暂缓。
- XHTTP 当前复用 VLESS UUID 身份；Linux 上 Xray 26.2.6 XHTTP over TCP 的 security none/TLS userDomainAccess allow/reject 互操作已通过，HTTP/3/REALITY 组合仍待单独核验。Socks5 用户名身份和 Trojan password identity 的 Linux TCP/UDP allow/reject 互操作也已通过。
- 文件配置、动态 API、`TestRoute` 和实际数据面需要使用同一套域名策略语义。
- route-only sniffing 的原始目标 IP 与 DNS 解析 IP 已在本地数据面和 `TestRoute` 中区分；Xray 26.2.6 VLESS TCP 的 HTTP `Host` 域名 allow/reject 端到端验证已通过，其他协议/传输组合仍待补充。
- 真实 Xray 客户端的 VLESS TCP/XUDP、Trojan TCP/UDP、Hysteria2 TCP/UDP、Socks5 TCP/UDP、VLESS XHTTP over TCP、Shadowsocks TCP/legacy UDP/2022 EIH UDP 用户域名允许/拒绝，以及 VLESS TCP unknown-target 审计已通过；Xray 原生 `routing.rules` 的 VLESS TCP `user + domain` 组合也已通过，更多目标组合的互操作证据尚未完成。

兼容性矩阵目前仍将 routing 标记为 Partial，见 [COMPATIBILITY.md](COMPATIBILITY.md)。

## 5. 范围边界

### 5.1 本阶段范围

- Linux 平台上的用户与域名匹配。
- Xray 原生 `user + domain` 配置解析和语义对齐。
- 域名规范化和匹配边界。
- 已知域名的允许/拒绝行为。
- 未知目标的放行和审计日志。
- 必要的 `domainStrategy` 行为。
- 认证身份到 routing user/策略身份的正确传递。
- 目标 outbound 建立前的统一策略检查。
- 单元测试、模块测试和最小真实客户端验证。

### 5.2 暂缓范围

以下能力保留现有行为，但暂不作为本阶段的主要实现目标：

- 全面的 IP/CIDR/GeoIP 策略扩展。
- Linux process routing 的完整增强。
- balancer、leastPing、leastLoad 的进一步扩展。
- TUN、WireGuard 和新的 outbound 协议生态。
- 复杂 UDP 会话模型的重新设计。
- 非 Linux 平台的 process lookup 扩展。
- 与域名限制无直接关系的 routing 重构。

暂缓不等于允许新增绕过路径。对于本阶段已经经过的主数据面路径，域名策略不能被静默跳过。

## 6. 目标架构与数据流

```text
Xray 配置 / Chimera 管理输入
              ↓
      共享配置解析与校验
              ↓
       RoutingState / policy
              ↓
协议认证 → canonical routing user
              ↓
      原始目标 / SNI / Host
              ↓
       域名是否已知？
          ┌───┴────┐
          │        │
        已知       未知
          │        │
   用户+域名匹配   allow + audit log
          │        │
    allow/reject   普通 routing 继续
          └───┬────┘
              ↓
       outbound 选择与连接
```

责任边界：

- `config`：解析 Xray 字段、保留省略值、执行配置校验。
- `routing`：只负责条件匹配和目标选择，不建立具体代理连接。
- `identity/policy`：保存用户策略和认证身份映射，不启动 socket。
- `session/protocol`：提供认证结果、原始目标和 sniffing 结果。
- `outbound`：消费 routing 结果并建立目标连接。
- `traffic/tracing`：记录审计和统计，不作为授权事实源。

## 7. 分阶段实施计划

### 阶段 0：固定行为契约和测试夹具

目标：先把“已知域名”和“未知目标”写成可执行测试。

任务：

- 固定 Xray 配置样例和对应预期结果。
- 建立用户 `alice`、`bob` 的最小 routing fixture。
- 建立已知域名、直接 IP、无 SNI、无 Host 四类目标。
- 为允许、拒绝、未知目标放行分别定义断言。
- 记录 Xray 源码提交、客户端版本、Linux 环境和 Cargo feature。

验收：单元测试能够明确区分：

```text
known domain + reject rule = reject
unknown target              = allow + audit
```

### 阶段 1：完善 Xray 域名规则语义

目标：让 Xray 原生 `user + domain` 规则在 Chimera 中产生等价结果。

任务：

- 校验 `full:`、`domain:`、普通字符串、`regexp:`、`keyword:` 等匹配形式。
- 处理大小写、尾部点、IDN/Punycode 和子域名边界。
- 确认同一规则内多个条件为 AND。
- 确认多条规则按顺序执行，第一条命中。
- 配置中的未知或未实现字段不能静默当作 no-op。

示例：

```text
full:example.com       只匹配 example.com
domain:example.com     匹配 example.com 及其子域名
domain:example.com     不匹配 badexample.com
```

验收：同一组 routing 配置分别在 Chimera 和 Xray 上执行 `TestRoute`，路由 tag 和错误结果一致。

### 阶段 2：接入用户身份和域名访问决策

目标：确保策略匹配的是认证后的用户，而不是未经确认的请求字段。

任务：

- 保持 Xray routing 的 `user`/email 字段不变。
- 为各协议建立明确的 canonical user 映射。
- 对需要额外匹配的 UUID、密码、用户名使用独立 policy identity。
- 已知域名在 outbound 选择前执行访问决策。
- 策略拒绝统一进入 `user-domain-access` blackhole 或等价失败路径。

示例：

```text
认证得到 alice@example.com
目标为 www.example.com
命中 alice + domain:example.com
→ 允许选择 direct
```

验收：策略拒绝时不发生目标 DNS、TCP 连接或代理握手；允许时保持原有 outbound 行为。

### 阶段 3：落实未知目标“放行并记录”

目标：避免用户通过直接 IP 被误拒，也避免域名策略静默吞掉无法识别的流量。

任务：

- 空域名、直接 IP、无 SNI、无 Host 统一视为 unknown target。
- 域名策略对 unknown target 固定返回 allow。
- 记录结构化审计事件。
- 对高频 UDP 或重复连接进行限流/去重。
- 日志只包含 inbound、协议、网络、目标、routing user 的安全摘要、决策和原因。
- 不记录密码、原始 UUID、私钥、认证报文或完整配置。

示例事件：

```text
event=unknown_target_domain
inbound_tag=vless-in
protocol=vless
network=tcp
target=203.0.113.10:443
decision=allow
reason=domain_not_available
```

注意：该事件表示域名策略放行；之后显式配置的 IP/端口/用户 routing 规则仍可正常生效。

### 阶段 4：统一 domainStrategy 和 resolver

目标：在不扩大 DNS 功能范围的前提下，保证域名路由判断的 DNS 时机与 Xray 一致。

任务：

- `AsIs`：优先按域名匹配，不主动解析。
- `IpIfNonMatch`：域名无匹配后解析，再按 IP 重新匹配。
- `IpOnDemand`：只有规则需要目标 IP 时解析。
- routing、`TestRoute` 和数据面共享同一 resolver 能力。
- 接入 Xray DNS 配置中与本阶段相关的 nameserver、hosts、缓存和 fallback 语义；当前切片已完成 `hosts` 静态 IP 映射、自定义域名规则、有界 `proxiedDomain` 链、响应码 host 值、基础 plain UDP `dns.servers`、字符串 `tcp://IP[:port]` nameserver、全局 `queryStrategy`、`enableParallelQuery`、全局 `disableFallback`/`disableFallbackIfMatch`、nameserver 基础对象的 `address`、`port`、`domains`、单服务器 `queryStrategy`、`timeoutMs`、`expectedIPs`/`expectIPs`/`unexpectedIPs`、`skipFallback`、`finalQuery` 和域名优先选择，其他字段不得静默忽略。
- 增加 DNS 循环保护，等价处理 Xray 的 skip-resolve 场景。
- DNS 失败要显式返回错误，不能伪装成域名策略拒绝。

验收示例：

```text
domainStrategy=IpIfNonMatch
example.com → DNS 返回 203.0.113.2
IP 规则匹配 203.0.113.2
→ 第二轮匹配命中
```

### 阶段 5：验证当前主数据面，不扩展新协议范围

目标：确认当前已经接入 routing 的路径不会绕过域名策略。

任务：

- 选择当前已有的代表性 TCP 和 UDP 路径。
- 验证协议认证身份能够到达 routing。
- 验证 sniffing 得到的域名能参与路由。
- 验证拒绝请求不会创建 outbound session。
- 覆盖 XUDP 等 session-based UDP 路径，确保原始域名在策略判断前不会被解析成 IP 而丢失。
- 验证 unknown target 仍然 allow + audit。
- 对尚未验证的协议组合保留 Partial 标记，不提前宣称完整兼容。

本阶段不重新设计复杂 UDP 会话，也不以扩大协议覆盖替代域名核心能力。

已完成的真实客户端切片：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_domain_access_policy_allows_and_rejects_vless_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera VLESS TCP 的 `allowed.example` 允许并完成 echo，`blocked.example` 被 `userDomainAccess` 拒绝且 echo 服务未收到第二个连接；随后直接 IP 目标也成功回显，并在 Chimera stderr 中观察到 `user_domain_access_unknown_target` 审计事件。该结果不覆盖 XUDP 或其他协议身份。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_xudp_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：同一 Xray 26.2.6 客户端通过 VLESS XUDP 发送 `allowed.example`，UDP echo 成功；发送 `blocked.example` 时没有收到成功回显。该测试确认 XUDP 保留原始域名并在解析前执行用户策略，但不覆盖其他协议身份。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_vmess_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera VMess TCP 的 `allowed.example` 允许并完成 echo，`blocked.example` 被 VMess UUID 对应的 `userDomainAccess` 策略拒绝且 echo 服务未收到第二个连接。该结果不覆盖 Trojan/Hysteria2 等其他协议身份。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_trojan_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera Trojan TCP 和 UDP 的 `allowed.example` 均允许并完成 echo，`blocked.example` 在两种网络类型下均被 Trojan 密码对应的 `userDomainAccess` 策略拒绝且没有成功回显。该结果覆盖 Trojan 的 TCP/UDP 用户域名策略路径，不覆盖其他传输组合。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_hysteria2_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera Hysteria2 TCP 和 UDP 的 `allowed.example` 均允许并完成 echo，`blocked.example` 在两种网络类型下均被 Hysteria2 auth 对应的 `userDomainAccess` 策略拒绝且没有成功回显。该结果覆盖 Hysteria2 的 TCP/UDP 用户域名策略路径，不覆盖其他传输组合。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_socks5_username_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera Socks5 的用户名认证用户在 TCP 和 UDP 中均可访问
`allowed.example`；`blocked.example` 在 TCP 和 UDP 中均未成功回显。结果为
`1 passed; 0 failed`，耗时约 6.31 秒。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_trojan_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera Trojan 的认证 password identity 在 TCP 和 UDP 中
均可访问 `allowed.example`；`blocked.example` 在 TCP 和 UDP 中均未成功回显。结果为
`1 passed; 0 failed`，耗时约 6.31 秒。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_native_routing_user_domain_rule_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux → Chimera VLESS TCP 的原生 `routing.rules` `user + full:blocked.example` 规则命中 `blackhole`，`allowed.example` 仍走默认 `direct` 并完成 echo；拒绝请求没有触达 echo 服务。该结果只覆盖 VLESS TCP 的原生 `routing.rules` per-user/domain 组合，不代表所有协议组合都已验证。

route-only sniffed domain 真实验证：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_route_only_sniffed_domain_reaches_user_policy \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux 通过 VLESS TCP 发送原始 IP 目标，Chimera 入站启用 `sniffing.routeOnly` 和 HTTP `destOverride` 后，从请求 `Host` 得到域名但保留原始 IP。`allowed.example` 成功回显，`blocked.example` 被 `userDomainAccess` 拒绝，echo 服务只收到允许请求。该证据覆盖 VLESS TCP + raw TCP + HTTP sniffing；其他协议、TLS/REALITY、WebSocket/gRPC/XHTTP 和 UDP route-only 组合仍待验证。

### 阶段 6：动态 API 和运维闭环

目标：使文件配置、管理 API 和运行时状态保持一致。

任务：

- `AddRule`、`RemoveRule`、`ListRule` 和 `TestRoute` 复用共享编译逻辑。
- 动态更新采用版本化/原子发布，不能让半套域名策略进入数据面。
- routing stats 能区分 allow、reject、unknown-target 和 DNS failure。
- 审计日志、统计和 webhook 不阻塞转发，也不成为授权事实源。
- 更新兼容矩阵和配置示例，明确已验证与未验证范围。

当前完成的控制面验证：

```sh
cargo test -p chimera_server_lib --lib \
  grpc::routing::tests::routing_add_rule_matches_user_and_domain_like_xray \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  grpc::user_domain::tests::user_domain_access_service_applies_reports_and_rolls_back \
  -- --exact --nocapture
```

另已通过 Linux 实际 Chimera 进程的 TCP gRPC 集成测试：

```sh
cargo test -p chimera_server_app --test grpc_all_interfaces_e2e \
  user_domain_access_service_applies_reports_and_rolls_back_policy \
  -- --exact --nocapture
```

结果：真实服务启动后，远程 `ApplyPolicy`、`GetPolicyStatus` 和 `RollbackPolicy` 均成功返回版本 1；下发 `defaultAction=reject` 后，远程 `RoutingService.TestRoute` 对域名目标返回 `user-domain-access`，策略统计记录 1 次拒绝。TCP 数据面和 session-based XUDP 的新建请求均已有更新后策略生效证据，并已补充同版本并发发布的本地原子性证据；真实 Xray 客户端通过远程 API 更新后发起 XUDP 的场景也已通过。动态更新接口已有本地原子快照基础，但既有连接、GlobalID 重附着、跨节点发布和高并发 gRPC 压测仍未完成验证。

动态 TCP 数据面验证：

```sh
cargo test -p chimera_server_app --test grpc_all_interfaces_e2e \
  dynamic_user_domain_policy_reaches_new_socks_tcp_requests \
  -- --exact --nocapture
```

结果：策略更新前允许域名请求完成 TCP echo；远程应用拒绝策略后，新建拒绝域名请求失败。该测试使用 SOCKS TCP，不覆盖 Xray 客户端互操作、XUDP 或既有连接的策略边界。

XUDP 动态数据面验证：

```sh
cargo test -p chimera_server_lib --lib \
  handler::xudp::message_stream::tests::session_runtime_uses_updated_user_domain_policy_for_new_session \
  -- --exact --nocapture
```

结果：同一个 session-based XUDP relay 先完成 `allowed.example`，随后在 relay 运行期间发布拒绝策略；新的 `blocked.example` session 没有响应，也没有创建/触达新的 UDP echo 转发。该测试覆盖共享运行时策略的更新边界，不覆盖真实 Xray gRPC 客户端、GlobalID 重附着或既有 session 的策略生命周期。

并发策略发布验证：

```sh
cargo test -p chimera_server_lib --lib \
  user_domain::tests::concurrent_same_version_activation_has_one_winner \
  -- --exact --nocapture
```

结果：两个并发发布任务对同一版本竞争时恰好一个成功，另一个返回 `FailedPrecondition`，最终 active revision 为该版本；策略不会出现两个成功发布者或部分可见状态。该测试不覆盖跨节点发布、真实 gRPC 高并发压测以及不同版本按任意到达顺序发布的性能特征。

真实 Xray 远程 XUDP 更新验证：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_remote_policy_update_reaches_new_xudp_session \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux 先通过 XUDP 完成允许域名回显；Chimera 运行期间接收 TCP gRPC `ApplyPolicy` 后，新建拒绝域名 XUDP 请求未成功回显。该测试覆盖真实客户端、远程控制面和新建 XUDP session 的组合，不覆盖既有 session、GlobalID 重附着、跨节点发布或其他协议/传输组合。

DNS 失败统计验证：

```sh
cargo test -p chimera_server_lib --lib \
  grpc::routing::tests::routing_test_route_records_dns_failure_separately_from_rejection \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  outbound::tests::tcp_domain_dns_failure_is_recorded_separately_from_policy_rejection \
  -- --exact --nocapture
```

结果：`TestRoute` 和 TCP outbound 的 fixture resolver 均返回明确 DNS 错误；每条路径记录 1 次 `dns_failures`，`rejected` 保持为 0。共享函数同时覆盖 session-based UDP 的目标解析分支；尚未覆盖真实 DNS 上游故障或统计聚合压测。

审计运维查询验证：

```sh
cargo test -p chimera_server_lib --lib \
  user_domain::tests::audit_events_keep_safe_context_and_return_newest_first \
  -- --exact --nocapture
cargo test -p chimera_server_app --test grpc_all_interfaces_e2e \
  user_domain_access_service_applies_reports_and_rolls_back_policy \
  -- --exact --nocapture
```

结果：策略服务能经真实 TCP gRPC 查询 direct-IP unknown-target 事件；返回事件的 target、allow 原因和时间戳可用，routing user 不包含原始 email，只返回 `sha256:` 摘要。事件队列有固定上限，查询 limit 也有固定上限。

DNS hosts 规则匹配验证：

```sh
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_hosts_domain_rule_forms \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::hosts_resolver_matches_xray_domain_rule_forms \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_hosts_response_codes \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::hosts_resolver_returns_xray_response_code_without_upstream_fallback \
  -- --exact --nocapture
```

结果：Xray hosts 的默认精确匹配、`domain:` 标签边界、`keyword:` 子串和 `regexp:` 规则均已在共享 resolver 中验证；多个规则命中时返回合并后的静态 IP，`proxiedDomain` 会沿 hosts 表有界递归并在静态别名未命中时对最终别名执行系统 DNS 查询，响应码 host 值按 Xray 语义直接返回 DNS 错误，未匹配的原始域名继续调用系统 resolver。queryStrategy 的 A/AAAA 选择已支持；geosite/ext 规则以及 nameserver 的高级 fallback/加密传输仍未实现。

`proxiedDomain` 解析和循环保护验证：

```sh
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_hosts_proxied_domain \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::hosts_resolver_unwraps_proxied_domain_and_falls_through_after_alias_miss \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::hosts_resolver_rejects_proxied_domain_cycles \
  -- --exact --nocapture
```

结果：单值和数组中的域名值会编译为 `proxiedDomain`；静态别名链能解析到 IP，未映射别名会把最终别名交给底层 resolver，循环或超过 5 次替换会返回明确错误。该切片尚未覆盖真实 Xray 客户端通过自定义上游 DNS 验证 alias 的端到端互操作。

plain UDP nameserver 验证：

```sh
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_plain_xray_dns_server_endpoints \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_queries_configured_server \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_query_strategy_aliases \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_applies_ipv4_query_strategy \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_server_ip_filters_and_aliases \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::dns_server_ip_filters_match_xray_prefer_and_reverse_semantics \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_falls_back_after_expected_ip_filter_removes_answer \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_applies_unexpected_ip_filter \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_server_fallback_controls \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_disables_fallback_after_domain_match \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_applies_xray_per_server_timeout \
  -- --exact --nocapture
```

结果：配置支持单个 IP nameserver、带端口的 IPv6 nameserver、字符串数组，以及包含 `address`、`port`、`clientIp`、`domains`、`queryStrategy`、`timeoutMs`、`expectedIPs`/`expectIPs`/`unexpectedIPs`、`skipFallback`/`finalQuery` 的基础 nameserver 对象；共享 resolver 通过本地 UDP DNS fixture 实际查询 A/AAAA 并将结果绑定到目标端口，顶层 `clientIp` 会生成 Xray 兼容的 EDNS Client Subnet，server 对象的 `clientIp` 会覆盖顶层值（IPv4 /24、IPv6 /96），匹配的 `domains` nameserver 会按 Xray 规则优先尝试，响应地址会按 Xray IP 规则筛选，筛选后为空时继续尝试下一个 nameserver，未匹配时仍按默认 fallback 顺序尝试，单服务器策略可以覆盖全局查询族，单服务器总查询超时可以覆盖 Xray 默认 4000ms（显式 0 仍使用默认值）。hosts 响应码 `#3`/`#0` 已通过配置和共享 resolver 定向测试。当前未覆盖 Xray nameserver 对象的其他 fallback 策略、DoH/DoT 或真实外部 DNS 服务；全局和单服务器 `queryStrategy` 的 A/AAAA 选择、全局 fallback 开关、单服务器 timeout、IP 筛选以及 clientIp 的 ECS wire/override 已有配置和 resolver 定向测试。

plain TCP nameserver 验证：

```sh
cargo test -p chimera_server_lib --lib \
  config::def::tests::compiles_xray_dns_tcp_server_endpoint \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::tcp_dns_resolver_queries_xray_tcp_server \
  -- --exact --nocapture
```

结果：`tcp://IP[:port]`（scheme 大小写不敏感）能够编译为 TCP nameserver；resolver 对本地 TCP fixture 完成两字节长度前缀的请求/响应收发，并返回预期 A 记录。该切片是直连 TCP；Xray 经 dispatcher 的远程 nameserver、`tcp+local`、DoH/DoT、nameserver 对象中的 TCP 表达仍未实现。

并行 nameserver 验证：

```sh
cargo test -p chimera_server_lib --lib \
  config::def::tests::accepts_xray_enable_parallel_query \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_parallel_query_returns_fast_same_policy_server \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  resolver::tests::udp_dns_resolver_parallel_query_preserves_policy_group_priority \
  -- --exact --nocapture
```

结果：`enableParallelQuery` 配置可进入共享 resolver；同一 policy group 内，较快的 nameserver 可以先返回；不同 policy group 时，即使低优先级 server 更快，也必须等待高优先级 group 失败后才接受结果。该切片的分组 key 基于当前 Chimera 已编译的 server 策略字段，未引入 Xray 的动态 policyID 或远程 dispatcher。

XHTTP 用户域名策略互操作验证：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_xhttp_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux 通过 VLESS XHTTP over TCP 连接 Chimera；VLESS UUID 对应的
`userDomainAccess` 策略允许 `allowed.example` 并完成 echo，拒绝
`blocked.example` 且没有触达 echo 服务。该证据覆盖 XHTTP over TCP + security none，
XHTTP 的 TLS/REALITY/HTTP/3 组合仍需单独验证。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_xhttp_tls_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux 通过 VLESS XHTTP over TCP + TLS 连接 Chimera；允许域名成功
完成 echo，拒绝域名没有成功回显。结果为 `1 passed; 0 failed`，耗时约 0.52 秒。
该证据不覆盖 XHTTP HTTP/3、REALITY 或 UDP 组合。

Socks5 用户名域名策略互操作验证：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_socks5_username_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux 通过 Socks5 username/password outbound 连接 Chimera；
`socksUsername` 对应的策略在 TCP 和 UDP 中均允许 `allowed.example` 并完成 echo，
拒绝 `blocked.example` 且没有成功回显。该证据覆盖 Socks5 TCP/UDP，其他传输组合仍需
单独验证。

Shadowsocks email 身份互操作验证：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_shadowsocks_email_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：Xray 26.2.6 / Linux 通过 Shadowsocks TCP 连接 Chimera；配置的 `email` 被作为
`MemoryUser.Email` 对应的 `shadowsocksEmail`，`allowed.example` 成功回显，
`blocked.example` 未触达 echo 服务。该证据覆盖 Shadowsocks TCP，不覆盖 Shadowsocks
UDP、2022 EIH 或其他传输组合。

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_shadowsocks_udp_email_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：随后使用同一身份映射验证 Shadowsocks legacy UDP：Xray 26.2.6 / Linux 的 UDP
`allowed.example` 成功回显，`blocked.example` 没有成功回显。该证据覆盖 legacy UDP
数据面，不覆盖其他未验证的传输组合。

2022 EIH UDP 身份互操作验证：

```sh
cargo test -p chimera_server_app --test xray_client_proxy_e2e \
  xray_client_shadowsocks_2022_eih_udp_email_domain_access_policy_allows_and_rejects_target \
  -- --ignored --exact --nocapture
```

结果：单用户 EIH 配置中的 email 能对应 `shadowsocksEmail`；Xray 26.2.6 / Linux 的
`allowed.example` UDP 请求成功回显，`blocked.example` 没有成功回显。该证据覆盖
2022 EIH UDP，不覆盖 EIH TCP 或其他传输组合。

domainStrategy 与 route-only 原始 IP 验证：

```sh
cargo test -p chimera_server_lib --lib \
  routing_state::tests::domain_strategy_keeps_original_target_ips_available_to_as_is \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  outbound::tests::as_is_route_only_domain_keeps_original_ip_rule \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  outbound::tests::ip_if_non_match_resolves_route_only_domain_over_original_ip \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib \
  outbound::tests::ip_on_demand_resolves_route_only_domain_with_original_ip \
  -- --exact --nocapture
cargo test -p chimera_server_lib --lib routing_state
```

结果：相关 routing_state 测试 79 个通过，完整库测试 1467 个通过。`AsIs` 不解析 route-only 域名但保留原始 IP 规则；`IpIfNonMatch` 在初始路由未命中后解析 route-only 域名并重试；`IpOnDemand` 仅在 IP 规则需要时解析。`TestRoute` 对调用方已提供的 `target_ips` 保留已解析候选语义。Xray 26.2.6 VLESS TCP 的 route-only HTTP `Host` allow/reject 端到端测试已通过；其他协议/传输组合仍待验证。

## 8. 配置示例

### 8.1 Xray 原生 routing 规则

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "user": ["alice@example.com"],
        "domain": ["domain:example.com"],
        "outboundTag": "direct",
        "ruleTag": "alice-example"
      },
      {
        "user": ["alice@example.com"],
        "domain": ["full:blocked.example.com"],
        "outboundTag": "blackhole",
        "ruleTag": "alice-blocked"
      }
    ]
  }
}
```

该配置只声明 Xray 原生语义。未知目标是否记录审计由 Chimera 的域名访问控制实现负责，但不能改变上述已知域名规则结果。

### 8.2 Chimera 动态策略扩展

如果需要后端统一下发大量用户策略，可以继续使用 `userDomainAccess` 作为 Chimera 扩展。它必须满足：

- 不改变 Xray 原生 `routing.rules` 的匹配顺序和字段含义。
- 已知域名的 allow/reject 结果与等价的 Xray 规则一致。
- unknown target 固定 allow，并产生审计事件。
- 策略更新具有版本、校验和和原子发布语义。
- 扩展字段未实现时显式报错，不能静默忽略。
- Shadowsocks legacy/2022 用户使用 Xray `MemoryUser.Email` 对应的 `shadowsocksEmail`，不能把 cipher、password 或原始认证材料写入 routing user。

### 8.3 当前已实现的 Xray DNS hosts 子集

```json
{
  "dns": {
    "hosts": {
      "example.com": "192.0.2.10",
      "api.example.com.": ["192.0.2.11", "2001:db8::11"],
      "alias.example": "mapped.example",
      "mapped.example": "192.0.2.12"
    }
  }
}
```

`hosts` 的键按 Xray 自定义域名规则处理：无前缀和 `full:` 为精确匹配，`domain:` 匹配域名自身及子域名，`keyword:` 为子串匹配，`regexp:` 和 `dotless:` 使用正则匹配。字面域名会统一大小写、去除末尾点并转换 IDN；多个命中规则的 IP 会合并。值可以是 IP、IP 数组、`proxiedDomain` 域名或响应码字符串（如 `#3`、`#0`）；响应码命中后直接返回对应 DNS 错误，不继续请求上游 nameserver；后者沿 hosts 表最多替换 5 层，静态映射未命中时对最终别名执行配置的 plain UDP/system resolver。`dns.servers` 当前支持单个 IP、`IP:port`、字符串数组、字符串 `tcp://IP[:port]` nameserver，以及包含 `address`、`port`、`clientIp`、`domains`、`queryStrategy`、`timeoutMs`、`expectedIPs`/`expectIPs`/`unexpectedIPs`、`skipFallback`/`finalQuery` 的 UDP 基础对象；顶层 `dns.clientIp` 对 plain UDP/TCP 查询生成 Xray 兼容的 EDNS Client Subnet，nameserver 对象的 `clientIp` 优先覆盖顶层值，IPv4 使用 /24，IPv6 使用 /96。`tcp://` 查询使用 Xray/RFC 7766 两字节长度前缀，复用现有 queryStrategy、timeout、IP 筛选和 fallback 语义。`domains` 默认按 Xray `Domain_Substr` 语义匹配，也支持 `domain:`、`full:`、`keyword:`、`regexp:`、`dotless:`，匹配 nameserver 优先于未匹配 nameserver，随后仍可按默认 fallback 顺序尝试；`skipFallback` 会从普通 fallback 中排除 server，`finalQuery` 会在选中后终止 server 选择，`timeoutMs` 控制该 nameserver 整次 A/AAAA 查询的等待时间，缺省和显式 0 使用 Xray 默认 4000ms。响应地址按 Xray IP 规则筛选，`*` 表示优先保留匹配结果，筛选为空时继续尝试下一个 nameserver。全局 `queryStrategy`、`disableFallback` 和 `disableFallbackIfMatch` 支持 `UseIP`、`UseIPv4`、`UseIPv6`、`UseSystem`，对象中的单服务器策略可覆盖全局值。其他 fallback 字段、URL、geosite/ext 规则、DoH/DoT 仍未实现；配置校验会明确拒绝尚未实现的字段。

## 9. 测试与验收矩阵

### 9.1 必测行为

| 场景 | 预期 |
| --- | --- |
| 用户 + 允许域名 | 允许并选择预期 outbound |
| 用户 + 拒绝域名 | 拒绝，不建立目标连接 |
| 子域名边界 | 与 Xray 一致 |
| 大小写/尾部点 | 与规范化结果一致 |
| 直接 IP/无域名 | 允许并记录 unknown-target |
| 无 SNI/无 Host | 允许并记录 unknown-target |
| `IpIfNonMatch` | 域名未命中后解析并重试 |
| `IpOnDemand` | 仅在 IP 规则需要时解析 |
| DNS 失败 | 显式 DNS 错误，不伪装成策略拒绝 |
| 动态策略更新 | 新请求使用完整新版本，旧请求不读到半套状态 |

### 9.2 验证命令

```sh
cargo fmt --all -- --check
cargo test -p chimera_server_lib --lib routing_state
cargo test -p chimera_server_lib --lib grpc::routing::tests::
cargo test -p chimera_server_lib --lib user_domain::tests::
cargo check -p chimera_server_lib --all-features --lib
```

真实互操作验证应固定：Xray 源码提交、Xray 客户端版本、Linux 内核/发行版、Cargo feature、配置文件和实际运行次数。单元测试通过不能替代 Xray client → Chimera server 的允许/拒绝验证。

## 10. 完成定义

本阶段只有同时满足以下条件，才能将 routing 的用户域名控制从 Partial 提升：

- Xray 原生 `user + domain` 配置能够解析并产生等价结果。
- 已知域名的允许/拒绝结果与 Xray 对照一致。
- 未知目标始终由域名策略放行并记录审计日志。
- 策略拒绝发生在 outbound 建立之前。
- 主要已接入数据面没有静默绕过。
- `AsIs`、`IpIfNonMatch`、`IpOnDemand` 的相关域名行为经过测试。
- 文件配置、`TestRoute`、动态 API 和数据面使用一致的编译/执行语义。
- 至少有一个 Linux 真实 Xray 客户端允许场景和拒绝场景通过。
- 未完成的 IP、进程、复杂 UDP 和 balancer 功能仍明确标记为未完成，不被本阶段的域名能力覆盖。

## 11. 后续交接规则

后续每次迭代只选择一个责任完整的切片：

```text
配置/匹配语义
→ 用户身份传递
→ 已知域名策略
→ unknown-target 审计
→ resolver/domainStrategy
→ 代表性数据面验证
```

每个切片都需要记录：代码路径、行为变化、Xray 对照位置、测试命令、通过数量、未验证范围和兼容性文档更新。不得因为内部实现已经完成，就把未进行真实互操作的能力标记为完全兼容。
