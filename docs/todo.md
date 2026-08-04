# TODO

更新时间：2026-08-04

本文件记录 TCP + REALITY + Vision 性能路线中尚未完成的生产级验收和后续工作。当前默认生产路径继续使用 `handoff`；`auto`、`splice-downlink` 和完整双向 `splice` 保持显式配置或诊断用途，直到以下验收完成。

## P0：生产验收

### 长时间稳定性测试

- [ ] 在受控主机上完成默认 `handoff` 后端的 1 小时 soak。
- [ ] 在受控主机上完成默认 `handoff` 后端的 24 小时 soak。
- [ ] 对计划投入使用的 `auto` 或 `splice-downlink` 配置执行同等级 soak。
- [ ] 全程开启端到端字节校验，确保 byte mismatch、丢失、重复和乱序均为 0。
- [ ] 保存完整 JSONL 结果、运行命令、Git commit、binary hash、内核和硬件信息。
- [ ] 冷却后确认 fd 无净增长，并核对 pipe、连接、任务和 RSS 不存在持续增长。

验收标准：

- 最终 fd delta 为 0；
- 无连接残留、pipe 泄漏或异常任务增长；
- RSS 在预先声明的门槛内稳定，不呈持续线性增长；
- 1 小时和 24 小时运行均无数据错误和未解释的 relay 错误。

### 独立物理机与物理网卡复测

- [ ] 使用 Generator、Chimera、Target 三台独立物理机搭建正式拓扑。
- [ ] 至少覆盖 10G 和 25G 物理网卡环境。
- [ ] 确认 raw TCP 基线不会被 generator 或 target CPU 限制。
- [ ] 固定并记录 CPU governor、turbo、NUMA、IRQ affinity、网卡队列、MTU 和 offload 设置。
- [ ] 在相同硬件和测试顺序下比较 raw TCP、Xray reference、handoff、auto 和 `splice-downlink`。

验收标准：

- 原始环境数据完整且可复现；
- Chimera Host 是主要变量；
- 测试前后的 raw TCP 基线没有明显环境漂移；
- 所有性能结论均来自稳定的多次运行，而不是单次峰值。

### 完整并发与负载矩阵

- [ ] 覆盖 1、8、16、32、64、256、512、1000 以及目标生产并发。
- [ ] 覆盖 uplink-only、downlink-only、full-duplex 和 90/10 非对称流量。
- [ ] 覆盖长连接大流、小流、高频建连和长短流混合场景。
- [ ] 覆盖 64 MiB 快速预检、1 GiB 单流以及持续 30–120 秒负载。
- [ ] 在 endpoint CPU 饱和时停止归因于代理，并记录瓶颈位置。

### Benchmark 稳定性和统计闭环

- [ ] 每个正式单流场景至少执行 3 次 warmup 和 10 次测量。
- [ ] 随机化 baseline 与 candidate 的执行顺序。
- [ ] 将单流 CV 控制在 3% 以内，并发场景 CV 控制在 5% 以内。
- [ ] 报告 median、p5/p95、MAD 或 95% bootstrap confidence interval。
- [ ] 保存每次原始结果，不仅保存聚合结果。
- [ ] 对当前高 CV 的 handoff、`splice-downlink` 和 copy-buffer 数据重新测量。

## P1：生产策略决策

### Auto 阈值与公平性

- [ ] 在真实生产负载形态下验证 `CHIMERA_TCP_AUTO_MAX_CONNECTIONS`。
- [ ] 检查阈值切换是否造成连接公平性、尾延迟或吞吐突变。
- [ ] 覆盖阈值附近的并发波动和大量短连接场景。
- [ ] 根据数据决定 `auto` 是否继续保持显式配置，或是否具备成为默认值的条件。

在完成评审前：

- `handoff` 保持默认；
- `auto` 仅作为低并发实验配置；
- `splice-downlink` 仅用于明确的低并发大流场景；
- 完整双向 `splice` 仅用于诊断，不进入生产默认。

### Copy buffer 跨平台复核

- [ ] 在独立物理机上复跑 8、16、32、64、128、256 KiB buffer 矩阵。
- [ ] 至少覆盖 single flow、64、512 和 1000 并发。
- [ ] 同时比较吞吐、CV、CPU-seconds/GiB 和 RSS/connection。
- [ ] 确认 32 KiB 仍是合理的通用默认值，或记录按平台覆盖的依据。

### 配置与可观测性完善

- [ ] 评估将 relay 配置从环境变量接入正式配置链：literal config → `ServerConfig` → handler。
- [ ] 为所有快路径提供统一 kill switch 和明确的解析失败行为。
- [ ] 补充低基数指标：Direct 命中、handoff 成功/拒绝、effective relay path、fallback reason、分方向字节和错误。
- [ ] 确保指标不使用 UUID、目标地址或连接 ID 等高基数标签。
- [ ] 在高吞吐模式下避免逐 chunk 日志。

## P2：系统级性能调优

- [ ] 比较 release、LTO、codegen-units、target-cpu、PGO 和 allocator 对吞吐及 CPU/GiB 的影响。
- [ ] 测试 Tokio worker 数量、CPU affinity、任务迁移和 acceptor/relay worker 分离。
- [ ] 评估 NIC IRQ affinity、RSS/RPS/XPS、GRO/GSO/TSO、MTU 和 socket autotuning。
- [ ] 采集 cycles/byte、instructions/byte、syscalls/GiB、context-switches/GiB 和 CPU migrations。
- [ ] 对性能基线按硬件、内核和编译配置分组，禁止跨环境直接比较 Mbps。

## 条件触发的后续实验

### io_uring splice

当前单连接 hardlink batch 探针未达到生产准入门槛，因此不接入生产数据面。

仅在普通 splice 的 syscall、epoll wakeup 或调度成本被证明是主要瓶颈时，再执行：

- [ ] 多连接共享 ring 原型；
- [ ] 跨连接批量提交；
- [ ] registered/fixed files；
- [ ] 可选 SQPOLL，并单独核算常驻 CPU；
- [ ] 与普通 splice 在生产并发下直接 A/B。

准入要求：相对普通 splice 有稳定吞吐或 CPU/GiB 收益，且不显著增加上下文切换和生命周期复杂度。

### BPF SOCKHASH

BPF SOCKHASH 不是当前必做项。只有物理机高并发数据证明网卡尚未饱和，同时 syscall、context switch 或用户态调度仍是主要瓶颈时才启动。

- [ ] 先完成高并发瓶颈分析并记录是否满足启动条件。
- [ ] 如满足条件，在独立 feature 下实现 SOCKHASH prototype。
- [ ] 覆盖 1、64、512、1000 和目标生产并发 A/B。
- [ ] 覆盖 full-duplex、FIN、RST、half-close、map 满、权限不足、attach 冲突和 daemon 重启。
- [ ] 验证 map 更新和删除幂等、fallback 正确、无长期残留映射。
- [ ] 完成 24 小时稳定性测试后再评估是否进入 `auto` 候选。

## 完成定义

只有在以下条件同时满足后，TCP + REALITY + Vision 性能路线才可标记为生产验收完成：

- 1 小时和 24 小时 soak 通过；
- 10G/25G 物理网络正式测试完成；
- 完整并发和流量方向矩阵完成；
- benchmark 稳定性达到声明门槛；
- relay 默认策略经过数据评审；
- 所有结果可由保存的命令、环境清单和原始 JSONL 重现。

## 用户与目标域名访问控制

详细设计见 [`user-domain-access-control.md`](./user-domain-access-control.md)。该能力用于实现“用户身份 + 目标域名”的联合访问控制，并由 backend 生成策略、通过 rnode 下发到 Chimera Server。

### P0：Chimera Server 决策引擎

当前进度：Chimera Server、Rust rnode、Nest 节点和中央 backend 的端到端实现均已完成。Chimera 负责策略编译、版本化 RuntimeState、原子持久化、回滚、防重放、节点目标校验、低基数指标和 CLI；两种节点实现均暴露一致的 JWT API 并转发到 Chimera gRPC；backend 已具备用户策略表、节点版本发布包、Apply/Rollback 审计事件、canonical checksum、SERIALIZABLE 版本分配及 HTTPS/JWT/可选 mTLS 调用。VLESS、VMess、Trojan、认证 HTTP、SOCKS、TUIC、Hysteria2 的身份均可映射到稳定 backend UUID；TCP、固定/多目标 UDP、XUDP、SOCKS UDP 及 QUIC TCP/UDP 均在 DNS 或出站建立前决策。目标为 IP/未知时会进行 5ms 有界 TLS ClientHello 探测并回放已读字节；ECH outer SNI 不被信任，统一按 `unknownTargetAction` 处理。生产加固已加入 `enforce/shadow/disabled`、固定维度运行指标、可选 Ed25519 发布验签和 Criterion 策略规模基准。

- [x] 增加用户域名策略配置结构和严格校验。
- [x] 在连接上下文中统一保存用户 UUID、协议身份、目标地址、端口、SNI、ECH 标记、HTTP Host 和传输类型。
- [x] 实现 `exact`、DNS label 边界安全的 `suffix` 匹配。
- [x] 实现 `allowlist`、`denylist`、`allow_all` 三种策略模式。
- [x] 明确未知目标、IP 直连、ECH 和不可识别 QUIC 流量的默认行为：不能得到可信域名时统一执行用户级 `unknownTargetAction`，未映射用户执行全局 `defaultAction`。
- [x] 在 DNS 解析和建立出站连接前执行 `allow`/`reject` 决策，覆盖 VLESS、VMess、Trojan、HTTP、SOCKS、TUIC、Hysteria2 的 TCP/UDP/QUIC 路径及 XUDP。
- [x] 为每次决策返回匹配规则、用户、目标分类和拒绝原因。
- [x] 增加 `enforce`、`shadow`、`disabled` 三种执行模式；shadow 记录原始拒绝但不阻断，disabled 不执行目标分类和 TLS 探测。

### P1：配置链与 rnode 发布

- [x] 按 `literal config → validation → RuntimeState → handler` 接入策略配置；策略是节点级共享控制面状态，不复制到每个 `ServerConfig`。
- [x] 增加配置版本、生成时间、目标节点、校验和及原子替换机制。checksum 使用排除自身字段、对象键排序的 canonical JSON SHA-256；版本严格递增并防止回滚后的旧包重放。
- [x] 配置校验失败时保留旧配置，并支持最近版本回滚。当前将当前策略、最近 5 个历史版本和 `highestSeenVersion` 原子持久化；重启后仍可回滚，且旧高版本继续防重放。
- [x] 通过 Rust rnode 或 Nest 节点接收 backend 的 JWT 发布请求，调用 Chimera gRPC Apply、Rollback、Status，并将结果返回 backend 确认。
- [x] 增加低基数的命中、拒绝、fallback 和策略版本日志/指标。GetStatus 现在覆盖原始 allow/reject、实际阻断、shadow 拒绝、disabled bypass、TLS 探测结果与字节数，以及 Apply/Rollback 成败。
- [x] 支持可选 Ed25519 策略签名验证；节点本地配置可信公钥和 `requireSignature`，验签失败在落盘及 RuntimeState 替换前拒绝。
- [x] 强化持久化边界：16 MiB 上限、拒绝 symlink/非普通文件、Unix `0600`、原子 rename 和失败时保留当前策略。
- [x] 限制策略资源规模：最多 100,000 用户、每用户 10,000 规则、总计 1,000,000 规则，并在大容量分配前校验。
- [x] 将 TLS ClientHello probe timeout/max bytes 接入节点配置，默认 5ms/64KiB，安全范围 1–100ms 与 1–256KiB；Status 返回有效值。

### P1：backend 对接

- [x] 设计用户策略存储模型，使用用户 UUID 作为稳定主键。
- [x] 增加用户策略查询、替换、删除、节点发布、状态、回滚和发布历史 API。
- [x] 在 backend 从用户 VLESS UUID、Trojan 密码和 username 生成各协议身份映射。
- [x] 记录不可变节点版本包及每次 Apply/Rollback 的状态、响应、错误和由已验证 JWT 推导的操作者。

### P1：测试与兼容性

- [x] 覆盖大小写、末尾点号、子域名边界和 exact/suffix 优先级。
- [x] 验证不同用户并发连接时不会串用策略。当前回归覆盖 64 个并发任务、每任务 100 轮允许/拒绝交叉决策。
- [x] 覆盖 TCP/TLS ClientHello、VLESS、VMess、Trojan、HTTP、SOCKS、TUIC、Hysteria2 和 XUDP 的协议级回归；真实外部客户端/节点联调属于发布环境验收。
- [x] 验证直接 IP、ECH、旁路 DNS 和不可识别目标符合 `unknownTargetAction`；ECH 测试确认 outer SNI 不参与域名放行。
- [x] 验证非法发布、错误节点、写盘失败不会覆盖当前有效配置，并验证重启选择正确当前版本、恢复历史回滚能力及保留最高版本防重放。
- [x] 增加 Criterion 基准，覆盖 1/100/10,000 用户和 1/10/100/1,000 exact/suffix 规则的编译、命中与 miss。

### P0：生产部署验收

- [ ] 在真实节点应用数据库 migration，并验证升级、回退和失败审计。
- [ ] 配置节点 JWT 或 mTLS 凭据，完成 Apply/Status/Rollback、断网恢复及 checksum 对账。
- [ ] 先以 `disabled` 校验发布链，再以 `shadow` 收集至少一个完整业务周期的 would-reject 数据。
- [ ] 为 shadow reject、unknown target、未映射用户、TLS timeout/ECH、Apply/Rollback 失败配置 dashboard 和告警门槛。
- [ ] 生成生产 Ed25519 signing key，完成离线私钥保护、公钥分发、双 key 轮换和旧 key 撤销演练。
- [ ] 在所有现有落盘策略均已签名后启用 `requireSignature`，并验证错误签名、未知 key 和签名缺失均 fail closed。
- [ ] 在固定硬件和 release 构建上执行完整 Criterion 基线，保存原始输出、Git commit、编译参数和硬件信息。
- [ ] 为决策 p95/p99、编译耗时和策略内存占用设定回归阈值并接入 CI 或发布门禁。
- [ ] 在 shadow 真实流量下比较 TLS probe 1/5/10/25ms 与 16/64/128/256KiB，确认首包延迟、SNI 识别率和 timeout 比例后固定生产值。
- [ ] 演练策略文件超限、symlink、权限错误、磁盘满、只读文件系统及进程在 rename 前被终止等故障。

代码层生产加固已完成；剩余项依赖真实节点、密钥管理、数据库和业务流量环境。

## Xray 兼容性下一阶段

详细差距分析见 [`20260804-234600-xray-parity-gap-analysis.zh.md`](./20260804-234600-xray-parity-gap-analysis.zh.md)。对比基线为仓库内 `ref/xray-core` 的 `5ca6f4b7d4dc`（Xray-core v26.7.28）。

当前结论：入站、路由、Stats/Handler/Routing/Observatory 控制面已经较完整；最大结构性缺口是只有 `freedom` 和 `blackhole` 能执行真实出站连接。通用 sniffing、Xray DNS/FakeDNS、mKCP、TUN、Reverse、WireGuard 和部分 XHTTP client/xmux/download 语义仍未完成。

### P0：Outbound Runtime

- [ ] 新增 typed outbound config，保留 `settings`、`streamSettings`、sender/via、proxySettings 和协议账户。
- [ ] 新增 `OutboundSession`、TCP/UDP connector trait 和 tag → connector registry。
- [ ] 将现有 Freedom/Blackhole 迁移到 registry，保持行为不变。
- [ ] 让静态配置和 HandlerService Add/RemoveOutbound 原子更新同一 registry。
- [ ] unsupported outbound 在编译或安装阶段 fail-closed，而不是连接时才失败。
- [ ] 支持 VLESS TCP plain outbound，并与固定 Xray-core inbound 做真实互通。
- [ ] 支持通用 outbound TLS/REALITY/WebSocket/HTTPUpgrade/gRPC transport pipeline。
- [ ] 依次接入 VMess、Trojan、SOCKS、HTTP、Shadowsocks TCP/UDP outbound。

### P0/P1：Sniffing 与 DNS

- [ ] 将 inbound `sniffing` 从未使用的 `Value` 改为严格 typed config。
- [ ] 建立独立 `SniffingContext`，支持 HTTP/TLS，后续扩展 QUIC/FakeDNS。
- [ ] 实现 `destOverride`、`metadataOnly`、`routeOnly`、domain/IP exclusions。
- [ ] 增加 typed 顶层 DNS 配置、static hosts、nameserver、query/fallback/cache strategy。
- [ ] 支持 domain-scoped nameserver、expected/unexpected IP、parallel query 和 stale cache。
- [ ] 在 Outbound Runtime 完成后实现 DNS outbound。
- [ ] 最后实现 FakeDNS 池和 sniffing/routing 映射恢复。

### P1：Transport 和 Xray 高级语义

- [ ] 将旧 `xhttp_gap_vs_xray.zh.md` 作为历史文档；当前 XHTTP 已支持 VLESS inner、mode、placement、流控、TTL、TLS/REALITY。
- [ ] 补 XHTTP outbound、HTTP/3/UNIX listener、`downloadSettings`、`xmux` 和 `noGRPCHeader` 数据面语义。
- [ ] 对 `network=kcp` 明确 fail-closed；真正实现 mKCP 前不得映射为 QUIC。
- [ ] 接入常用 `sockopt`：interface、mark、keepalive、TFO、original destination、acceptProxyProtocol。
- [ ] 将顶层 `policy` 从未使用的 Value map 改为 Xray level/system policy，并接 timeout/stats/buffer。
- [ ] 补 VLESS `xorMode`、`secondsFrom/secondsTo`、`padding` 和通用 userLevel。

### P2：扩展能力

- [ ] TUN inbound。
- [ ] Reverse bridge/portal。
- [ ] Loopback outbound，并增加路由环检测。
- [ ] WireGuard outbound。
- [ ] Prometheus/HTTP metrics endpoint。
- [ ] FinalMask、Tagged transport、Browser Dialer、TCP header/mask。

### 推荐立即执行的切片

- [ ] Slice 1：只建立 Outbound Registry 基础层，并迁移 Freedom/Blackhole；不在同一提交中实现 VLESS wire protocol。
- [ ] Slice 2：VLESS TCP plain outbound。
- [ ] Slice 3：复用式 outbound transport pipeline。
