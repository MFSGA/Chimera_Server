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

当前进度：Chimera Server、Rust rnode、Nest 节点和中央 backend 的端到端实现均已完成。Chimera 负责策略编译、版本化 RuntimeState、原子持久化、回滚、防重放、节点目标校验、低基数指标和 CLI；两种节点实现均暴露一致的 JWT API 并转发到 Chimera gRPC；backend 已具备用户策略表、节点版本发布包、Apply/Rollback 审计事件、canonical checksum、SERIALIZABLE 版本分配及 HTTPS/JWT/可选 mTLS 调用。VLESS、VMess、Trojan、认证 HTTP、SOCKS、TUIC、Hysteria2 的身份均可映射到稳定 backend UUID；TCP、固定/多目标 UDP、XUDP、SOCKS UDP 及 QUIC TCP/UDP 均在 DNS 或出站建立前决策。目标为 IP/未知时会进行 5ms 有界 TLS ClientHello 探测并回放已读字节；ECH outer SNI 不被信任，统一按 `unknownTargetAction` 处理。

- [x] 增加用户域名策略配置结构和严格校验。
- [x] 在连接上下文中统一保存用户 UUID、协议身份、目标地址、端口、SNI、ECH 标记、HTTP Host 和传输类型。
- [x] 实现 `exact`、DNS label 边界安全的 `suffix` 匹配。
- [x] 实现 `allowlist`、`denylist`、`allow_all` 三种策略模式。
- [x] 明确未知目标、IP 直连、ECH 和不可识别 QUIC 流量的默认行为：不能得到可信域名时统一执行用户级 `unknownTargetAction`，未映射用户执行全局 `defaultAction`。
- [x] 在 DNS 解析和建立出站连接前执行 `allow`/`reject` 决策，覆盖 VLESS、VMess、Trojan、HTTP、SOCKS、TUIC、Hysteria2 的 TCP/UDP/QUIC 路径及 XUDP。
- [x] 为每次决策返回匹配规则、用户、目标分类和拒绝原因。

### P1：配置链与 rnode 发布

- [x] 按 `literal config → validation → RuntimeState → handler` 接入策略配置；策略是节点级共享控制面状态，不复制到每个 `ServerConfig`。
- [x] 增加配置版本、生成时间、目标节点、校验和及原子替换机制。checksum 使用排除自身字段、对象键排序的 canonical JSON SHA-256；版本严格递增并防止回滚后的旧包重放。
- [x] 配置校验失败时保留旧配置，并支持最近版本回滚。当前将当前策略、最近 5 个历史版本和 `highestSeenVersion` 原子持久化；重启后仍可回滚，且旧高版本继续防重放。
- [x] 通过 Rust rnode 或 Nest 节点接收 backend 的 JWT 发布请求，调用 Chimera gRPC Apply、Rollback、Status，并将结果返回 backend 确认。
- [x] 增加低基数的命中、拒绝、fallback 和策略版本日志/指标。当前使用固定 action/reason 原子计数，并由 GetStatus 返回累计值。

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

代码完成后只剩部署验收：应用数据库 migration，配置节点 JWT 或 mTLS 凭据，在真实节点执行 Apply/Status/Rollback、重启恢复、断网失败审计和监控告警验证。
