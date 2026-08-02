# Chimera TCP + REALITY + Vision 极致吞吐演进与数据验收指南

> 文档状态：初版性能路线图
> 适用项目：Chimera_Server、Chimera_Client
> 核心协议：TCP + VLESS + REALITY + `xtls-rprx-vision`
> 目标平台：Linux 为第一优化平台，其他平台保持可靠回退
> 基准日期：2026-08-03

---

## 1. 文档目标

本文不是一份“直接把某项技术打开即可提速”的配置清单，而是一套可执行的工程路线，用于让 Chimera 的 TCP + REALITY + Vision 在保证以下前提下逐步逼近机器、内核和网卡所允许的最大吞吐：

1. 协议正确，不丢字节、不重复、不乱序；
2. 与 Xray 和 Chimera Client 保持兼容；
3. half-close、RST、超时和取消语义正确；
4. 每一项优化都能通过可复现数据证明；
5. 快路径失败时可以自动回退，而不是让连接失败；
6. 不以平均吞吐掩盖 CPU、内存、尾延迟或稳定性退化。

本文采用以下总路线：

```text
可信基准系统
    ↓
优化现有用户态 copy
    ↓
优化 Vision/REALITY 连接初期热路径
    ↓
安全提取两端 raw TCP socket
    ↓
Linux splice 双向转发
    ↓
必要时评估 io_uring splice
    ↓
仅在高并发数据证明有收益时引入 BPF SOCKHASH
```

最终生产路径建议保持三级或四级回退：

```text
SOCKHASH（可选实验快路径）
    ↓ 失败
splice / io_uring splice
    ↓ 失败
优化后的用户态 copy
    ↓ 不满足 Direct 条件
现有 REALITY/Vision 协议流转发
```

---

## 2. 最重要的结论

### 2.1 最大吞吐的关键不是扩大 Vision 帧

Vision framing 只应存在于连接初期。进入 `CMD_DIRECT` 后，长期流量不应继续经过：

- Vision frame 编解码；
- padding 计算与随机填充；
- REALITY/TLS record 处理；
- 临时 `Bytes`/`Vec` 分配；
- 通用 `AsyncRead`/`AsyncWrite` 包装层；
- 每个数据块的用户态 read/write copy。

因此，8 KiB、16 KiB 或 32 KiB 的 Vision 过渡块只影响连接初期的少量工作，必须测试，但不应被当作主要吞吐杠杆。

### 2.2 第一项高收益工作是建立可信基准

当前仓库已经有 `bench/throughput.py` 和 `bench/baseline-throughput.json`，但现有数据不能用于宣布性能结论：

- 当前基线只有 `socks-direct` 一项；
- 每项仅 3 次运行；
- 32 MiB 负载可能不足以进入稳定态；
- 基线标准差非常大；
- Python 接收循环反复执行不可变 `bytes += chunk`，会反复复制累计数据；
- echo server 会把完整 payload 保存在内存中；
- download 计时开始前，首个 `recv()` 可能已经同时读入部分 echo 数据，导致下载时间被低估；
- 单线程 echo server 不支持可信并发测试；
- loopback 数据无法代表物理网卡、IRQ、NUMA、TCP 拥塞控制和真实 RTT。

在修复基准之前，任何“提高了 20%”都可能只是测量误差。

### 2.3 技术引入顺序必须是 copy → splice → io_uring/BPF

不建议直接从当前 `tokio::io::copy_bidirectional` 跳到 BPF。正确顺序是：

1. 先确认当前 copy buffer、分配和包装成本；
2. 再建立 raw socket handoff；
3. 先实现相对简单、可调试的 `splice`；
4. 只有 perf 数据显示 syscall/调度仍是显著瓶颈时才评估 io_uring；
5. 只有目标高并发场景中 SOCKHASH 确实降低 CPU 或提高聚合吞吐时才投入生产化。

---

## 3. 当前项目状态评估

### 3.1 已经具备的正确性基础

当前 `RealityVisionServerStream` 已经具备重要的切换保护：

- 写路径有 `PendingDirect` 状态；
- `CMD_DIRECT` 对应的 REALITY ciphertext 写完后才进入 Direct；
- 读路径在收到 Direct 时会先提取 session 中已解密 plaintext；
- 随后提取已提前读入的 raw ciphertext；
- leftover 会在未来原始 TCP 数据之前交给上层；
- 当前写入内容通过 `MAX_WRITE_CONTENT_LEN = 16 * 1024` 限制，避免服务端生成超出 `u16` 的 frame；
- 已有 Xray 与 Chimera Client 的正向、负向 REALITY/Vision 端到端矩阵。

这些能力是未来 raw relay 的前提，不能为了性能绕过。

### 3.2 当前稳态性能瓶颈

当前主 TCP 转发最终仍进入类似以下路径：

```rust
tokio::io::copy_bidirectional(
    &mut server_stream,
    &mut client_stream,
).await
```

两侧还会包装 `MeteredStream`。即使 `RealityVisionServerStream` 内部已经进入 `ReadMode::Direct` 和 `WriteMode::Direct`，整个连接仍然以通用 stream 的形式被 Tokio 驱动。

因此当前 Direct 更准确地说是：

```text
绕过 REALITY/Vision 处理
但尚未绕过用户态双向 copy
```

当前代码还有几处可测量的连接初期复制：

1. `queue_padded_packet()` 先构造独立 `Bytes`，再复制到 `pending_write`；
2. `handle_padded_read()` 把新增内容 `to_vec()` 后再交给 TLS 状态观察器；
3. `drain_plaintext_from_session()` 先构造 `Vec`，上层随后又把内容复制到 `BytesMut` 或 `ReadBuf`；
4. `pending_write.clear()` 会复用容量，但 frame 的中间对象仍有分配和复制；
5. `MeteredStream` 的计数位置会阻碍未来直接拿到 raw fd。

这些不是最终稳态最大瓶颈，但应在 raw handoff 前清理，使状态机更清晰。

### 3.3 长度安全仍应做防御式加固

虽然服务端当前调用链把 frame content 限制在 16 KiB，底层 `vision_pad::pad()` 仍使用：

```rust
let content_len = data.len() as u16;
```

建议改成 checked conversion：

```rust
let content_len = u16::try_from(data.len()).map_err(|_| {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Vision frame content exceeds u16",
    )
})?;
```

安全不变量应同时存在于调用层和编码层。调用层负责性能分块，编码层负责绝不静默损坏。

---

## 4. 性能目标与验收指标

### 4.1 主目标

性能优化的主目标不是单一的 Mbps，而是：

```text
在零数据错误、兼容性不退化、尾延迟可控的前提下，
最大化目标并发规模下的总有效吞吐，并最小化 CPU/Gbit。
```

### 4.2 必须同时采集的指标

| 类别 | 指标 | 说明 |
|---|---|---|
| 吞吐 | uplink/downlink/full-duplex Gbit/s | 分方向测量，不能只测 echo 合计 |
| CPU 效率 | CPU-seconds/GiB、cycles/byte | 比单纯 CPU% 更适合跨机器比较 |
| 系统调用 | syscalls/GiB | 判断 splice/BPF 是否真正减少用户态参与 |
| 调度 | context-switches/GiB、CPU migrations | 判断 Tokio wakeup 和任务迁移成本 |
| 内存 | RSS、峰值 RSS、bytes/connection | 防止用大 buffer 换吞吐 |
| 分配 | allocations/connection、allocated bytes | 重点观察 Vision 切换和 copy buffer |
| 延迟 | connect、REALITY handshake、Direct transition、p50/p95/p99 RTT | 避免只优化大流量 |
| TCP | retransmits、cwnd、rtt、delivery_rate | 区分代理瓶颈和网络瓶颈 |
| 快路径 | Direct 命中率、splice/BPF 命中率、fallback 原因 | 证明优化真正被使用 |
| 正确性 | byte mismatch、duplicate、truncation、ordering failures | 必须始终为 0 |
| 稳定性 | fd/map/pipe 泄漏、连接残留、24h 错误数 | 防止短测通过、长测失效 |

推荐派生指标：

```text
吞吐效率 = 代理有效吞吐 / raw TCP 有效吞吐
CPU 效率 = CPU-seconds / GiB
周期效率 = CPU cycles / transferred byte
内存效率 = 峰值 RSS / 活跃连接数
```

### 4.3 推荐准入门槛

以下门槛是项目建议值，应在获得稳定历史数据后调整。

#### 所有优化的共同门槛

- 所有协议、边界和兼容性测试通过；
- 全量测试中 byte mismatch、丢失、重复和乱序为 0；
- benchmark 单流变异系数建议不超过 3%；
- 并发 benchmark 变异系数建议不超过 5%；
- 不接受只出现一次的峰值结果；
- 至少报告 median、p95、MAD 或 95% bootstrap confidence interval；
- 候选版本和基线必须在相同机器、内核、编译参数和测试顺序策略下运行。

#### 低风险优化准入

满足以下任一性能条件，并且 p99 和内存没有明显恶化：

- median throughput 提升至少 5%；或
- CPU-seconds/GiB 降低至少 10%。

#### 新快路径准入

例如 splice、io_uring、SOCKHASH，建议满足：

- 目标并发下聚合吞吐提升至少 10%；或
- CPU-seconds/GiB 降低至少 20%；
- p99 延迟恶化不超过 5%；
- RSS/connection 增幅不超过 10%；
- fallback 可用且正确；
- 24 小时稳定性测试无 fd、pipe、BPF map entry 泄漏。

SOCKHASH 还应满足：

- map 注册失败不会让连接失败；
- fallback 比例在正常环境下低于 0.1%；
- 不支持的内核、权限不足、`EBUSY` 和 map 满均有覆盖；
- daemon 异常退出或重启后不存在长期残留错误映射。

---

## 5. 目标架构

### 5.1 两阶段数据平面

将连接生命周期明确分成两阶段。

#### 阶段 A：协议阶段

```text
TCP accept
→ REALITY handshake
→ VLESS request parse
→ Vision padding/unpadding
→ inner TLS state observation
→ CMD_DIRECT transition barrier
```

该阶段允许使用用户态状态机和小型可复用 buffer，因为连接正确性和协议识别优先。

#### 阶段 B：raw relay 阶段

```text
确认两端均可 Direct
→ drain plaintext leftover
→ drain raw ciphertext leftover
→ flush CMD_DIRECT
→ 停止旧 reader/writer
→ 交出两个 raw TcpStream/OwnedFd
→ 选择 copy/splice/io_uring/SOCKHASH
```

进入阶段 B 后，任何协议 wrapper 都不应继续持有原始 socket 的活跃读写权。

### 5.2 必须存在的切换屏障

raw handoff 必须同时满足：

```text
write_mode == Direct
read_mode == Direct
pending_write.is_empty()
pending_read 已被顺序交付或显式作为 prefix 移交
REALITY session 不再拥有待处理 plaintext/ciphertext
没有并发任务仍在 poll 旧 stream
两个底层对象均可安全提取 raw TCP fd
```

建议定义显式 handoff 结果：

```rust
enum RelayHandoff<Wrapped, Raw> {
    Wrapped(Wrapped),
    RawReady {
        client: Raw,
        remote: Raw,
        client_prefix: Bytes,
        remote_prefix: Bytes,
    },
}
```

不要通过布尔标志让外层“猜测”当前 stream 是否已可 unwrap。

### 5.3 统一 relay 抽象

建议建立：

```rust
enum TcpRelayMode {
    Auto,
    Copy,
    Splice,
    IoUringSplice,
    Sockhash,
}
```

以及统一结果：

```rust
struct RelayOutcome {
    mode: EffectiveRelayMode,
    uploaded: u64,
    downloaded: u64,
    fallback_reason: Option<RelayFallbackReason>,
}
```

生产默认建议先保持 `Auto`：

```text
尝试成熟快路径
→ 不满足条件或初始化失败时自动回退
→ 保证连接可用
```

---

## 6. 分阶段演进计划

## 阶段 0：修复测量系统

### 目标

建立不会成为瓶颈、不会误计时、可以复现的性能基准。

### 建议新增

建立原生 Rust benchmark 工具，例如：

```text
bench/chimera_perf/
├── Cargo.toml
├── src/bin/generator.rs
├── src/bin/target.rs
├── src/bin/orchestrator.rs
├── src/protocol.rs
└── schemas/result-v1.json
```

### benchmark 协议建议

不要让 target 缓存完整 payload。建议使用固定长度、流式校验协议：

```text
RequestHeader {
    magic,
    version,
    mode,
    payload_len,
    response_len,
    pattern_seed,
}

客户端流式发送 payload
服务端流式计数并校验固定 pattern
服务端发送 upload ACK
服务端流式发送 response
客户端流式计数并校验
```

性能测试时不要对每个字节执行昂贵哈希。可以采用：

- 预生成 1–16 MiB pattern ring，循环发送；
- correctness 运行开启全量校验；
- throughput 运行使用低成本 pattern/分段采样；
- 结果中必须记录是否开启 full verification。

### 必须保留的对照组

每次正式测试至少包含：

1. raw TCP，无 Chimera；
2. Chimera SOCKS direct；
3. VLESS TCP，无 REALITY；
4. VLESS + REALITY，无 Vision Direct 或强制保持 wrapper；
5. VLESS + REALITY + Vision Direct；
6. 相同机器上的 Xray reference；
7. 候选 relay：copy/splice/io_uring/SOCKHASH。

### 临时修复现有 Python benchmark

在 Rust harness 完成前，至少修复：

- 用 `bytearray`、预分配 buffer 或只计数，不使用 `bytes += chunk`；
- echo server 不保存完整 payload；
- 明确 upload ACK 与 download payload 的分帧语义；
- download timer 必须覆盖已经和 ACK 同一个 `recv()` 到达的 payload；
- 支持多连接并发；
- 输出每次原始结果，而不仅是汇总；
- 记录机器、CPU、内核、commit、binary hash、编译参数；
- 至少运行 warmup 3 次、正式运行 10 次；
- 测试顺序随机化，防止温度和频率漂移只影响后面的候选。

### 阶段验收

- raw TCP 结果稳定；
- 单流 CV ≤ 3%；
- 同一 commit 重复两组测试的 median 差异 ≤ 3%；
- Python 与 Rust harness 在低速限制条件下结果一致；
- benchmark endpoint CPU 不成为瓶颈；
- 结果以 JSON 保存，可进入历史数据库。

---

## 阶段 1：优化当前用户态路径

### 目标

在不引入 raw fd 和平台专用代码前，确认通用 copy 路径的最佳可达性能。

### 1. copy buffer 矩阵

当前通用 `copy_bidirectional` 默认使用较小的双向缓冲。建立配置或实验分支测试：

```text
8 KiB
16 KiB
32 KiB
64 KiB
128 KiB
256 KiB
```

不要直接假设 64 KiB 最佳。必须分别测：

- 单连接大流量；
- 64/512/目标并发；
- uplink、downlink、full-duplex；
- RSS/connection；
- cache miss 和 cycles/byte。

如果 128 KiB 只提高单流 2%，但令目标并发内存翻倍，则不应作为默认值。

### 2. 消除 Vision 中间分配

建议重构 `queue_padded_packet()`，直接写入复用的 `pending_write`：

```text
reserve
→ write UUID/header
→ append content
→ resize padding
→ RNG 直接填入目标切片
```

避免：

```text
构造临时 BytesMut
→ freeze 成 Bytes
→ 再复制进 pending_write
```

### 3. 避免 uplink 观察复制

当前新增数据被 `to_vec()` 后交给 `tls_state.observe_uplink()`。应重构借用范围，使观察器直接读取 `pending_read[previous_len..]`，或者在 unpad 时同时把内容送入观察器。

### 4. 直接 drain 到目标 buffer

把：

```text
session → Vec → pending_read/ReadBuf
```

改成：

```text
session → pending_read
```

或在当前 `ReadBuf` 有足够容量时直接写入 `ReadBuf`，只把剩余部分放入 `pending_read`。

### 5. checked length

编码器必须使用 `u16::try_from`。上层继续使用 bounded chunk；两者不能互相替代。

### 6. Vision chunk 只做实验，不先改默认

测试：

```text
8 KiB / 8171 bytes
16 KiB
32 KiB
65535 bytes
```

关注的不是稳态吞吐，而是：

- time-to-Direct；
- connection setup CPU；
- 首包延迟；
- 单连接临时内存；
- compatibility。

没有数据前，保留当前 16 KiB 是合理的低风险选择。

### 阶段验收

- 所有已有 Xray/Chimera Client E2E 通过；
- 新增长度和 fragmented TLS 测试通过；
- 用户态 copy 最佳 buffer 已由数据选择；
- 低风险优化达到准入门槛；
- heap profile 显示 Vision 连接初期临时分配下降。

---

## 阶段 2：实现 raw socket handoff

### 目标

让 Direct 不再只是 stream 内部状态，而是可以把 raw TCP socket 安全移交给专用 relay。

### 设计要求

建议为 `RealityVisionServerStream` 增加受约束的提取接口：

```rust
fn try_into_raw_parts(self) -> Result<RawVisionParts, Self>;
```

只有全部条件满足时返回：

```rust
struct RawVisionParts {
    client: TcpStream,
    pending_client_to_remote: Bytes,
    pending_remote_to_client: Bytes,
}
```

如果底层 `IO` 不是 raw TCP、仍有 wrapper、仍有 pending ciphertext 或状态未完成，则返回原对象，继续走通用 copy。

### 关键约束

- 提取动作必须消费 `self`，避免旧 stream 继续被 poll；
- leftover 必须有确定方向；
- 先完整发送 leftover，再启用新的内核快路径；
- 计数器不能依赖原 `MeteredStream`；
- timeout、连接注册和 shutdown 责任必须转移给 relay；
- 上下行可以在不同时间完成 Direct，只有双方都满足 raw 条件才可做双向内核快路径。

### 阶段验收

- raw handoff 单元测试覆盖所有拒绝条件；
- 在每个字节都触发 partial write/read 的模拟 IO 中顺序正确；
- Direct frame 与首个 raw byte 绝不交叉；
- leftover 顺序测试覆盖 plaintext + raw ciphertext 同时存在；
- half-close 和 RST 与原路径行为一致；
- 关闭 raw handoff feature 时行为完全不变。

---

## 阶段 3：Linux 双向 splice

### 目标

把稳态数据从：

```text
socket → Rust buffer → socket
```

改成：

```text
socket → kernel pipe buffer → socket
```

### 建议实现

每个方向一条 pipe：

```text
client → pipe_up → remote
remote → pipe_down → client
```

使用非阻塞 fd，并通过 Tokio `AsyncFd` 或专用线程/事件循环处理 readiness。

建议 API：

```rust
async fn splice_bidirectional(
    client: TcpStream,
    remote: TcpStream,
    counters: RelayCounters,
    cancellation: CancellationToken,
) -> io::Result<RelayOutcome>;
```

### 必须正确处理

- `EAGAIN`；
- partial splice；
- pipe 中仍有数据时一侧 EOF；
- FIN 的单向传播；
- RST；
- cancellation；
- idle timeout；
- `splice()` 不支持或返回 `EINVAL`；
- 计数器按实际写入目标 socket 的字节更新；
- 两方向同时退出的竞态；
- 退出时 pipe fd 和 socket fd 只关闭一次。

### 不要做的事情

- 不要在 splice 外再包 `MeteredStream`；
- 不要在每次 splice 后进行高基数日志；
- 不要每个连接创建独立阻塞线程；
- 不要在 CMD_DIRECT 未 flush 时启动 splice；
- 不要在 prefix 尚未写完时注册 BPF 或 splice raw 流量。

### 阶段验收

- 单流和高并发均达到新快路径准入门槛；
- syscalls/GiB、context-switches/GiB 和 cycles/byte 明显下降；
- 所有错误均自动回退或正确终止；
- 24h soak 无 pipe/fd 泄漏；
- 在不支持 splice 的平台自动使用 copy。

---

## 阶段 4：评估 io_uring splice

### 引入条件

只有 perf 证明以下成本仍显著时才进入本阶段：

- 大量 `splice` syscall；
- epoll wakeup 和 context switch 占明显 CPU；
- 高并发下事件循环成为瓶颈；
- 网络和网卡尚未饱和。

### 潜在收益

- 批量提交 SQE；
- 批量消费 CQE；
- 减少 syscall 和 wakeup；
- 可以维持多个 in-flight 操作。

### 风险

- cancellation 和 fd 生命周期复杂；
- half-close 状态机更难验证；
- ring 饱和和 backpressure 需要专门设计；
- 内核版本差异可能改变行为；
- Rust runtime 集成成本高。

### 准入规则

如果相对普通 splice：

- throughput 提升不足 5%；并且
- CPU-seconds/GiB 降低不足 10%，

则不建议承担生产复杂度。

---

## 阶段 5：实验性 BPF SOCKHASH

### 定位

BPF 只用于双方已完成 Vision Direct 之后的 raw TCP socket stitching。REALITY handshake、VLESS 解析和 Vision 状态判断仍在用户态。

不建议使用 XDP 处理本项目的 TCP 代理稳态数据，因为那会逼近自行维护 TCP/NAT 状态和包级转发，复杂度与当前 socket-based 架构不匹配。

### 建议数据平面

```text
用户态：完成协议和 Direct transition
    ↓
把 client/remote socket 加入 SOCKHASH
    ↓
建立 client → remote 与 remote → client 映射
    ↓
sk_skb 或 sk_msg verdict 重定向
    ↓
用户态只处理生命周期、超时、统计与回退
```

### 控制面要求

- BPF program 和 map 由独立模块加载；
- 使用明确的 connection generation/cookie，不只依赖 fd 数字；
- map 更新、删除和连接状态机必须幂等；
- map 满、权限不足、program attach 冲突、`EBUSY` 和 verifier 失败均回退；
- 不能要求生产环境必须拥有不必要的广泛 root 权限；
- 提供完全关闭 BPF 的 kill switch；
- 用户态应能检测“已配置但未真正命中 redirect”的情况。

### 统计要求

不要对共享全局 map 做每小块高竞争原子更新。优先：

- per-CPU counters；
- 周期批量读取；
- connection close 时聚合；
- 只保留必要的低基数字段。

### BPF 专属验收

- 1、64、512、目标并发下与 splice A/B；
- 大流和小流分别测试；
- full-duplex；
- FIN/RST/half-close；
- map 满；
- socket 已附着其他 parser/verdict；
- daemon 重启；
- BPF program reload；
- 内核版本矩阵；
- 24h 稳定性；
- fallback 后连接数据仍正确。

只有在目标生产并发中确实提高聚合吞吐或显著降低 CPU 时，才应进入默认 `Auto` 候选。

---

## 阶段 6：系统级调优

系统调优应在数据路径确定后进行，否则容易掩盖代码瓶颈。

### 编译

分别测试并记录：

- `--release`；
- LTO；
- `codegen-units`；
- target CPU 优化；
- PGO；
- allocator 选择。

不能只比较不同编译参数的二进制大小，必须比较 cycles/byte、吞吐和构建可重复性。

### Tokio/runtime

测试：

- worker 数量；
- worker CPU affinity；
- 连接任务是否频繁迁移；
- blocking pool 是否参与数据路径；
- acceptor 与 relay worker 是否需要分离。

### 网络与 CPU 拓扑

正式 benchmark 应记录并控制：

- CPU governor/turbo 状态；
- NUMA node；
- NIC IRQ affinity；
- RSS/RPS/XPS；
- GRO/GSO/TSO；
- MTU；
- TCP congestion control；
- socket autotuning；
- 网卡队列数；
- `SO_REUSEPORT` listener 分布。

不要默认关闭所有 offload。应分别测试并记录，因为生产部署通常会依赖硬件 offload。

---

## 7. 完整测试设计

## 7.1 单元与属性测试

### Vision 长度边界

| 用例 ID | 输入长度 |
|---|---:|
| VLEN-001 | 0 |
| VLEN-002 | 1 |
| VLEN-003 | 15/16/17 |
| VLEN-004 | 8170/8171/8172 |
| VLEN-005 | 16383/16384/16385 |
| VLEN-006 | 65534/65535/65536/65537 |
| VLEN-007 | 1 MiB |

验证：

- 编码层超限明确报错；
- 上层分块无丢失；
- partial write 返回值正确；
- frame command 顺序正确；
- Direct 后剩余数据不再 framing。

### TLS record 分片

| 用例 ID | 场景 |
|---|---|
| VTLS-001 | 5-byte header 每字节分片 |
| VTLS-002 | body 每字节分片 |
| VTLS-003 | 多个 record 合并在一次 read |
| VTLS-004 | record 跨多个 Vision frame |
| VTLS-005 | TLS 1.3 application data 完整 |
| VTLS-006 | TLS 1.2，只 End 不 Direct |
| VTLS-007 | 不支持 cipher，只 End 不 Direct |
| VTLS-008 | 非 TLS plaintext |
| VTLS-009 | TLS control/post-handshake 无 application data |

### Direct transition

| 用例 ID | 场景 |
|---|---|
| VDTR-001 | CMD_DIRECT 一次写完 |
| VDTR-002 | CMD_DIRECT 每次只写 1 byte |
| VDTR-003 | flush 多次 Pending |
| VDTR-004 | plaintext leftover |
| VDTR-005 | raw ciphertext leftover |
| VDTR-006 | 两类 leftover 同时存在 |
| VDTR-007 | leftover 后立即 EOF |
| VDTR-008 | transition 时 cancellation |
| VDTR-009 | transition 时 RST |
| VDTR-010 | 上下行不同步进入 Direct |

必须验证字节顺序：

```text
Vision content
→ decrypted leftover
→ raw leftover
→ future raw TCP bytes
```

## 7.2 兼容性 E2E

保留并扩展当前 Xray 和 Chimera Client 矩阵：

- Xray client → Chimera Server；
- Chimera Client → Chimera Server；
- 可选 Chimera Client → Xray Server reference；
- IPv4、domain target、真实 IPv6；
- 多 serverName；
- 多 shortId；
- 正确/错误 public key；
- 正确/错误 UUID；
- Vision flow 缺失；
- 普通账户错误声明 Vision；
- 明确 min/max client version；
- 默认版本策略；
- sequential 和 concurrent connections；
- 64 KiB、1 MiB、1 GiB payload；
- full-duplex；
- half-close。

## 7.3 relay 正确性

每种 relay 都必须运行同一套 contract tests：

```text
CopyRelay
SpliceRelay
IoUringRelay
SockhashRelay
```

合同包括：

- 双方向完整复制；
- 只关闭一侧写方向；
- 对端继续返回；
- RST；
- slow reader；
- slow writer；
- cancellation；
- idle timeout；
- 连接计数和字节计数；
- prefix/leftover；
- 错误回退；
- 资源释放。

## 7.4 性能负载矩阵

### 数据量

- 64 MiB：快速预检；
- 1 GiB：主要单流测试；
- 持续 30–120 秒：稳定吞吐；
- 24 小时：soak。

### 并发

```text
1, 8, 64, 256, 512, 1000, 目标生产并发
```

不要在 endpoint CPU 已饱和后继续把结果归因于代理。

### 方向

- uplink-only；
- downlink-only；
- full-duplex 50/50；
- 非对称 90/10；
- 大流 + 大量小流混合。

### 网络条件

- 低 RTT 局域网；
- 10 ms；
- 50 ms；
- 100 ms；
- 0、0.1%、1% loss；
- 100 Mbit/s、1 Gbit/s、10/25/100 Gbit/s；
- 标准 MTU 与 jumbo frame，分别记录。

`tc netem` 适合功能和趋势测试，但最终最大吞吐结论应来自真实多机和目标速率网卡。

### 连接类型

- 长连接大象流；
- 每连接 1–64 KiB 小流；
- 高频建立连接；
- 长短流混合；
- TLS 1.3 Direct；
- 不可 Direct 的 REALITY wrapped 流量。

---

## 8. 推荐 benchmark 拓扑

## 8.1 正式性能拓扑

优先使用三台物理机：

```text
Generator Host
    │ dedicated NIC/network
    ▼
Chimera Host
    │ dedicated NIC/network
    ▼
Target Host
```

要求：

- generator 和 target 有足够 CPU；
- raw TCP 基线能跑满预期链路；
- Chimera Host 是唯一变量；
- 三台机器时钟同步；
- 记录 NIC、driver、firmware、内核和 BIOS 设置；
- 不让 generator/target 的校验算法成为瓶颈。

## 8.2 CI 拓扑

CI 可使用 network namespace + veth：

```text
ns-client ↔ ns-chimera ↔ ns-target
```

用途：

- 自动回归；
- netem；
- 路由和 half-close；
- relay 模式一致性。

但不能把 namespace/loopback 结果作为最终网卡吞吐结论。

---

## 9. 实验方法

### 9.1 每次实验固定变量

记录：

```text
Git commit
binary SHA-256
Rust version
Cargo.lock hash
kernel version/config
CPU model/microcode
RAM/NUMA
NIC/driver/firmware
IRQ affinity
runtime worker count
relay mode
copy buffer size
Vision chunk size
logging level
socket options
test topology
payload/concurrency/direction
```

### 9.2 运行顺序

推荐：

1. 检查 raw TCP；
2. warmup 3 次；
3. 把 baseline/candidate 顺序随机化；
4. 每个场景至少 10 次；
5. 高成本正式测试可做 5 个较长重复，但必须报告置信区间；
6. 测试前后再次运行 raw TCP，检查环境漂移。

### 9.3 统计

主要看 median，不看最大值。推荐输出：

- median；
- p5/p95；
- MAD；
- 95% bootstrap CI；
- 每次原始值；
- 相对 raw TCP 和 Xray reference 的比例。

当候选与基线置信区间大量重叠时，应判定“无明确收益”，而不是选择更好看的均值。

---

## 10. 结果数据格式

建议每次运行输出一条 JSON：

```json
{
  "schema": 1,
  "timestamp": "...",
  "commit": "...",
  "binary_sha256": "...",
  "kernel": "...",
  "cpu": "...",
  "nic": "...",
  "scenario": "vless-reality-vision-direct",
  "relay_requested": "auto",
  "relay_effective": "splice",
  "fallback_reason": null,
  "connections": 64,
  "direction": "full-duplex",
  "payload_bytes_per_connection": 1073741824,
  "rtt_ms": 0.3,
  "loss_pct": 0.0,
  "upload_gbps": 0.0,
  "download_gbps": 0.0,
  "cpu_seconds": 0.0,
  "cycles": 0,
  "instructions": 0,
  "context_switches": 0,
  "syscalls": 0,
  "peak_rss_bytes": 0,
  "direct_transition_p99_us": 0,
  "byte_mismatches": 0,
  "errors": 0
}
```

汇总表建议：

| Commit | Mode | Conn | Up Gbps | Down Gbps | CPU s/GiB | cycles/B | ctx/GiB | RSS/conn | p99 | Errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | copy-8K | 1 |  |  |  |  |  |  |  | 0 |
| candidate | copy-64K | 1 |  |  |  |  |  |  |  | 0 |
| candidate | splice | 1 |  |  |  |  |  |  |  | 0 |
| candidate | sockhash | 512 |  |  |  |  |  |  |  | 0 |

文档、PR 和发布说明禁止填写未经测量的示例性能数字。

---

## 11. 性能诊断工具

### perf stat

建议至少采集：

```bash
perf stat \
  -e task-clock,cycles,instructions,cache-references,cache-misses,\
context-switches,cpu-migrations,page-faults \
  -p "$CHIMERA_PID" -- sleep 60
```

### perf record

```bash
perf record -F 999 -g -p "$CHIMERA_PID" -- sleep 30
perf report
```

重点确认热点是否位于：

- `copy_bidirectional`；
- `poll_read`/`poll_write`；
- `memcpy`；
- buffer 扩容；
- REALITY session；
- RNG；
- 日志；
- scheduler；
- splice/BPF fallback。

### 网络状态

```bash
ss -tinp
ip -s link
ethtool -S <nic>
nstat -az
```

### syscall 和调度

根据环境使用：

```bash
strace -c -f -p "$CHIMERA_PID"
pidstat -u -r -w -p "$CHIMERA_PID" 1
```

### BPF

```bash
bpftool prog show
bpftool map show
bpftool map dump id <id>
```

生产环境必须避免开启会显著改变性能的高频 trace，只在诊断运行中使用。

---

## 12. CI 与发布策略

### 每个 PR

- unit/property tests；
- Vision boundary tests；
- transition contract tests；
- Xray/Chimera Client 关键 E2E；
- relay contract tests；
- 编译所有 feature 和平台回退；
- microbenchmark 只记录，不建议在共享 CI 上硬 gate 微小差异。

### Nightly

- 完整正向/负向 E2E；
- namespace + netem；
- 10 次 throughput 运行；
- copy buffer 确认场景；
- fd/内存泄漏检查；
- 与最近稳定基线比较。

### 定期或发布前

- 三机物理网络；
- Xray reference；
- 目标 NIC 速率；
- 目标并发；
- 1h 和 24h soak；
- splice/io_uring/BPF A/B；
- 保存完整环境清单与原始 JSON。

性能基线应按硬件/内核分组，不能把不同 CI 机器的 Mbps 直接比较。

---

## 13. 可观测性设计

建议新增低基数指标：

```text
vision_connections_total
vision_direct_eligible_total
vision_direct_transition_total{result}
vision_direct_transition_seconds
vision_pending_plaintext_bytes
vision_pending_raw_bytes
relay_connections_total{mode}
relay_fallback_total{from,to,reason}
relay_bytes_total{mode,direction}
relay_errors_total{mode,kind}
splice_calls_total{direction,result}
splice_bytes_total{direction}
sockhash_entries
sockhash_update_total{result}
sockhash_redirect_total{result}
```

不要把 UUID、目标地址或连接 ID 作为 metrics label。

日志建议只在状态变化时记录：

- Direct eligible；
- transition complete；
- raw handoff success/reject reason；
- effective relay mode；
- fallback；
- connection final counters。

高吞吐模式下关闭逐 chunk debug 日志。

---

## 14. 配置与回滚

建议加入实验配置：

```json5
{
  "tcpRelay": {
    "mode": "auto", // auto|copy|splice|io-uring|sockhash
    "copyBufferBytes": 65536,
    "allowVisionRawHandoff": true,
    "allowBpf": false
  }
}
```

初始默认应保守：

1. 先提供 `copy` 与 `splice` 显式开关；
2. splice 稳定后进入 `auto`；
3. io_uring 和 BPF 先保持 opt-in；
4. 所有快路径均可通过单个 kill switch 关闭；
5. 配置解析失败不应默默启用实验路径。

---

## 15. 建议的实施提交序列

按以下顺序拆分提交，避免大爆炸重构：

1. 修复 benchmark 计时和 buffer 行为；
2. 新增 Rust benchmark harness 与结果 schema；
3. 建立当前 commit 的可信基线；
4. 增加 copy buffer 可配置实验；
5. Vision 编码 checked conversion；
6. 消除 Vision 临时 frame 和 uplink `to_vec()`；
7. 增加 relay contract test 框架；
8. 增加 raw socket handoff API，但默认关闭；
9. handoff E2E 与 fault injection；
10. 实现 Linux splice；
11. splice metrics、fallback 和 soak；
12. 数据评审，决定是否默认启用 splice；
13. perf 证明有需要后再做 io_uring prototype；
14. 在独立 feature 下实现 SOCKHASH prototype；
15. 高并发数据评审，决定是否生产化 BPF。

每一步都应能单独回滚。

---

## 16. 最终决策表

| 技术 | 首要收益 | 主要风险 | 何时采用 |
|---|---|---|---|
| 调整 copy buffer | 简单、跨平台 | 内存/连接增加 | 阶段 1 数据证明后 |
| Vision 减少分配 | 降低连接初期开销 | 借用/状态机复杂 | 应做，但需 microbench 和 E2E |
| raw handoff | 为所有内核快路径奠基 | 顺序和所有权错误 | splice 前必须完成 |
| splice | 降低用户态复制 | half-close、pipe 状态机 | 第一生产级 Linux 快路径 |
| io_uring splice | 降低 syscall/wakeup | 实现和内核复杂度 | perf 证明 splice 调度成本显著时 |
| BPF SOCKHASH | 高并发下让用户态退出稳态路径 | 权限、内核、生命周期、冲突 | 目标并发 A/B 数据明确胜出时 |
| XDP | 包级极致性能 | 接近重做 TCP 代理 | 当前项目不建议 |
| PGO/CPU 亲和 | 进一步压榨 CPU | 环境特化 | 数据路径稳定后 |

---

## 17. 近期最优行动

当前项目最合理的下一步不是立即写 BPF，而是：

1. 修复 `bench/throughput.py` 的测量失真；
2. 建立 Rust 原生三端 benchmark；
3. 测出 raw TCP、Xray、当前 Chimera Vision Direct 的可信基线；
4. 测试 `copy_bidirectional_with_sizes` 的 8–256 KiB 矩阵；
5. 清理 Vision 中间分配并增加 checked conversion；
6. 设计并验证 raw socket handoff；
7. 实现 Linux splice；
8. 用 cycles/byte、CPU-seconds/GiB、syscalls/GiB 和聚合吞吐决定是否继续做 io_uring/BPF。

若 splice 已经跑满目标网卡，并且 CPU 余量充足，继续引入 BPF不会提高有效吞吐，只会增加系统复杂度。若在数百至数千连接时 CPU、context switch 和 syscall 成为明显瓶颈，而网卡未饱和，SOCKHASH 才是有价值的下一项实验。

---

## 18. 参考依据

本路线图的外部技术依据包括：

- Linux Kernel Documentation：`BPF_MAP_TYPE_SOCKMAP and BPF_MAP_TYPE_SOCKHASH`；
- Linux Kernel Documentation：XDP redirect 与支持的 map 类型；
- Linux `splice(2)` manual page；
- liburing `io_uring_prep_splice(3)` manual page；
- Tokio `copy_bidirectional` 与 `copy_bidirectional_with_sizes` 文档；
- Linux Kernel Documentation：perf/workload tracing。

项目内依据包括：

- `RealityVisionServerStream` 当前 Direct 状态机；
- REALITY session leftover 提取实现；
- `vision_pad` 和 `VisionUnpadder`；
- 当前 Xray/Chimera Client REALITY Vision E2E 矩阵；
- `bench/throughput.py` 与现有 baseline JSON；
- 本地 Xray-core VisionWriter、8 KiB pool 和 raw/splice 路径。

---

## 19. 一句话路线

```text
先让基准可信，再让 Direct 真正交出 raw socket；
先用 splice 获得生产级低复制路径，最后才让 io_uring 或 SOCKHASH 用数据证明自己。
```
