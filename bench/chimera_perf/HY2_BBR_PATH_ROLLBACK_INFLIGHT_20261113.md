# HY2 / Quinn BBR — 路径验证超时回退与旧路径在途包研究（2026-11-13）

**状态：L3 HOLD。** 本轮在隔离 quinn-proto 副本上完成真实连接级回归和最小采样元数据清理修复；研究样本仍不进入 BBR pacing / cwnd / max_filter，不代表 HY2 吞吐已提升或 Xray 完全兼容。

## 研究范围与来源

- 主工作区：`/home/si/Desktop/mfsga/Chimera_Server`，`master` HEAD `aea6a11`。用户原有未提交 tracked 修改、`ref/` gitlink 及 untracked 研究记录全部保留；本轮没有 stage/commit/rebase/push/merge/deploy。
- 独立源码副本：`/tmp/chimera-bbr-rollback-20261113-4pNhh6/`，复制自上轮研究副本 `/tmp/chimera-bbr-conn-integrated-20261113-Ir2m9E/`，不额外创建 Git worktree。
- 固定参考：`ref/xray-core` `e7a69fa8`，HY2 BBR `bandwidth_sampler.go` 的发送/ACK 采样语义。目标是保证以 Xray 语义采样时旧路径状态不污染新路径，内部池的生命周期仍由 Quinn `Connection` 所有。
- **本轮唯一最新完整累计研究候选**：`bench/chimera_perf/HY2_BBR_PATH_ROLLBACK_INFLIGHT_RESEARCH_20261113.patch`，相对于**当前含已有未提交改动的主工作区 vendor/quinn-proto 源文件**生成；**不要与先前** `HY2_BBR_PATH_0RTT_INTEGRATION_RESEARCH_20261113.patch` **叠加应用**。仅执行过 `git apply --check`，从未应用到主库源码。

## 新增真实连接级复现 1：PathValidation 超时回退

在 Quinn 原有 `Pair` 的真实 client/server 通路中，先完成 QUIC handshake、服务端发送一条 FIN 标记的 4096B unidirectional STREAM；**将旧路径服务端发出的待收包保存而不交给客户端**，保证多个 `SentPacket` 及采样句柄仍在途。改变客户端源 IPv4 地址并发送实际 PING，引发服务端 `migrate()`，使 `PathData::generation` 增加、新路径激活，并将 `PATH_CHALLENGE` 等新路径探测响应丢弃。

在真实 `Timer::PathValidation` 设定的 deadline（通过只读 test accessor 获取）调用原生 `handle_timeout(deadline)`；验证服务端恢复原 client socket address 和原 generation、速率 anchor 失效，但旧路径在途包仍保留。随后恢复客户端原地址，将先前保存的旧路径报文送达，并经真实 STREAM/ACK 验证客户端**完整收到 4096B 正确内容**。

### 实际复现出的新缺陷

首次运行时数据、回退均成功，但额外的断言显示 bounded snapshot pool **剩余 2 个占用槽位**。新增仅测试用只读诊断枚举 `PacketSpace::sent_packets` 并按 `path_generation` 分类，得出：

```text
rollback snapshot diagnostic:
pool = 2
packet owners (all, current_generation, other_generation) = (2, 0, 2)
```

这表明 **2 个槽位均由已放弃的新路径代次的在途包持有**。原研究设计只在未来 ACK、判丢、丢弃时释放句柄；回退以后若这些包再无响应，就可能长期挤占固定容量的元数据池。它是**尚未合入的研究采样器的生命周期缺陷**，不是声称上游 Quinn 原生代码存在内存泄漏。

### 隔离最小修复

在 `Connection::handle_timeout` 的 `Timer::PathValidation` 分支、`prev_path` 即将恢复前，通过 `#[cfg(test)]` 路径遍历各 `PacketSpace::sent_packets` 中属于 **abandoned_generation（即拒绝的新路径）**的包，调用 `delivery_sampler.discard(packet.delivery_handle.take())`。**只清空快照句柄并归还池槽位，不移除/修改 `SentPacket` 本身的包编号、帧、发送时间、重传队列或原 Quinn 拥塞状态。** 随后恢复 `prev_path` 并重置 delivery anchor。

修复后该真实连接回归从 RED 到 GREEN：客户端完整收到 4096B；池占用与现存有效 SentPacket 句柄数量相等；**其他（abandoned）路径快照为 0**。旧路径仍在途包并未因回退被提前删除。

## 新增真实连接级复现 2：迁移成功、旧路径仍在途

另一条测试在旧路径先排队 2048B STREAM + FIN，保存该路径待接收包以维持未确认状态，然后改变客户端源地址、发真实 PING 触发迁移，并让新路径成功通过验证。确认新路径已激活，旧路径快照在切换时依然保持；最后恢复此前保存的旧路径包送达真实客户端。

验收条件：收到的 2048B 内容完全正确，旧路径迟到 ACK/判丢通过现有释放入口释放快照，`DeliverySampler` occupied 与跟踪中的 `SentPacket` 句柄数量一致，并且不遗留旧代次句柄。该测试已通过。无需修改真实 Quinn stream/loss 控制逻辑。

## 验证记录（真实执行）

```bash
study=/tmp/chimera-bbr-rollback-20261113-4pNhh6
CARGO_BUILD_JOBS=2 cargo test --locked --offline --manifest-path "$study/Cargo.toml" --target-dir /tmp/chimera-pacer-red-9oZjRu/target --lib --quiet
CARGO_BUILD_JOBS=2 cargo test --locked --offline --manifest-path "$study/Cargo.toml" --target-dir /tmp/chimera-pacer-red-9oZjRu/target --doc --quiet
CARGO_BUILD_JOBS=2 cargo check --locked --offline --manifest-path "$study/Cargo.toml" --target-dir /tmp/chimera-pacer-red-9oZjRu/target --lib
CARGO_BUILD_JOBS=2 cargo clippy --locked --offline --manifest-path "$study/Cargo.toml" --target-dir /tmp/chimera-pacer-red-9oZjRu/target --lib --tests -- -D warnings -A clippy::manual_filter
rustfmt --edition 2021 --check "$study/src/connection/delivery_rate_pool.rs"
git apply --check bench/chimera_perf/HY2_BBR_PATH_ROLLBACK_INFLIGHT_RESEARCH_20261113.patch
cargo fmt --all -- --check
git diff --check
```

- 隔离 crate 完整 **292/292** lib 单测：PASS，0 failed/ignored；其中新增 2 条真实连接级回归；上轮 290 个仍通过。
- 隔离 crate 文档测试 **3/3** PASS。
- 普通非测试 `cargo check --lib` PASS。
- 严格 Clippy PASS，仅按此前明确例外豁免原始 `connection/packet_crypto.rs` 中既有 `clippy::manual_filter`，未豁免本轮新增 lint；曾在新增测试发现 `assert_eq!(bool, true)`，改成 `assert!(bool)` 后无警告。
- 研究采样模块 rustfmt PASS；主工作区 cargo fmt check、git diff check、补丁 `git apply --check` PASS；**没有应用补丁或触及 vendor 生产文件**。
- 这两条真实连接测试使用 Quinn `Pair` 网络仿真，包含实际协议包/ACK/stream 和 Quinn 定时器截止逻辑，**不代表公网真实 WAN/UDP socket 系统级测试**。

## 限制与后续建议

1. 整份累计候选仍大部分为 `#[cfg(test)]` 旁路采样，但沿袭上轮对 `PathData::sent` 返回值的**非测试内部 API 调整**；后续整合必须专门审查，不能宣称“所有更改都是 test only”。
2. `Timer::PathValidation` 通过读取真实 deadline 和调用 `handle_timeout` 验证，未进行真实 OS timer + socket 的网络端到端测试。旧路径仍可能存在多次连续迁移/地址切换、多代次在途包及重排/ACK 乱序交叠，需要更复杂压力验证。
3. 未验证正式 BBR 读取新 `RateSample` 的行为；实验不改变 BBR 的现有带宽过滤器、窗口和 pacing，MinMax 老化仍是独立问题。
4. 未完成 Xray HY2/H3 client 双向全字节互通、GSO/partial-send、长期饱和与池耗尽、CPU/RSS、CUBIC 共瓶颈 Jain 公平性、WAN RTT/loss/ACK 压缩、MSRV/跨平台或独立 L3 Reviewer。
5. 下一轮建议：在隔离副本中做**连续两次迁移、路径验证失败并回退、三代路径仍有在途包**的场景，检验只回收 abandoned generation 的策略不会留下更早的过时快照；随后为 A/B BBR 采样决策设计只读与可回滚的开关，先做因果验证再谈性能。

**结论：L3 HOLD。** 主分支、远端、历史和线上运行状态未改变；研究代码可作为下一轮独立审查的输入。
