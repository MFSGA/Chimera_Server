# Chimera_Server 真实线上/WAN 性能联调执行手册

> 日期：2026-09-07
>
> 目标：把现有 loopback 性能结论推进到真实跨主机/WAN A/B，优先比较 Chimera 与当前稳定线上服务（例如 Xray reference），同时记录正确性、吞吐、稳定性、进程和网络指标。
>
> 本方案不要求把生产用户流量当 benchmark。建议使用独立测试端口、独立测试账号/UUID 和受控压测客户端。

## 1. 新增工具

### `bench/chimera_perf/src/bin/wan_probe.rs`

一个 Rust 跨主机性能 probe，包含两个子命令：

- `server`：部署在独立 target 主机，提供高吞吐、流式、确定性 payload 校验；
- `client`：从压测客户端经 `direct` 或一个/多个 SOCKS5 入口访问 target。

它支持：

- 多 endpoint A/B；
- 1/16/64 等并发矩阵；
- roundtrip：完整上传后同步，再完整下载；
- duplex：同时上传和下载；
- 每连接确定性 payload 校验；
- warmup + 正式样本；
- endpoint 顺序确定性打散，避免固定 A/B 顺序偏差；
- setup p50/p99；
- per-flow p50/p99；
- 聚合吞吐；
- 连接/flow 成功率；
- CV；
- 仓库约定的 3% 稳定性门槛。

`client` 只依赖 SOCKS5，因此协议层可以自由替换：

```text
wan_probe client
  -> Xray local SOCKS -> Xray online server -> target
  -> Chimera/compatible local SOCKS -> Chimera online server -> target
```

只要两条路径最终都能通过 SOCKS5 CONNECT 到同一个 target，就能使用完全相同的 payload、并发和统计逻辑比较。

### `bench/online_metrics.py`

Linux 只读采样器，直接读取 `/proc` 和 `/sys`，不需要 `pidstat`/`sar`。

可记录：

- 目标进程 CPU ticks / CPU%；
- VmRSS / VmHWM；
- fd；
- thread；
- voluntary / nonvoluntary context switches；
- NIC RX/TX bytes、packets、errors、drops；
- NIC 实时 Mbps；
- TCP `RetransSegs`、`OutRsts`、`InErrs`、连接计数变化；
- NET_RX / NET_TX softirq 总量和 delta。

采样器不会读取进程命令行参数或环境变量，避免把配置凭据写入性能结果。

### `bench/online_compare.py`

读取 `wan_probe client` JSON，输出 Markdown A/B 表格，并可执行：

- 3% CV strict gate；
- 可选最大吞吐回归阈值。

### `bench/run_online_ab.sh`

一键跑：

1. release 构建 `wan_probe`；
2. roundtrip A/B；
3. full-duplex A/B；
4. 生成 raw JSON；
5. 生成 Markdown 汇总；
6. 检查 3% CV；
7. 可选检查最大允许回归百分比。

## 2. 推荐真实拓扑

最有价值的是四段式拓扑：

```text
Load generator
  -> local protocol client / SOCKS
  -> online proxy server (Xray or Chimera)
  -> independent WAN target (`wan_probe server`)
```

其中：

- generator 与 online proxy server 不要是同一台机器；
- target 最好也不要与 online proxy server 同机；
- Xray 与 Chimera A/B 应指向同一个 target；
- 两个 server 最好使用相同规格、相同区域、相同内核/MTU；
- 如果只能在同一台 server A/B，必须保证测试时只启用一个候选数据面，避免 CPU/NIC 互相干扰。

如果 target 与 online proxy server 同机，只能验证 inbound + 用户态处理，不能代表完整公网 outbound 数据路径。

## 3. 构建

在仓库根目录：

```bash
cargo build --release \
  --manifest-path bench/chimera_perf/Cargo.toml \
  --bin wan_probe
```

生成：

```text
bench/chimera_perf/target/release/wan_probe
```

正式记录中应同时保存：

```bash
git rev-parse HEAD
sha256sum target/release/chimera_server_app
sha256sum bench/chimera_perf/target/release/wan_probe
uname -a
```

如果 server 使用 systemd/Nix 构建的实际线上二进制，应对实际执行文件取 hash，而不是对另一个本地 build 取 hash。

## 4. 部署独立 target

把 `wan_probe` release binary 放到独立 target 主机，然后启动：

```bash
./wan_probe server \
  --bind 0.0.0.0:20000
```

只应通过安全组/防火墙允许测试源和 online proxy server 访问这个 benchmark 端口，不要把该端口无条件暴露给公网。

默认单 flow 最大 payload 是 64 GiB，可以按测试需求降低：

```bash
./wan_probe server \
  --bind 0.0.0.0:20000 \
  --max-payload-bytes 4294967296
```

验证从 generator 的真实路由：

```bash
ip route get <TARGET_IP>
```

若测试目标应该经过物理 NIC，却显示：

```text
local ... dev lo
```

则这仍然不是跨主机测试。

## 5. 准备 A/B SOCKS 入口

推荐在 generator 上准备两个互不冲突的本地 SOCKS5 端口：

```text
127.0.0.1:1081 -> stable/reference online server
127.0.0.1:1082 -> Chimera online server
```

例如：

```text
xray=127.0.0.1:1081
chimera=127.0.0.1:1082
```

协议可以是：

- VLESS TCP；
- VLESS + REALITY；
- VLESS + REALITY + Vision；
- Hysteria2；
- 其他最终提供 SOCKS CONNECT 的客户端路径。

不同协议不要混在同一组 A/B 中。每一组只改变一个主要变量。

## 6. 先跑正确性 smoke

先用 1 MiB、c1/c4 验证：

```bash
bench/chimera_perf/target/release/wan_probe client \
  --target-host <TARGET_HOST> \
  --target-port 20000 \
  --endpoint xray=127.0.0.1:1081 \
  --endpoint chimera=127.0.0.1:1082 \
  --concurrency 1,4 \
  --payload-bytes 1048576 \
  --warmup 1 \
  --runs 2 \
  --output /tmp/wan-smoke.json
```

然后 duplex：

```bash
bench/chimera_perf/target/release/wan_probe client \
  --target-host <TARGET_HOST> \
  --target-port 20000 \
  --endpoint xray=127.0.0.1:1081 \
  --endpoint chimera=127.0.0.1:1082 \
  --concurrency 1,4 \
  --payload-bytes 1048576 \
  --mode duplex \
  --warmup 1 \
  --runs 2 \
  --output /tmp/wan-smoke-duplex.json
```

只要出现：

- payload mismatch；
- timeout；
- SOCKS CONNECT failure；
- flow failure；

就先修正确性/网络问题，不接受吞吐结论。

## 7. 正式 A/B

默认正式矩阵：

```text
concurrency: 1,16,64
payload:     64 MiB / flow / direction
warmup:      3
formal:      10
```

直接运行：

```bash
TARGET_HOST=<TARGET_HOST> \
TARGET_PORT=20000 \
BASELINE_LABEL=xray \
BASELINE_PROXY=127.0.0.1:1081 \
CANDIDATE_LABEL=chimera \
CANDIDATE_PROXY=127.0.0.1:1082 \
bash bench/run_online_ab.sh
```

默认输出目录：

```text
bench/results/online-YYYYmmdd-HHMMSS/
  roundtrip.json
  roundtrip.md
  duplex.json
  duplex.md
```

如果需要 CI/验收式回归门槛，例如候选在稳定样本上最多允许比 reference 慢 5%：

```bash
MAX_REGRESSION_PCT=5 \
TARGET_HOST=<TARGET_HOST> \
BASELINE_PROXY=127.0.0.1:1081 \
CANDIDATE_PROXY=127.0.0.1:1082 \
bash bench/run_online_ab.sh
```

注意：CV > 3% 时脚本会拒绝把该样本当作稳定结论，而不是用不稳定数据触发“小幅回归”判断。

## 8. 线上 server 指标采集

在 Xray reference server 测试期间：

```bash
python3 bench/online_metrics.py \
  --pid <XRAY_PID> \
  --interface <WAN_IFACE> \
  --interval 1 \
  --output xray-server-metrics.jsonl
```

在 Chimera server 测试期间：

```bash
python3 bench/online_metrics.py \
  --pid <CHIMERA_PID> \
  --interface <WAN_IFACE> \
  --interval 1 \
  --output chimera-server-metrics.jsonl
```

如果脚本不在 server 上，可以只复制这个单文件 Python 工具；它只依赖 Python 标准库。

正式比较至少确认：

```text
process.cpu_percent_one_core_100
process.rss_kib
process.hwm_kib
process.fd_count
process.*context_switches_delta
interface_rate.rx_mbps / tx_mbps
tcp_delta.RetransSegs
tcp_delta.OutRsts
softirq_delta.net_rx_delta
softirq_delta.net_tx_delta
```

不要只比较平均 CPU%。在线上代理场景更建议最终换算：

```text
CPU seconds / GiB forwarded
```

同一时间段用 probe bytes 与进程 CPU seconds delta 即可计算。

## 9. 建议测试层级

### 第 1 组：TCP + REALITY + Vision

这是当前 TCP 性能工作的首要真实验证组。

```text
raw/direct target
Xray reference
Chimera handoff/default
Chimera splice-downlink（仅作为候选）
```

先测：

```text
c1
c16
c64
roundtrip
duplex
```

### 第 2 组：Hysteria2

同样使用两个本地 SOCKS endpoint，把传输层切为 Hysteria2。

额外记录：

- RTT；
- packet loss；
- QUIC retrans/loss；
- pacing；
- CPU/GiB。

不要把 Hysteria2 结果与 TCP REALITY 混成一个“总吞吐分数”。

### 第 3 组：高 RTT / WAN

至少选择：

```text
低 RTT：< 10 ms
中 RTT：20-50 ms
高 RTT：80-150 ms
```

如果没有多个真实地域，可以先用独立 network namespace/netem 做机制验证，但最终仍应使用至少一个真实跨地域路径。

## 10. 线上灰度

benchmark 通过后才进入灰度。

灰度关注：

- 建连错误率；
- TLS/REALITY handshake failure；
- timeout/reset；
- retransmit；
- server CPU；
- RSS/HWM；
- fd 泄漏；
- p95/p99 用户请求延迟；
- fast-path/fallback 日志或指标。

建议只使用专门测试账号、测试节点或可回滚的小流量入口，不把 benchmark 工具直接打到未限流的正式用户入口。

## 11. 判定规则

一个候选优化进入生产前至少满足：

### 正确性

```text
payload mismatch = 0
unexpected flow failure = 0
connection success = 100%（排除已确认的外部网络故障）
```

### 统计稳定性

```text
3 warmup
10 formal runs
CV <= 3% 才讨论小幅性能差异
```

### 性能

不能只看 throughput。

至少同时比较：

```text
aggregate throughput
per-flow p50/p99
setup p50/p99
CPU-s/GiB
RSS/HWM
context switch
retransmit/reset
NIC drops
softirq
```

### fast-path

如果测试 splice/handoff/其他 fast path，还必须证明：

```text
candidate path actually hit
fallback reason known
fallback correctness passes
```

如果吞吐增加但 CPU/GiB、p99 或公平性明显恶化，不应自动认定为优化。

## 12. 当前仓库状态下的推荐执行顺序

```text
1. 本机 wan_probe correctness smoke
2. 独立公网 target
3. 线上 Xray vs Chimera TCP REALITY/Vision c1/c16/c64
4. full-duplex 对照
5. online_metrics CPU/RSS/NIC/TCP/softirq
6. 低/中/高 RTT
7. Hysteria2 独立矩阵
8. 小流量灰度
9. 根据真实 profile 决定下一项代码优化
```

当前不建议在完成这些真实数据前继续投入：

- generic io_uring splice；
- SOCKHASH；
- 更大的通用 splice pipe；
- generic UDP mmsg；
- 更复杂的 Brutal pacing scheduler。

这些方向在现有 loopback/production-shaped benchmark 中要么已经出现负结果，要么尚缺真实部署准入证据。
