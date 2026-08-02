# TCP + REALITY + Vision 阶段 3：Raw Handoff 与 Linux Splice 实验报告

日期：2026-08-03

分支：`perf/tcp-reality-vision-throughput`

## 1. 本阶段目标

本阶段验证以下问题：

1. Vision `DIRECT` 切换是否能够安全交出 raw TCP fd；
2. Linux `splice(2)` 是否能够提升 TCP + REALITY + Vision 的稳态吞吐；
3. 双向 splice、仅下行 splice和用户态 handoff 哪一种更适合当前实现；
4. 性能提升是否同时满足协议正确性、half-close、流量统计和客户端兼容性。

## 2. 最终结论

当前推荐策略：

```text
默认：handoff
Linux 少量长连接实验配置：auto
强制仅下行 splice：splice-downlink
完整双向 splice：仅诊断，不作为生产默认
```

核心结论：

- Xray 当前只启用了下行 splice；其源码中的上行 splice 仍标记为 TODO。
- Chimera 的完整双向 splice 在 64 并发下明显退化，不具备生产准入条件。
- 仅下行 splice 在单连接长流中表现良好：下载中位吞吐提高约 46%，服务端 CPU/GiB 降低约 16%。
- 仅下行 splice 在高并发下不应覆盖所有连接；`auto` 会根据活动连接数选择下行 splice或 handoff。
- 当前 `auto` 保持显式配置，尚未替换默认 handoff。

## 3. 正确性缺陷与修复

### 3.1 Handoff 前缺少 flush 屏障

发现的缺陷：

```text
Vision poll_write 接受明文
→ REALITY 仍有密文待写
→ relay 认为方向已经 idle
→ 只等待对端读取
→ TLS ServerHello 可能滞留
→ 后续真实 TLS 会话 Broken pipe / EOF
```

修复：

- `CopyDirection` 增加 `flush_pending`；
- 每次成功 `poll_write` 后必须完成 `poll_flush`；
- 只有待写数据与 flush 都完成后，方向才属于 idle；
- raw handoff 只能在双方向都 idle 且 Vision 双向 Direct 时发生。

新增回归测试：

```text
beginning::tcp_relay::tests::prelude_flushes_accepted_writes_before_becoming_idle
```

测试 writer 只在 `poll_flush` 时让数据可见，证明 accepted write 不能被误认为已完成。

真实链路验证：

- 本地 REALITY TLS decoy；
- Xray 客户端；
- Chimera handoff；
- 内层真实 rustls TLS；
- 3 次预热 + 16 次正式会话；
- 每连接上/下行各 16 MiB；
- 开启全量字节校验。

结果：19/19 全部通过。修复前通常在第 3～5 条连接出现重置。

## 4. Splice 正确性证明

新增测试覆盖：

```text
splice_preserves_bidirectional_data_and_half_close
downlink_splice_preserves_bidirectional_data_and_half_close
```

覆盖内容：

- 双方向不等长 payload；
- 双向并发传输；
- 双方主动 half-close；
- EOF 后向对应目标执行 `SHUT_WR`；
- 精确字节计数。

`strace` 快路径证明：

- 64 MiB 上行 + 64 MiB 下行；
- 开启全量字节校验；
- 服务端观察到 4,244 次 `splice()`；
- 仅 4 次非阻塞重试；
- 端到端校验通过。

## 5. Xray 实现对照

Xray `CopyRawConnIfExist()` 在 Linux 上调用：

```text
TCPConn.ReadFrom(readerConn)
```

其 Go runtime 可进入内核 splice 路径。

Vision 源码中的方向策略：

```text
下行 splice：已启用
上行 splice：TODO
```

因此 Chimera 新增：

```text
splice-downlink
```

数据路径：

```text
client → target：用户态 copy
target → client：Linux splice
```

这比强制双向 splice 更接近当前 Xray 行为。

## 6. 测试环境

硬件：

```text
AMD Ryzen 7 5800
8 核 / 16 线程
```

系统：

```text
Linux 6.18.35
x86_64
```

客户端：

```text
Xray 26.2.6
go1.25.7
```

拓扑：

```text
native generator
→ Xray SOCKS
→ VLESS + REALITY + Vision
→ Chimera Server
→ native TLS streaming target
```

REALITY decoy与负载 target 完全分离，均使用本地 TLS 服务，避免公网抖动。

正式实验使用 `taskset` 将 generator、Xray、Chimera、target、decoy 放到不同 CPU 集合。

## 7. 单连接吞吐

负载：

```text
4 GiB upload
4 GiB download
2 warmups
7 measured runs
64 KiB userspace buffer
64 KiB splice pipe
```

### 7.1 Handoff

```text
upload median:   16.252 Gbps
upload CV:        5.6%
download median: 12.151 Gbps
download CV:      6.1%
```

### 7.2 完整双向 splice

```text
upload median:   14.830 Gbps
upload CV:       17.1%
download median: 16.924 Gbps
download CV:     17.0%
```

环境波动过大，不能据此批准完整双向 splice。

### 7.3 仅下行 splice

```text
upload median:   16.609 Gbps
upload CV:        3.1%
download median: 17.739 Gbps
download CV:      5.5%
```

相对 handoff 中位数：

```text
upload:   +2.2%
download: +46.0%
```

上传结果已接近 3% CV 门槛；下载仍略高于正式 3% 门槛，但方向性收益明显。

## 8. 单连接 CPU 成本

负载：

```text
8 GiB upload
8 GiB download
```

数据来自 `/proc/<pid>/stat`，只统计 Chimera Server CPU 时间。

### Handoff

```text
CPU total:           4.200 s
CPU-seconds/GiB:     0.262500
upload:              15.989 Gbps
download:            17.293 Gbps
VmHWM:               ~10.5 MiB
```

### 仅下行 splice

```text
CPU total:           3.530 s
CPU-seconds/GiB:     0.220625
upload:              15.898 Gbps
download:            17.409 Gbps
VmHWM:               ~10.1 MiB
```

相对 handoff：

```text
CPU-seconds/GiB: -15.95%
```

## 9. 高并发结果

### 9.1 64 并发 handoff

每连接：128 MiB upload + 128 MiB download。

```text
upload median:       5.577 Gbps
upload CV:           3.8%
download median:    42.279 Gbps
download CV:        16.2%
CPU-seconds/GiB:     1.886719
context switches:    1,669,441
VmHWM:              33,068 KiB
```

### 9.2 64 并发完整双向 splice

```text
upload median:       5.357 Gbps
download median:    24.431 Gbps
CPU-seconds/GiB:     2.036719
context switches:    1,524,362
VmHWM:              29,928 KiB
```

相对 handoff：

```text
upload:             -3.9%
download:          -42.2%
CPU-seconds/GiB:    +7.9%
```

结论：完整双向 splice 拒绝生产准入。

### 9.3 256 KiB pipe 实验

将 pipe 从 64 KiB 扩大至 256 KiB 后：

```text
upload median:       5.353 Gbps
download median:    23.026 Gbps
CPU-seconds/GiB:     2.131719
```

扩大 pipe 没有解决问题，反而进一步退化。因此默认恢复为 64 KiB。

### 9.4 仅下行 splice 并发交叉点

```text
并发    handoff download    splice-downlink download    结论
1       12.151 Gbps         17.739 Gbps                 明显有利
8       39.915 Gbps         44.365 Gbps                 约 +11.2%
16      42.680 Gbps         42.779 Gbps                 基本持平
32      43.108 Gbps         43.655 Gbps                 下载持平，上传下降
64      42.279 Gbps         22.039 Gbps                 明显退化
```

不同实验轮次存在主机波动，因此此表用于判断趋势，不应把每个百分比当作精确硬件结论。

## 10. Auto 策略

配置：

```text
CHIMERA_TCP_RELAY_BACKEND=auto
CHIMERA_TCP_AUTO_MAX_CONNECTIONS=8
```

行为：

- auto relay 在连接进入转发时增加活动计数；
- 活动连接数不超过阈值时，可使用仅下行 splice；
- 超过阈值时使用 handoff；
- 连接结束后自动减少计数；
- 设置阈值为 0 可禁用 auto splice。

路径证明：

- 单连接：约 16.8 MiB 下行中约 16.80 MiB 记录为 bypassed download；
- 16 并发短连接：16 条连接的 bypassed download 全部为 0。

当前决定：

```text
auto 保持显式配置
handoff 保持默认
```

在独立物理机、隔离 CPU 和固定 governor 上完成更稳定的跨轮次 A/B 前，不将 auto 设为默认。

## 11. 兼容性结果

Auto 后端：

```text
Xray 正向矩阵：          17/17 passed
Xray 负向矩阵：           9/9 passed
Chimera Client 正向矩阵： 9/9 passed
Chimera Client 负向矩阵： 9/9 passed
```

覆盖：

- 真实 TLS 1.3；
- TLS1.3-only ClientHello；
- 连续 32 次 TLS 会话；
- 大 payload 与长度边界；
- 并发连接；
- domain target；
- serverName / shortId；
- explicit min/max version；
- wrong key / UUID / flow；
- half-close 与 Xray 对照。

Chimera Client 外部进程 E2E 必须使用：

```text
--test-threads=1
```

否则多个 Tokio 测试 runtime 同时启动外部客户端，可能产生监听端口启动超时。

## 12. 配置说明

```text
CHIMERA_TCP_RELAY_BACKEND=handoff|auto|splice-downlink|splice|copy
CHIMERA_TCP_COPY_BUFFER_SIZE=4096..1048576
CHIMERA_TCP_SPLICE_PIPE_SIZE=4096..1048576
CHIMERA_TCP_AUTO_MAX_CONNECTIONS=0..4096
```

建议：

```text
通用生产：handoff
少量大象流实验：auto，阈值 8
明确低并发环境：splice-downlink
诊断：splice
兼容对照：copy
```

## 13. 下一阶段准入条件

在继续 io_uring 或 BPF 之前，需要：

1. 在独立测试机完成至少 10 次正式运行，CV ≤3%；
2. 记录 cycles/byte、instructions/byte、syscalls/GiB；
3. 物理网卡环境覆盖 10G/25G；
4. 验证 1、8、16、32、64、256、1000 并发；
5. 至少 1 小时稳定性与 24 小时 soak；
6. 确认 auto 阈值在生产工作负载下不会造成公平性退化。

只有当 syscall/唤醒仍是主要瓶颈时，才进入 io_uring splice；只有高并发下 io_uring/epoll 仍被调度开销限制时，才进入 BPF SOCKHASH。
