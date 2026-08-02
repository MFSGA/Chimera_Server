# TCP + REALITY + Vision 用户态 Copy Buffer 矩阵

日期：2026-08-03

分支：`perf/tcp-reality-vision-throughput`

## 1. 目的

确定 handoff 后用户态双向 copy 的生产默认缓冲区大小。

候选值：

```text
8 KiB
16 KiB
32 KiB
64 KiB
128 KiB
256 KiB
```

目标不是追求单次峰值，而是在以下指标之间取得平衡：

- 单连接长流吞吐；
- 64 并发聚合吞吐；
- coefficient of variation；
- 服务端峰值 RSS；
- 每连接内存上限。

## 2. 测试拓扑

```text
native generator
→ Xray SOCKS
→ VLESS + REALITY + Vision
→ Chimera handoff relay
→ native rustls TLS streaming target
```

REALITY decoy 与负载 target 均为本地 TLS 服务。

进程使用 `taskset` 固定到不同 CPU 集合。Chimera 使用：

```text
CHIMERA_TCP_RELAY_BACKEND=handoff
CHIMERA_TCP_COPY_BUFFER_SIZE=<candidate>
```

## 3. 单连接矩阵

每项：

```text
1 GiB upload
1 GiB download
1 warmup
5 measured runs
```

| Buffer | Upload median | Upload CV | Download median | Download CV |
|---:|---:|---:|---:|---:|
| 8 KiB | 6.051 Gbps | 8.4% | 6.532 Gbps | 12.4% |
| 16 KiB | 11.133 Gbps | 4.4% | 11.143 Gbps | 5.1% |
| 32 KiB | 16.514 Gbps | 3.3% | 16.721 Gbps | 11.2% |
| 64 KiB | 15.404 Gbps | 6.6% | 12.751 Gbps | 16.6% |
| 128 KiB | 17.079 Gbps | 4.7% | 13.763 Gbps | 12.1% |
| 256 KiB | 17.560 Gbps | 21.8% | 18.306 Gbps | 7.1% |

结论：

- 8 KiB 对单连接吞吐形成明显瓶颈；
- 16 KiB 仍明显低于 32 KiB；
- 32 KiB 已进入 16 Gbps 以上区间，并拥有候选中较低的 upload CV；
- 128/256 KiB 没有形成稳定、双方向一致的优势；
- 256 KiB 上传 CV 21.8%，不能作为默认值。

## 4. 64 并发矩阵

每项：

```text
64 connections
64 MiB upload per connection
64 MiB download per connection
1 warmup
3 measured runs
```

| Buffer | Upload median | Upload CV | Download median | Download CV | Chimera VmHWM |
|---:|---:|---:|---:|---:|---:|
| 8 KiB | 6.156 Gbps | 18.1% | 16.909 Gbps | 0.5% | 24.8 MiB |
| 32 KiB | 5.366 Gbps | 2.1% | 37.821 Gbps | 3.6% | 29.7 MiB |
| 64 KiB | 5.319 Gbps | 2.8% | 38.697 Gbps | 10.5% | 32.9 MiB |
| 128 KiB | 5.484 Gbps | 2.6% | 33.616 Gbps | 3.7% | 47.3 MiB |

32 KiB 相对 64 KiB：

```text
upload median: +0.9%
download median: -2.3%
VmHWM:         -9.7%
download CV:   3.6% vs 10.5%
```

128 KiB 相对 32 KiB：

```text
upload median: +2.2%
download median: -11.1%
VmHWM:         +59.0%
```

## 5. 决策

生产默认从：

```text
8 KiB
```

调整为：

```text
32 KiB
```

理由：

1. 单连接吞吐相对 8 KiB 提高约 2.6 倍；
2. 64 并发下载吞吐相对 8 KiB 提高约 2.24 倍；
3. 与 64 KiB 的高并发吞吐基本持平；
4. 比 64 KiB 更省内存，且本轮 download CV 更低；
5. 128/256 KiB 的额外内存没有换来稳定、双方向一致的收益。

## 6. 回归策略

保留环境变量：

```text
CHIMERA_TCP_COPY_BUFFER_SIZE
```

用于不同硬件和工作负载重新调参。

单元测试固定验证默认值为 32 KiB，同时继续验证配置边界：

```text
4 KiB .. 1 MiB
```

正式发布前应在独立物理机和物理网卡环境复跑：

```text
single flow
64 connections
512 connections
1000 connections
10G / 25G NIC
```

若不同平台数据表明 64 KiB 或其他值显著更优，可通过环境变量覆盖；在获得跨平台数据前，32 KiB 是当前证据支持的最佳通用默认值。
