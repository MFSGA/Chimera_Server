# TCP relay io_uring splice 准入评估

日期：2026-08-03

## 目标

评估 Linux `IORING_OP_SPLICE` 是否值得接入 Chimera Server 的生产 TCP relay。

本阶段只在独立的 `bench/chimera_perf` 探针中实现候选方案，不修改生产数据面。准入条件为：在相同负载下同时优于普通 `splice(2)` 的吞吐与 CPU/GiB，稳定性可接受，并且不显著增加上下文切换。

## Probe

新增 `relay_probe`，支持：

- `copy`：用户态 read/write relay；
- `splice`：同步 `splice(2)`，TCP -> pipe -> TCP；
- `uring-splice`：`IORING_OP_SPLICE`，使用 hardlink SQE batch。

探针具备：

- 固定字节数；
- 可配置 chunk size；
- 可配置 io_uring batch depth；
- 可选全量内容校验；
- 吞吐、CPU/GiB、上下文切换 JSON 输出；
- 内核 opcode probe；
- 短生命周期，便于 `strace -f -c` 采集。

## 正确性

以下测试通过：

```text
copy + splice 双向计数和内容校验
IORING_OP_SPLICE 运行时 opcode probe
64 MiB uring-splice 全量内容校验
cargo test: 11 个普通测试通过，1 个 io_uring 测试显式运行通过
cargo clippy --all-targets --all-features -- -D warnings: 通过
```

## 1 GiB 稳定矩阵

参数：

```text
bytes = 1 GiB
chunk = 64 KiB
warmup = 2
runs = 10
```

| 后端 | 中位吞吐 | CV | CPU-s/GiB | 上下文切换中位数 |
|---|---:|---:|---:|---:|
| copy | 24.98 Gbps | 9.3% | 0.470 | 16,549 |
| splice | 30.72 Gbps | 6.5% | 0.420 | 12,415 |
| uring depth=1 | 18.73 Gbps | 6.0% | 0.582 | 65,355 |
| uring depth=4 | 20.75 Gbps | 8.0% | 0.503 | 43,281 |
| uring depth=16 | 24.52 Gbps | 3.0% | 0.473 | 33,044 |
| uring depth=64 | 27.96 Gbps | 3.8% | 0.429 | 27,611 |
| uring depth=128 | 25.31 Gbps | 9.8% | 0.482 | 29,522 |

最佳候选为 depth=64，但相对普通 splice：

- 吞吐低约 9%；
- CPU/GiB 高约 2.2%；
- 上下文切换约高 2.2 倍。

## 最终 512 MiB 复核

参数：

```text
bytes = 512 MiB
chunk = 64 KiB
uring depth = 64
warmup = 1
runs = 5
```

| 后端 | 中位吞吐 | CV | CPU-s/GiB | 上下文切换中位数 |
|---|---:|---:|---:|---:|
| copy | 23.66 Gbps | 7.7% | 0.501 | 8,377 |
| splice | 29.06 Gbps | 6.5% | 0.451 | 6,469 |
| uring-splice | 25.93 Gbps | 6.0% | 0.556 | 19,297 |

最终复核仍显示 io_uring 候选吞吐更低、CPU 和调度成本更高。

## Syscall 分析

256 MiB、depth=1 时约有 4,111 次 `io_uring_enter`，接近每 64 KiB 一次提交，因此首版性能较差。

batch hardlink 后，depth=128 将 `io_uring_enter` 降到约 63 次/256 MiB，但吞吐反而下降。说明此环境中的主要问题不再是 enter 次数，而是长 hardlink 链、pipe 串行依赖和 completion 等待带来的调度成本。

普通 splice 同一 256 MiB 场景约有：

```text
8,481 splice calls
4,096 sendto calls
4,347 recvfrom calls
```

虽然 syscall 总数较高，但同步 splice 路径在本机内核和单 relay 模型下仍更高效。

## 决策

`uring-splice` **不满足生产准入门槛**，不接入 Chimera Server 数据面。

保留 `relay_probe`，用途包括：

1. 在新内核、新硬件或不同 io_uring 实现下重新评估；
2. 作为普通 copy/splice 的短生命周期 syscall 和 CPU 基准；
3. 验证未来多连接共享 ring、registered files、SQPOLL 等模型。

后续若继续 io_uring，必须改变模型，而不是继续增大当前单连接 hardlink batch：

- 多连接共享一个 ring；
- 跨连接批量提交；
- registered files / fixed files；
- 可选 SQPOLL，且必须单独核算常驻 CPU；
- 与生产多连接负载直接比较。

在上述模型证明收益前，生产默认继续使用 `handoff`，普通 splice 仅保留为显式实验后端。
