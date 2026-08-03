# REALITY + Vision 稳定性 Soak Runner

日期：2026-08-03

## 目标

把路线图中的 1 小时与 24 小时稳定性门槛变成可重复执行的 benchmark 能力，而不是依赖人工循环和临时 shell 采样。

## Generator 扩展

`bench/chimera_perf/src/bin/generator.rs` 新增：

- `--duration-secs`：测量最短持续时间；仍至少完成 `--runs` 指定的轮数；
- `--monitor-pid`：每轮读取被监控进程的 `/proc/<pid>/fd` 和 `/proc/<pid>/status`；
- `--emit-every-runs`：长时间测试仅周期性输出单轮 JSON，第一轮和最后一轮始终输出；
- `--cooldown-secs`：测量完成后等待，再采集最终进程状态；
- `--max-fd-delta`：最终 fd 增长超过门槛时失败；
- `--max-rss-delta-kib`：最终 RSS 增长超过门槛时失败。

Summary 新增：

- 实际测量时长；
- 完成轮数和连接数；
- 总上传与下载字节；
- 被监控进程的起始、结束和峰值 fd；
- 起始、结束、峰值 RSS 与 HWM；
- 线程峰值；
- 配置的增长门槛。

进程统计使用流式聚合，不保存所有历史快照，因此 24 小时运行的监控内存不会随轮数线性增长。输出文件在每次实际输出记录后 flush，异常中断时仍保留已有进度。

## 自动测试

通过：

```text
cargo test --manifest-path bench/chimera_perf/Cargo.toml
cargo clippy --manifest-path bench/chimera_perf/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path bench/chimera_perf/Cargo.toml --all -- --check
```

Generator 单元测试覆盖：

- duration 是 runs 之外的最短下限；
- Linux `/proc/<pid>/status` 解析；
- fd/RSS/HWM/线程峰值流式聚合；
- 当前进程快照读取；
- 冷却后的 fd/RSS 增长门槛通过和拒绝。

## Direct TLS smoke

参数：

```text
5 秒测量
4 并发
每连接双向 8 MiB
TLS 1.3
全量字节校验
每 50 轮输出一次
```

结果：

```text
85 轮
340 条连接
双向各 2.66 GiB
fd 10 -> 10
fd 峰值 10
RSS 5252 -> 5528 KiB
RSS 峰值 5528 KiB
线程峰值 2
```

所有连接完成全量字节校验。

## REALITY + Vision handoff smoke

链路：

```text
Generator TLS 1.3
-> Xray SOCKS5
-> VLESS + REALITY + Vision
-> Chimera Server handoff
-> TLS benchmark target
```

参数：

```text
5.1 秒测量
3 秒结束冷却
8 并发
每连接双向 8 MiB
全量字节校验
max fd delta = 0
max RSS delta = 65536 KiB
```

结果：

```text
35 轮
280 条连接
双向各 2.19 GiB
fd 12 -> 10
fd 峰值 15
RSS 12136 -> 17232 KiB
RSS 峰值 17504 KiB
HWM 17504 KiB
线程峰值 17
```

所有连接通过 REALITY + Vision 和内层 TLS 全量校验，配置的 fd/RSS 门槛均通过。

另一次 15 秒 smoke 完成 106 轮、848 条连接，最终 fd 12 -> 12；RSS 增长约 4.5 MiB。短时 RSS 增长更像 allocator 和缓存预热，但不能据此证明长期无泄漏。

## 正式验收命令

建议生产默认 `handoff` 先运行：

```bash
server_pid=$(pgrep -n chimera_server_app)

bench/chimera_perf/target/release/generator \
  --target 127.0.0.1:52080 \
  --socks5 127.0.0.1:52101 \
  --inner-tls \
  --tcp-nodelay \
  --full-verify \
  --label reality-vision-handoff-soak-1h \
  --upload-bytes 67108864 \
  --download-bytes 67108864 \
  --concurrency 16 \
  --warmup 3 \
  --runs 1 \
  --duration-secs 3600 \
  --monitor-pid "$server_pid" \
  --cooldown-secs 10 \
  --max-fd-delta 0 \
  --max-rss-delta-kib 65536 \
  --emit-every-runs 100 \
  --output bench/results/reality-vision-handoff-soak-1h.jsonl
```

24 小时测试将 duration 改为 `86400`。

## 当前结论

Soak runner 已具备正式 1h/24h 测试所需的持续运行、进度保存、资源采样、冷却和失败门槛。

当前仅完成短时 smoke，尚未执行完整 1 小时和 24 小时测试，因此不能声称生产数据面已经满足长期无泄漏验收。正式 soak 仍需在受控主机上执行并保存 JSONL 结果。
