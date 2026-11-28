# 精简 Hysteria2 本机吞吐基线（2026-11-28）

## 目的与结论

为 HY2 建立独立于其他可选代理协议的 Server 构建档位，并与无代理直连 TLS 源站对比。该构建通过同一 `chimera_server_app` 入口启动生产 Hysteria2 handler 和生产流量计量路径；它没有替换协议实现，也没有加入只供基准使用的数据转发代码。

普通 release 的 90 秒无 profiler 混合负载中，精简 HY2 Server 的接收端有效吞吐为 **14.004 Gbit/s 下行、13.410 Gbit/s 上行**。同一 payload target 的无代理 TLS 直连、并发相同 API 请求为 **24.095/24.351 Gbit/s**。HY2 分别达到直连吞吐的 58.1%/55.1%；小 API 响应的 p99 从直连的 0.915 ms 增至 HY2 的 30.278 ms。旧全功能 Server 的既有值也在相近范围，但 source SHA 和 Cargo.lock 不同；这些结果只能说明数值接近，不能据此得出减少 feature 导致或没有导致性能变化。

这些是本机 loopback 数据，不是 Bsy 或公网线路结果。吞吐差值覆盖 Client、QUIC、H3、Server 和本机 UDP socket 队列，不能只归因于 Server。

## 构建档位

新增 app feature：

```toml
minimal-hysteria = ["chimera_server_lib/hysteria", "chimera_server_lib/traffic"]
```

`traffic` 必须保留，才能测试与默认生产路径相同的流量计量 wrapper。默认 feature 仍是 `full`。构建和检查命令：

```bash
cargo check --locked -p chimera_server_app --no-default-features --features minimal-hysteria
cargo build --locked --release -p chimera_server_app --no-default-features --features minimal-hysteria
```

Cargo manifest 将 `minimal-hysteria` 映射到 `hysteria` 和 `traffic`。这个 profile 会排除 `chimera_server_lib/full` 中的 VLESS、VMess、Shadowsocks、Trojan、REALITY、WireGuard、TUIC 和 library gRPC `api` feature；MCP 仍可能按运行时配置启动。共享的非可选依赖仍会编译，因此它是可复用的 app feature profile，不表示只剩 QUIC 一个 crate。

## 环境和固定输入

- Linux `6.18.35`，AMD Ryzen 7 5800；Server、Client、payload target 固定在 CPU 0–7。
- Hysteria2 在本机 UDP loopback 上运行；payload target 为本机 TLS TCP 服务，服务名 `benchmark.local`。
- 代理侧使用 Client q4 / 4 MiB 请求配置和 BBR；bulk 为 8 条并发 SOCKS TCP 流，每条上下行 payload 配置 64 MiB，TLS payload，64 KiB generator buffer。
- API 负载为 4 条持久 HTTP/1.1 会话，每条按 10 请求/秒请求本机 256 字节响应。
- 直连控制使用同一 payload target、TLS 和 generator 参数，不启动 Client SOCKS 代理。
- 90 秒主测期间关闭 perf、QUIC 诊断日志和 payload 全量校验；另做独立的 1 MiB/方向 `--full-verify` smoke。
- 正式吞吐使用普通 optimized release Server；另有 debug symbols + frame pointers 的独立 profiler build，只用于热点定位。

Server 源码基线为 `ca78fd50b9fdd96bb5aefd952c0355f859b5089b` 加本次尚未提交的 feature/doc diff。普通 release 精简 Server 二进制 SHA-256：`7fa4b60928264155fc6992d1d2937b54c6bd243b233686fdbfd7d1ed509c496d`，大小 17,928,160 bytes。Profiler 精简 Server 二进制 SHA-256：`775cc27fa1363d66ef7ef5c682bb3bde024576e1cccefefa3afc25150a0efbeb`。Client 二进制 SHA-256：`d025619dc44f4ce6c35a9be37c1046ae0119923bc274eb40916c15d0ecb0bbad`。Generator：`8195e43c63e967cb25181b865acf9d23c7837746aefb3648ff056555e83782be`。TLS payload target：`dfeab347492d4c7db84bb97397e6cb251a9072892c83dec56a100fce21a265d8`。

## 结果

吞吐是 generator 成功交付业务数据的十进制 Gbit/s 中位数；CV 是同一轮测量速率的变异系数。

| 路径 | 持续时间 | 测量轮数 | 下行 | 上行 | 下行/上行 CV | API 结果 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| TLS payload 直连，无代理 | 45 秒 | 124 | 24.213 Gbit/s | 24.454 Gbit/s | 2.03% / 2.62% | 未同时运行 API 负载 |
| TLS payload 直连 + API | 90 秒 | 246 | 24.095 Gbit/s | 24.351 Gbit/s | 2.29% / 3.34% | 3,604/3,604 成功；p50 0.668 ms、p95 0.816 ms、p99 0.915 ms |
| 本机 HY2，空闲 API | 15 秒 | — | — | — | — | 604/604 成功；p99 0.954 ms |
| 本机 HY2，8 路 bulk + API，普通 release | 90 秒 | 138 | 14.004 Gbit/s | 13.410 Gbit/s | 5.38% / 6.82% | 3,604/3,604 成功；p50 6.977 ms、p95 21.023 ms、p99 30.278 ms |
| 旧提交全功能 Server，本机 HY2 + API | 90 秒 | — | 13.914 Gbit/s | 13.148 Gbit/s | — | 3,604/3,604 成功；p99 约 35.040 ms |

最后一行来自 Server `52d0108c9f6044532bdaade81d26583f0a551797`、binary SHA `9fc93b3775d465b9c4f4b33528fbddecdccc5dd7832f38db414b420bae5ab982` 的既有本机结果；该 run 使用当时的本地 `master`，后来快进到 `ca78fd50` 并更新 Cargo.lock。更早的 candidate `5454718b9ff9c40253d1345a8f7a41625883e274` 是另一条分支快照，没有用于这里列出的 90 秒结果。该组只能作方向性参考，不是同 SHA 的严格 A/B。

90 秒普通 release HY2 运行时 Client、Server、payload target 平均消耗分别为 **2.728、2.582、0.547 CPU 核**。记录到 Client UDP socket drop 18,290、Server UDP socket drop 36,933；同一时段 `/proc/net/snmp` 的系统 UDP `RcvbufErrors` 增加 55,223。该数值在本轮恰好等于两侧 socket drops 之和，表示本机接收队列压力，不是公网丢包率。

单独的 45 秒 profiler build 运行吞吐为 13.508/13.080 Gbit/s，4 个 API 会话共 1,804 次成功请求、p99 34.174 ms。Profiler attach 已启用，因此这个吞吐只用于热点定位，不与普通 release 的 90 秒正式结果混算。6,651 个采样栈的首帧分布中，AWS-LC AEAD `UnboundKey` 占约 30.3%，Quinn `Connection` 8.3%，Quinn Endpoint 4.3%，Quinn UDP socket 3.4%，H3 `SendStream` 3.0%，Server 的 HY2 `MeteredStream<H3RawStream>` 3.0%，Quinn `PacketBuilder` 1.3%。这些是采样栈首帧占比，属于热点定位线索，不是源码行级 CPU 精确归因。Profiler 原始文件保存在本机 `/tmp/chimera-hy2-minimal-hysteria-profile-ca78fd50-20261128/server.perf.data` 和 `server.perf.stat.txt`；对应带符号二进制副本为同目录下的 `chimera_server_app.frameptr`。

本轮采样没有出现 `memmove` 的首帧，因此没有证据把先前全功能 profile 中观察到的拷贝帧直接视为本次最热点。Server H3 读取仍会把 `Bytes` 复制到 Tokio `ReadBuf`，位置在 `chimera_server_lib/src/handler/hysteria2/connection/tcp_stream.rs` 的 `poll_read_quic_chunks`；源码已避免为此额外创建 `Bytes` 句柄。后续应先分别对 Client 和 Server 的 QUIC/AEAD 快路径做同条件采样，再决定是否重构缓冲所有权。

## 验证与限制

- `cargo check --locked -p chimera_server_app --no-default-features --features minimal-hysteria`、默认 feature `cargo check --locked -p chimera_server_app`、普通 release 构建均通过；Hysteria feature 下以 `hysteria2` 过滤的单元测试为 135 passed、0 failed。
- 普通 release 本机 HY2 请求和固定 90 秒双向混合吞吐均通过；1 MiB/方向的 `--full-verify` smoke 完成 48 轮且 generator 正常退出。
- 主测为吞吐测量，没有对全部大流 payload 逐字节全量校验。
- 精简 profile 检查仍报告若干未使用的 XHTTP/通用代码告警；它们不阻止构建，但说明 feature 边界尚未做到所有源码模块都条件编译。
- 本机回环的 UDP 接收队列有 drops；直连基线记录了 payload/API 进程 CPU，但没有记录 generator CPU，因此目前不能直接量化直连与 HY2 的全部 CPU 成本。
- 尚未测试 Bsy 远端线路、公网 RTT/丢包、Mihomo/Xray/官方 HY2 对照、GSO/GRO 开关 A/B，亦未从本轮结果推断这些项目的性能。

## 下一步

1. 使用同一最小负载分别采样 Client 和 Server 的 AEAD、QUIC packet build/receive 路径，保留原始 `perf.data` 和二进制 SHA。
2. 做有重复和顺序轮换的 socket receive-buffer / GSO / GRO 单变量测试；记录 per-socket drop 与端到端 goodput。
3. 把精简 Server profile 接到既有 cross-client/cross-server 矩阵，再测试 Bsy 线路；公网测试和本机上限分开报告。

## 复现参数与逐轮结果

Server 命令为 `chimera_server_app --config <本机 loopback HY2 配置> --format json`；Client 为 `chimera-hy2-core-perf-client --config <q4/4 MiB 配置> --proxy-name local-hy2 --listen 127.0.0.1:59805`。配置文件内容保留在本机，不写入结果文档。

源站命令行参数：`target --listen 127.0.0.1:52080 --buffer-size 65536 --worker-threads 1 --tcp-nodelay --tls-cert <本机证书> --tls-key <本机私钥>`。Generator 的共同参数为：

```text
--target 127.0.0.1:52080
--upload-bytes 67108864 --download-bytes 67108864 --concurrency 8
--warmup 0 --runs 10 --duration-secs 90 --buffer-size 65536
--inner-tls --tcp-nodelay --tls-server-name benchmark.local
--timeout-secs 120 --worker-threads 1
```

HY2 场景另加 `--socks5 127.0.0.1:59805`。直连场景不传 `--socks5`。API 源站是本机 Python HTTP/1.1 服务，固定返回 256 字节；4 个连接分别以 10 请求/秒运行。去除本机路径和其他元数据后的 508 条逐轮 goodput 记录见 [CSV](results/MINIMAL_HYSTERIA_LOCAL_GOODPUT_2026-11-28.csv)。
