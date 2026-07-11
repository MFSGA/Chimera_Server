# Draft: Proxy Throughput Workflow Design

## 项目现状

### 已有测试基础设施
- `chimera_server_app/tests/socks_external_integration.rs` — SOCKS inbound e2e 回声测试（已可用）
- `chimera_server_app/tests/grpc_xray_compat_e2e.rs` — gRPC API 兼容性矩阵（已可用，产出 `target/grpc-xray-compat/report.{json,md}`）
- `chimera_server_app/tests/grpc_all_interfaces_e2e.rs` — gRPC 通用接口测试
- 无基准/性能测试基础设施
- CI: `.github/workflows/ci.yml`（lint + test + compile），`.github/workflows/release.yml`

### 已支持的入站协议
- SOCKS (noauth + password) — 已通过 e2e 测试验证
- VMess — 配置解析 + handler 实现
- VLESS — 配置解析 + handler 实现（gRPC 兼容性测试中有 multi-user 流程）
- Trojan — 配置解析中

### 已支持的出站协议
- `freedom` — 直连
- `blackhole` — 黑洞

### 参考: clash-rs throughput 测试模式
- `ref/clash-rs/bench/format_throughput.py` — JSON-lines → 分协议 MD 表格
- `ref/clash-rs/bench/collect_env.py` — 环境信息收集
- `ref/clash-rs/bench/run_tun_benchmark.py` — TUN 吞吐基准
- 测试架构：SOCKS client → clash-rs → Docker 协议服务器 → echo server
- 使用 sync byte (`0xAC`) 做 upload barrier 确保准确计时
- 每个测试跑 3 次，取 median ± stdev

## 吞吐测试设计

### 架构（Tier 1 — 直接可用）

```
┌─────────────────────────────────────────────┐
│ test process                                 │
│                                              │
│  ┌──────────┐   SOCKS    ┌──────────────┐   │
│  │ iperf3 / │───────────►│ Chimera      │   │
│  │ Rust     │            │ socks:freedom│   │
│  │ client   │            └──────┬───────┘   │
│  └──────────┘                    │           │
│       ▲                         │ freedom   │
│       │ download                ▼           │
│  ┌────┴────┐            ┌──────────────┐    │
│  │  echo   │◄───────────┤ localhost:N  │    │
│  │  server │            └──────────────┘    │
│  └─────────┘                                │
└─────────────────────────────────────────────┘
```

### Tier 2 — 协议入站吞吐（需要 xray 二进制做客户端）

```
┌─────────────────────────────────────────────────────┐
│ test process                                         │
│                                                      │
│  ┌──────┐  SOCKS  ┌──────┐  VMess  ┌───────────┐   │
│  │client├────────►│ xray ├────────►│ Chimera   │   │
│  └──────┘         │ local│         │ vmess:    │   │
│       ▲           │ out  │         │ freedom   │   │
│       │           └──────┘         └─────┬─────┘   │
│       │ download                         │ freedom  │
│  ┌────┴────┐                     ┌───────┴──────┐  │
│  │  echo   │◄────────────────────┤ localhost:N  │  │
│  │  server │                     └──────────────┘  │
│  └─────────┘                                       │
└─────────────────────────────────────────────────────┘
```
