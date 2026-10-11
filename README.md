# Chimera Server

**Languages:** **简体中文** | [English](README.en.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

Chimera Server 是用 Rust 编写的服务端网络核心，目标是兼容 [Xray-core](https://github.com/XTLS/Xray-core)
的服务端配置与运行行为，让现有客户端在受支持的组合下无需修改即可连接。

项目仍在持续开发，**不代表已经完整兼容 Xray-core**。不同协议、传输、安全方式和 TCP/UDP 组合的实现与验证程度不同。使用前请查看[兼容性矩阵](COMPATIBILITY.md)和[Xray 配置示例及验证记录](examples/xray-compatible/README.md)。

## 当前范围

- 主要工作聚焦在 Xray 风格的服务端入站、传输、安全层、配置校验与运行生命周期。
- 同时维护入站所需的转发、路由、DNS、流量统计和管理接口；这些能力的覆盖边界以兼容性矩阵为准。
- 提供 gRPC 管理服务及部分 Xray 管理 API 兼容能力。3x-ui 等面板的兼容状态和限制见配置示例文档。
- VLESS Reverse 与 Linux 站点网关是独立的扩展能力，不能据此推断完整支持 Xray TUN 或所有 outbound。

兼容性开发以仓库中的 [`ref/xray-core`](ref/xray-core/) 作为配置及可观察行为参考，使用 [`ref/shoes`](ref/shoes/) 作为实现参考，并参考 [`ref/clash-rs`](ref/clash-rs/) 的分层方式。每项兼容结论应以具体版本、测试组合和记录的验证结果为准。

## 快速开始

### 环境

- Rust stable 工具链（通过 [rustup](https://rustup.rs/) 安装）
- Git

克隆仓库并构建：

```bash
git clone https://github.com/MFSGA/Chimera_Server.git
cd Chimera_Server
cargo build --release -p chimera_server_app
```

先用仓库示例检查配置，再启动服务：

```bash
cargo run -p chimera_server_app -- \
  --config examples/xray-compatible/socks-tcp-noauth.json5 --check

cargo run -p chimera_server_app -- \
  --config examples/xray-compatible/socks-tcp-noauth.json5
```

示例监听 `127.0.0.1:11001`，并使用 `freedom` 出站。`--check` 校验配置，但不尝试绑定端口或启动服务。服务端也支持 JSON 配置；YAML 支持范围较窄。格式和字段限制请查阅[兼容性矩阵](COMPATIBILITY.md)。

CLI 也接受 `-config`、`-check` 等旧式单横线参数；新用法请使用 `--config`、`--check`。查看全部参数：

```bash
cargo run -p chimera_server_app -- --help
```

### 配置示例

- [SOCKS 无认证 TCP](examples/xray-compatible/socks-tcp-noauth.json5)：本地快速启动
- [VLESS TCP](examples/xray-compatible/vless-tcp-none.json5)
- [VLESS WebSocket + TLS](examples/xray-compatible/vless-ws-tls.json5)
- [VLESS XHTTP + TLS](examples/xray-compatible/vless-xhttp-tls.json5)
- [Shadowsocks TCP/UDP](examples/xray-compatible/shadowsocks-tcp-udp.json5)
- [Hysteria2](examples/xray-compatible/hysteria-quic-tls.json5)
- [3x-ui 默认 API 配置示例](examples/xray-compatible/3x-ui-default-api.json5)
- [Hub、Edge 与 Office Gateway 部署模板](examples/site-to-site/README.md)

部分示例需要证书、地理数据文件、Linux TUN 或特定编译 feature。每个组合的状态和前置条件见对应示例说明，不要将示例通过配置检查视为互通验证。

## 安装

Linux 发布版安装、从源码安装、服务注册、升级与回滚流程见[安装指南](AGENT_INSTALL.md)。安装脚本默认保留目标机器上已有的配置文件。发布资产和支持平台以 Releases 与安装指南为准。

## 命令行工具

工作区还包含 `chimera-cli`，目前提供与 Xray 类似的 X25519 密钥生成命令：

```bash
cargo run -p chimera_cli -- x25519 --count 1 --format base64
```

输出包含私钥和公钥；请妥善保管私钥。格式可选 `base64` 或 `hex`。

## 开发

主要工作区 crate：

| Crate | 用途 |
| --- | --- |
| `chimera_server_app` | 服务端可执行程序与 CLI 入口 |
| `chimera_server_lib` | 配置、运行时、入站、转发与管理接口 |
| `chimera_cli` | 辅助命令行工具 |
| `chimera_tcp_reality_server` | 独立的 TCP REALITY 服务程序 |

常用检查命令：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

GitHub Actions 还会在 Windows 上运行测试，并检查 feature 组合及 Linux GNU、Linux musl、Windows 目标构建；这些平台矩阵无法由一台 Linux 主机完全复现。完整流程见 [CI 工作流](.github/workflows/ci.yml)。

本仓库提供提交前格式检查 hook。启用后，每次提交都会运行与 CI 相同的 rustfmt 检查；格式错误会阻止提交，hook 不会自动改写文件：

```bash
git config core.hooksPath .githooks
```

配置格式与字段说明见 [`chimera_server_lib/src/config/README.md`](chimera_server_lib/src/config/README.md)。架构目标和实际迁移记录见 [`ARCHITECTURE.md`](ARCHITECTURE.md) 与 [`ITERATION_GUIDE.md`](ITERATION_GUIDE.md)。

## 参与贡献

欢迎通过 Issue 报告问题，或提交 PR。提交前请说明涉及的协议/传输/安全组合、Xray 基线和验证命令；互通声明应记录客户端版本与测试结果。功能实现和验证边界请同步更新兼容性矩阵及相关配置文档。

有使用问题时，也可以先查看[项目 Wiki](https://mfsga.github.io/Proxy_WIKI/)，并在提问时附上脱敏后的配置片段、运行平台和错误信息。请勿公开私钥、密码、UUID 或完整生产配置。
