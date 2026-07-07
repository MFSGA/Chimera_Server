# Chimera_Server

**Languages:** **简体中文** | [English](README.en.md) | [Русский](README.ru.md) | [فارسی](README.fa.md)

## 中文说明

### 项目目标
Chimera_Server 是一个使用 Rust 编写的网络服务核心，目标是尽可能与开源项目 **xray-core**
保持兼容。当前阶段重点聚焦于 **inbound 配置与入站协议行为**，尽量对齐上游的字段命名、
默认值、握手流程与运行时语义。

### 当前状态
- 入站解析与分发逻辑正在持续完善，当前优先覆盖 VMess、VLESS、Trojan 等常见协议。
- 出站、路由、策略等模块仍在逐步建设中，目前只有基础能力或占位实现。
- 仓库按职责拆分为 `chimera_server_app`（应用入口）、`chimera_server_lib`
  （核心库）和 `chimera_cli`（辅助 CLI 工具）。

### 参考实现
为了缩小与 xray-core 的差距，部分入站解析与协议处理逻辑参考了社区项目
[shoes](https://github.com/cfal/shoes)。其在握手流程、默认行为与错误处理上的实现思路，
对当前项目有直接参考价值。

### 快速开始
1. 通过 `rustup` 安装最新稳定版 Rust 工具链。
2. 克隆仓库并进入项目目录。
3. 使用以下命令启动服务：

```bash
cargo run --package chimera_server_app -- --config path/to/config.json5
```

4. 如需热重载，可使用仓库中的 `start.sh` 或 `start_server.ps1`；运行前建议先检查脚本中的环境假设。

### 让 Agent 安装到服务器
如果你希望 Codex、Claude Code、Cursor 或其他 LLM agent 帮你把当前项目的二进制安装到 Linux
服务器，可以直接把下面这段提示发给 agent：

```text
Install Chimera Server on this Linux server by following the full guide here:
https://raw.githubusercontent.com/MFSGA/Chimera_Server/refs/heads/master/AGENT_INSTALL.md
Use the release installer unless I explicitly ask you to build from source. Verify the install before
you finish, and do not overwrite an existing /usr/local/etc/chimera/config.json5.
```

完整流程见 [Agent 安装指南](AGENT_INSTALL.md)。该指南会引导 agent 选择 GitHub Release
安装或本地源码构建，调用仓库中的 `install.sh`，并完成服务注册、配置校验、状态检查、回滚和卸载说明。

### CLI 工具
`chimera_cli` 提供了一个辅助二进制 `chimera-cli`，用于对齐 `xray x25519` 的使用方式。
在工作区根目录执行：

```bash
cargo run -p chimera_cli -- x25519 --count 1 --format base64
```

该命令会按与 xray-core 一致的顺序输出私钥 / 公钥对，并支持 `base64` 与 `hex` 两种格式。

### 配置说明
- 配置文件沿用 xray-core 的整体结构，目前重点支持 `inbounds` 数组及相关协议/传输设置。
- 解析器会尽量对齐上游字段名和默认值，以便已有 xray-core 配置可以较低成本迁移过来。
- 当前更推荐使用 `json5` 配置；仓库中的 `examples/` 目录提供了多个可参考示例。
- 当前协议和配置兼容边界见 [兼容性矩阵](COMPATIBILITY.md)；未列为稳定支持的组合应先按实验能力评估。

### 入站示例
```json
{
  "inbounds": [
    {
      "tag": "vmess-tcp",
      "protocol": "vmess",
      "listen": "0.0.0.0",
      "port": 10086,
      "settings": {
        "clients": [
          {
            "id": "YOUR-UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp"
      }
    }
  ]
}
```

### 示例配置
仓库当前包含以下示例配置，可作为起点：

- `examples/01-api.json5`
- `examples/02_trojan_ws_tls_30919.json5`
- `examples/03_vless_ws_tls_36050.json5`
- `examples/04_vless_tcp_50584.json5`
- `examples/05_vless_ws_56321.json5`
- `examples/06-hysteria-43210.json5`

### 开发命令
```bash
cargo build --all-features
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

### 路线图
1. 持续对齐最新 xray-core 的已实现入站协议，覆盖更多可选字段与流控行为。
2. 建立系统化的单元测试与集成测试，并与 xray-core 行为进行对照验证。
3. 在入站能力稳定后，继续完善出站、路由与策略模块，逐步实现端到端兼容。

## 贡献

#### 有任何使用上的问题，或者代码实现上的问题，欢迎 Issue 以及 PR
#### 即使你是完全的计算机新手小白，在查阅完 [wiki](https://mfsga.github.io/Proxy_WIKI/) 后，再针对性的提问，我会抽出时间一一回复 
#### 本项目另一大目的也也是为了吸引更多的开发者参与其中。

## 如果觉得有帮助，欢迎点个 star 🧡
