# Chimera_Server

**Languages:** [简体中文](README.md) | **English** | [Русский](README.ru.md) | [فارسی](README.fa.md)

## Project Goal
Chimera_Server is a Rust-based network service core that aims to stay compatible with the open-source
**xray-core** project. The current milestone focuses on the **inbound configuration surface and inbound
protocol behavior**, keeping field names, defaults, handshake flows, and runtime semantics aligned with
upstream xray-core wherever possible.

## Current Status
- Inbound parsing and dispatch logic is under active development, with VMess, VLESS, Trojan, and other
  common entry protocols as the current priority.
- Outbound, routing, and policy modules are still being designed; only minimal or placeholder
  implementations exist for now.
- The repository is split into `chimera_server_app` (application entry), `chimera_server_lib` (core
  library), and `chimera_cli` (helper CLI utility).

## Reference Implementation
To narrow the gap with xray-core, parts of the inbound parsing and protocol handling are informed by the
community project [shoes](https://github.com/cfal/shoes). Its handshake flow, default behavior, and error
handling patterns are useful references for this project.

## Getting Started
1. Install the latest stable Rust toolchain with `rustup`.
2. Clone the repository and enter the project directory.
3. Start the service with:

```bash
cargo run --package chimera_server_app -- --config path/to/config.json5
```

4. For hot reloading, use `start.sh` or `start_server.ps1` after checking their environment assumptions.

## CLI Utility
`chimera_cli` ships a helper binary, `chimera-cli`, to mirror the `xray x25519` workflow. From the
workspace root:

```bash
cargo run -p chimera_cli -- x25519 --count 1 --format base64
```

The command prints the private/public key pair in the same order as xray-core and supports both `base64`
and `hex` output.

## Configuration
- Configuration files follow the xray-core structure, with current emphasis on the `inbounds` array and
  related protocol / transport settings.
- Parsers aim to match upstream field names and defaults so that existing xray-core configurations can be
  adapted with minimal changes.
- `json5` is currently the preferred config format, and the `examples/` directory provides several sample
  files.

## Example Inbound
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

## Example Configs
- `examples/01-api.json5`
- `examples/02_trojan_ws_tls_30919.json5`
- `examples/03_vless_ws_tls_36050.json5`
- `examples/04_vless_tcp_50584.json5`
- `examples/05_vless_ws_56321.json5`
- `examples/06-hysteria-43210.json5`

## Development Commands
```bash
cargo build --all-features
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Roadmap
1. Keep aligning implemented inbound protocols with the latest xray-core behavior, including optional
   fields and flow-control details.
2. Build systematic unit and integration tests and compare behavior against xray-core.
3. Once inbound coverage is stable, extend outbound, routing, and policy modules toward full end-to-end
   compatibility.

## Contributing

#### If you run into usage issues or implementation problems, issues and pull requests are welcome.
#### Even if you are completely new to computers, please check the [wiki](https://mfsga.github.io/Proxy_WIKI/) first, then ask specific questions. I will reply when time allows.
#### Another major goal of this project is to attract more developers to participate.

## If this project helps you, a star is appreciated
