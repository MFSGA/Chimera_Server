# Chimera Server Agent Install Guide

This guide is written for LLM agents that need to install Chimera Server binaries on a Linux server.
Read it end to end before running commands. Prefer the non-interactive command forms below so the
user can review exactly what will happen.

## What Lands on Disk

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/chimera_server_app` | Installed server binary |
| `/usr/local/bin/chimera-server` | Stable symlink to the server binary |
| `/usr/local/bin/chimera_cli` | Optional helper CLI when present in the build source |
| `/usr/local/bin/chimera-cli` | Stable symlink to the helper CLI |
| `/usr/local/etc/chimera/config.json5` | Runtime config, copied only when absent |
| `/usr/local/share/chimera/` | Optional geo data files |
| `/usr/local/lib/chimera/backup/` | Previous binary backups for rollback |
| `/var/log/chimera/` | Service logs for non-systemd managers |

The installer supports `systemd`, `openrc`, `runit`, or binary-only installation when no supported
service manager exists.

## For Humans

Paste this prompt into Codex, Claude Code, Cursor, or another coding agent that has shell access to
the target server:

```text
Install Chimera Server on this Linux server by following the full guide here:
https://raw.githubusercontent.com/MFSGA/Chimera_Server/refs/heads/master/AGENT_INSTALL.md
Use the release installer unless I explicitly ask you to build from source. Verify the install before
you finish, and do not overwrite an existing /usr/local/etc/chimera/config.json5.
```

If the target machine already has this repository checked out and you want the current checkout built
and installed, use this prompt instead:

```text
Build and install this Chimera_Server checkout by following:
https://raw.githubusercontent.com/MFSGA/Chimera_Server/refs/heads/master/AGENT_INSTALL.md
Use the local checkout path, install the service, and verify the installed config.
```

## For LLM Agents

Fetch this guide with `curl` from the target server so you do not miss flags or verification steps:

```bash
curl -fsSL https://raw.githubusercontent.com/MFSGA/Chimera_Server/refs/heads/master/AGENT_INSTALL.md
```

### Step 0: Identify the Install Mode

Ask or infer these choices before running the installer:

| Question | Recommended default | Installer flags |
| --- | --- | --- |
| Install source | Latest GitHub Release | `install --latest` |
| Existing config file | Ask user if unknown | `--config /path/to/config.json5` |
| Service manager | Auto-detect | omit `--manager` |
| Enable service at boot | Yes | omit `--no-enable` |
| Start now | Yes after config exists | `--start` |
| Download geo data | Only when config needs it | `--update-geo` |
| Roll back on failed restart | Yes | omit `--no-rollback` |

If the user has not provided a config and `/usr/local/etc/chimera/config.json5` does not already
exist, install the binary and service without `--start`. Tell the user the config path they need to
create before starting the service.

### Step 1: Check Prerequisites

For release installation, the server needs:

```bash
command -v curl || command -v wget
uname -m
```

Supported release architectures are `x86_64` and `aarch64`.

For local source installation, the server also needs Rust:

```bash
command -v cargo
cargo --version
```

### Step 2A: Install from Latest Release

Use this when the user wants a normal server install and does not need the exact local checkout.

```bash
curl -fsSLo /tmp/chimera-install.sh \
  https://raw.githubusercontent.com/MFSGA/Chimera_Server/refs/heads/master/install.sh
chmod +x /tmp/chimera-install.sh
sudo /tmp/chimera-install.sh install --latest --start
```

With an explicit config file:

```bash
sudo /tmp/chimera-install.sh install --latest --config /path/to/config.json5 --start
```

With geo data:

```bash
sudo /tmp/chimera-install.sh install --latest --config /path/to/config.json5 --update-geo --start
```

To install a specific release:

```bash
sudo /tmp/chimera-install.sh install --version v0.3.2 --config /path/to/config.json5 --start
```

The release asset name is expected to be:

```text
chimera_server_app-<tag>-linux-<x86_64|aarch64>
```

### Step 2B: Build and Install from a Local Checkout

Use this when the user wants the current repository state installed.

```bash
cd /path/to/Chimera_Server
cargo build --release --all-features
sudo ./install.sh install --config /path/to/config.json5 --start
```

If the config already exists at `/usr/local/etc/chimera/config.json5`, the config flag can be omitted:

```bash
sudo ./install.sh install --start
```

The installer copies the config only when the target config is absent. It should not overwrite an
existing server config.

### Step 3: Verify

Run these checks before reporting success:

```bash
command -v chimera-server
chimera-server --help
sudo chimera-server /usr/local/etc/chimera --config config.json5 --check
sudo /tmp/chimera-install.sh status
```

When installing from a local checkout, use the local installer for status instead:

```bash
sudo ./install.sh status
```

For `systemd`, also check:

```bash
systemctl is-enabled chimera.service
systemctl is-active chimera.service
journalctl -u chimera.service -n 50 --no-pager
```

If the service is not started because no config was available, verification is still acceptable when
`chimera-server --help` works and the service file exists.

### Step 4: Update, Roll Back, or Uninstall

Update to the latest release:

```bash
sudo /tmp/chimera-install.sh update --latest --start
```

Roll back to the previous installed binary:

```bash
sudo /tmp/chimera-install.sh rollback --start
```

Uninstall binaries and service files while keeping config, data, backups, and logs:

```bash
sudo /tmp/chimera-install.sh uninstall
```

## Agent Safety Rules

- Run `git status` before touching a local checkout.
- Do not overwrite `/usr/local/etc/chimera/config.json5`.
- Do not start the service without a valid config.
- Prefer `--latest` release installs for production servers unless the user asks for a source build.
- Use `--version` when the user needs reproducibility.
- Report the installed binary path, service manager, config path, and verification result.
- If restart fails, keep the installer's default rollback behavior enabled.
