## Xray XHTTP Deployment

This directory contains a minimal `VLESS + TLS + XHTTP` client/server pair for `xray-core`.

Files:

- `server-config.example.json`: Example server config.
- `client-config.example.json`: Example client config.
- `install_server_xhttp.sh`: One-shot server installer and launcher.
- `install_client_xhttp.sh`: One-shot client installer and launcher.
- `test_local_xhttp_tls_compat.sh`: Local self-signed `xray-core -> chimera_server` TLS/H2 compatibility test.

Server quick start:

```bash
sudo bash deploy/xray-xhttp/install_server_xhttp.sh \
  --domain your.server.domain \
  --uuid your-uuid \
  --path /xhttp \
  --cert /etc/letsencrypt/live/your.server.domain/fullchain.pem \
  --key /etc/letsencrypt/live/your.server.domain/privkey.pem
```

If `--cert` and `--key` are omitted, the script generates a self-signed certificate for testing and
exports a matching client config with `pinnedPeerCertSha256` and `verifyPeerCertByName`.

Client quick start:

```bash
bash deploy/xray-xhttp/install_client_xhttp.sh \
  --server your.server.domain \
  --uuid your-uuid \
  --path /xhttp
```

The client script installs Xray under `~/.local/share/xray-xhttp-client/`, writes the config, and
starts a local SOCKS5 proxy on `127.0.0.1:10808`.

Local TLS/H2 compatibility test:

```bash
bash deploy/xray-xhttp/test_local_xhttp_tls_compat.sh
```

The script:

- generates a self-signed certificate and pins it in the xray client config
- starts a local Python HTTP target
- starts `chimera_server_app` with `--no-default-features --features minimal-vless-tls`
- starts local `xray-core` as a SOCKS5 client
- verifies end-to-end traffic with `curl --socks5-hostname`

Zero-config local preset:

```bash
bash deploy/xray-xhttp/run_local_ready_stack.sh
```

This preset does not require you to manually choose:

- `xray` binary path
- `uuid`
- `xhttp path`
- certificate files
- client pin hash

Generated files are written to `deploy/xray-xhttp/.generated/local-ready/`, including:

- `server-ready.local.json`
- `client-ready.local.json`
- `ready-bundle.env`

Stop the local stack with:

```bash
bash deploy/xray-xhttp/stop_local_ready_stack.sh
```
