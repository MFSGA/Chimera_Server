# Config Notes

This folder defines literal config structs and the conversion into runtime `ServerConfig`.

## TUIC v5 inbound (feature: tuic)

- `protocol`: `"tuic"` (alias `"tuicV5"`)
- `settings`:
  - `uuid`: string (required)
  - `password`: string (required)
  - `zeroRttHandshake`: bool (optional, default `false`)
- `streamSettings.tlsSettings` is required and provides the certificate/key used for QUIC.

## XHTTP transport (feature: xhttp)

- `streamSettings.network`: `"xhttp"` (alias `"splithttp"`)
- settings object:
  - `streamSettings.xhttpSettings` (alias `streamSettings.splithttpSettings`)
  - supported fields (xray-core naming): `host`, `path`, `mode`, `headers`, `xPaddingBytes`
- current runtime scope in Chimera:
  - supported `mode`: `auto`, `packet-up`
  - `streamSettings.security` with xhttp is not supported yet
