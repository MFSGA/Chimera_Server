# Config Notes

This folder defines literal config structs and the conversion into runtime `ServerConfig`.

## TUIC v5 inbound (feature: tuic)

- `protocol`: `"tuic"` (alias `"tuicV5"`)
- `settings`:
  - `uuid`: string (required)
  - `password`: string (required)
  - `zeroRttHandshake`: bool (optional, default `false`)
- `streamSettings.tlsSettings` is required and provides the certificate/key used for QUIC.
