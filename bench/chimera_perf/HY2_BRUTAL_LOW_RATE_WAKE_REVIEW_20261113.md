# HY2 Brutal low-rate pacing wake regression (2026-11-13)

**L3 HOLD. Signed review candidate only. Do not merge, push or deploy.**

## Goal and reference

Candidate is restricted to vendor/quinn-proto/src/connection/pacing.rs on branch codex/brutal-pacing-review-20261113. Pinned ref/xray-core/transport/internet/hysteria/congestion/common/pacer.go TimeUntilSend waits for one datagram budget, whereas this Quinn candidate previously waited for 75 percent of the fixed-rate capacity. No production modifications to master.

## RED to GREEN evidence

- Test conditions: fixed 65,536 bytes/second, MTU 1200 bytes, RTT 100 microseconds, cwnd 3 MTU, bucket minimum 10 MTU and no available tokens.
- Old candidate: deterministic test failed; scheduled wake 137.329102 milliseconds (about 9000 bytes at 65536 B/s).
- Next packet: 1200 * 1e9 / 65536 => **18.310547 ms**, rounded up to nanoseconds.
- Minimal candidate fix: only when capacity equals the 10 MTU floor, schedule against min(75% capacity, max(packet bytes, credit for 3 ms at configured rate)). The high-rate policy is unchanged; no increase in configured refill rate or congestion window.
- Added tests assert exact next-packet timing at 65,536 B/s and unchanged 75% early wake at 500 Mbit/s (62,500,000 B/s, 4ms capacity 250,000 B).
- After minimal patch: Quinn-proto 270/270 lib tests PASS, Clippy --lib --tests -- -D warnings -A clippy::manual_filter PASS (one existing upstream lint excepted). A first high-rate test incorrectly expected 307200 B max capacity rather than actual 250000 B; corrected test and reran. Code was regenerated from exact previous candidate file to avoid unrelated rustfmt changes, then fully retested.
- Prior candidate had isolated Quinn 268/268 and Chimera HY2 112/112 passes. Those checks do not substitute for testing this revised candidate against real HY2 network traffic.

## Unverified gates

The host was at Tctl 75.125 C, above the previously adopted <=73 C benchmark start gate (abort at >=79 C), so no high-load builds or networking tests were run. Archived official client 2x2 harness expects /tmp/chimera-xray-v26.10.29-2638788/xray, which no longer exists. Historical 12/12 loopback full-byte runs were on a different Debug binary, not the present candidate. Independent L3 Codex review is blocked by an app-server socket sandbox isolation failure and has NOT reviewed this code.

Next: independent review, pin/verify current Xray client binary provenance, then thermally safe real HY2 client compatibility at low/60/200/500 Mbps; follow with WAN delay/loss, stream fairness, latency, CPU/RSS and protocol compatibility. No change to master, refs, host networking or deployment.
