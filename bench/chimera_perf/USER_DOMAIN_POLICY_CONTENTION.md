# User-domain policy contention probe

This probe measures repeated in-memory decisions against one active policy. It exists to compare contention in `UserDomainAccessStore`; it does not measure sockets, routing, DNS, relay throughput, latency, or full-server capacity.

## Reproduction

Run from the repository root:

```bash
cargo test -p chimera_server_lib --lib --release policy_check_contention_probe -- --ignored --nocapture
```

The test uses one allowed suffix rule and performs 50,000 decisions per worker, five times at each worker count (1, 2, 4, 8, 16). It reports the median operations per second. The release profile uses LTO and one codegen unit. The baseline production implementation was `5bc06bf`; the ignored probe itself was temporarily added as test-only code because that commit did not contain the benchmark. The candidate measurements used the same probe in the changed checkout. Both used rustc `1.98.0` on an AMD Ryzen 7 5800 with 8 cores / 16 threads and 16 online logical CPUs.

To reproduce the historical baseline, apply [`USER_DOMAIN_POLICY_CONTENTION_BASELINE.patch`](USER_DOMAIN_POLICY_CONTENTION_BASELINE.patch) to a clean `5bc06bf` checkout, then run the command above. The patch adds only the ignored test harness and does not change production code.

## Results

Operations per second (millions; each candidate column is a separate invocation):

| Workers | Baseline | Candidate run 1 | Candidate run 2 |
| ---: | ---: | ---: | ---: |
| 1 | 6.07 | 6.62 | 6.64 |
| 2 | 10.25 | 10.48 | 10.20 |
| 4 | 5.07 | 10.96 | 11.52 |
| 8 | 3.29 | 10.58 | 10.85 |
| 16 | 2.51 | 12.81 | 13.07 |

The single-worker result is slightly higher and two-worker throughput is effectively unchanged. The measured contention collapse at four or more workers improved in both candidate runs; the 16-worker rate was about 5.1–5.2 times the baseline. Each invocation contains five samples, but this is still a short, synthetic microbenchmark and scheduler/frequency variation applies. Do not extrapolate these numbers to mixed workloads, long-lived servers, or end-to-end proxy throughput.

The implementation uses 32 mutex-protected counter shards assigned once per thread. Active policy publication owns its decision-statistics generation so reset/rollback and stale in-flight checks retain their existing externally visible accounting semantics. DNS-failure accounting keeps the policy-state write-lock linearization point; unknown-domain and unsupported-protocol audit paths remain serialized and bounded. The probe exercises only the ordinary known-domain decision path.
