# TCP auto splice slot-limit probe

This follow-up isolates the `CHIMERA_TCP_AUTO_MAX_CONNECTIONS` capacity decision from Tokio scheduling effects.

The existing `tcp_auto_slot_scope_probe` lets raw-ready flows race directly into their relay path. That is useful for lifecycle tests, but it is a poor way to calibrate the capacity limit because a fast splice relay can finish and release its slot before another task reaches the reservation point. A run configured with eight slots can therefore report far more than eight total splice hits.

The probe now accepts `--synchronize-ready`. In auto modes it uses a reusable Tokio barrier twice: once immediately before slot reservation, and once immediately after every flow has either reserved a slot or selected copy fallback. This makes the initial raw-ready contention deterministic without changing the measured relay implementation. With 64 simultaneous flows, the measured splice-hit count is therefore exactly the configured slot limit.

## September 2026 Linux measurements

Release builds used 64 established loopback TCP flows, eight Tokio workers, a 128 KiB splice pipe request, a 32 KiB userspace copy buffer, no artificial slow prelude, and one warmup per independent process. Slot-limit comparisons used alternating execution order.

For 256 KiB/flow, ten independent 8-slot versus 32-slot pairs produced:

- median CPU: about 211.9 us/flow at 8 slots versus 183.9 us/flow at 32 slots;
- median paired 32/8 CPU ratio: 0.853x;
- 32 slots used less CPU in 10/10 pairs; observed paired ratio range was about 0.769x-0.980x;
- median aggregate throughput: about 48.1 Gbit/s at 8 slots versus 54.9 Gbit/s at 32 slots;
- synchronized effective-path counts were exactly 8 splice / 56 copy at the eight-slot limit and 32 splice / 32 copy at the 32-slot limit.

Payload-size checks show where the capacity increase matters:

- 64 KiB/flow, eight pairs: median paired 32/8 CPU ratio about 0.999x, 4/8 pairs favored 32 slots. This is effectively neutral at the noise floor.
- 128 KiB/flow, six pairs: median paired ratio about 0.983x, 4/6 pairs favored 32 slots. No stable improvement or regression was established.
- 192 KiB/flow, six pairs: median paired ratio about 0.798x, and 32 slots won 6/6 pairs.
- 256 KiB/flow, ten pairs: median paired ratio about 0.853x, and 32 slots won 10/10 pairs.

The mechanism is consistent with earlier short-flow relay measurements: at payload sizes where downlink splice is already cheaper than userspace copy, an eight-connection cap forces too many simultaneously raw-ready flows onto the more expensive path. Raising the default to 32 preserves the existing configurable safety valve while allowing more of the proven 192-256 KiB crossover region to use splice. The benchmark does not justify removing the cap, adding adaptive capacity logic, or raising it beyond 32.
