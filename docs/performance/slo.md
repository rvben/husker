# Performance Baselines and SLOs

## Baseline test

- Test: `cargo test -p husker-api --test perf_baseline -- --nocapture`
- Current sample (microseconds):
  - health p95: 89
  - health p99: 121
  - list p95: 61
  - list p99: 121

## CI SLO thresholds

- health p95 <= 75,000 us
- health p99 <= 125,000 us
- list p95 <= 75,000 us
- list p99 <= 125,000 us

These thresholds are intentionally conservative for hosted CI stability and intended to catch large regressions.

## Boot latency

Measure guest-side, not wall-clock. `husker job <img> -- cat /proc/uptime` reports
how long the guest had been running when the command executed; the remainder of the
wall clock is transport, rootfs clone, VMM setup and teardown. Wall clock over a
remote (SSH) transport varies by a second or more between runs on an idle host, so
**wall clock cannot detect a regression of this size; guest uptime can** (it holds
to about +/-0.04s across reps).

Reference sample, husker01 (Intel N100, 16GB, NVMe, XFS data dir, Firecracker),
`--cpus 2 --memory 2048`, median of 5:

| | guest uptime at exec | kernel to `/init` | userspace |
|---|---|---|---|
| 0.4.36 (before probe suppression) | 1.83s | ~1.05s | ~0.77s |
| with `LEGACY_PROBE_SUPPRESSION` | **0.60s** | ~0.56s | ~0.14s |

Rootfs size does not affect boot: 0.32GB and 2.21GB images both land within noise
of each other, because the data dir is reflink-capable and clones are O(1). Do not
"optimise" clone cost without re-measuring on the target filesystem.

Regression guards: `direct_kernel_base_args_suppresses_legacy_hardware_probes`
(husker-core) and `default_boot_args_suppress_legacy_hardware_probes` (husker-vmm).
Both fail if the suppression tokens are dropped from a cmdline builder.

## Runtime observability

- `/v1/metrics` exposes:
  - request/error/rate-limit counters
  - exec/file/shell counters
  - VM gauges and API uptime

## Expansion backlog

- Automate the boot-latency sample above (currently measured by hand on husker01).
- Add exec latency benchmarks.
- Add shell relay throughput baseline.
- Add multi-VM soak and contention profiling lane.
- Investigate the remaining ~0.56s of kernel boot: the guest kernel still compiles
  in `CONFIG_SERIO_I8042`, `e100`, `e1000`, `e1000e`, `sky2`, `agpgart` and 9p,
  none of which a Firecracker guest can use.
