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

## Runtime observability

- `/v1/metrics` exposes:
  - request/error/rate-limit counters
  - exec/file/shell counters
  - VM gauges and API uptime

## Expansion backlog

- Add lifecycle and exec latency benchmarks.
- Add shell relay throughput baseline.
- Add multi-VM soak and contention profiling lane.
