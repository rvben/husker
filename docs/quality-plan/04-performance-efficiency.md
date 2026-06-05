# Performance and Efficiency Plan (68 -> 100)

## Definition of 100

- [x] No unbounded memory behavior on high-volume API paths.
- [x] VM lifecycle, exec, shell, and logs have benchmark baselines and SLOs.
- [x] Performance regressions are gated in CI.
- [x] Resource usage is observable and documented.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| PERF-001 | Rework `logs?follow=true` to stream without full-file preload | P1 | Done | Commit `ded9179`, bounded preload + streaming follow |
| PERF-002 | Add payload size limits and streaming patterns for read/write file endpoints | P1 | Done | Commit `ded9179`, policy-enforced file size limits |
| PERF-003 | Add benchmark harness for VM create, exec, shell latency, log throughput | P2 | Done | Commit `762f3dc`, `crates/husker-api/tests/perf_baseline.rs` |
| PERF-004 | Add p95 and p99 latency SLOs and fail CI on major regression | P2 | Done | Commit `762f3dc`, perf baseline CI lane |
| PERF-005 | Profile protocol encoding and evaluate switching to optimized base64 crate | P3 | Done | Commit `ec097fb`, `docs/performance/protocol-encoding-evaluation.md` |
| PERF-006 | Optimize hot allocation paths in shell relay loops | P3 | Done | Commit `ded9179`, shell/log relay hot paths tightened and bounded |
| PERF-007 | Add large-scale soak test (many VMs and concurrent operations) | P2 | Done | Commits `762f3dc`, `ec097fb`, nightly soak/chaos/perf workflow |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | PERF-001 and PERF-002 merged | Week 2 |
| M2 | PERF-003 and PERF-004 merged | Week 4 |
| M3 | PERF-005, PERF-006, PERF-007 merged | Week 6 |
| M4 | Two perf-gated CI cycles pass without regression | Week 7 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker-api/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker-agent/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker-agent-proto/src/lib.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | PERF-001 and PERF-002 merged | High-volume API paths now enforce bounded behavior |
| 2026-02-16 | PERF-003 and PERF-004 merged | Baseline test + SLO gate added to CI |
| 2026-02-16 | PERF-005, PERF-006, PERF-007 completed | Protocol/perf decisions documented and nightly soak lanes enabled |
