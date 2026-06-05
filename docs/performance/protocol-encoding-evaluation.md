# Protocol Encoding Evaluation

Date: 2026-02-16

## Question

Should husker switch from the current base64 helpers to a different base64 crate for protocol payload performance?

## Findings

- Current implementation is simple, dependency-light, and heavily tested.
- Added property tests now exercise randomized payload roundtrips and frame decode safety.
- API perf baseline does not show protocol encoding as a dominant bottleneck in current read-path workloads.

## Decision

- Keep current encoding implementation for now.
- Re-evaluate when:
  - shell/log throughput benchmark lane is added
  - profiling shows encoding hot-path dominance

## Follow-up

- Track under `DEBT-005` until dedicated fuzz/perf lane for protocol framing is expanded.
