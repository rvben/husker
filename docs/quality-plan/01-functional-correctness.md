# Functional Correctness Plan (63 -> 100)

## Definition of 100

- [x] Firecracker honors `initrd_path` end-to-end.
- [x] Port-forward add/remove paths are atomic between nftables and SQLite state.
- [x] API returns stable, intentional status codes for all expected failure classes.
- [x] VM lifecycle operations are idempotent where documented.
- [x] No open correctness bugs in the last 30 days from regression suite runs.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| FC-001 | Add Firecracker `initrd_path` wiring in `/boot-source` payload and cover with integration tests | P1 | Done | Commit `5efa1b3`, `cargo test -p husker-vmm` |
| FC-002 | Make `add_port_forward` transactional: rollback nft rule if DB insert fails, or persist first then apply with compensation | P1 | Done | Commit `1fd8f61`, `cargo test -p husker-core` |
| FC-003 | Map transient agent-connect failures during boot to 503 (not 500), and keep mapping deterministic | P1 | Done | Commit `b44f38c`, `cargo test -p husker-api` |
| FC-004 | Add startup reconciler for nftables rules vs `port_forwards` table drift | P2 | Done | Commit `ded9179`, `cargo test -p husker-core` |
| FC-005 | Define and enforce idempotency behavior for stop/pause/resume/destroy endpoints | P2 | Done | Commit `00cb6b8`, `cargo test -p husker-core -p husker-api` |
| FC-006 | Add property-style lifecycle tests for random valid/invalid state transitions | P2 | Done | Commit `ded9179`, `cargo test -p husker-core --test state_transitions` |
| FC-007 | Add regression tests for all previously reported correctness defects | P2 | Done | Commits `b44f38c`, `ded9179`, `762f3dc`, regression suites green |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | FC-001, FC-002, FC-003 merged | Week 1 |
| M2 | FC-004 and FC-005 merged | Week 2 |
| M3 | FC-006 and FC-007 merged | Week 3 |
| M4 | 2 consecutive weeks with zero correctness regressions | Week 5 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker-vmm/src/firecracker.rs`
  - `/Users/ruben/Projects/husker/crates/husker-core/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker-api/src/lib.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | FC-001, FC-002, FC-003 merged in Phase 0 | P1 correctness blockers closed |
| 2026-02-16 | FC-005 merged (idempotent stop/pause/resume no-op semantics) | API lifecycle behavior stabilized |
| 2026-02-16 | FC-004 and FC-006 merged | Restart reconciliation and lifecycle property coverage added |
| 2026-02-16 | FC-007 closed | Regression suites cover previously reported correctness defects |
