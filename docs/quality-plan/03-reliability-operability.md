# Reliability and Operability Plan (60 -> 100)

## Definition of 100

- [x] Startup, shutdown, and restart behavior are deterministic and tested.
- [x] Recovery from partial failure is automatic where safe.
- [x] Health endpoints reflect real subsystem state.
- [x] Metrics and logs support fast incident triage.
- [x] Runbooks exist for all common failure modes.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| REL-001 | Expand health endpoint with subsystem checks (state DB, VMM backend, network backend) | P1 | Done | Commit `ded9179`, health integration tests |
| REL-002 | Add startup reconciliation for stale VM/process/network artifacts | P1 | Done | Commit `ded9179`, startup recovery logs/tests |
| REL-003 | Make log follow robust to rotation/truncation without silent stalls | P2 | Done | Commit `ded9179`, log-follow resilience tests |
| REL-004 | Add graceful-shutdown drills in CI, including timeout and forced-stop paths | P1 | Done | Commit `762f3dc`, `scripts/ci/graceful_shutdown_drill.sh` |
| REL-005 | Export Prometheus metrics for lifecycle operations, errors, and queue latency | P2 | Done | Commits `ded9179`, `ec097fb`, `/v1/metrics` + docs |
| REL-006 | Standardize structured logs with request and VM correlation IDs | P2 | Done | Commit `ded9179`, `x-request-id` middleware |
| REL-007 | Write incident runbooks for top 10 operational failures | P2 | Done | Commit `ec097fb`, `docs/operations/runbooks.md` |
| REL-008 | Add chaos tests: kill daemon mid-create, mid-port-forward, mid-userdata | P1 | Done | Commit `762f3dc`, `scripts/ci/chaos_restart_drill.sh` |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | REL-001, REL-002, REL-004 merged | Week 3 |
| M2 | REL-003, REL-005, REL-006 merged | Week 5 |
| M3 | REL-007 and REL-008 merged | Week 6 |
| M4 | 14-day reliability burn-in with no Sev-1 incidents in test environment | Week 8 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker/src/main.rs`
  - `/Users/ruben/Projects/husker/crates/husker-api/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker-core/src/lib.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | REL-001, REL-002, REL-003, REL-005, REL-006 completed | Health/metrics/logging/recovery posture hardened |
| 2026-02-16 | REL-004 and REL-008 drill automation added | Graceful shutdown and chaos restart paths validated in automation |
| 2026-02-16 | REL-007 runbooks published | Top operational failures now have documented response playbooks |
