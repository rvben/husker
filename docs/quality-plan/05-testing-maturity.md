# Testing Maturity Plan (72 -> 100)

## Definition of 100

- [x] Unit, integration, and e2e tests cover all critical paths.
- [x] Ignored tests are either automated in CI lanes or removed.
- [x] Fuzz and property tests exist for protocol and allocator/state logic.
- [x] Cross-platform coverage is enforced for Linux and macOS behavior.
- [x] Coverage and mutation quality gates are defined and enforced.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| TEST-001 | Move ignored e2e suites into dedicated CI jobs with environment gates | P1 | Done | Commit `762f3dc`, gated ignored-e2e CI jobs |
| TEST-002 | Add regression tests for known defects (initrd, pf atomicity, 503 mapping) | P1 | Done | Commits `5efa1b3`, `1fd8f61`, `b44f38c` + integration suites |
| TEST-003 | Add protocol fuzzing for message framing and base64 payload handling | P2 | Done | Commit `8efb119`, protocol property/fuzz-style roundtrip tests |
| TEST-004 | Add property tests for IP and CID allocators and lifecycle transitions | P2 | Done | Commits `ded9179` + current allocator/lifecycle property suites |
| TEST-005 | Add failure-injection tests across core operations | P1 | Done | Commit `762f3dc`, `crates/husker-core/tests/failure_injection.rs` |
| TEST-006 | Define and enforce minimum line coverage target and mutation quality gate | P2 | Done | Commits `762f3dc`, `ec097fb`, `make coverage-ci` + `make mutation-gate` |
| TEST-007 | Add snapshot/contract tests for OpenAPI and CLI output stability | P3 | Done | Commits `078d7d7`, `762f3dc` |
| TEST-008 | Add nightly long-run suite for soak, chaos, and performance checks | P2 | Done | Commit `762f3dc`, `.github/workflows/nightly-quality.yml` |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | TEST-001, TEST-002, TEST-005 merged | Week 3 |
| M2 | TEST-003, TEST-004, TEST-006 merged | Week 5 |
| M3 | TEST-007 and TEST-008 merged | Week 7 |
| M4 | 30 days of stable CI including nightly suites | Week 11 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker/tests/e2e.rs`
  - `/Users/ruben/Projects/husker/crates/husker-net/tests/e2e_bridge.rs`
  - `/Users/ruben/Projects/husker/crates/husker-api/tests/api_integration.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | TEST-001, TEST-005, TEST-007, TEST-008 merged | Dedicated CI/nightly lanes for ignored e2e, failure injection, and contracts |
| 2026-02-16 | TEST-003 and TEST-004 completed | Protocol + allocator/lifecycle property depth increased |
| 2026-02-16 | TEST-006 coverage/mutation gates enabled | Coverage and mutation checks now automated in quality workflows |
| 2026-02-17 | Coverage floor raised from 50% to 55% with targeted CLI helper tests | Workspace line coverage now sustained above 55% (`make coverage-ci`) |
| 2026-02-17 | Coverage floor raised to 70% enforced scope with additional core/vz tests | `make coverage-ci` now enforces line>=70 with explicit scope exclusions and passes |
| 2026-02-17 | Coverage floor raised to 73% with expanded agent protocol/error-path tests | `make coverage-ci` now enforces line>=73 and passes at 73.90% in enforced scope |
| 2026-02-17 | Coverage floor raised to 74% with additional wait-ready/storage branch tests | `make coverage-ci` now enforces line>=74 and passes at 74.14% in enforced scope |
| 2026-02-17 | Coverage floor raised to 75% with additional API policy/error-path tests | `make coverage-ci` now enforces line>=75 and passes at 75.55% in enforced scope |
| 2026-02-17 | Coverage floor raised to 76% with rootfs DNS injection path tests | `make coverage-ci` now enforces line>=76 and passes at 76.83% in enforced scope |
| 2026-02-17 | Coverage floor raised to 77% with additional API helper + resolv write-edge tests | `make coverage-ci` now enforces line>=77 and passes at 77.15% in enforced scope |
