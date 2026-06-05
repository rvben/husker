# API and UX Consistency Plan (70 -> 100)

## Definition of 100

- [x] API status codes and error schema are predictable and documented.
- [x] CLI behavior and messaging match API semantics.
- [x] OpenAPI spec is complete and tested against runtime behavior.
- [x] Interactive shell and logs UX is robust under edge cases.
- [x] Backward compatibility rules are defined and enforced.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| UX-001 | Introduce canonical error response schema: `code`, `message`, `hint`, `details` | P1 | Done | Commit `ded9179`, API error contract tests |
| UX-002 | Align 5xx vs 4xx mapping for transient and state errors (including agent readiness) | P1 | Done | Commits `b44f38c`, `ded9179` |
| UX-003 | Add consistent idempotency semantics for lifecycle and port-forward endpoints | P2 | Done | Commits `00cb6b8`, `ded9179` |
| UX-004 | Improve CLI hints and error normalization across all commands | P2 | Done | Commit `078d7d7`, normalized CLI error handling |
| UX-005 | Add JSON output mode for CLI (`--output json`) with stable schema | P3 | Done | Commit `078d7d7`, CLI output contract tests |
| UX-006 | Complete OpenAPI examples and ensure docs include all platform-specific caveats | P2 | Done | Commits `762f3dc`, `ec097fb`, OpenAPI contract tests + docs |
| UX-007 | Harden shell and logs UX around disconnects, truncation, and close signaling | P2 | Done | Commit `ded9179`, shell/log robustness tests |
| UX-008 | Add compatibility policy and deprecation workflow for API/CLI changes | P3 | Done | Commit `ec097fb`, `docs/compatibility.md` |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | UX-001, UX-002 merged | Week 2 |
| M2 | UX-003, UX-004, UX-006 merged | Week 4 |
| M3 | UX-005, UX-007, UX-008 merged | Week 6 |
| M4 | Zero contract drift across two releases | Week 10 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker-api/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker/src/main.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | UX-001, UX-002, UX-003, UX-007 completed | API contract/status consistency and shell/log edge-case handling improved |
| 2026-02-16 | UX-004 and UX-005 completed | CLI messages normalized and machine-readable JSON output added |
| 2026-02-16 | UX-006 and UX-008 completed | OpenAPI contract coverage and compatibility policy documented |
