# Maintainability and Code Quality Plan (84 -> 100)

## Definition of 100

- [x] Architectural boundaries are explicit and documented.
- [x] Duplicate logic is reduced with shared abstractions where justified.
- [x] Error handling and API error contracts are uniform and typed.
- [x] Linting, formatting, and static analysis are complete and enforced.
- [x] New contributors can ship changes using clear developer docs and runbooks.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| MAINT-001 | Add architecture decision records for networking, auth, and protocol choices | P2 | Done | Commit `ec097fb`, `docs/adr/` |
| MAINT-002 | Extract shared vsock-connect handshake helper used by core and vmm code | P2 | Done | Commit `551d5c8` |
| MAINT-003 | Normalize error taxonomy with machine-readable codes at API boundary | P1 | Done | Commit `ded9179`, typed API error schema + tests |
| MAINT-004 | Introduce dependency policy (`cargo deny`) and document approved crates | P2 | Done | Commits `2b54546`, `ec097fb` |
| MAINT-005 | Add module-level docs for all public crates and key internals | P3 | Done | Commit `ec097fb`, crate-level rustdoc headers |
| MAINT-006 | Add changelog and release checklist with required quality gates | P3 | Done | Commit `ec097fb`, `CHANGELOG.md`, `docs/release-checklist.md` |
| MAINT-007 | Add debt register with severity, owner, and due date | P2 | Done | Commit `ec097fb`, `docs/debt-register.md` |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | MAINT-003 and MAINT-002 merged | Week 4 |
| M2 | MAINT-001, MAINT-004, MAINT-007 merged | Week 6 |
| M3 | MAINT-005 and MAINT-006 merged | Week 7 |
| M4 | Two release cycles with checklist pass and zero major rollback | Week 11 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker-core/src/agent_client.rs`
  - `/Users/ruben/Projects/husker/crates/husker-api/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker-vmm/src/firecracker.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | MAINT-002 and MAINT-003 completed | Shared handshake abstraction and typed API error taxonomy in place |
| 2026-02-16 | MAINT-001, MAINT-004, MAINT-006, MAINT-007 completed | ADR/dependency/release/debt governance established |
| 2026-02-16 | MAINT-005 completed | Public crates now include module-level documentation headers |
