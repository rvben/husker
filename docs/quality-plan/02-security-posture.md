# Security Posture Plan (45 -> 100)

## Definition of 100

- [x] API access is authenticated and authorized for non-local use.
- [x] Secure defaults prevent accidental remote exposure.
- [x] Guest file and command operations enforce least privilege policy.
- [x] Threat model documented and validated with tests.
- [x] Dependency, secret, and vulnerability scanning are mandatory in CI.
- [x] No open high or critical findings in code or dependencies.

## Work items

| ID | Task | Priority | Status | Evidence to close |
|---|---|---|---|---|
| SEC-001 | Enforce local-only default plus explicit `--allow-remote` guardrail for non-loopback binds | P1 | Done | Commit `f577f2e`, `cargo test -p husker` |
| SEC-002 | Add API auth (token or mTLS) and enforce on all mutating and shell endpoints | P1 | Done | Commit `538072d`, `cargo test -p husker-api -p husker` |
| SEC-003 | Add rate limits for shell, exec, and file endpoints to reduce abuse blast radius | P2 | Done | Commit `ded9179`, 429 middleware tests |
| SEC-004 | Add optional guest path allowlist for read/write operations | P1 | Done | Commit `ded9179`, allowlist enforcement tests |
| SEC-005 | Add execution policy hooks (timeout, command allow/deny list, env key allowlist) | P1 | Done | Commit `ded9179`, exec policy tests |
| SEC-006 | Add structured audit log for sensitive operations (exec, write_file, shell) | P2 | Done | Commits `5bb461f`, `ded9179` |
| SEC-007 | Produce STRIDE-based threat model and map controls to code | P2 | Done | Commit `ec097fb`, `docs/security/threat-model.md` |
| SEC-008 | Add `cargo audit` and `cargo deny` CI gates | P1 | Done | Commits `6ded528`, `2b54546`, `ec097fb` |
| SEC-009 | Add hardening guide for capabilities, user permissions, and deployment topology | P2 | Done | Commit `ec097fb`, `docs/security/hardening-guide.md` |
| SEC-010 | Security regression suite: auth bypass, unsafe default, and abuse tests | P1 | Done | Commits `762f3dc`, `ec097fb`, `docs/security/regression-suite.md` |

## Milestones

| Milestone | Exit criteria | Target |
|---|---|---|
| M1 | SEC-001, SEC-002, SEC-008 merged | Week 2 |
| M2 | SEC-004, SEC-005, SEC-006 merged | Week 4 |
| M3 | SEC-003, SEC-007, SEC-009, SEC-010 merged | Week 6 |
| M4 | No high/critical findings in two consecutive scans | Week 7 |

## Notes

- Source hotspots:
  - `/Users/ruben/Projects/husker/crates/husker-api/src/lib.rs`
  - `/Users/ruben/Projects/husker/crates/husker/src/main.rs`
  - `/Users/ruben/Projects/husker/crates/husker-agent/src/lib.rs`

## Progress log

| Date | Update | Impact |
|---|---|---|
| 2026-02-16 | Plan created | Baseline established |
| 2026-02-16 | SEC-001 and SEC-002 merged | Remote exposure and unauthenticated mutating access risks reduced |
| 2026-02-16 | SEC-006 partial implementation merged | Sensitive operation audit fields now emitted in API logs |
| 2026-02-16 | SEC-008 partial implementation merged | `cargo-deny` gate active; `cargo-audit` version/tooling alignment pending |
| 2026-02-16 | SEC-003, SEC-004, SEC-005 completed | Least-privilege and abuse controls enforced on file/exec endpoints |
| 2026-02-16 | SEC-007, SEC-009, SEC-010 completed | Threat model, hardening guide, and security regression suite documented and enforced |
