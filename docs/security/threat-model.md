# Threat Model (STRIDE)

Last updated: 2026-02-16

## Scope

- Daemon API (`crates/husker-api`)
- Core lifecycle/state engine (`crates/husker-core`, `crates/husker-state`)
- Guest agent channel (`crates/husker-agent`, `crates/husker-agent-proto`)
- Host networking and port-forward path (`crates/husker-net`, Linux only)

## Assets

- Host integrity (process control, nftables rules, filesystem)
- VM isolation boundaries and lifecycle state
- Guest command/file execution channels
- API credentials and audit trail
- Persistent state (SQLite and runtime files)

## STRIDE analysis

| Category | Threat | Current control(s) | Validation |
|---|---|---|---|
| Spoofing | Unauthorized API caller invokes mutating endpoints | Bearer token auth on protected routes; local-only default bind unless `--allow-remote` | `cargo test -p husker-api` auth middleware tests |
| Tampering | Guest file operations target unsafe paths | Path normalization + optional read/write allowlists | API integration tests for policy denial |
| Repudiation | Sensitive actions not attributable | Structured audit logs for `exec`, file read/write, shell start/exit; request ID propagation | API unit/integration tests + log schema checks |
| Information Disclosure | Excessive file read payload leaks data | Read-size policy limits; explicit policy error code | API integration tests |
| Denial of Service | Abuse via shell/exec/files endpoints | Sliding-window per-client rate limit on sensitive routes; request body max limit | Rate-limit middleware tests (429 path) |
| Elevation of Privilege | Dangerous guest commands or env injection | Exec allow/deny policy, env allowlist, timeout | Exec policy tests in API crate |
| Tampering/DoS | State/network drift after crash/restart | Startup reconciliation of persisted port forwards; idempotent lifecycle ops | Core startup reconciliation + lifecycle tests |

## Residual risk

- Bearer token auth is single-factor; mTLS is not implemented yet.
- Host hardening remains deployment-dependent (system user, service manager, firewall).
- Privileged Linux networking actions still require elevated permissions on host.

## Planned periodic validation

- CI security gates: `cargo deny`, `cargo audit`, security regression tests.
- Nightly drills: chaos restart + graceful shutdown scripts.
- Pre-release checklist: no open high/critical dependency findings.
