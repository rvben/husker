# Technical Debt Register

> Reviewed 2026-08-17. There are no accepted active debt items. New debt must
> include an owner, severity, review-by date, and a concrete retirement test.

## Active debt

None.

## Closed debt

| ID | Area | Closed | Resolution and retirement evidence |
|---|---|---:|---|
| DEBT-001 | Auth | 2026-08-17 | ADR 0002 defines one daemon as one trust domain. Remote identity belongs at a loopback proxy or service-mesh boundary; Husker's shared bearer token is intentionally not multi-user RBAC. See `docs/adr/0002-api-authentication.md`, `docs/security/hardening-guide.md`, and `docs/security/threat-model.md`. |
| DEBT-002 | CLI | 2026-08-17 | `husker --output json config check` emits a typed report, includes effective environment overrides, and has process-level success and failure tests (`26cbe1b`). |
| DEBT-003 | Testing | 2026-08-17 | Privileged Linux and macOS self-hosted runners execute the gated E2E workflows. Scheduled and dispatch runs were verified green on 2026-08-17 for Firecracker, QEMU, VZ cloud images, OCI boot, idle policy, suspend/fork, pools, and rollback. Workflow definitions remain the executable evidence under `.github/workflows/`. |
| DEBT-004 | Performance | 2026-08-17 | The privileged Firecracker suite now bounds cold boot, exec p95, output-before-exit, shell readiness, serial-log transfer, and destroy latency (`66549f4`, `runtime_performance_baseline`). |
| DEBT-005 | Protocol | 2026-08-17 | `cargo-fuzz` targets cover protocol frames and base64, with scheduled and manual CI campaigns plus local smoke targets (`557aec4`, `fuzz/`, `.github/workflows/protocol-fuzz.yml`). |
| DEBT-006 | Images | 2026-08-17 | The initramfs starts the `hvc0` getty only when `/dev/hvc0` exists and keeps a supervisor sleep fallback. `guest/test-initramfs.sh` guards both properties (`64796ea`). |
| DEBT-007 | Runtime | 2026-08-17 | Startup orphan reaping kills only the VMM process identified by persisted runtime state. Linux tests cover identified-process reaping, dead/stopped skips, and the non-QEMU running case. |
| DEBT-008 | Protocol | 2026-08-17 | Protocol v4 streams binary-safe stdout/stderr chunks with backpressure, timeouts, and exit status through agent, WebSocket API, `husker exec`, and text-mode `husker job`. JSON output remains intentionally atomic. Old daemons fall back only before command submission; old guest images use buffered execution with an actionable refresh warning. Compatibility, ordering, and no-replay behavior are covered (`102c55d`, `23fddd1`). A live CacheFerret job on Linux emitted markers before process exit and completed its full acceptance workflow. |
| DEBT-009 | Deployment | 2026-08-17 | Transactional Linux deploys use a locked, root-owned Cargo cache and stable checksum-synchronized source mirror, copy the candidate into the commit-private stage before cutover, and retain full-LTO release semantics outside the fast deploy profile (`efacbed`, `28050c6`, `f7379a3`). The general E2E gate preserves the embedded-agent build input so a warm run does not rebuild the workspace (`7f4499a`). Verified deployment times were 4m15s for changed code and 23-33s for docs-only or unchanged commits, down from roughly 20 minutes. |
| DEBT-010 | Build | 2026-08-17 | Swagger UI assets are vendored through the lockfile, eliminating an unverified build-time GitHub download (`7c70fe8`). E2E scripts explicitly embed the agent from custom `CARGO_TARGET_DIR` paths and assert the resulting capability (`3f09626`). |
| DEBT-011 | Testing | 2026-08-17 | CLI fallback process tests force an unreachable loopback endpoint and remove inherited context selection, so running the suite beside a live daemon cannot create a VM (`e91e874`). |

## Latest retirement verification

Verified on 2026-08-17 at `23fddd1`:

- Linux workspace: 1,256 tests passed under nextest; 29 explicitly skipped.
- Privileged Firecracker general E2E: 12 of 12 passed, including output before
  exit, VM lifecycle, shell, suspend/resume, fork, and runtime performance.
- Linux `make lint`: formatting, warnings-denied Clippy, macOS configuration
  validation, and deployment-script checks passed.
- Live CacheFerret acceptance: library, CLI, CLI Spec v0.3, Clippy, release
  build, schema, scan, dry-run, targeted cleanup, safe no-op cleanup, and XDG
  cache fallback all passed inside a fresh Husker VM.
- A final same-commit deployment completed in 33.494s, reused the identical
  artifact without restarting the service, removed its staging directory, and
  left the production daemon healthy with zero automatic restarts.

## Review policy

- Close an item only when its retirement test or architectural decision is in
  the repository and has been exercised on the relevant platform.
- Reopen by moving the row back to **Active debt** with a current owner and
  review-by date; do not silently weaken the closure evidence.
- A consciously bounded product model is not debt when the boundary, threat
  model, and operator responsibility are explicit.
