# Testing Quality Gates

## Mandatory CI gates

- Unit/integration suite: `make test`
- macOS compile/test lane: `make check-macos`, `make test-macos`
- Contracts:
  - OpenAPI contract tests
  - CLI JSON output schema tests
- Failure-injection lifecycle tests
- Perf baseline regression test
- Coverage threshold gate (`cargo llvm-cov`)
- Mutation smoke gate (`cargo mutants --list --package husker-agent-proto`)
- Scheduled libFuzzer campaigns for protocol frames and base64 input
- Dependency security/policy (`cargo audit`, `cargo deny`)

## Gated suites

- Ignored end-to-end suites are executed only when explicitly enabled:
  - `HUSKER_RUN_IGNORED_E2E=1`
  - `HUSKER_RUN_NET_E2E=1`
- These lanes run in CI and nightly with environment gates.

## Nightly lane

- `make nightly-quality` runs:
  - perf baseline
  - failure injection
  - mutation gate
  - graceful shutdown drill
  - chaos restart drill
  - gated ignored e2e suites

## Coverage policy

- Workspace coverage floor (enforced by `make coverage-ci`):
  - line >= 77%
- Coverage scope exclusions:
  - `crates/husker/src/main.rs` (CLI binary entrypoint orchestration)
  - `crates/husker-agent/src/main.rs` (agent binary entrypoint bootstrap)
  - `crates/husker-vmm/src/apple_vz.rs` (platform-specific Virtualization.framework FFI shim)
- Last validated:
  - 2026-02-17 (`make coverage-ci` passed with 77.15% line coverage in enforced scope)

## Mutation policy

- CI enforces mutation-tooling viability via `make mutation-gate`.
- Scope is focused on protocol semantics and complements the fuzz lane.

## Fuzzing policy

- `make fuzz-check` compiles all fuzz targets with nightly Rust.
- `make fuzz-smoke` runs bounded local campaigns.
- `.github/workflows/protocol-fuzz.yml` runs independent three-minute scheduled
  campaigns and preserves any crash artifacts for reproduction.
