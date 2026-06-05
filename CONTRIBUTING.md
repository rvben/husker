# Contributing to husker

Thanks for your interest. husker is pre-1.0 and moves quickly — please open an issue before starting non-trivial work so we can agree on scope.

## Development setup

Requires Rust 1.90+ (2024 edition) and `cargo-nextest`.

```bash
make build
make test          # nextest, fast
make test-unit     # --lib only
make lint          # fmt --check + clippy -D warnings
make check         # cargo check --workspace
```

macOS builds disable the `linux-net` feature automatically via `make test-macos` / `make check-macos` / `make install`. Anything that touches host networking belongs behind `#[cfg(feature = "linux-net")]`.

See [CLAUDE.md](CLAUDE.md) for the architecture overview and `docs/` for per-area guides.

## Commit messages

Conventional Commits with the affected crate as scope:

```
feat(core): add port forwarding support
fix(agent): handle vsock connection timeouts
refactor(vmm): simplify Firecracker API client
```

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `chore`, `test`, `ci`.

Keep messages factual. Avoid subjective qualifiers and references to internal planning labels.

## Pull requests

- One logical change per PR. Unrelated cleanup goes in a separate PR.
- Tests required for behavior changes. Use the mock `VmmBackend` and in-memory state store — integration tests should not require a real hypervisor.
- CI runs on Ubuntu and macOS and enforces `-D warnings`. Fix clippy warnings; don't paper them over with `#[allow(...)]`.
- No dead code. Wire it up or delete it.
- Error handling: `thiserror` in libraries, `anyhow` in binaries.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for security reports.

## License

By contributing, you agree that your contributions are licensed under the project's [LICENSE](LICENSE) (MIT).
