# Contributing to husker

Thanks for your interest. husker is pre-1.0 and moves quickly, so please open an issue before starting non-trivial work so we can agree on scope.

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

See `docs/` for per-area guides and [docs/adr/](docs/adr/) for the architecture decisions behind them.

## Packaging notes

- `[tool.maturin] include = [{ path = "LICENSE", format = "sdist" }]` is load-bearing. Maturin adds `License-File: LICENSE` to PKG-INFO, and PyPI rejects an sdist that does not contain that file.
- macOS wheels are codesigned after the build (unpack, `codesign -s -`, repack), because pip extracts the wheel payload into `$venv/bin/husker` and the signature has to be on the binary that lands there.
- The placeholder crate at `contrib/crates-io-placeholder-husker/` is a self-contained sub-workspace (empty `[workspace]` table), so `cargo build --workspace` ignores it and `cargo publish` bundles only its own sources.
- The default guest kernel is a modules-free build with all virtio drivers compiled in, so pulled images boot without an initramfs on Apple VZ. The initramfs from `guest/build-initramfs.sh` is needed only for a legacy modular kernel such as Alpine `linux-virt`, where `virtio_blk` is a loadable module and booting without it panics at root mount.

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
- Tests required for behavior changes. Use the mock `VmmBackend` and in-memory state store; integration tests should not require a real hypervisor.
- CI runs on Ubuntu and macOS and enforces `-D warnings`. Fix clippy warnings; don't paper them over with `#[allow(...)]`.
- No dead code. Wire it up or delete it.
- Error handling: `thiserror` in libraries, `anyhow` in binaries.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for security reports.

## License

By contributing, you agree that your contributions are licensed under the project's [LICENSE](LICENSE) (MIT).
