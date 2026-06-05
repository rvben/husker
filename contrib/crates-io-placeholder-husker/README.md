# husker (crates.io name placeholder)

This directory contains a minimal crate published to crates.io as `husker` to
reserve the name. **husker is intentionally not distributed via crates.io** - it
ships as a prebuilt binary:

- `pip install husker`
- `brew install rvben/tap/husker`
- GitHub Releases: <https://github.com/rvben/husker/releases>

The binary in this crate just prints those instructions and exits non-zero, so
anyone who runs `cargo install husker` is pointed at the real install methods.
The internal workspace crates (`husker-core`, `husker-vmm`, etc.) are
implementation modules and are deliberately not published.

It is **not** part of the main workspace. Building from the repository root with
`cargo build --workspace` ignores this crate.

## Publishing

```bash
cd contrib/crates-io-placeholder-husker
cargo publish
```
