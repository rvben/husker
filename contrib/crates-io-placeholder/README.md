# shuck (deprecated crates.io name)

This directory contains a minimal crate published to crates.io as `shuck`.
The project was renamed to **husker** (the old name collided with an existing
shell linter). This crate now exists only to redirect: its binary prints a
notice pointing at the new project and exits non-zero.

Install the current tool from <https://github.com/rvben/husker>.

It is **not** part of the main workspace. Building from the repository root
with `cargo build --workspace` ignores this crate.

## Publishing the deprecation notice

```bash
cd contrib/crates-io-placeholder
cargo publish
```

The version must be greater than the last published `shuck` (currently
`0.0.1`), so this crate is pinned to `0.0.2`.
