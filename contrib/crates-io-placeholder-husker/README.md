# husker (crates.io name placeholder)

This directory contains a minimal crate published to crates.io as `husker`
solely to reserve the name while the project works toward its first real
release. The binary prints a redirect to the GitHub repository and exits
non-zero.

It is **not** part of the main workspace. Building from the repository root
with `cargo build --workspace` ignores this crate.

## Publishing

```bash
cd contrib/crates-io-placeholder
cargo publish
```

## Removal

When the first real release lands on crates.io, this directory is deleted
and the `husker` crate name transitions from placeholder to the actual
microVM manager binary.
