# Roadmap

Uncommitted working notes. What's shipped, what's next, and the sequencing.

## Shipped: v0.1.0

- `husker images pull` downloads the default kernel + rootfs (and initramfs on macOS) for the host arch, verifying against a `SHA256SUMS` manifest.
- `husker run` with no rootfs arg falls back to the configured default rootfs/kernel/initrd. If any default is missing, the CLI prints the path and hints at `husker images pull`.
- On Linux, `husker run` offers to auto-install a pinned Firecracker release when the binary is missing from PATH and `HUSKER_AUTO_INSTALL_FIRECRACKER=1` is set.
- Default images built monthly by `.github/workflows/build-images.yml` and published as `images-YYYY-MM-DD` GitHub Releases with a merged `SHA256SUMS`.
- Apple VZ boot path validated end-to-end: Alpine `linux-virt` kernel + arch-specific initramfs + ext4 rootfs, agent reachable over vsock port 52.

## Shipped: v0.0.1

- `pip install husker` → native binary, codesigned on macOS with Apple VZ entitlement.
- PyPI wheels: `manylinux_2_28` x86_64 + aarch64, macOS x86_64 + arm64.
- GitHub Release at `v0.0.1` with matching tar.gz archives + SHA256.
- crates.io: name held by placeholder (`contrib/crates-io-placeholder/`, `0.0.1`).
- BYO expected: users supplied their own kernel and rootfs.

## In progress / next

- QEMU/KVM backend (Linux, direct-kernel boot): selectable via `vmm = "qemu"` in config
  or `HUSKER_VMM=qemu`; guest agent reachable over vsock, same model as the Firecracker
  path. Future phases: OVMF/cloud-image boot, graphical console, VFIO device passthrough.

## Not blocking v0.1.0 but worth tracking

- Homebrew tap formula for `husker` (unifi-cli workflow has a template to crib).
- `cargo install husker` story: either publish real crates (more maintenance, full namespace) or keep the placeholder forever and point people at PyPI + GitHub Releases.
- Project-scoped PyPI trusted publishing via OIDC instead of a long-lived token.
- Firecracker download sha256 verification — currently out of scope; GitHub release is trusted. Pin and verify in a follow-up.
- `macos-14` arm64 runners are the default on `macos-latest` now; the x86_64-apple-darwin build is cross-compiled on arm64. If it ever flakes badly, fall back to explicit `macos-13` for that entry.

## Known quirks to remember

- `[tool.maturin] include = [{ path = "LICENSE", format = "sdist" }]` is load-bearing. Maturin auto-adds `License-File: LICENSE` to PKG-INFO; PyPI rejects sdists where that file isn't in the archive. Don't remove it.
- macOS wheel codesigning happens post-build via unpack → `codesign -s -` → repack, because pip extracts the wheel payload into `$venv/bin/husker` and the signature has to be on the binary that lands there.
- The placeholder crate at `contrib/crates-io-placeholder/` is a self-contained sub-workspace (empty `[workspace]` table) so `cargo build --workspace` ignores it and `cargo publish` bundles just its own sources.
- The default husker kernel is a from-source modules-free build with all virtio drivers compiled in; freshly pulled images boot without an initramfs on Apple VZ. The initramfs (built by `guest/build-initramfs.sh`) is only required when booting a legacy modular kernel such as Alpine `linux-virt`, where `virtio_blk` is a loadable module and omitting the initramfs causes a root-mount panic.
