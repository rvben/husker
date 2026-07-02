# Roadmap

Working notes on direction. The authoritative list of what has shipped is
[`CHANGELOG.md`](../CHANGELOG.md); this file only tracks direction and
sequencing, not a per-release feature log.

## Where things stand

Husker is pre-1.0. The core lifecycle (create/exec/shell/cp/destroy), one-shot
jobs, hot pools, services with a self-healing reconciler, persistent volumes,
memory balloon, port forwarding, bridged networking, cloud-image boot, OCI
import, idle policy, snapshots, secrets, and the `husker schema` contract are
all implemented. See the README platform matrix and `CHANGELOG.md` for the
current surface.

Backend maturity is uneven and this is the main thing to keep honest with users:

- **Linux / Firecracker** - most mature; the reference backend.
- **Linux / QEMU-KVM** - functional, incl. cloud-image (OVMF) boot and virtiofs
  host mounts; less battle-tested than Firecracker.
- **macOS / Apple VZ** - experimental; cloud-image EFI boot works on Apple
  Silicon, but a number of features (`--volume`, `--mount`, `--balloon`,
  services) are intentionally rejected there.

## Current focus (path to production-ready)

Grounded in the 2026-07 excellence audit (`.claude/investigations/`):

1. **Trustworthy CI** - real, monitored e2e for pools, suspend/fork, OCI boot,
   and cloud-image boot on every backend (several gates are currently disabled
   or unwired).
2. **Host-reality reconciliation** - sweep and reclaim orphaned TAP devices,
   sockets, cloned rootfs images, and IP allocations after an unclean daemon
   exit.
3. **Admission control** - max-VMs and memory-oversubscription limits, bounded
   exec-output capture.
4. **Scaling the daemon** - move SQLite off the async reactor, and stop pool
   checkout serializing on the template lock.
5. **Maintainability** - decompose the three oversized files that hold the bulk
   of the source.

## Known quirks to remember

- `[tool.maturin] include = [{ path = "LICENSE", format = "sdist" }]` is load-bearing. Maturin auto-adds `License-File: LICENSE` to PKG-INFO; PyPI rejects sdists where that file isn't in the archive. Don't remove it.
- macOS wheel codesigning happens post-build via unpack -> `codesign -s -` -> repack, because pip extracts the wheel payload into `$venv/bin/husker` and the signature has to be on the binary that lands there.
- The placeholder crate at `contrib/crates-io-placeholder-husker/` is a self-contained sub-workspace (empty `[workspace]` table) so `cargo build --workspace` ignores it and `cargo publish` bundles just its own sources.
- The default husker kernel is a from-source modules-free build with all virtio drivers compiled in; freshly pulled images boot without an initramfs on Apple VZ. The initramfs (built by `guest/build-initramfs.sh`) is only required when booting a legacy modular kernel such as Alpine `linux-virt`, where `virtio_blk` is a loadable module and omitting the initramfs causes a root-mount panic.
