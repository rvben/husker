# Ship a QEMU-bootable kernel (the QEMU backend cannot boot husker's own kernel)

Status: design proposal (promote to `plans/` + `specs/` when scheduled).
Author context: surfaced while proving host bind-mounts end to end on a
bare-metal host. `--mount` auto-selects the QEMU backend (Firecracker cannot do
virtiofs), and the QEMU backend could not boot the kernel husker itself ships.

## Problem

`husker image pull` provides a flat `vmlinux`, and `guest/build-microvm-kernel.sh`
builds `make ARCH=x86_64 vmlinux` (`KTARGET=vmlinux`). QEMU direct-kernel boot
(`-kernel <vmlinux>`) rejects a flat uncompressed ELF that has no PVH ELF note:

```
Error loading uncompressed kernel without PVH ELF Note
```

So the QEMU/KVM backend cannot boot husker's own published or built kernel. Every
QEMU user must supply their own bzImage out of band. Because host bind-mounts
(`--mount`) auto-select QEMU, the feature is unusable out of the box on a host
that only has the husker-provided `vmlinux`.

Proven on a bare-metal N100 host: a `bzImage` built from the *same*
`build-microvm-kernel.sh` config boots cleanly under QEMU (gated tests
`qemu_boots_and_vsock` and `qemu_host_share_visible_in_guest` both pass), while
the flat `vmlinux` fails with the error above.

## Design (pick one)

**A. Emit a bzImage alongside vmlinux, ship both.**
`build-microvm-kernel.sh` also runs `make ARCH=x86_64 bzImage` and writes
`arch/x86/boot/bzImage` next to `vmlinux`; `husker image pull` ships both. The
daemon uses the bzImage for the QEMU backend and the flat `vmlinux` for
Firecracker (Firecracker needs the flat ELF, QEMU needs the bzImage - they are
genuinely different artifacts). Most robust; one extra, fast, incremental build
step (the compressed/boot wrapper over the already-compiled tree).

**B. Enable `CONFIG_PVH`, keep a single kernel.**
Add `cfg --enable PVH` so the single `vmlinux` carries the PVH ELF note and
*both* backends boot it. Simpler (one artifact) but only if (1) Firecracker still
boots a PVH-noted vmlinux and (2) `CONFIG_PVH`'s Kconfig dependencies are
satisfiable in the modules-free config. Verify both before choosing B over A.

## Daemon kernel selection

Whichever artifact is chosen, the QEMU backend must resolve a QEMU-bootable
kernel. Today `husker run|job --kernel <path>` is the only override; the daemon's
default kernel is a single flat `vmlinux`. Options: pick the bzImage automatically
when the backend is QEMU and a sibling bzImage exists, or add a per-backend
kernel path to `config.toml`.

## Secondary bug: build-microvm-kernel.sh exits 1 on success

`cleanup() { [ "$_OWN_WORK_DIR" = 1 ] && rm -rf "$WORK_DIR"; }` is the `EXIT`
trap. When `WORK_DIR` is provided externally (`_OWN_WORK_DIR=0`), the `[ ... ]`
test is false, the `&&` short-circuits, and the function returns 1 - so the
script exits 1 even though the kernel built successfully. Any caller that sets
`WORK_DIR` to keep the compiled tree (e.g. to then run `make bzImage`) sees a
false failure. Fix:

```sh
cleanup() { if [ "$_OWN_WORK_DIR" = 1 ]; then rm -rf "$WORK_DIR"; fi; }
```

## Verify

- `readelf -n vmlinux` on the current build: no `Xen PVH`/`PHYS32_ENTRY` note.
- After A or B: the QEMU gated e2e (`make test-qemu-e2e-gated`) boots without an
  out-of-band `HUSKER_E2E_KERNEL`.
- Firecracker boot still green after any kernel-config change (option B).
