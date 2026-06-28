# Host Bind-Mounts (`--mount`)

`husker run` and `husker job` can share a host directory into a VM over
[virtiofs](https://virtio-fs.gitlab.io/), making live host files available
inside the guest without copying.

## When to use `--mount` vs `--sync-cwd`

| | `--mount` | `--sync-cwd` |
|---|---|---|
| Mechanism | virtiofs (live share, no copy) | git-aware rsync into the VM |
| Host changes visible in guest? | Yes, immediately | No - snapshot at launch |
| Guest writes visible on host? | Yes, immediately | Only via `--out` / `--write-back` |
| QEMU only? | Yes | No |
| Works with `--pool`? | Yes (QEMU pool) | Yes |

Use `--mount` when the guest needs to read or write host files in real time
(e.g. a Rust build that writes to the host source tree or a long-running
service that watches a config file). Use `--sync-cwd` when you want
isolation and controlled write-back.

## Syntax

```
husker job --mount <host>:<guest>[:ro] -- <cmd>
husker run --mount <host>:<guest>[:ro] --name <vm>
```

- `<host>` - absolute path on the host that the daemon is allowed to share
- `<guest>` - mount point inside the VM (created if absent)
- `:ro` - optional suffix to mount the share read-only in the guest
- The flag is repeatable; each use adds one share.
- Default guest path when `<guest>` is omitted: `/mnt/<host-basename>`.
- `--mount` runs on the QEMU backend; husker selects QEMU automatically when
  `--vmm` is unset (Firecracker cannot do virtiofs), so no `--vmm qemu` is needed.

## Example: Rust iterative build

Build a Rust project inside a fresh QEMU VM, with the source tree live-shared
from the host and a persistent cargo cache volume:

```bash
husker job \
  --profile rust \
  --mount "$(pwd):/work" \
  --volume cargo-cache \
  -- sh -c 'cd /work && CARGO_HOME=/data cargo build --release'
```

- `--profile rust` selects a pre-configured VM preset (CPUs, memory, image).
- `--mount "$(pwd):/work"` shares the current directory into `/work` in the guest.
- `--volume cargo-cache` attaches a named persistent disk. The guest agent
  auto-mounts it at `/data` - no manual `mount /dev/vdb` step required.
- `CARGO_HOME=/data` points Cargo at the auto-mounted volume so the registry
  and compiled deps survive across jobs.
- On teardown the daemon sends a graceful flush signal to the guest agent,
  which calls `sync()` and unmounts `/data` before the VM process is killed,
  so all writes to the volume are durable. No manual `sync; umount` is needed.
- The build artifacts land in `$(pwd)/target/` on the host in real time.

## Security

The daemon gates host paths through the `allowed_mount_host_paths` list in
`config.toml`. An empty list (the default) denies all mounts - no path can be
shared unless the operator explicitly opts it in:

```toml
[daemon]
allowed_mount_host_paths = ["/home/ci/workspace", "/data/builds"]
```

Paths are matched as exact prefixes: a configured path of `/home/ci/workspace`
allows any sub-path under it. Paths outside the allowlist are rejected by the
daemon before the VM starts.

For untrusted or agentic jobs, mount only the paths the job strictly needs. Do
not add broad directories like `/home` or `/` to the allowlist.

## Volume auto-mount and durable teardown

When a volume is attached with `--volume <name>`, the guest supervisor
auto-mounts it at `/data` before the workload starts. This applies to
direct-kernel VMs (the default microVM path using a husker OCI image).
Cloud-image VMs already mount `/dev/vdb` at `/data` via cloud-init and
are handled by the same convention.

On `destroy` (or when a `husker job` completes), the daemon sends a
`Shutdown` message to the in-guest agent before killing the VM process.
The agent calls `sync()` to flush all dirty pages to disk and unmounts
`/data` with a lazy detach, then replies. The daemon waits up to 3 s for
the reply before proceeding with the hard kill. This guarantees that writes
to the volume are durable on the host even when the VM is force-killed.

No manual `mount /dev/vdb ...`, `sync`, or `umount` step is needed.

## Known limitations

**QEMU only.** Firecracker does not support virtiofs, so `--mount` runs on the
QEMU backend. When `--vmm` is unset, husker selects QEMU automatically as soon
as a `--mount` is present, so you do not need to pass `--vmm qemu`. Passing
`--vmm firecracker` together with `--mount` is rejected rather than silently
producing a VM without the share.

**Cloud-image (UEFI) VMs.** When booting with `--cloud-image`, the virtiofs
device is attached to the VM but the guest does not receive the
`husker.share=` kernel command-line token (UEFI boot has no kernel command
line). The guest-agent host-share auto-mount path therefore does not trigger
for `--mount`. Use the direct-kernel OCI rootfs path (`husker images pull`)
for host shares; cloud images do not benefit from `--mount` in the current
release. Volume auto-mount (`--volume`) is unaffected: cloud-init handles it.

**QEMU direct-kernel boot needs a PVH kernel.** The husker default x86_64 kernel
(`husker images pull`) is built with `CONFIG_PVH`, so QEMU direct-boots it and
`--mount` works out of the box; the same image still boots under Firecracker.
Only a custom kernel built without the PVH ELF note (a plain `vmlinux`) fails
under QEMU with "loading uncompressed kernel without PVH ELF Note"; pass a PVH or
bzImage kernel via `--kernel` in that case.
